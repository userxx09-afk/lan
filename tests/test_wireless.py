"""Wi-Fi: a PC reports its connection and BSSID, the AP is named from the controller's list or a switch port's LLDP
neighbour, controller polls place every client, and each client keeps an AP history.
Run: python tests/test_wireless.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from datetime import timedelta
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv import wireless
from netinv.db import Device, DeviceNic, NetworkDevice, SessionLocal, SwitchPort, WifiSighting, utcnow
from netinv.ingest import EndpointPayload, apply_endpoint

assert wireless.near("20:4c:03:aa:00:10", "20:4c:03:aa:00:3f") and not wireless.near("20:4c:03:aa:00:10", "20:4c:03:aa:01:10")

WMAC = "a4:c3:f0:77:00:01"
with TestClient(m.app) as c:
    with SessionLocal() as db:
        # an AP only known as a switch port's LLDP neighbour (no controller): the PC's BSSID is a few above its MAC
        sw = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == "10.0.0.12"))
        p = db.scalar(select(SwitchPort).where(SwitchPort.switch_id == sw.id, SwitchPort.ifindex == 777)) or \
            SwitchPort(switch_id=sw.id, ifindex=777, name="1/1/77", oper_up=True, neighbor="ap-warehouse", neighbor_kind="ap",
                       neighbor_mac="00:11:74:00:aa:00", is_uplink=True)
        db.add(p)
        db.commit()
        apply_endpoint(db, EndpointPayload(hostname="WIFI-LAPTOP", connection="wireless", nics=[{"mac": WMAC, "ip": "10.20.0.9"}],
                                           wifi={"ssid": "CORP", "bssid": "00-11-74-00-AA-03", "signal": 81, "mac": WMAC}))
        db.commit()
        dev = db.scalar(select(Device).where(Device.hostname == "WIFI-LAPTOP"))
        assert (dev.connection, dev.wifi_ssid, dev.wifi_ap, dev.wifi_signal) == ("wireless", "CORP", "ap-warehouse", 81), dev.wifi_ap

        # a controller poll: two APs, the laptop now on ap-yard, and a phone we know nothing else about
        msg = wireless.store_poll(db, "unifi",
            [{"key": "00:22:00:00:00:10", "name": "ap-yard", "mac": "00:22:00:00:00:10", "bssids": ["00:22:00:00:00:11"]},
             {"key": "00:22:00:00:00:20", "name": "ap-dock", "mac": "00:22:00:00:00:20"}],
            [{"mac": WMAC, "ap_mac": "00:22:00:00:00:10", "ssid": "CORP", "ip": "10.20.0.9", "last_seen": utcnow()},
             {"mac": "02:99:00:00:00:01", "ap_mac": "00:22:00:00:00:20", "ssid": "GUEST", "name": "Pixel-8", "last_seen": utcnow()}])
        db.commit()
        assert "2 access points, 2 Wi-Fi clients (1 of them our computers)" in msg, msg
        db.refresh(dev)
        assert dev.wifi_ap == "ap-yard", dev.wifi_ap
        assert wireless.ApIndex(db).ap_for("00:22:00:00:00:11")["name"] == "ap-yard"
        assert wireless.ApIndex(db).ap_for("00:22:00:00:00:23")["name"] == "ap-dock"     # near its MAC
        phone = db.scalar(select(WifiSighting).where(WifiSighting.mac == "02:99:00:00:00:01"))
        assert phone.ap_name == "ap-dock" and phone.client_name == "Pixel-8"

    d = c.get("/api/devices/WIFI-LAPTOP").json()
    aps = [x["ap"] for x in d["wifi"]]
    assert aps[:2] == ["ap-yard", "ap-warehouse"], d["wifi"]
    wh = d["wifi"][1]
    assert (wh["switch_name"], wh["port"]) == (sw.sysname, "1/1/77"), wh
    assert d["device"]["connection"] == "wireless" and d["device"]["wifi_ap"] == "ap-yard"

    # settings: off by default, validation, secrets never returned, poll refuses until set up
    assert c.get("/api/wireless/settings").json()["kind"] in (None, "unifi")
    assert c.put("/api/wireless/settings", json={"kind": "aruba"}).status_code == 400
    r = c.put("/api/wireless/settings", json={"kind": "unifi", "url": "unifi.corp.local:8443/manage", "user": "ro", "secret": "s3cret"}).json()
    assert r["url"] == "https://unifi.corp.local:8443" and r["secret_set"] and "secret" not in r, r
    with SessionLocal() as db:
        assert wireless.is_set_up(db)
        from netinv.db import set_setting
        set_setting(db, "wlc:last_poll", utcnow().isoformat())
        db.commit()
        assert not wireless.due(db)
        set_setting(db, "wlc:last_poll", (utcnow() - timedelta(minutes=20)).isoformat())
        db.commit()
        assert wireless.due(db)
    r = c.put("/api/wireless/settings", json={"kind": None}).json()
    assert not r["secret_set"] and r["kind"] is None
    assert c.post("/api/wireless/poll").json()["ok"] is False

# controller parsers against canned API answers
calls = []
def fake_http(opener, method, url, body=None, headers=None):
    calls.append(url)
    if url.endswith("/api/auth/login"):
        return {}, {"X-CSRF-Token": "t"}
    if url.endswith("/stat/device"):
        return {"data": [{"type": "uap", "mac": "00:33:00:00:00:10", "name": "ap-hall", "ip": "10.0.5.30", "model": "U6LR",
                          "vap_table": [{"bssid": "00:33:00:00:00:11", "essid": "CORP"}]}, {"type": "usw", "mac": "00:33:00:00:00:99"}]}, {}
    if url.endswith("/stat/sta"):
        return {"data": [{"mac": "02:33:00:00:00:01", "ap_mac": "00:33:00:00:00:10", "essid": "CORP", "hostname": "iPad", "last_seen": 1763550000},
                         {"mac": "02:33:00:00:00:02", "is_wired": True}]}, {}
    if url.endswith("/organizations"):
        return [{"id": "o1"}], {}
    if "/devices" in url:
        return [{"serial": "Q2XX", "name": "mr-lobby", "mac": "00:44:00:00:00:10", "lanIp": "10.0.6.2"}], {}
    if "/networks?" in url:
        return [{"id": "N1", "productTypes": ["wireless"]}, {"id": "N2", "productTypes": ["switch"]}], {}
    if "/clients" in url:
        return [{"mac": "02:44:00:00:00:01", "ssid": "CORP", "recentDeviceSerial": "Q2XX", "recentDeviceConnection": "Wireless",
                 "lastSeen": "2026-11-19T10:00:00Z"}, {"mac": "02:44:00:00:00:02", "recentDeviceConnection": "Wired"}], {}
    raise AssertionError(url)
wireless._http = fake_http
with SessionLocal() as db:
    from netinv.db import set_setting
    from netinv.secrets import encrypt
    for k, v in {"wlc:kind": "unifi", "wlc:url": "https://u.local", "wlc:user": "ro", "wlc:secret": encrypt("x")}.items():
        set_setting(db, k, v)
    db.commit()
    aps, cl = wireless.poll_unifi(db)
    assert [a["name"] for a in aps] == ["ap-hall"] and aps[0]["bssids"] == ["00:33:00:00:00:11"]
    assert len(cl) == 1 and cl[0]["ap_name"] == "ap-hall" and cl[0]["name"] == "iPad" and cl[0]["last_seen"]
    assert any("/proxy/network/api/s/default/stat/sta" in u for u in calls), calls
    aps, cl = wireless.poll_meraki(db)
    assert aps[0]["name"] == "mr-lobby" and len(cl) == 1 and cl[0]["ap_name"] == "mr-lobby" and cl[0]["last_seen"].hour == 10
    assert "1 access points, 1 Wi-Fi clients" in wireless.poll(db)
    set_setting(db, "wlc:kind", None)
    set_setting(db, "wlc:secret", None)
    db.commit()
print("wireless: PC-reported AP, controller poll, AP history and settings OK")
