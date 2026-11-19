"""Switch port up/down status and when a down port last had a link (ifOperStatus, ifAdminStatus, ifLastChange).
Run: python tests/test_port_status.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from datetime import timedelta
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv.collectors import snmp
from netinv.db import IpSighting, MacSighting, NetworkDevice, SessionLocal, SwitchPort, utcnow

now = utcnow()
day = 8_640_000                     # one day in TimeTicks (1/100 s)
# down 2 hours ago: it changed (went down) at uptime - 2 h, and was in use until then
when, since_boot, last = snmp.port_activity(now, 10 * day, 10 * day - 720_000, False, None, None)
assert since_boot and abs((now - when) - timedelta(hours=2)) < timedelta(seconds=1) and last == when
# up: last active is now
assert snmp.port_activity(now, 10 * day, 5 * day, True, None, None)[2] == now
# down and unchanged since the switch started: nothing to say, keep what we knew
old = now - timedelta(days=40)
when, since_boot, last = snmp.port_activity(now, 10 * day, 0, False, old, None)
assert since_boot is False and abs((now - when) - timedelta(days=10)) < timedelta(seconds=1) and last == old
# a MAC learned on it more recently than anything else wins; a wrapped counter gives no change time
mac = now - timedelta(days=3)
assert snmp.port_activity(now, 5, 10, False, old, mac) == (None, None, mac)
assert snmp.port_activity(now, None, None, None, None, None) == (None, None, None)

with TestClient(m.app) as c:
    base = dict(sys={"name": "stat-sw", "descr": "Aruba 6300", "location": "", "uptime": str(30 * day)},
                names={1: "1/1/1", 2: "1/1/2", 3: "1/1/3", 4: "1/1/4"}, aliases={}, speeds={},
                oper={1: True, 2: False, 3: False, 4: False}, admin={1: True, 2: True, 3: True, 4: False},
                last_change={1: day, 2: 30 * day - 360_000, 3: 0, 4: 20 * day},
                arp=[], port_vlan={}, fdb=[("02:ee:00:00:00:01", 1, 20)], neighbors={})
    with SessionLocal() as db:
        snmp.store(db, "10.77.0.252", base, 6)
        db.commit()
        sw = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == "10.77.0.252"))
        p3 = db.scalar(select(SwitchPort).where(SwitchPort.switch_id == sw.id, SwitchPort.name == "1/1/3"))
        # a MAC was seen on 1/1/3 45 days ago (before this version tracked link state): that is its last activity
        db.add(MacSighting(mac="02:ee:00:00:00:03", port_id=p3.id, first_seen=now - timedelta(days=50), last_seen=now - timedelta(days=45)))
        p3.last_up = None
        db.commit()
        snmp.store(db, "10.77.0.252", base, 6)
        db.commit()

    sp = {r["port"]: r for r in c.post("/api/query", json={"dataset": "v_switch_ports", "limit": 1000,
          "filters": [{"field": "switch_ip", "op": "eq", "value": "10.77.0.252"}]}).json()["rows"]}
    assert [sp[p]["status"] for p in ("1/1/1", "1/1/2", "1/1/3", "1/1/4")] == ["up", "down", "down", "disabled"], sp
    age = lambda v: utcnow() - __import__("datetime").datetime.fromisoformat(str(v).replace("Z", ""))  # noqa: E731
    assert age(sp["1/1/1"]["last_active"]) < timedelta(minutes=1)
    assert timedelta(minutes=59) < age(sp["1/1/2"]["last_active"]) < timedelta(minutes=61), sp["1/1/2"]
    assert timedelta(days=44) < age(sp["1/1/3"]["last_active"]) < timedelta(days=46), sp["1/1/3"]
    assert not sp["1/1/3"]["changed_since_boot"] and sp["1/1/2"]["changed_since_boot"]
    assert timedelta(days=9) < age(sp["1/1/4"]["last_active"]) < timedelta(days=11), sp["1/1/4"]   # shut down 10 days ago
    r = c.get("/api/switch-port", params={"switch_ip": "10.77.0.252", "port": "1/1/2"}).json()["port"]
    assert r["status"] == "down" and r["last_active"], r

    # the demo has empty desks: down an hour ago, last week, two months ago, never since boot, and shut down
    demo = c.post("/api/query", json={"dataset": "v_switch_ports", "limit": 1000,
                  "filters": [{"field": "switch_ip", "op": "eq", "value": "10.0.0.10"}, {"field": "status", "op": "ne", "value": "up"}]}).json()["rows"]
    assert sorted(x["status"] for x in demo) == ["disabled", "down", "down", "down", "down"], demo
    rep = [x for x in c.get("/api/library").json() if x["id"] == "net_ports_down"]
    assert rep and c.get("/api/library/net_ports_down").status_code == 200
    # what is plugged in where there is no computer record: the DHCP name and IP, else only the MAC
    with SessionLocal() as db:
        if not db.scalar(select(IpSighting).where(IpSighting.mac == "02:ee:00:00:00:01")):
            db.add(IpSighting(ip="10.77.9.9", hostname="PRN-LOBBY", mac="02:ee:00:00:00:01", source="dhcp:DC1", first_seen=now, last_seen=now))
            db.commit()
    pm = {x["mac"]: x for x in c.post("/api/query", json={"dataset": "v_port_map", "limit": 100000,
          "filters": [{"field": "switch_ip", "op": "eq", "value": "10.77.0.252"}]}).json()["rows"]}
    assert pm["02:ee:00:00:00:01"]["dhcp_name"] == "PRN-LOBBY" and pm["02:ee:00:00:00:01"]["dhcp_ip"] == "10.77.9.9", pm
    assert not pm["02:ee:00:00:00:03"]["dhcp_name"] and not pm["02:ee:00:00:00:03"]["ip"] and not pm["02:ee:00:00:00:03"]["hostname"]
    r = c.get("/api/switch-port", params={"switch_ip": "10.77.0.252", "port": "1/1/1"}).json()["macs"]
    assert r[0]["dhcp_name"] == "PRN-LOBBY" and r[0]["dhcp_ip"] == "10.77.9.9", r
    # one switch's ports with what is plugged in, straight from its MAC table
    d = c.get("/api/switch-ports", params={"switch_ip": "10.77.0.252"}).json()
    assert {p["port"] for p in d["ports"]} == {"1/1/1", "1/1/2", "1/1/3", "1/1/4"} and d["switch"]["ip"] == "10.77.0.252"
    on = {(m["port"], m["mac"]): m for m in d["macs"]}
    assert on[("1/1/1", "02:ee:00:00:00:01")]["current"] == 1 and on[("1/1/1", "02:ee:00:00:00:01")]["dhcp_name"] == "PRN-LOBBY"
    assert on[("1/1/3", "02:ee:00:00:00:03")]["current"] == 0          # seen 45 days ago, not at the last poll
    assert d["uplink_macs"] == 0 and d["port_map"]["error"] is None
    # the same rows the Port map lists for this switch lead (current); the switch's own MAC table only adds history
    assert d["port_map_rows"] >= 1 and any(m.get("source") == "port map" and m["port"] == "1/1/1" for m in d["macs"]), d["macs"]
    assert len({(m["port"], m["mac"]) for m in d["macs"]}) == len(d["macs"]), "no device twice on a port"
    # a browser must never pair the new page with an app.js it cached before an update
    import re as _re
    page = c.get("/").text
    assert _re.search(r'src="/static/app\.js\?v=[0-9a-f]{12}"', page) and "style.css?v=" in page, page[:300]
    # find a device on any switch (the old Port map page): by DHCP name, by MAC typed with dashes, too short
    f = c.get("/api/port-find", params={"q": "prn-lob"}).json()["rows"]
    assert any(r["mac"] == "02:ee:00:00:00:01" and r["port"] == "1/1/1" for r in f), f
    f = c.get("/api/port-find", params={"q": "02-EE-00-00-00-01"}).json()["rows"]
    assert any(r["mac"] == "02:ee:00:00:00:01" for r in f), f
    assert c.get("/api/port-find", params={"q": "x"}).json()["rows"] == []
print("switch port status: up/down/disabled, last active from link changes and MAC history OK")
