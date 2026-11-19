"""Speed and storage (0.34): the stored switch port map follows the data, retention trims old history, the dashboard
summary doesn't need the whole software table, and an agent report that changes nothing leaves the port map alone.
Run: python tests/test_performance.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from datetime import timedelta
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text
import netinv.main as m
from netinv import portmap, retention
from netinv.correlate import PORT_MAP_LIVE, PORT_MAP_COLS, dialect_sql
from netinv.db import (ChangeEvent, CollectorRun, Device, LogonEvent, MacSighting, SessionLocal, SwitchPort, WifiSighting,
                       set_setting, utcnow)
from netinv.ingest import EndpointPayload, Nic, apply_endpoint


def live(db):
    sql = dialect_sql(PORT_MAP_LIVE, db.get_bind().dialect.name)
    return sorted(tuple(r) for r in db.execute(text(f"SELECT {', '.join(PORT_MAP_COLS)} FROM ({sql}) x")))


def stored(db):
    return sorted(tuple(r) for r in db.execute(text(f"SELECT {', '.join(PORT_MAP_COLS)} FROM v_port_map")))


with TestClient(m.app) as c:
    with SessionLocal() as db:
        portmap.refresh(db)
        assert stored(db) == live(db) and stored(db), "port_map must match the live computation"
        # a PC plugged into another access port: the stored map follows on the next request, no waiting for the timer
        dev = db.scalar(select(Device).join(Device.nics).limit(1))
        mac = dev.nics[0].mac
        port = db.scalar(select(SwitchPort).where(SwitchPort.is_uplink.is_(False), SwitchPort.mac_count < 3)
                         .order_by(SwitchPort.id.desc()).limit(1))
        db.add(MacSighting(mac=mac, port_id=port.id, vlan=7, first_seen=utcnow(), last_seen=utcnow() + timedelta(minutes=5)))
        db.commit()
        assert portmap.status()["stale"], "a MAC sighting must mark the port map stale"
        host = dev.hostname
    r = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname", "switch_port", "vlan"],
                                   "filters": [{"field": "hostname", "op": "eq", "value": host}]}).json()["rows"][0]
    assert r["switch_port"] == port.name and r["vlan"] == 7, r
    assert not portmap.status()["stale"]
    with SessionLocal() as db:
        assert stored(db) == live(db)

        # an agent report with the same NICs doesn't rewrite them (so the map isn't recomputed after every report)
        dev = db.get(Device, dev.id)
        nics = [Nic(mac=n.mac, ip=n.ip, description=n.description) for n in dev.nics]
        apply_endpoint(db, EndpointPayload(hostname=dev.hostname, nics=nics))
        db.commit()
        assert not portmap.status()["stale"], "unchanged NICs must not mark the port map stale"
        apply_endpoint(db, EndpointPayload(hostname=dev.hostname, nics=nics + [Nic(mac="02:00:5e:10:20:30", ip="10.1.2.3")]))
        db.commit()
        assert portmap.status()["stale"], "a new NIC must mark it stale"
        portmap.refresh(db)

        # retention: old rows go, recent ones stay, 0 keeps everything
        old, new = utcnow() - timedelta(days=400), utcnow() - timedelta(days=1)
        db.add_all([LogonEvent(time=old, username="perf-old", source="dc:PERF"), LogonEvent(time=new, username="perf-new", source="dc:PERF"),
                    ChangeEvent(device_id=dev.id, time=utcnow() - timedelta(days=4000), kind="perf", detail="ancient"),
                    WifiSighting(mac="02:00:5e:00:00:99", ap_key="PERF-AP", source="pc", first_seen=old, last_seen=old),
                    CollectorRun(collector="perf", started=old)])
        db.commit()
        set_setting(db, "retention:wifi", "0")
        db.commit()
        removed = retention.run(db)
        assert removed.get("logons", 0) >= 1 and removed.get("changes", 0) >= 1 and removed.get("runs", 0) >= 1, removed
        names = set(db.scalars(select(LogonEvent.username).where(LogonEvent.source == "dc:PERF")))
        assert names == {"perf-new"}, names
        assert db.scalar(select(WifiSighting).where(WifiSighting.ap_key == "PERF-AP")), "0 days keeps rows forever"
        db.execute(delete(WifiSighting).where(WifiSighting.ap_key == "PERF-AP"))
        db.execute(delete(LogonEvent).where(LogonEvent.source == "dc:PERF"))
        set_setting(db, "retention:wifi", None)
        db.commit()

    r = c.get("/api/retention").json()
    assert {t["key"] for t in r["tables"]} >= {"logons", "mac", "wifi"} and r["last_result"], r
    assert c.put("/api/retention", json={"days": {"logons": 99999}}).status_code == 400
    assert c.put("/api/retention", json={"days": {"logons": 365}}).json()["tables"][0]["days"] == 365
    assert c.put("/api/retention", json={"days": {"logons": 180}}).status_code == 200

    s = c.get("/api/summary").json()
    assert "insight_counts" not in s and s["counts"]["mapped_to_port"] >= 1, s["counts"]
    al = {a["id"]: a for a in c.get("/api/alerts").json()}
    assert al["outdated_sw"]["error"] is None and al["outdated_sw"]["count"] >= 1, al["outdated_sw"]
    rows = c.get("/api/alerts/outdated_sw").json()["rows"]
    assert all({"hostname", "name", "version", "required"} <= set(x) for x in rows), rows[:2]
print("performance: port map, retention, summary OK")
