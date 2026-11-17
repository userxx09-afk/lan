"""DC logon events: the computer column is the PC the user was on, not the DC that logged it.
Run: python tests/test_logon_client.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from datetime import timedelta
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select, delete
import netinv.main as m
from netinv import correlate
from netinv.db import ArpEntry, Device, DeviceNic, LogonEvent, SessionLocal, set_setting, utcnow
from netinv.ingest import LogonIn, add_logons, dc_client_host

assert dc_client_host("IS-DC-06", "10.9.0.5", "dc:IS-DC-06") is None          # DC's own name: unknown client
assert dc_client_host("IS-DC-06", "::1", "dc:IS-DC-06") == "IS-DC-06"          # really on the DC
assert dc_client_host("PC-A", "10.9.0.5", "dc:IS-DC-06") == "PC-A"             # real workstation name kept
assert dc_client_host(None, "-", "dc:IS-DC-06") == "IS-DC-06"
assert dc_client_host(None, None, "dc:IS-DC-06") is None

with TestClient(m.app) as c:
    with SessionLocal() as db:
        pcs = sorted(db.scalars(select(Device)), key=lambda d: d.hostname)
        a, b = pcs[0], pcs[1]
        db.execute(delete(DeviceNic).where(DeviceNic.ip.in_(["10.99.0.11", "10.99.0.12"])))
        db.add(DeviceNic(device_id=a.id, mac="AA:BB:CC:00:00:11", ip="10.99.0.11"))
        db.add(DeviceNic(device_id=b.id, mac="AA:BB:CC:00:00:12", ip=None))          # IP known only from ARP
        db.add(ArpEntry(ip="10.99.0.12", mac="AA:BB:CC:00:00:12", source="core"))
        now = utcnow()
        # Row stored by an older version: the DC's own name as the computer.
        db.add(LogonEvent(time=now - timedelta(hours=2), username="zkern", hostname="IS-DC-06", ip="10.99.0.11",
                          logon_type=3, source="dc:IS-DC-06"))
        set_setting(db, "migr:logon_client_v1", None)
        db.commit()
        add_logons(db, [
            LogonIn(time=now - timedelta(minutes=5), username="GRHS\\zkern", hostname="IS-DC-06", ip="10.99.0.12", logon_type=3, source="dc:IS-DC-06"),
            LogonIn(time=now - timedelta(minutes=4), username="zkern", ip="::ffff:10.99.0.11".replace("::ffff:", ""), logon_type=0, source="dc:IS-DC-07"),
            LogonIn(time=now - timedelta(minutes=3), username="zkern", hostname="IS-DC-06", ip="127.0.0.1", logon_type=3, source="dc:IS-DC-06"),
        ])
        db.commit()
        correlate.resolve_logon_hosts(db, dns=False)

    rows = c.get("/api/users/zkern").json()["logons"]
    got = sorted((r["hostname"], r["dc"], r["in_inventory"]) for r in rows)
    assert got == sorted([(a.hostname, "IS-DC-06", 1), (b.hostname, "IS-DC-06", 1), (a.hostname, "IS-DC-07", 1),
                          ("IS-DC-06", "IS-DC-06", 0)]), got
    comps = {x["hostname"] for x in c.get("/api/users/zkern").json()["computers"]}
    assert {a.hostname, b.hostname} <= comps, comps
    dev = c.get(f"/api/devices/{a.hostname}").json()
    assert any(l["username"] == "zkern" and l["dc"] == "IS-DC-07" for l in dev["logons"]), dev["logons"][:3]
    assert correlate.reverse_dns([], 1) == {}
    print("logon client computer OK")
