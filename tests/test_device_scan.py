"""Scan now on the Network tab (0.47): poll one network device, or all of them, over SNMP right away.
SNMP is faked. Run: python tests/test_device_scan.py (DATABASE_URL set, demo loaded)."""
import logging, sys, time
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv import devscan
from netinv.collectors import snmp
from netinv.db import AuditLog, CollectorRun, NetworkDevice, ScanTarget, SessionLocal

assert devscan.in_range("10.1.2.3", "10.1.2.0/24")
assert devscan.in_range("10.1.2.3", "10.0.0.1, 10.1.2.1-10")
assert devscan.in_range("10.1.2.3", "10.1.2.3")
assert not devscan.in_range("10.1.2.30", "10.1.2.1-10; 10.9.0.0/16")
assert not devscan.in_range("nope", "10.1.2.0/24") and not devscan.in_range("10.1.2.3", "garbage, x-y")

day = 8_640_000
polled, slow = [], set()


async def fake_poll(ip, cfg):
    polled.append((ip, cfg.get("community")))
    if ip in slow:
        import asyncio
        await asyncio.sleep(0.6)
    if ip == "10.66.0.3" or cfg.get("community") != "right":
        raise TimeoutError("No SNMP response received before timeout")
    return dict(sys={"name": f"sw-{ip.rsplit('.', 1)[1]}", "descr": "Cisco IOS", "location": "Lab", "uptime": str(3 * day)},
                names={1: "Gi1/0/1"}, aliases={}, speeds={}, oper={1: True}, admin={1: True}, last_change={1: day},
                arp=[], port_vlan={}, fdb=[(f"02:66:00:00:00:{ip.rsplit('.', 1)[1].zfill(2)}", 1, 10)], neighbors={})
snmp.poll_device = fake_poll


def wait(c, key):
    n = key.split(":")[1]
    for _ in range(200):
        st = c.get(f"/api/network-devices/scan/{n}").json()
        if not st["running"]:
            return st
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


with TestClient(m.app) as c:
    wrong = c.post("/api/credentials", json={"name": "DS wrong", "kind": "snmp2", "secret": "wrong"}).json()["id"]
    right = c.post("/api/credentials", json={"name": "DS right", "kind": "snmp2", "secret": "right"}).json()["id"]
    with SessionLocal() as db:
        for d in db.scalars(select(NetworkDevice)):     # only our 3 switches (ORM delete: their ports go too)
            db.delete(d)
        db.flush()
        for i in (1, 2, 3):
            db.add(NetworkDevice(ip=f"10.66.0.{i}", sysname=f"old-{i}"))
        # the range holding .1 and .2 has the right community; another target (tried after it) has the wrong one
        db.add(ScanTarget(kind="ip_range", value="10.99.0.0/24", credential_ids=str(wrong), enabled=True))
        db.add(ScanTarget(kind="ip_range", value="10.66.0.1-2", credential_ids=str(right), enabled=True))
        db.commit()
        assert devscan.cred_ids_for(db, "10.66.0.1")[:2] == [right, wrong]
        assert devscan.cred_ids_for(db, "10.66.0.3")[0] == wrong      # not in a range: saved targets in order

    # unknown device / nothing given
    r = c.post("/api/network-devices/scan", json={"ips": ["10.66.9.9"]})
    assert r.status_code == 400 and "Not a known network device" in r.json()["detail"], r.text

    # one device: first credential that answers wins, row is updated, audit + run recorded
    polled.clear()
    r = c.post("/api/network-devices/scan", json={"ips": ["10.66.0.1"]}).json()
    assert r["ok"] and r["ips"] == ["10.66.0.1"], r
    st = wait(c, r["key"])
    assert st["ok"] and st["results"]["10.66.0.1"]["ok"] and "sw-1" in st["message"], st
    assert polled == [("10.66.0.1", "right")], polled
    with SessionLocal() as db:
        nd = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == "10.66.0.1"))
        assert nd.sysname == "sw-1" and nd.last_polled and nd.poll_error is None and len(nd.ports) == 1, (nd.sysname, nd.last_polled, nd.poll_error, len(nd.ports))
        run = db.scalars(select(CollectorRun).where(CollectorRun.collector == "device").order_by(CollectorRun.id.desc())).first()
        assert run.ok and run.finished and "sw-1" in run.message
        acts = [a.action for a in db.scalars(select(AuditLog).where(AuditLog.action.like("scan.device%")))]
        assert "scan.device" in acts and "scan.device.done" in acts, acts
    assert c.get("/api/network-devices/scan").json()["busy"] == {}

    # Scan all: every device, a failing one keeps its error on the row
    polled.clear()
    r = c.post("/api/network-devices/scan", json={"ips": None}).json()
    assert sorted(r["ips"]) == ["10.66.0.1", "10.66.0.2", "10.66.0.3"], r
    st = wait(c, r["key"])
    assert st["ok"] and "2 of 3 devices answered" in st["message"] and not st["results"]["10.66.0.3"]["ok"], st
    with SessionLocal() as db:
        bad = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == "10.66.0.3"))
        assert "timeout" in (bad.poll_error or "").lower(), bad.poll_error
        assert db.scalar(select(NetworkDevice).where(NetworkDevice.ip == "10.66.0.2")).sysname == "sw-2"

    # while a device is being scanned: shown as busy, a second Scan now of it is refused, Scan all skips it
    slow.add("10.66.0.2")
    r = c.post("/api/network-devices/scan", json={"ips": ["10.66.0.2"]}).json()
    assert c.get("/api/network-devices/scan").json()["busy"] == {"10.66.0.2": r["key"]}
    again = c.post("/api/network-devices/scan", json={"ips": ["10.66.0.2"]})
    assert again.status_code == 400 and "Already being scanned" in again.json()["detail"], again.text
    r2 = c.post("/api/network-devices/scan", json={}).json()
    assert "10.66.0.2" not in r2["ips"] and r2["skipped"] == ["10.66.0.2"], r2
    # it shows on the Scanning tab and can be cancelled there like a one-time scan
    assert any(x["key"] == r["key"] for x in c.get("/api/scanning").json()["running"]), c.get("/api/scanning").json()
    wait(c, r["key"]); wait(c, r2["key"])
    slow.clear()

    # the page has the buttons
    assert 'id="ndscanall"' in c.get("/").text
print("device scan OK")
