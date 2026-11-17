"""Scan targets: "Include in scheduled scans" only affects scheduled runs (Scan now uses every target and its
credentials); scans with nothing to do are recorded as skipped with the reason; this server's own account (id 0).
Run: python tests/test_scan_targets.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import delete, select
import netinv.main as m
from netinv import fixes, jobs, scanning
from netinv.collectors import ad, snmp
from netinv.db import CollectorRun, Credential, Deployment, ScanJob, ScanTarget, SessionLocal

seen = []
ad.collect = lambda db, cfg: seen.append(cfg) or "2 domain controllers, 3 users"
snmp.collect = lambda db, cfg: "0 devices polled"
import netinv.reach as reach
reach.sweep = lambda ips, parallel=128: {}

with TestClient(m.app) as c, SessionLocal() as db:
    db.execute(delete(ScanTarget))
    db.add(Credential(name="AD WB", kind="windows", username="CORP\\svc", secret=None))
    db.commit()
    cid = db.scalar(select(Credential.id).where(Credential.name == "AD WB"))
    t = ScanTarget(kind="ad_domain", value="corp.example.com", enabled=False, credential_ids=str(cid), collect="computers,users")
    db.add(t)
    db.commit()

    # Scan now: the target is left out of the schedule, but Scan now still scans it with its credential
    r = jobs.run_job("ad")
    assert r.ok, r.message
    assert seen and seen[-1]["domain"] == "corp.example.com", seen

    # a scheduled run skips it and says why, and isn't "ok"
    with scanning.scoped(None, scheduled=True):
        try:
            scanning.run_ad(db)
            raise AssertionError("expected NothingToDo")
        except scanning.NothingToDo as exc:
            assert "corp.example.com" in str(exc) and "left out of scheduled scans" in str(exc), exc

    job = ScanJob(name="AD only", enabled=True, collectors="ad", target_ids=str(t.id), every_min=60)
    db.add(job)
    db.commit()
    jobs._run_scan_job(job.id, "schedule")
    db.refresh(job)
    assert job.last_ok is False and job.last_result.startswith("Skipped"), job.last_result
    jobs._run_scan_job(job.id, "alice")      # Run now from Scan schedule: scans it
    db.refresh(job)
    assert job.last_ok is True, job.last_result

    # no IP range target at all: skipped, not ok
    r = jobs.run_job("snmp")
    assert r.ok is False and r.message.startswith("Skipped: no IP range target"), r.message

    # a target with no Windows credential: the PC scan says which target
    t.credential_ids = ""
    db.commit()
    r = jobs.run_job("pcs")
    assert r.ok is False and "corp.example.com" in r.message and "credential" in r.message, r.message

    # this server's own account as a target credential
    t.credential_ids = "0"
    db.commit()
    cfg = scanning.winrm_cfg(db)
    assert cfg and cfg["creds"] == [{"user": None, "password": None, "integrated": True}], cfg
    assert c.get("/api/service-account").json()["id"] == 0

    # agent push dialog lists the accounts; a push with a chosen account keeps it on the deployment
    st = c.get("/api/agents/push").json()
    assert any(a["id"] == cid for a in st["accounts"]) and st["service_account"], st
    dep = fixes.enqueue(db, db.scalar(select(m.Device.hostname)), "reboot", "alice", "now", cred_id=0)
    assert fixes._cfg(db, dep)["creds"] == [scanning.service_cfg()]
    dep2 = fixes.enqueue(db, dep.hostname, "reboot", "alice", "now", cred_id=cid)
    assert fixes._cfg(db, dep2)["creds"][0]["user"] == "CORP\\svc"
    db.execute(delete(Deployment).where(Deployment.id.in_([dep.id, dep2.id])))
    db.commit()
print("scan targets OK")
