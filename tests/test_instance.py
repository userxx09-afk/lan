"""Running-processes check: each server registers itself, its job results carry ran_by, and a result written by a
process that doesn't record itself (an older version still running against the database) is reported.
Run: python tests/test_instance.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import instance, jobs
from netinv.db import ScanJob, SessionLocal, utcnow

jobs.JOBS["dc_logons"] = lambda db: "0 logon events from 0 DCs"

with TestClient(m.app) as c:
    with SessionLocal() as db:
        instance.beat(db)
        db.query(ScanJob).filter(ScanJob.name.in_(["t-new", "t-old"])).delete()
        for n in ("t-new", "t-old"):
            db.add(ScanJob(name=n, collectors="dc_logons", every_min=60))
        db.commit()
        new_id = db.query(ScanJob).filter_by(name="t-new").one().id
    jobs.run_scan_job(new_id)
    with SessionLocal() as db:
        old = db.query(ScanJob).filter_by(name="t-old").one()     # what a process from before this check does
        old.last_run, old.last_result = utcnow(), "dc_logons: failed (OperationalError: ...)"
        db.commit()
    u = c.get("/api/update").json()["instances"]
    assert [r for r in u["running"] if r["this"]], u
    assert u["old_process_results"] == ["t-old"], u
    js = {j["name"]: j for j in c.get("/api/jobs").json()["jobs"]}
    assert js["t-new"]["ran_by"] == instance.ran_by(), js["t-new"]
    assert js["t-old"]["ran_by"] is None
    # Once this version runs the job again, the warning goes away.
    jobs.run_scan_job(js["t-old"]["id"])
    assert c.get("/api/update").json()["instances"]["old_process_results"] == []
print("instance check OK")
