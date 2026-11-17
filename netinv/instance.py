"""Which NetInventory server processes are running against this database, and which one wrote a result.

Every server registers itself at start and updates last_seen every minute. Settings lists the ones seen in the
last few minutes, so a second copy (another server pointed at the same database, or a process from an old
version that an upgrade didn't stop) is visible. Scan results carry ran_by. Every result written by this version has it,
so a result written after this process started without one came from an older process that is still running.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, select

from . import __version__
from .db import CollectorRun, ScanJob, ServerInstance, SessionLocal, utcnow

log = logging.getLogger(__name__)
ID = uuid.uuid4().hex
HOST = socket.gethostname()[:128]
PID = os.getpid()
CODE_PATH = str(Path(__file__).resolve().parent)[:512]
STARTED = utcnow()
ALIVE = timedelta(minutes=3)


def ran_by() -> str:
    return f"{__version__} on {HOST}, pid {PID}"[:200]


def beat(db) -> None:
    row = db.get(ServerInstance, ID)
    if row is None:
        row = ServerInstance(id=ID, version=__version__[:32], host=HOST, pid=PID, code_path=CODE_PATH, started=STARTED)
        db.add(row)
    row.last_seen = utcnow()
    db.execute(delete(ServerInstance).where(ServerInstance.last_seen < utcnow() - timedelta(days=7)))
    db.commit()


def loop(stop: threading.Event) -> None:
    log.info("NetInventory %s started on %s (pid %s), code in %s", __version__, HOST, PID, CODE_PATH)
    try:   # rows of earlier processes on this computer (a restart, an upgrade); one still running re-adds itself within a minute
        with SessionLocal() as db:
            db.execute(delete(ServerInstance).where(ServerInstance.host == HOST, ServerInstance.id != ID))
            db.commit()
    except Exception:
        log.exception("instance cleanup")
    while not stop.is_set():
        try:
            with SessionLocal() as db:
                beat(db)
        except Exception:
            log.exception("instance heartbeat")
        stop.wait(60)
    try:
        with SessionLocal() as db:
            db.execute(delete(ServerInstance).where(ServerInstance.id == ID))
            db.commit()
    except Exception:
        pass


def status(db) -> dict:
    since = utcnow() - ALIVE
    running = [{"version": r.version, "host": r.host, "pid": r.pid, "path": r.code_path,
                "started": r.started.isoformat(timespec="seconds") + "Z", "this": r.id == ID}
               for r in db.scalars(select(ServerInstance).where(ServerInstance.last_seen >= since)
                                   .order_by(ServerInstance.started))]
    if not any(r["this"] for r in running):      # before the first heartbeat lands
        running.append({"version": __version__, "host": HOST, "pid": PID, "path": CODE_PATH,
                        "started": STARTED.isoformat(timespec="seconds") + "Z", "this": True})
    # A job started since this process started whose result this version didn't write (no ran_at, or an older one
    # than the start) was run by a process that doesn't record itself: an older version. Jobs running here
    # right now are skipped; their result isn't written yet.
    from .jobs import JOB_STATE
    old = [j.name for j in db.scalars(select(ScanJob).where(ScanJob.last_run > STARTED, ScanJob.last_result.is_not(None)))
           if j.id not in JOB_STATE and (j.ran_at is None or j.ran_at < j.last_run)]
    old += [f"collector {c}" for (c,) in db.execute(
        select(CollectorRun.collector).where(CollectorRun.started > STARTED, CollectorRun.finished.is_not(None),
                                             CollectorRun.ran_by.is_(None)).distinct())]
    return {"this": {"version": __version__, "host": HOST, "pid": PID, "path": CODE_PATH},
            "running": running, "old_process_results": sorted(set(old))}
