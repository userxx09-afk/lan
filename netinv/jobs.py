"""Collector jobs, used by the CLI, the UI "scan now" buttons and the built-in scheduler."""
from __future__ import annotations

import logging
import threading
import time

from .config import settings
from .db import CollectorRun, ScanTarget, SessionLocal, get_setting, utcnow
from . import scanning

log = logging.getLogger(__name__)
_lock = threading.Lock()
RUNNING: dict[str, float] = {}   # job name -> start time, for the "scanning" banner

JOBS = {
    "ad": lambda db: scanning.run_ad(db),
    "snmp": lambda db: scanning.run_ip(db),
    "pcs": lambda db: scanning.run_pcs(db, check_pending=False),
    "pcs_updates": lambda db: scanning.run_pcs(db, check_pending=True),
    "dc_logons": lambda db: scanning.run_dc_logons(db),
}
# Order matters for "all": AD first (gives the PC list), then IP ranges (finds hosts), then the PCs.
ALL_ORDER = ["ad", "snmp", "pcs", "dc_logons"]
DEFAULT_INTERVALS = {"ad": 60, "snmp": 15, "pcs": 240, "pcs_updates": 1440, "dc_logons": 30}


def run_job(name: str) -> CollectorRun:
    RUNNING[name] = time.time()
    try:
        return _run_job(name)
    finally:
        RUNNING.pop(name, None)


def run_all() -> None:
    for n in ALL_ORDER:
        run_job(n)


def _run_job(name: str) -> CollectorRun:
    with _lock, SessionLocal() as db:
        run = CollectorRun(collector=name, started=utcnow())
        db.add(run)
        db.commit()
        try:
            run.message = JOBS[name](db)
            run.ok = True
        except Exception as exc:
            db.rollback()
            log.exception("job %s failed", name)
            run.ok, run.message = False, f"{type(exc).__name__}: {exc}"
        run.finished = utcnow()
        db.add(run)
        db.commit()
        return run


def intervals(db) -> dict[str, int]:
    return {k: int(get_setting(db, f"interval:{k}", None) or settings.schedule.get(k, v)) for k, v in DEFAULT_INTERVALS.items()}


def scheduler_loop(stop: threading.Event) -> None:
    """Small interval scheduler. Intervals (minutes, 0 = off) come from Settings, then config [schedule]."""
    last: dict[str, float] = {}
    stop.wait(20)
    while not stop.is_set():
        try:
            with SessionLocal() as db:
                iv = intervals(db)
                ready = _configured(db)
            for name in ALL_ORDER + ["pcs_updates"]:
                if iv.get(name) and time.time() - last.get(name, 0) >= iv[name] * 60 and ready.get(name):
                    last[name] = time.time()
                    run_job(name)
        except Exception:
            log.exception("scheduler")
        stop.wait(30)


def _configured(db) -> dict[str, bool]:
    from sqlalchemy import select
    kinds = {k for (k,) in db.execute(select(ScanTarget.kind).where(ScanTarget.enabled.is_(True)))}
    ad = bool(kinds & set(scanning.AD_KINDS)) or bool(settings.ad.get("server"))
    ip = "ip_range" in kinds or bool(settings.snmp.get("targets"))
    win = bool(kinds) or bool(settings.winrm.get("user"))
    return {"ad": ad, "snmp": ip, "pcs": win, "pcs_updates": win, "dc_logons": win and ad}
