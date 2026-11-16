"""Collector jobs, used by the CLI, the UI "scan now" buttons and the built-in scheduler."""
from __future__ import annotations

import logging
import threading
import time

from .config import settings
from .db import CollectorRun, ScanTarget, SessionLocal, get_setting, utcnow
from . import progress, scanning

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


short_error = scanning.short_error


def run_job(name: str) -> CollectorRun:
    RUNNING[name] = time.time()
    run = progress.start(f"manual:{name}:{threading.get_ident()}", name, steps=[name], who="Scan now")
    run.begin_step(name)
    try:
        return _run_job(name)
    finally:
        progress.end(run)
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
            run.ok, run.message = False, short_error(exc)
        run.finished = utcnow()
        db.add(run)
        db.commit()
        _refresh_groups(db)
        return run


def _refresh_groups(db) -> None:
    """New scan data can move PCs in or out of rule-based groups."""
    from . import groups
    try:
        groups.refresh(db)
    except Exception:
        db.rollback()
        log.exception("group refresh")


def intervals(db) -> dict[str, int]:
    return {k: int(get_setting(db, f"interval:{k}", None) or settings.schedule.get(k, v)) for k, v in DEFAULT_INTERVALS.items()}


# ------------------------------------------------------------------ scheduled scan jobs (Settings > Scan schedule)
COLLECTOR_ORDER = ["ad", "snmp", "pcs", "pcs_updates", "dc_logons"]   # AD first: it gives the PC list
JOB_STATE: dict[int, str] = {}       # job id -> "queued" | "running"
_slots = threading.Condition()
_active = 0


def max_concurrent(db) -> int:
    try:
        return max(1, min(8, int(get_setting(db, "jobs:max_concurrent", None) or 1)))
    except ValueError:
        return 1


def _local(utc_naive):
    """UTC (naive, as stored) -> server local time (naive)."""
    from datetime import timezone
    return utc_naive.replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None) if utc_naive else None


def _in_window(job, t) -> bool:
    if str(t.weekday()) not in (job.days or "0123456"):
        return False
    a, b = job.window_start, job.window_end
    if a is None or b is None or a == b:
        return True
    return a <= t.hour < b if a < b else (t.hour >= a or t.hour < b)     # 18-6 wraps past midnight


def is_due(job, now_local, last_local) -> bool:
    if job.at_time:
        hh, mm = (int(x) for x in job.at_time.split(":"))
        slot = now_local.replace(hour=hh, minute=mm, second=0, microsecond=0)
        return (now_local >= slot and str(now_local.weekday()) in (job.days or "0123456")
                and (last_local is None or last_local < slot))
    if not job.every_min:
        return False
    from datetime import timedelta
    return _in_window(job, now_local) and (last_local is None or now_local - last_local >= timedelta(minutes=job.every_min))


def next_run(job, now_local=None):
    """When the scheduler will next start this job (server local time), or None."""
    from datetime import datetime, timedelta
    if not job.enabled or not (job.at_time or job.every_min):
        return None
    now = (now_local or datetime.now()).replace(second=0, microsecond=0)
    last = _local(job.last_run)
    t = now
    for _ in range(8 * 24 * 60):          # minute steps, up to 8 days ahead
        if is_due(job, t, last):
            return t
        t += timedelta(minutes=1)
    return None


def describe(job) -> str:
    names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    d = job.days or "0123456"
    days = "" if d == "0123456" else " on " + ", ".join(names[int(c)] for c in d)
    if job.at_time:
        return f"daily at {job.at_time}{days}"
    if not job.every_min:
        return "manual only"
    e = job.every_min
    every = f"every {e // 1440} days" if e % 1440 == 0 and e > 1440 else "every day" if e == 1440 else \
        f"every {e // 60} hours" if e % 60 == 0 and e > 60 else "every hour" if e == 60 else f"every {e} minutes"
    win = f", {job.window_start:02d}:00-{job.window_end:02d}:00" if job.window_start is not None and job.window_end is not None \
        and job.window_start != job.window_end else ""
    return every + win + days


QUEUE: list[int] = []                # job ids waiting for a slot, first in line first
QUEUED: dict[int, tuple[float, str]] = {}   # job id -> (queued at, who)


def run_scan_job(job_id: int, who: str = "schedule") -> None:
    """Run one job: waits its turn for a free slot (global cap), never overlaps itself."""
    global _active
    with _slots:
        if JOB_STATE.get(job_id):
            return
        JOB_STATE[job_id] = "queued"
        QUEUE.append(job_id)
        QUEUED[job_id] = (time.time(), who)
    acquired = False
    try:
        with _slots:
            while True:
                if job_id not in QUEUE:          # taken off the queue (cancelled)
                    return
                with SessionLocal() as db:
                    cap = max_concurrent(db)
                if _active < cap and QUEUE[0] == job_id:
                    QUEUE.remove(job_id)
                    _active += 1
                    acquired = True
                    break
                _slots.wait(15)
            JOB_STATE[job_id] = "running"
            QUEUED.pop(job_id, None)
        _run_scan_job(job_id, who)
    finally:
        with _slots:
            JOB_STATE.pop(job_id, None)
            QUEUED.pop(job_id, None)
            if job_id in QUEUE:
                QUEUE.remove(job_id)
            if acquired:
                _active -= 1
            _slots.notify_all()


def move_to_front(job_id: int) -> bool:
    with _slots:
        if job_id not in QUEUE:
            return False
        QUEUE.remove(job_id)
        QUEUE.insert(0, job_id)
        _slots.notify_all()
    return True


def cancel_job(job_id: int, who: str) -> str | None:
    """Takes a queued job off the queue, or stops a running one. Returns what happened, None if it wasn't active."""
    with _slots:
        if job_id in QUEUE:
            QUEUE.remove(job_id)
            _slots.notify_all()
            return "removed from the queue"
    if progress.cancel(f"job:{job_id}", who):
        return "stopping: PCs already being scanned finish, the rest are skipped"
    return None


def queue_snapshot() -> list[tuple[int, float, str]]:
    with _slots:
        return [(j, *QUEUED.get(j, (time.time(), "?"))) for j in QUEUE]


def _run_scan_job(job_id: int, who: str) -> None:
    from .db import ScanJob
    with SessionLocal() as db:
        job = db.get(ScanJob, job_id)
        if job is None:
            return
        name, colls = job.name, [c for c in COLLECTOR_ORDER if c in (job.collectors or "").split(",")]
        ids = [int(x) for x in (job.target_ids or "").split(",") if x.strip().isdigit()]
        par, expected = job.max_parallel, job.last_seconds
        ipm = {m for m in (job.ip_methods or "").split(",") if m} or None
        grp = job.group_name or None
        job.last_run = utcnow()
        db.commit()
    key = f"job: {name}"
    RUNNING[key] = time.time()
    prog = progress.start(f"job:{job_id}", name, job_id=job_id, steps=colls,
                          who=None if who == "schedule" else who, expected=expected)
    started, parts, ok = time.time(), [], True
    try:
        with SessionLocal() as db:
            run = CollectorRun(collector=f"job:{job_id}", started=utcnow())
            db.add(run)
            db.commit()
            with scanning.scoped(ids, par, ipm, grp):
                for c in colls:
                    if prog.stop.is_set():
                        break
                    prog.begin_step(c)
                    try:
                        parts.append(f"{c}: {JOBS[c](db)}")
                        db.commit()
                    except Exception as exc:
                        db.rollback()
                        log.exception("scan job %s, %s failed", name, c)
                        ok = False
                        parts.append(f"{c}: failed ({short_error(exc)})")
            msg = ("; ".join(parts) or "nothing to do") + ("" if who == "schedule" else f" (started by {who})")
            if prog.stop.is_set():
                ok = False
                msg = f"Cancelled by {prog.cancelled_by or 'someone'}. " + msg
            run.ok, run.message, run.finished = ok, msg[:4000], utcnow()
            db.add(run)
            _refresh_groups(db)
            job = db.get(ScanJob, job_id)
            if job:
                job.last_ok, job.last_result = ok, msg[:4000]
                if not prog.stop.is_set():      # a cancelled run would make the next ETA too short
                    job.last_seconds = int(time.time() - started)
            db.commit()
    finally:
        progress.end(prog)
        RUNNING.pop(key, None)


def scheduler_loop(stop: threading.Event) -> None:
    """Starts scan jobs when they're due. Each runs in its own thread, waits for a free slot (Settings: how many
    jobs may run at once) and is skipped while its previous run is still queued or running."""
    from datetime import datetime
    from sqlalchemy import select
    from .db import ScanJob
    stop.wait(20)
    while not stop.is_set():
        try:
            with SessionLocal() as db:
                migrate_schedule(db)
                from . import groups
                groups.refresh_if_stale(db)     # agent reports and edits change membership between scans too
                now = datetime.now()
                due = [j.id for j in db.scalars(select(ScanJob).where(ScanJob.enabled.is_(True)))
                       if not JOB_STATE.get(j.id) and is_due(j, now, _local(j.last_run))]
            for jid in due:
                threading.Thread(target=run_scan_job, args=(jid,), daemon=True).start()
        except Exception:
            log.exception("scheduler")
        stop.wait(30)


def migrate_schedule(db) -> None:
    """Versions before 0.7 had one interval per collector. Turn those into jobs over all targets, once."""
    from sqlalchemy import select
    from .db import ScanJob, set_setting
    if get_setting(db, "jobs:migrated"):
        return
    if not db.scalar(select(ScanJob.id).limit(1)):
        iv = intervals(db)
        ready = _configured(db)
        names = {"ad": "Active Directory import", "snmp": "Network devices (SNMP) and WinRM sweep",
                 "pcs": "PC inventory (WinRM)", "pcs_updates": "Pending Windows updates (WinRM)",
                 "dc_logons": "Logons from domain controllers"}
        for c in COLLECTOR_ORDER:
            db.add(ScanJob(name=names[c], collectors=c, every_min=iv[c] or DEFAULT_INTERVALS[c],
                           enabled=bool(iv[c]) and settings.schedule.get("enabled", True) is not False))
    set_setting(db, "jobs:migrated", "1")
    db.commit()


def _configured(db) -> dict[str, bool]:
    from sqlalchemy import select
    kinds = {k for (k,) in db.execute(select(ScanTarget.kind).where(ScanTarget.enabled.is_(True)))}
    ad = bool(kinds & set(scanning.AD_KINDS)) or bool(settings.ad.get("server"))
    ip = "ip_range" in kinds or bool(settings.snmp.get("targets"))
    win = bool(kinds) or bool(settings.winrm.get("user"))
    return {"ad": ad, "snmp": ip, "pcs": win, "pcs_updates": win, "dc_logons": win and ad}
