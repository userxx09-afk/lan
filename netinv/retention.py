"""How long the high-volume history tables keep rows (Settings > Data retention). Runs once a day.

Deletes go in batches so a first run on a large database doesn't hold one huge transaction. 0 days = keep forever.
The audit log is never trimmed here, and current data (where a MAC is now, a PC's current IP) is never touched:
only sightings that stopped being seen longer ago than the limit.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from .db import get_setting, set_setting, utcnow

log = logging.getLogger(__name__)
BATCH = 20000

# key: (table, time column, label, default days, extra WHERE)
TABLES: dict[str, tuple[str, str, str, int, str]] = {
    "logons": ("logon_events", "time", "Logon events", 180, ""),
    "mac": ("mac_sightings", "last_seen", "Switch MAC sightings not seen since", 90, ""),
    "arp": ("arp_entries", "last_seen", "Router ARP entries not seen since", 90, ""),
    "wifi": ("wifi_sightings", "last_seen", "Wi-Fi access point history", 180, ""),
    "changes": ("change_events", "time", "Computer change history", 730, ""),
    "runs": ("collector_runs", "started", "Scan run history", 90, ""),
    "deployments": ("deployments", "created", "Finished pushes and scripts", 365,
                    " AND status IN ('success', 'failed', 'expired', 'cancelled')"),
}


def days(db: Session) -> dict[str, int]:
    out = {}
    for k, (_, _, _, default, _) in TABLES.items():
        try:
            out[k] = max(0, int(get_setting(db, f"retention:{k}", str(default))))
        except ValueError:
            out[k] = default
    return out


def describe(db: Session) -> dict:
    d = days(db)
    rows = []
    for k, (table, _, label, default, _) in TABLES.items():
        try:
            n = db.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
        except Exception:
            db.rollback()
            n = None
        rows.append({"key": k, "label": label, "days": d[k], "default": default, "rows": n})
    return {"tables": rows, "last_run": get_setting(db, "retention:last_run"), "last_result": get_setting(db, "retention:last_result")}


def save(db: Session, values: dict) -> None:
    for k, v in values.items():
        if k in TABLES and v is not None:
            n = int(v)
            if not 0 <= n <= 3650:
                raise ValueError(f"{TABLES[k][2]}: 0 (keep forever) to 3650 days")
            set_setting(db, f"retention:{k}", str(n))
    db.commit()


def run(db: Session) -> dict[str, int]:
    removed = {}
    now = utcnow()
    for k, n in days(db).items():
        if not n:
            continue
        table, col, _, _, extra = TABLES[k]
        cut = now - timedelta(days=n)
        total = 0
        while True:
            r = db.execute(text(f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {col} < :c{extra} LIMIT {BATCH})"),
                           {"c": cut}).rowcount or 0
            db.commit()
            total += r
            if r < BATCH:
                break
        if total:
            removed[k] = total
    msg = ", ".join(f"{TABLES[k][0]} {v}" for k, v in removed.items()) or "nothing to remove"
    set_setting(db, "retention:last_run", now.isoformat(sep=" ", timespec="seconds"))
    set_setting(db, "retention:last_result", msg)
    db.commit()
    if removed:
        log.info("retention: removed %s", msg)
        if "mac" in removed or "arp" in removed:
            from . import portmap
            portmap.mark_dirty()
    return removed


def loop(stop: threading.Event) -> None:
    from .db import SessionLocal
    if stop.wait(600):              # not during startup
        return
    while True:
        try:
            with SessionLocal() as db:
                run(db)
        except Exception:
            log.exception("data retention")
        if stop.wait(24 * 3600):
            return
