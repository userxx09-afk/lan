"""The port_map table behind v_port_map: where each MAC is plugged in now.

Working it out ranks every MAC sighting on every switch and looks up the owner of each MAC, which takes about a
second on a large network. v_devices used to do that inside the view, once per computer per column, so the
Computers list, the dashboard and the switch pages took minutes once the MAC tables filled up.

Now the result is stored and recomputed only when what it depends on changes:
  - any write to mac_sightings, switch_ports, network_devices, device_nics, ip_sightings or arp_entries, or a computer
    being added or removed, marks it stale (an after_flush hook, so every collector is covered without changes);
  - a background thread refreshes a stale map within REFRESH_DELAY seconds, and every SAFETY_INTERVAL anyway (for raw
    SQL writes and the command-line collectors, which run in another process);
  - a request that reads it while it's stale refreshes it first (ensure_fresh), so a page never shows a map older
    than the data that was just written.
"""
from __future__ import annotations

import logging
import threading
import time

from sqlalchemy import event, text
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)
REFRESH_DELAY = 20          # seconds: let a burst of writes (a switch poll, a DHCP import) finish first
SAFETY_INTERVAL = 900       # seconds: refresh at least this often, whatever the hook saw

_lock = threading.Lock()
_state = {"dirty": True, "dirty_since": 0.0, "last": 0.0, "seconds": None, "rows": None, "error": None}
_WATCH = {"mac_sightings", "switch_ports", "network_devices", "device_nics", "ip_sightings", "arp_entries"}


def mark_dirty() -> None:
    if not _state["dirty"]:
        _state["dirty_since"] = time.time()
    _state["dirty"] = True


@event.listens_for(Session, "after_flush")
def _after_flush(session, _ctx) -> None:
    if _state["dirty"]:
        return
    for obj in (*session.new, *session.deleted, *session.dirty):
        t = getattr(obj, "__tablename__", None)
        if t in _WATCH or (t == "devices" and obj not in session.dirty):
            mark_dirty()
            return


@event.listens_for(Session, "do_orm_execute")
def _bulk(orm_ctx) -> None:
    """delete(MacSighting)... / update(...) statements don't go through flush."""
    if _state["dirty"] or not (orm_ctx.is_delete or orm_ctx.is_update or orm_ctx.is_insert):
        return
    try:
        t = orm_ctx.bind_mapper.local_table.name if orm_ctx.bind_mapper else None
    except Exception:
        t = None
    if t in _WATCH or t == "devices":
        mark_dirty()


def refresh(db: Session) -> int:
    """Recompute port_map from the MAC tables. One transaction: readers see the old map until it's done."""
    from .correlate import PORT_MAP_COLS, PORT_MAP_LIVE, dialect_sql
    with _lock:
        _state["dirty"] = False          # writes during the refresh mark it dirty again
        t0 = time.time()
        cols = ", ".join(PORT_MAP_COLS)
        try:
            if db.get_bind().dialect.name == "postgresql":
                # one refresh at a time across processes (the server and a command-line collect); readers aren't blocked
                db.execute(text("LOCK TABLE port_map IN EXCLUSIVE MODE"))
            db.execute(text("DELETE FROM port_map"))
            n = db.execute(text(f"INSERT INTO port_map ({cols}) SELECT {cols} FROM ("
                                f"{dialect_sql(PORT_MAP_LIVE, db.get_bind().dialect.name)}) live")).rowcount
            db.commit()
        except Exception as exc:
            db.rollback()
            _state["dirty"] = True
            _state["error"] = f"{type(exc).__name__}: {str(getattr(exc, 'orig', None) or exc).splitlines()[0][:300]}"
            raise
        _state.update(last=time.time(), seconds=round(time.time() - t0, 2), rows=n, error=None)
        return n or 0


def ensure_fresh(db: Session) -> None:
    """Refresh first if something changed since the last refresh. Doesn't wait for a refresh already running."""
    if not _state["dirty"] or _lock.locked():
        return
    try:
        refresh(db)
    except Exception:
        log.exception("refreshing the switch port map")


def status() -> dict:
    return {"stale": _state["dirty"], "refreshed": _state["last"], "seconds": _state["seconds"], "rows": _state["rows"],
            "error": _state["error"]}


def loop(stop: threading.Event) -> None:
    from .db import SessionLocal
    while not stop.wait(5):
        now = time.time()
        due = (_state["dirty"] and now - _state["dirty_since"] >= REFRESH_DELAY) or now - _state["last"] >= SAFETY_INTERVAL
        if not due or _lock.locked():
            continue
        try:
            with SessionLocal() as db:
                refresh(db)
        except Exception:
            log.exception("refreshing the switch port map")
