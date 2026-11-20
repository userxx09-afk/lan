"""Scan now for network devices (Network tab): poll one switch/router over SNMP right away, or all known ones.

Only the SNMP poll runs (system info, ports, MAC table, LLDP/CDP, ARP), the same collector a scheduled IP-range scan
uses, so the results land in the same tables. No ping sweep and no WinRM: the device is already known by its IP.

SNMP credentials tried for a device, in order: the ones ticked on the saved IP-range targets whose range holds the
device's IP, then the ones on every other saved target, then every stored SNMP credential, then the [snmp] block of
the config file. The first that answers is used.

Each run shows live on the Scanning tab like a one-time scan (key "once:<n>", so it can be cancelled there), is a
CollectorRun ("device"), and is in the audit log when it starts and when it ends. Its result is kept in DONE for a
while so the Network tab can show it next to the row.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import AuditLog, CollectorRun, Credential, NetworkDevice, ScanTarget, SessionLocal, utcnow
from . import instance, oneshot, progress, scanning

log = logging.getLogger(__name__)

KEEP_DONE = 3600                     # seconds a finished run's result is kept for the Network tab
DONE: dict[str, dict] = {}           # "once:<n>" -> {"ok", "message", "ips", "results", "finished"}
BUSY: dict[str, str] = {}            # device IP -> key of the run scanning it now
_lock = threading.Lock()


def in_range(ip: str, value: str) -> bool:
    """Is ip inside a target value (IPs, CIDRs, a-b ranges, comma or semicolon separated), without expanding it."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for part in value.replace(";", ",").split(","):
        part = part.strip()
        try:
            if "/" in part:
                if a in ipaddress.ip_network(part, strict=False):
                    return True
            elif "-" in part:
                lo, hi = (x.strip() for x in part.split("-", 1))
                if "." not in hi:
                    hi = lo.rsplit(".", 1)[0] + "." + hi
                if int(ipaddress.ip_address(lo)) <= int(a) <= int(ipaddress.ip_address(hi)):
                    return True
            elif part and ipaddress.ip_address(part) == a:
                return True
        except ValueError:
            continue
    return False


def cred_ids_for(db: Session, ip: str, targets: list[ScanTarget] | None = None) -> list[int]:
    """SNMP credential ids to try on this device, best first (see the module docstring)."""
    kinds = ("snmp2", "snmp3")
    targets = targets if targets is not None else list(db.scalars(select(ScanTarget).order_by(ScanTarget.id)))
    covering = [t for t in targets if t.kind == "ip_range" and in_range(ip, t.value or "")]
    ids: list[int] = []
    for t in covering + [t for t in targets if t not in covering]:
        ids += [int(x) for x in (t.credential_ids or "").split(",") if x.strip().isdigit()]
    ids += [c.id for c in db.scalars(select(Credential).where(Credential.kind.in_(kinds)).order_by(Credential.name))]
    out = []
    for i in dict.fromkeys(ids):
        c = db.get(Credential, i) if i != scanning.SERVICE_CRED_ID else None
        if c and c.kind in kinds:
            out.append(i)
    return out


def _creds(db: Session, ip: str, targets: list[ScanTarget]) -> list[dict]:
    out = [scanning.cred_cfg(db.get(Credential, i)) for i in cred_ids_for(db, ip, targets)]
    if settings.snmp.get("community") or settings.snmp.get("v3_user"):
        out.append({})               # the config file's [snmp] block (snmp.poll_device reads cfg)
    return out


def busy() -> dict[str, str]:
    with _lock:
        return dict(BUSY)


def _prune() -> None:
    now = time.time()
    for k in [k for k, v in DONE.items() if now - v["finished"] > KEEP_DONE]:
        DONE.pop(k, None)


def start(db: Session, who: str, ips: list[str] | None) -> dict:
    """Starts the scan in its own thread. ips None = every network device. Raises ValueError with a message for the user."""
    known = {d.ip: d for d in db.scalars(select(NetworkDevice))}
    if ips is None:
        ips = sorted(known, key=lambda ip: (known[ip].sysname or ip).lower())
        if not ips:
            raise ValueError("No network devices yet. Add an IP range with SNMP ticked under Settings > Scan targets, "
                             "or run a one-time scan of a switch's IP.")
        what = f"all {len(ips)} network devices"
    else:
        ips = list(dict.fromkeys(i.strip() for i in ips if i and i.strip()))
        unknown = [i for i in ips if i not in known]
        if unknown or not ips:
            raise ValueError(f"Not a known network device: {', '.join(unknown) or '(none given)'}")
        what = ", ".join(known[i].sysname or i for i in ips)
    with _lock:
        taken = [i for i in ips if i in BUSY]
        if taken and len(taken) == len(ips):
            raise ValueError(f"Already being scanned: {', '.join(known[i].sysname or i for i in taken)}")
        ips = [i for i in ips if i not in BUSY]     # Scan all leaves the ones already running to their own scan
        key = f"once:{next(oneshot._n)}"
        for i in ips:
            BUSY[i] = key
    name = f"Scan now: {what}" if len(what) <= 80 else f"Scan now: {what[:77]}..."
    oneshot.ACTIVE[key] = {"name": name, "who": who}
    db.add(AuditLog(actor=who, action="scan.device", target=what[:120], result=f"started: SNMP poll of {len(ips)} device(s)"))
    db.commit()
    threading.Thread(target=_run, args=(key, name, what, ips, who), daemon=True, name=key).start()
    return {"ok": True, "key": key, "ips": ips, "skipped": taken,
            "output": f"Scanning {what} over SNMP" + (f" ({len(taken)} already being scanned)" if taken else "") + "."}


async def _poll(db: Session, ips: list[str], creds: dict[str, list[dict]], parallel: int) -> list[tuple]:
    from .collectors import snmp
    prog = progress.current()
    sem = asyncio.Semaphore(parallel)

    async def one(ip):
        async with sem:
            if prog and prog.stop.is_set():
                return ip, None, "cancelled"
            if prog:
                prog.host_start(ip)
            err = "no SNMP credential to try (add one under Settings > Credentials and tick it on the IP range)"
            for cred in creds[ip]:
                try:
                    data = await snmp.poll_device(ip, {**settings.snmp, **cred})
                    if prog:
                        prog.host_end(ip, True)
                    return ip, data, None
                except Exception as exc:
                    err = str(exc) or type(exc).__name__
            if prog:
                prog.host_end(ip, False, err)
            return ip, None, err
    return await asyncio.gather(*(one(ip) for ip in ips))


def _run(key: str, name: str, what: str, ips: list[str], who: str) -> None:
    from .collectors import snmp
    from .correlate import track_port_moves
    from . import jobs
    jobs.RUNNING[name] = time.time()
    prog = progress.start(key, name, steps=["snmp"], who=who)
    prog.begin_step("snmp")
    prog.hosts(len(ips))
    results: dict[str, dict] = {}
    ok, msg = False, ""
    try:
        with SessionLocal() as db:
            run = CollectorRun(collector="device", started=utcnow())
            db.add(run)
            db.commit()
            targets = list(db.scalars(select(ScanTarget).order_by(ScanTarget.id)))
            creds = {ip: _creds(db, ip, targets) for ip in ips}
            polled = asyncio.run(_poll(db, ips, creds, int(settings.snmp.get("parallel", 20))))
            good = 0
            for ip, data, err in polled:
                nd = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == ip))
                if err:
                    if nd and err != "cancelled":
                        nd.poll_error = err[:2000]
                    results[ip] = {"ok": False, "message": err if err != "cancelled" else "Cancelled before it started"}
                    db.commit()
                    continue
                try:
                    line = snmp.store(db, ip, data, settings.snmp.get("uplink_mac_threshold", 6))
                    db.commit()
                    good += 1
                    results[ip] = {"ok": True, "message": line}
                except Exception as exc:
                    db.rollback()
                    log.exception("scan now %s: store", ip)
                    results[ip] = {"ok": False, "message": f"answered, but saving failed: {scanning.short_error(exc)}"}
            moved = 0
            if good:
                try:
                    moved = track_port_moves(db)
                except Exception:
                    db.rollback()
                    log.exception("scan now: port moves")
            bad = len(ips) - good
            if len(ips) == 1:
                msg = results[ips[0]]["message"]
            else:
                msg = f"{good} of {len(ips)} devices answered" + (f", {bad} did not" if bad else "")
                fails = [f"{ip}: {r['message']}" for ip, r in results.items() if not r["ok"]]
                if fails:
                    msg += " (" + "; ".join(fails[:5]) + ("; …" if len(fails) > 5 else "") + ")"
            if moved:
                msg += f". {moved} PCs moved port."
            ok = good > 0
            if prog.stop.is_set():
                ok, msg = False, f"Cancelled by {prog.cancelled_by or 'someone'}. " + msg
            full = f"{what}: {msg} (started by {who})"
            run.ok, run.message, run.finished, run.ran_by = ok, full[:4000], utcnow(), instance.ran_by()
            db.add(run)
            db.add(AuditLog(actor=who, action="scan.device.done", target=what[:120],
                            result=("ok: " if ok else "") + msg[:1900]))
            db.commit()
            jobs._refresh_groups(db)
    except Exception as exc:
        log.exception("scan now %s", what)
        ok, msg = False, f"failed: {scanning.short_error(exc)}"
        for ip in ips:
            results.setdefault(ip, {"ok": False, "message": msg})
    finally:
        with _lock:
            _prune()
            DONE[key] = {"ok": ok, "message": msg, "ips": ips, "results": results, "finished": time.time()}
            for ip in ips:
                if BUSY.get(ip) == key:
                    BUSY.pop(ip, None)
        progress.end(prog)
        jobs.RUNNING.pop(name, None)
        oneshot.ACTIVE.pop(key, None)


def status(key: str) -> dict:
    with _lock:
        if key in DONE:
            return {"running": False, **{k: v for k, v in DONE[key].items() if k != "finished"}}
        running = key in oneshot.ACTIVE
    snap = next((r for r in progress.snapshot() if r["key"] == key), None)
    if not running and not snap:
        return {"running": False, "unknown": True}
    return {"running": True, "done": snap["done"] if snap else 0, "total": snap["total"] if snap else 0,
            "failed": snap["failed"] if snap else 0}
