"""Shared ingest logic.

The agentless WinRM collector and any future endpoint agent both produce the same
EndpointPayload, so adding an agent later only means a new way of delivering it
(POST /api/ingest/endpoint) - the storage, insights and reports stay the same.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from .db import ChangeEvent, Device, DeviceNic, PhysicalDisk, Disk, LogonEvent, Software, UpdateItem, norm_host, norm_mac, utcnow


class Nic(BaseModel):
    mac: str
    ip: str | None = None
    description: str | None = None


class DiskIn(BaseModel):
    drive: str
    size_gb: float
    free_gb: float


class SoftwareIn(BaseModel):
    name: str
    version: str | None = None
    publisher: str | None = None
    install_date: str | None = None
    product_code: str | None = None
    scope: str | None = None


class HotfixIn(BaseModel):
    kb: str | None = None
    installed_on: datetime | None = None
    title: str | None = None


class PendingIn(BaseModel):
    kb: str | None = None
    title: str | None = None
    severity: str | None = None


class AvIn(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    up_to_date: bool | None = None


class PhysDiskIn(BaseModel):
    model: str | None = None
    serial: str | None = None
    media: str | None = None
    size_gb: float | None = None
    health: str | None = None
    predict_failure: bool | None = None


class LogonIn(BaseModel):
    time: datetime
    username: str
    hostname: str | None = None
    ip: str | None = None
    logon_type: int | None = None
    source: str | None = None


class EndpointPayload(BaseModel):
    hostname: str
    fqdn: str | None = None
    source: str = "winrm"            # winrm | agent
    agent_version: str | None = None
    os_caption: str | None = None
    os_build: str | None = None
    os_display_version: str | None = None
    last_boot: datetime | None = None
    manufacturer: str | None = None
    model: str | None = None
    serial: str | None = None
    cpu: str | None = None
    gpu: str | None = None
    ram_gb: float | None = None
    current_user: str | None = None
    nics: list[Nic] = []
    disks: list[DiskIn] = []
    software: list[SoftwareIn] = []
    hotfixes: list[HotfixIn] = []
    pending_updates: list[PendingIn] | None = None   # None = not checked this run
    pending_reboot: bool | None = None
    logons: list[LogonIn] = []
    antivirus: list[AvIn] | None = None
    physical_disks: list[PhysDiskIn] | None = None


def get_or_create_device(db: Session, hostname: str) -> Device:
    host = norm_host(hostname)
    dev = db.scalar(select(Device).where(Device.hostname == host))
    if dev is None:
        dev = Device(hostname=host)
        db.add(dev)
        db.flush()
    return dev


def _naive(dt: datetime | None) -> datetime | None:
    """Store everything as naive UTC."""
    if dt is None or dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def log_change(db: Session, dev: Device, kind: str, detail: str) -> None:
    db.add(ChangeEvent(device_id=dev.id, kind=kind, detail=detail[:2000]))


def _track_changes(db: Session, dev: Device, p: EndpointPayload) -> None:
    if dev.agent_last_report is None:
        log_change(db, dev, "inventory", f"First inventory via {p.source}")
        return
    for attr, label in (("os_caption", "OS"), ("os_display_version", "OS version"), ("os_build", "OS build"),
                        ("ram_gb", "RAM (GB)"), ("cpu", "CPU"), ("serial", "Serial"), ("model", "Model")):
        old, new = getattr(dev, attr), getattr(p, attr)
        if new is not None and old is not None and str(old) != str(new):
            log_change(db, dev, "os" if attr.startswith("os") else "hardware", f"{label}: {old} -> {new}")
    old_sw = {(s.name, s.version) for s in dev.software}
    new_sw = {(s.name.strip(), s.version) for s in p.software if s.name.strip()}
    old_names = {n for n, _ in old_sw}
    new_names = {n for n, _ in new_sw}
    for n, v in sorted(new_sw - old_sw):
        if n in old_names:
            prev = next((ov for on, ov in old_sw if on == n), None)
            log_change(db, dev, "software_updated", f"{n}: {prev} -> {v}")
        else:
            log_change(db, dev, "software_added", f"{n} {v or ''}".strip())
    for n, v in sorted(old_sw - new_sw):
        if n not in new_names:
            log_change(db, dev, "software_removed", f"{n} {v or ''}".strip())


def apply_endpoint(db: Session, p: EndpointPayload) -> Device:
    dev = get_or_create_device(db, p.hostname)
    _track_changes(db, dev, p)
    for attr in ("fqdn", "os_caption", "os_build", "os_display_version", "manufacturer", "model",
                 "serial", "cpu", "gpu", "ram_gb", "current_user", "pending_reboot", "agent_version"):
        val = getattr(p, attr)
        if val is not None:
            setattr(dev, attr, val)
    dev.last_boot = _naive(p.last_boot) or dev.last_boot
    dev.agent_last_report = utcnow()

    dev.nics = [DeviceNic(mac=m, ip=n.ip, description=n.description)
                for n in p.nics if (m := norm_mac(n.mac))]
    if p.antivirus is not None:
        av = [a for a in p.antivirus if a.name]
        on = [a for a in av if a.enabled]
        best = (on or av or [None])[0]
        dev.av_name = ", ".join(a.name for a in av) or None
        dev.av_enabled = bool(on) if av else False
        dev.av_up_to_date = bool(best and best.up_to_date) if av else None
    if p.physical_disks is not None:
        dev.physical_disks = [PhysicalDisk(model=d.model, serial=d.serial or None, media=d.media, size_gb=d.size_gb,
                                           health=d.health, predict_failure=d.predict_failure) for d in p.physical_disks]
    dev.disks = [Disk(drive=d.drive, size_gb=round(d.size_gb, 1), free_gb=round(d.free_gb, 1)) for d in p.disks]

    seen = set()
    sw = []
    for s in p.software:
        key = (s.name.strip(), s.version)
        if s.name.strip() and key not in seen:
            seen.add(key)
            sw.append(Software(name=s.name.strip()[:255], version=(s.version or None) and s.version[:64],
                               publisher=(s.publisher or None) and s.publisher[:255], install_date=s.install_date,
                               product_code=(s.product_code or None) and s.product_code[:255],
                               scope=s.scope if s.scope in ("machine", "user") else None))
    dev.software = sw

    pending_old = [u for u in dev.updates if u.status == "pending"]
    items = [UpdateItem(kb=h.kb, title=h.title, status="installed", installed_on=_naive(h.installed_on))
             for h in p.hotfixes]
    if p.pending_updates is None:
        # Pending check skipped this run (it is slow over WinRM) - keep the previous result.
        items += [UpdateItem(kb=u.kb, title=u.title, status="pending", severity=u.severity) for u in pending_old]
    else:
        items += [UpdateItem(kb=u.kb, title=u.title, status="pending", severity=u.severity)
                  for u in p.pending_updates]
        dev.pending_updates = len(p.pending_updates)
    dev.updates = items
    dates = [i.installed_on for i in items if i.installed_on]
    dev.last_patch_installed = max(dates) if dates else dev.last_patch_installed

    if p.logons:
        add_logons(db, [l.model_copy(update={"hostname": l.hostname or dev.hostname,
                                              "source": l.source or f"local:{dev.hostname}"})
                        for l in p.logons])
    return dev


LOCAL_IPS = {"", "-", "127.0.0.1", "::1"}


def dc_client_host(host: str | None, ip: str | None, source: str) -> str | None:
    """The computer the user signed in from, for an event read off a DC's Security log.

    4624 often names the DC itself in WorkstationName (Kerberos network logons on newer Windows).
    That says nothing about the client, so drop it unless the logon really came from the DC
    (no or loopback address); the IP is then matched to a PC by resolve_logon_hosts."""
    dc = norm_host(source[3:])
    local = (ip or "").strip() in LOCAL_IPS
    if host == dc and not local:
        return None
    return host or (dc if local and ip is not None else None)


LOGON_NTLM = 100          # pseudo logon type for 4776 (NTLM credential validation on a DC); 0 = 4768 Kerberos TGT
EVENT_OF_TYPE = {0: 4768, LOGON_NTLM: 4776}


def _drop_known_ipless(db: Session, rows: list[dict]) -> list[dict]:
    """The unique key includes ip, and NULLs never conflict, so 4776 rows (no IP) read twice at the edge of a
    DC pull would be stored twice. Skip the ones already there."""
    ipless = [r for r in rows if r["ip"] is None]
    if not ipless:
        return rows
    lo, hi = min(r["time"] for r in ipless), max(r["time"] for r in ipless)
    have = {(s, u, t, lt) for s, u, t, lt in db.execute(
        select(LogonEvent.source, LogonEvent.username, LogonEvent.time, LogonEvent.logon_type)
        .where(LogonEvent.ip.is_(None), LogonEvent.time >= lo, LogonEvent.time <= hi))}
    out, seen = [], set()
    for r in rows:
        if r["ip"] is None:
            k = (r["source"], r["username"], r["time"], r["logon_type"])
            if k in have or k in seen:
                continue
            seen.add(k)
        out.append(r)
    return out


def add_logons(db: Session, logons: list[LogonIn]) -> int:
    from .exclusions import Exclusions
    excl = Exclusions.load(db)
    rows = []
    for l in logons:
        user = l.username.split("\\")[-1].split("@")[0].lower()
        if not user or user.endswith("$") or user in {"system", "anonymous logon", "-"}:
            continue  # computer accounts / system noise
        # Logons come from Security events 4768 (Kerberos TGT, logon_type 0), 4776 (NTLM, LOGON_NTLM) and 4624.
        if excl.event("Microsoft-Windows-Security-Auditing", EVENT_OF_TYPE.get(l.logon_type, 4624)):
            continue
        if excl.host(l.hostname) or excl.ip(l.ip):
            continue
        host = norm_host((l.hostname or "").strip().lstrip("\\"))     # 4776 can say \\PC01
        if l.source and l.source.lower().startswith("dc:"):
            host = dc_client_host(host, l.ip, l.source)
        rows.append(dict(time=_naive(l.time), username=user[:128], hostname=host and host[:64],
                         ip=(l.ip or None) and l.ip[:64], logon_type=l.logon_type, source=(l.source or None) and l.source[:64],
                         host_via="event" if host else None))
    if not rows:
        return 0
    rows = _drop_known_ipless(db, rows)
    if not rows:
        return 0
    dialect = db.get_bind().dialect.name
    ins = pg_insert if dialect == "postgresql" else sqlite_insert
    # One INSERT per 1,000 rows: PostgreSQL allows at most 65,535 parameters per statement (a DC can return 50,000 events).
    for i in range(0, len(rows), 1000):
        db.execute(ins(LogonEvent).values(rows[i:i + 1000]).on_conflict_do_nothing())
    return len(rows)
