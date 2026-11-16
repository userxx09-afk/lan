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


def add_logons(db: Session, logons: list[LogonIn]) -> int:
    rows = []
    for l in logons:
        user = l.username.split("\\")[-1].split("@")[0].lower()
        if not user or user.endswith("$") or user in {"system", "anonymous logon", "-"}:
            continue  # computer accounts / system noise
        rows.append(dict(time=_naive(l.time), username=user, hostname=norm_host(l.hostname),
                         ip=l.ip, logon_type=l.logon_type, source=l.source))
    if not rows:
        return 0
    dialect = db.get_bind().dialect.name
    ins = pg_insert if dialect == "postgresql" else sqlite_insert
    db.execute(ins(LogonEvent).values(rows).on_conflict_do_nothing())
    return len(rows)
