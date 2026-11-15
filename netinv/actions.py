"""Per-device actions from the asset page: ping, Wake-on-LAN, rescan, reboot, RDP file.

Everything runs from the NetInventory server, so "ping" and "Wake on LAN" are from the
server's point of view. Reboot uses WinRM with the configured service account and is
logged in the device history.
"""
from __future__ import annotations

import platform
import re
import socket
import subprocess
import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import Device, SessionLocal
from .ingest import log_change

HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,255}$")


def _addr(dev: Device) -> str:
    addr = dev.fqdn or dev.hostname
    if not HOST_RE.match(addr):
        raise ValueError("invalid host name")
    return addr


def ping(dev: Device, count: int = 2) -> dict:
    addr = _addr(dev)
    win = platform.system() == "Windows"
    cmd = ["ping", "-n" if win else "-c", str(count), "-w" if win else "-W", "1000" if win else "1", addr]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        text = (out.stdout or out.stderr).strip()
        return {"ok": out.returncode == 0, "output": text[-1500:]}
    except FileNotFoundError:
        # No ping binary (e.g. slim container): fall back to a TCP probe on WinRM / RDP / SMB.
        for port in (5985, 3389, 445):
            try:
                with socket.create_connection((addr, port), timeout=2):
                    return {"ok": True, "output": f"TCP {port} open on {addr}"}
            except OSError:
                continue
        return {"ok": False, "output": f"{addr} did not answer on TCP 5985, 3389 or 445"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "ping timed out"}


def wake_on_lan(dev: Device) -> dict:
    macs = [n.mac for n in dev.nics] or []
    if not macs:
        from sqlalchemy import text
        # Fall back to the MAC seen on the switch port.
        with SessionLocal() as db:
            m = db.execute(text("SELECT mac FROM v_port_map WHERE hostname = :h LIMIT 1"), {"h": dev.hostname}).scalar()
            macs = [m] if m else []
    if not macs:
        return {"ok": False, "output": "No MAC address known for this device."}
    targets = settings.winrm.get("wol_broadcasts") or ["255.255.255.255"]
    # Also send a directed broadcast to the PC's own /24, which crosses routers that allow it.
    ip = next((n.ip for n in dev.nics if n.ip), None)
    if ip and ip.count(".") == 3:
        targets = list(targets) + [ip.rsplit(".", 1)[0] + ".255"]
    sent = []
    for mac in macs:
        payload = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for bcast in targets:
                s.sendto(payload, (bcast, 9))
                sent.append(f"{mac} -> {bcast}")
    return {"ok": True, "output": "Magic packet sent: " + ", ".join(sent)}


def rescan(hostname: str) -> dict:
    """Re-run the WinRM inventory for one PC in the background."""
    from . import jobs
    from .collectors import winrm

    def work():
        key = f"rescan:{hostname}"
        jobs.RUNNING[key] = time.time()
        try:
            with SessionLocal() as db:
                dev = db.scalar(select(Device).where(Device.hostname == hostname))
                from .scanning import winrm_cfg
                base = winrm_cfg(db) or dict(settings.winrm)
                cfg = {**base, "hosts": [_addr(dev)], "include_ad": False}
                msg = winrm.collect_endpoints(db, cfg, check_pending=True)
                dev = db.scalar(select(Device).where(Device.hostname == hostname))
                log_change(db, dev, "action", f"Rescan: {msg}")
                db.commit()
        finally:
            jobs.RUNNING.pop(key, None)
    threading.Thread(target=work, daemon=True).start()
    return {"ok": True, "output": "Rescan started. This takes up to a few minutes including the Windows Update check."}


def reboot(db: Session, dev: Device, who: str) -> dict:
    from .collectors.winrm import run_ps
    from .scanning import winrm_cfg
    cfg = winrm_cfg(db)
    if not cfg:
        return {"ok": False, "output": "No Windows credential is configured (Settings > Credentials)."}
    try:
        run_ps(_addr(dev), cfg, "Restart-Computer -Force; '\"ok\"'")
    except Exception as exc:
        return {"ok": False, "output": f"Reboot failed: {exc}"}
    log_change(db, dev, "action", f"Reboot requested by {who}")
    db.commit()
    return {"ok": True, "output": f"Reboot sent to {dev.hostname}."}


def rdp_file(dev: Device) -> str:
    return (f"full address:s:{_addr(dev)}\r\nprompt for credentials:i:1\r\nadministrative session:i:0\r\n"
            "screen mode id:i:2\r\nauthentication level:i:2\r\n")
