"""Is it up? A light reachability check that keeps every PC's status dot live.

Each address gets one ICMP echo (Windows: IcmpSendEcho, which needs no admin rights) and, if that gets no
answer, a TCP connect to a few ports Windows PCs usually expose. A refused connection still proves the host is
up. Nothing is installed or run on the PCs. Runs every few minutes (Settings, default 5) in a background thread.
"""
from __future__ import annotations

import ipaddress
import logging
import platform
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Device, DeviceNic, SessionLocal, get_setting, utcnow

log = logging.getLogger(__name__)
TCP_PORTS = (445, 135, 3389, 5985, 22, 80, 443)
DEFAULT_INTERVAL = 5
_WIN = platform.system() == "Windows"
_icmp = None


def _icmp_handle():
    global _icmp
    if _icmp is None:
        import ctypes
        from ctypes import wintypes
        lib = ctypes.WinDLL("iphlpapi.dll")
        lib.IcmpCreateFile.restype = wintypes.HANDLE
        lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD, ctypes.c_void_p,
                                     ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        lib.IcmpSendEcho.restype = wintypes.DWORD
        lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        _icmp = lib
    return _icmp


def icmp(ip: str, timeout_ms: int = 800) -> bool:
    """One echo request. Windows only (no admin needed); False elsewhere or on any error."""
    if not _WIN:
        return False
    try:
        import ctypes
        lib = _icmp_handle()
        h = lib.IcmpCreateFile()
        try:
            dest = struct.unpack("<I", socket.inet_aton(ip))[0]   # IPAddr is the address in network byte order
            data = b"netinv"
            reply = ctypes.create_string_buffer(64 + len(data) + 8)
            n = lib.IcmpSendEcho(h, dest, data, len(data), None, reply, len(reply), timeout_ms)
            status = struct.unpack_from("<I", reply.raw, 4)[0]    # ICMP_ECHO_REPLY.Status, 0 = success
            return n > 0 and status == 0
        finally:
            lib.IcmpCloseHandle(h)
    except Exception:
        return False


_trust_refused = True


def tcp(ip: str, timeout: float = 0.8, ports=TCP_PORTS) -> bool:
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            if _trust_refused:
                return True        # something answered: the host is up, the port is just closed
        except OSError:
            continue
    return False


def _calibrate() -> None:
    """A firewall that rejects (rather than drops) would make every address look up. 192.0.2.1 is a documentation
    address that never exists: if it 'refuses', refusals prove nothing on this network and only open ports count."""
    global _trust_refused
    try:
        socket.create_connection(("192.0.2.1", 445), timeout=0.8).close()
        _trust_refused = False
    except ConnectionRefusedError:
        _trust_refused = False
    except OSError:
        _trust_refused = True


def probe(addr: str) -> tuple[bool, str]:
    """(up, how): how is ping, tcp, dns (name doesn't resolve) or '' when nothing answered."""
    try:
        ip = str(ipaddress.ip_address(addr))
    except ValueError:
        try:
            ip = socket.gethostbyname(addr)
        except OSError:
            return False, "dns"
    if icmp(ip):
        return True, "ping"
    if tcp(ip, ports=TCP_PORTS[:4] if _WIN else TCP_PORTS):
        return True, "tcp"
    return False, ""


def sweep(addrs: list[str], parallel: int = 64) -> dict[str, tuple[bool, str]]:
    _calibrate()
    with ThreadPoolExecutor(max_workers=max(1, min(parallel, len(addrs) or 1))) as pool:
        return dict(zip(addrs, pool.map(probe, addrs)))


def mark(dev: Device, up: bool, via: str, now=None) -> None:
    now = now or utcnow()
    if dev.online is None or dev.online != up:
        dev.online_changed = now
    dev.online, dev.online_checked, dev.online_via = up, now, via or dev.online_via


def interval(db: Session) -> int:
    try:
        return max(0, min(1440, int(get_setting(db, "reach:interval_min", None) or DEFAULT_INTERVAL)))
    except ValueError:
        return DEFAULT_INTERVAL


def _address(dev: Device, nics: list[DeviceNic]) -> str:
    ips = [n.ip for n in nics if n.ip]
    return ips[0] if ips else (dev.fqdn or dev.hostname)


def check_all(db: Session) -> str:
    """Probe every active PC once and update its status. Agent heartbeats in the last few minutes count as up."""
    from .exclusions import Exclusions
    excl = Exclusions.load(db)
    devs = [d for d in db.scalars(select(Device)) if (d.state or "Active") not in ("Retired", "Disposed")
            and d.ad_enabled is not False and not excl.target(hostname=d.hostname, fqdn=d.fqdn, dn=d.ad_dn)]
    nics: dict[int, list] = {}
    for n in db.scalars(select(DeviceNic)):
        nics.setdefault(n.device_id, []).append(n)
    now = utcnow()
    fresh_agent = now - timedelta(minutes=max(10, 3 * interval(db)))
    todo = {}
    for d in devs:
        if d.agent_last_report and d.agent_last_report >= fresh_agent:
            mark(d, True, "scan", now)
            continue
        addr = _address(d, nics.get(d.id, []))
        if addr and not excl.ip(addr):
            todo.setdefault(addr, []).append(d)
    res = sweep(list(todo))
    up = 0
    for addr, (ok, how) in res.items():
        for d in todo[addr]:
            mark(d, ok, how, now)
            up += ok
    db.commit()
    return f"{up} of {len(devs)} PCs online"


def loop(stop: threading.Event) -> None:
    stop.wait(15)
    while not stop.is_set():
        mins = DEFAULT_INTERVAL
        try:
            with SessionLocal() as db:
                mins = interval(db)
                if mins:
                    log.info("reachability: %s", check_all(db))
        except Exception:
            log.exception("reachability check")
        stop.wait(60 * (mins or 5))
