"""Scanning exclusions (Settings > Scanning exclusions).

- ip:    a single address, a CIDR (10.0.5.0/24) or a range (10.0.5.10-10.0.5.50 or 10.0.5.10-50)
- host:  a host name, wildcards allowed (KIOSK-*, *.lab.example.com); matched against the short name and FQDN
- ou:    an AD distinguished name; anything at or below it is skipped (OU=Lab,DC=corp,DC=example,DC=com),
         or a partial path such as OU=Lab,OU=Sites that matches wherever it appears
- mac:   a MAC address in any common format; a trailing * matches a vendor prefix (00:15:5D*)
- event: a Windows event source and ID ("Microsoft-Windows-DistributedCOM 10009"). Source names match loosely:
         case, the "Microsoft-Windows-" prefix and punctuation are ignored, and DCOM = DistributedCOM.

ip, host, ou and mac are skipped by every scan (AD import, WinRM, SNMP, the WinRM port sweep).
Events matching an event exclusion are not stored, so they never reach reports or alerts.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re

from sqlalchemy import select

KINDS = {"event": "Windows event", "ip": "IP address or range", "host": "Host name", "ou": "AD OU / distinguished name",
         "mac": "MAC address"}

# Noisy DCOM/WMI events most inventory tools exclude by default; added once, deletable.
DEFAULT_EVENTS = ["DCOM 10009", "DistributedCOM 10009", "Microsoft-Windows-DistributedCOM 10009",
                  "Microsoft-Windows-DistributedCOM 10028", "Microsoft-Windows-WMI 5605"]
_ALIASES = {"dcom": "distributedcom"}


def _src(s: str) -> str:
    s = re.sub(r"[^a-z0-9]", "", s.lower().removeprefix("microsoft-windows-").removeprefix("microsoft windows "))
    s = s.removeprefix("microsoftwindows")
    return _ALIASES.get(s, s)


def parse_event(value: str) -> tuple[str, int]:
    m = re.fullmatch(r"\s*(.*?)[\s:/#]+(\d{1,5})\s*", value or "")
    if not m or not m.group(1).strip():
        raise ValueError('enter the event source and ID, e.g. "Microsoft-Windows-DistributedCOM 10009"')
    return _src(m.group(1)), int(m.group(2))


def parse_ip(value: str) -> tuple[int, int]:
    """(first, last) as integers."""
    v = value.strip()
    try:
        if "/" in v:
            n = ipaddress.ip_network(v, strict=False)
            return int(n.network_address), int(n.broadcast_address)
        if "-" in v:
            a, b = (x.strip() for x in v.split("-", 1))
            first = ipaddress.ip_address(a)
            if b.isdigit():
                b = ".".join(a.split(".")[:3] + [b])
            last = ipaddress.ip_address(b)
            if int(last) < int(first):
                raise ValueError
            return int(first), int(last)
        a = ipaddress.ip_address(v)
        return int(a), int(a)
    except ValueError:
        raise ValueError("enter an IP address, a CIDR like 10.0.5.0/24, or a range like 10.0.5.10-10.0.5.50") from None


def norm_mac(v: str) -> str:
    return re.sub(r"[^0-9a-f*]", "", (v or "").lower())


def validate(kind: str, value: str) -> str:
    """Returns the value to store, or raises ValueError with a message for the user."""
    v = (value or "").strip()
    if kind not in KINDS:
        raise ValueError("unknown exclusion type")
    if not v or len(v) > 500:
        raise ValueError("enter a value")
    if kind == "event":
        parse_event(v)
    elif kind == "ip":
        parse_ip(v)
    elif kind == "mac":
        m = norm_mac(v)
        if not re.fullmatch(r"[0-9a-f]{2,12}\*?", m) or ("*" not in m and len(m) != 12):
            raise ValueError("enter a MAC address like 00:15:5D:01:02:03, or a prefix with * like 00:15:5D*")
    elif kind == "ou":
        if "=" not in v:
            raise ValueError("enter a distinguished name like OU=Lab,DC=corp,DC=example,DC=com")
    elif kind == "host" and not re.fullmatch(r"[A-Za-z0-9.*?_-]+", v):
        raise ValueError("host names can use letters, digits, - . _ and the wildcards * and ?")
    return v


class Exclusions:
    """Loaded once per scan; cheap to query for each target."""

    def __init__(self, rows=()):
        self.ips, self.hosts, self.ous, self.macs, self.events = [], [], [], [], set()
        for kind, value in rows:
            try:
                if kind == "ip":
                    self.ips.append(parse_ip(value))
                elif kind == "host":
                    self.hosts.append(value.lower())
                elif kind == "ou":
                    self.ous.append(re.sub(r"\s*,\s*", ",", value.strip().lower()))
                elif kind == "mac":
                    self.macs.append(norm_mac(value))
                elif kind == "event":
                    self.events.add(parse_event(value))
            except ValueError:
                continue    # a row saved by hand that doesn't parse: ignore it rather than break scans

    @classmethod
    def load(cls, db) -> "Exclusions":
        from .db import ScanExclusion
        try:
            return cls(db.execute(select(ScanExclusion.kind, ScanExclusion.value)).all())
        except Exception:
            return cls()

    def ip(self, addr: str | None) -> bool:
        if not addr or not self.ips:
            return False
        try:
            n = int(ipaddress.ip_address(addr.strip()))
        except ValueError:
            return False
        return any(a <= n <= b for a, b in self.ips)

    def host(self, *names: str | None) -> bool:
        for name in names:
            if name:
                n = name.lower()
                short = n.split(".")[0]
                if any(fnmatch.fnmatchcase(n, p) or fnmatch.fnmatchcase(short, p) for p in self.hosts):
                    return True
        return False

    def dn(self, dn: str | None) -> bool:
        if not dn or not self.ous:
            return False
        d = "," + re.sub(r"\s*,\s*", ",", dn.lower()) + ","
        return any(("," + o + ",") in d for o in self.ous)

    def mac(self, *macs: str | None) -> bool:
        for m in macs:
            n = norm_mac(m or "")
            if n and any(n.startswith(p[:-1]) if p.endswith("*") else n == p for p in self.macs):
                return True
        return False

    def event(self, source: str | None, event_id: int | None) -> bool:
        if not self.events or event_id is None:
            return False
        s = _src(source or "")
        return any(i == event_id and (s == p or s.endswith(p) or p.endswith(s)) for p, i in self.events if s)

    def target(self, address: str | None = None, hostname: str | None = None, fqdn: str | None = None,
               dn: str | None = None, macs=()) -> bool:
        """True when a scan target matches any ip/host/ou/mac exclusion."""
        return (self.ip(address) or self.host(hostname, fqdn, address if address and not _is_ip(address) else None)
                or self.dn(dn) or self.mac(*macs))


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def seed(db) -> None:
    """Adds the default event exclusions the first time this version runs."""
    from .db import ScanExclusion, get_setting, set_setting
    if get_setting(db, "exclusions:seeded"):
        return
    for v in DEFAULT_EVENTS:
        db.add(ScanExclusion(kind="event", value=v, note="default", created_by="setup"))
    set_setting(db, "exclusions:seeded", "1")
    db.commit()
