"""Computer groups.

A group is either
- static: computers added by hand (Computers > Add to group, or a PC's page), or
- rule-based ("dynamic"): defined by conditions, and its members follow the inventory. A PC that moves OU, gets a
  new IP or is renamed joins or leaves the group on the next refresh (after every scan, every few minutes, and
  whenever the group is saved or used as a target).

Members of both kinds live in device_groups, so the Groups column, report filters, scripts, pushes and scan jobs
all see them the same way; rule-based rows carry dynamic = true and are rewritten on each refresh. Computers added
by hand to a rule-based group stay in it whatever the rules say ("also include").

Conditions (all of them must match, or any one of them):
  hostname      LAB-*, KIOSK??       wildcards * and ?; without one, "contains"
  ip            10.1.20.0/24, 10.1.20.10-80, 10.1.20.5     any of the PC's addresses
  model         OptiPlex 70*         contains / wildcards
  manufacturer  Dell*
  os            *Windows 11*
  ou            corp.example.com/Sites/Office or OU=Office,OU=Sites,DC=corp,...     at or below that OU
  state         Active, Stock
Several values in one condition, comma-separated, mean "any of these". A condition can be negated ("is not").
"""
from __future__ import annotations

import fnmatch
import json
import logging
import re
import threading
import time

from sqlalchemy import delete, select

from .db import Device, DeviceGroup, DeviceNic, GroupDef, utcnow

log = logging.getLogger(__name__)

FIELDS = {
    "hostname": "Host name",
    "ip": "IP address or range",
    "model": "Hardware model",
    "manufacturer": "Manufacturer",
    "ou": "AD OU",
    "os": "Operating system",
    "state": "State",
    "other": "Other field...",
}
# "Other field": any column of the v_devices view (the Computers list / report builder fields).
OTHER_OPS = {"is": "is", "not": "is not", "lt": "is less than", "gt": "is more than", "empty": "is empty",
             "not_empty": "is not empty"}
HINTS = {
    "hostname": "LAB-*, KIOSK?? (wildcards * and ?; plain text = contains)",
    "ip": "10.1.20.0/24, 10.1.20.10-80 or 10.1.20.5",
    "model": "OptiPlex 70*, EliteDesk",
    "manufacturer": "Dell, HP*",
    "ou": "corp.example.com/Sites/Office/PCs or OU=PCs,OU=Office,DC=corp,DC=example,DC=com (includes sub-OUs)",
    "os": "Windows 11, *Server 2019*",
    "state": "Active, Stock, Retired",
    "other": "a value; wildcards * and ?, or a number or date (2026-01-31) for less / more than",
}
SHORT = {"hostname": "host name", "ip": "IP", "model": "model", "manufacturer": "manufacturer", "ou": "OU", "os": "OS",
         "state": "state", "other": "field"}
MAX_CONDITIONS = 20
_lock = threading.Lock()
_last_refresh = 0.0


def _split(value: str) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _ou_dn(v: str) -> str:
    from .scanning import normalize_dn
    dn = normalize_dn(v)
    return re.sub(r"\s*,\s*", ",", dn.strip()).lower()


def device_columns(db) -> list[str]:
    from .reports import columns
    # groups is left out: a group defined by group membership could depend on itself and flip on every refresh
    return [c for c in columns(db, "v_devices") if c not in ("id", "device_id", "groups")]


def validate(match: str, conditions: list[dict], db=None) -> list[dict]:
    """Returns cleaned conditions, or raises ValueError with a message for the user."""
    from .exclusions import parse_ip
    if match not in ("all", "any"):
        raise ValueError("match must be all or any")
    out = []
    cols = None
    for c in conditions or []:
        field, value, neg = c.get("field"), str(c.get("value") or "").strip(), bool(c.get("not"))
        if field not in FIELDS:
            raise ValueError("unknown condition type")
        if field == "other":
            col, op = str(c.get("column") or ""), str(c.get("op") or ("not" if neg else "is"))
            if cols is None:
                cols = device_columns(db) if db is not None else None
            if not col or (cols is not None and col not in cols):
                raise ValueError("pick the field for each \"Other field\" condition")
            if op not in OTHER_OPS:
                raise ValueError("unknown comparison")
            if op in ("empty", "not_empty"):
                out.append({"field": "other", "column": col, "op": op, "value": "", "not": False})
                continue
            if not value:
                continue
            if len(value) > 1000:
                raise ValueError(f"{col}: value too long")
            out.append({"field": "other", "column": col, "op": op, "value": value, "not": op == "not"})
            continue
        if not value:
            continue
        if len(value) > 1000:
            raise ValueError(f"{FIELDS[field]}: value too long")
        for v in _split(value):
            if field == "ip":
                try:
                    parse_ip(v)
                except ValueError as exc:
                    raise ValueError(f"IP address: {v}: {exc}") from None
            elif field == "ou":
                try:
                    _ou_dn(v)
                except ValueError as exc:
                    raise ValueError(f"AD OU: {exc}") from None
        out.append({"field": field, "value": value, "not": neg})
    if not out:
        raise ValueError("add at least one condition")
    if len(out) > MAX_CONDITIONS:
        raise ValueError(f"at most {MAX_CONDITIONS} conditions")
    return out


class _Cond:
    def __init__(self, c: dict):
        from .exclusions import parse_ip
        self.field, self.neg = c["field"], bool(c.get("not"))
        vals = _split(c["value"])
        if self.field == "other":
            self.column, self.op, self.neg = c["column"], c.get("op") or "is", False
            self.raw = (c.get("value") or "").strip()
            self.pats = [_bool_word(v) or (v.lower() if any(ch in v for ch in "*?[") else v.lower()) for v in vals]
            self.wild = [any(ch in v for ch in "*?[") for v in vals]
            return
        if self.field == "ip":
            self.ranges = [parse_ip(v) for v in vals]
        elif self.field == "ou":
            self.dns = [_ou_dn(v) for v in vals]
        else:
            self.pats = [v.lower() if any(ch in v for ch in "*?[") else f"*{v.lower()}*" for v in vals]
            if self.field == "state":     # state is a short word: exact unless wildcards are used
                self.pats = [v.lower() for v in vals]

    def test(self, d: dict) -> bool:
        return self._test(d) != self.neg

    def _test(self, d: dict) -> bool:
        if self.field == "other":
            return self._other(d.get("x", {}).get(self.column))
        if self.field == "ip":
            return any(a <= ip <= b for ip in d["ips"] for a, b in self.ranges)
        if self.field == "ou":
            dn = d["dn"]
            return bool(dn) and any(dn.endswith("," + o) or dn == o for o in self.dns)
        v = d.get(self.field)
        if self.field == "hostname":
            names = [x for x in (d["hostname"], d["fqdn"]) if x]
            return any(fnmatch.fnmatchcase(n.lower(), p) for n in names for p in self.pats)
        return bool(v) and any(fnmatch.fnmatchcase(v.lower(), p) for p in self.pats)


    def _other(self, v) -> bool:
        if self.op == "empty":
            return v is None or str(v).strip() == ""
        if self.op == "not_empty":
            return not (v is None or str(v).strip() == "")
        if v is None or str(v).strip() == "":
            return self.op == "not"
        if self.op in ("lt", "gt"):
            a, b = _num(v), _num(self.raw)
            if a is None or b is None:
                a, b = str(v).strip().lower(), self.raw.lower()     # dates and text: ISO dates sort as text
            return a < b if self.op == "lt" else a > b
        sv = _bool_word(v) or str(v).strip().lower()
        hit = any(fnmatch.fnmatchcase(sv, p) if w else
                  (sv == p if isinstance(v, (bool, int, float)) or _bool_word(v) else p in sv)
                  for p, w in zip(self.pats, self.wild))
        return hit != (self.op == "not")


def _bool_word(v) -> str | None:
    if isinstance(v, bool):
        return "true" if v else "false"
    s = str(v).strip().lower()
    return {"yes": "true", "no": "false", "true": "true", "false": "false"}.get(s)


def _num(v):
    if isinstance(v, bool):
        return None
    try:
        return float(str(v).strip().rstrip("%"))
    except ValueError:
        return None


def _extra(db, cols: set[str]) -> dict[str, dict]:
    """hostname -> {column: value} from v_devices, for "Other field" conditions."""
    from sqlalchemy import text
    allowed = set(device_columns(db))
    cols = sorted(c for c in cols if c in allowed)
    if not cols:
        return {}
    q = "SELECT hostname, " + ", ".join(f'"{c}"' for c in cols) + " FROM v_devices"
    return {r[0]: dict(zip(cols, r[1:])) for r in db.execute(text(q))}


def _devices(db) -> list[dict]:
    import ipaddress
    ips: dict[int, list[int]] = {}
    for did, ip in db.execute(select(DeviceNic.device_id, DeviceNic.ip).where(DeviceNic.ip.is_not(None))):
        for part in str(ip).replace(";", ",").split(","):
            try:
                ips.setdefault(did, []).append(int(ipaddress.IPv4Address(part.strip())))
            except ValueError:
                pass
    out = []
    for d in db.execute(select(Device.id, Device.hostname, Device.fqdn, Device.model, Device.manufacturer, Device.ad_dn,
                               Device.os_caption, Device.ad_os, Device.state)):
        out.append({"id": d.id, "hostname": d.hostname, "fqdn": d.fqdn, "model": d.model, "manufacturer": d.manufacturer,
                    "dn": re.sub(r"\s*,\s*", ",", d.ad_dn.strip()).lower() if d.ad_dn else None,
                    "os": d.os_caption or d.ad_os, "state": d.state or "Active", "ips": ips.get(d.id, [])})
    return out


def evaluate(db, match: str, conditions: list[dict], devices: list[dict] | None = None) -> list[dict]:
    conds = [_Cond(c) for c in conditions]
    if not conds:
        return []
    devs = devices if devices is not None else _devices(db)
    need = {c.column for c in conds if c.field == "other"}
    if need:
        ext = _extra(db, need)
        devs = [{**d, "x": ext.get(d["hostname"], {})} for d in devs]
    agg = all if match == "all" else any
    return [d for d in devs if agg(c.test(d) for c in conds)]


def conditions_of(g: GroupDef) -> list[dict]:
    try:
        return json.loads(g.conditions or "[]")
    except ValueError:
        return []


def refresh(db, only: str | None = None) -> dict[str, int]:
    """Rewrites the rule-based members of every group (or one). Returns {group name: members}."""
    global _last_refresh
    with _lock:
        defs = list(db.scalars(select(GroupDef).where(GroupDef.name == only) if only else select(GroupDef)))
        if not defs:
            return {}
        devs = _devices(db)
        counts = {}
        for g in defs:
            try:
                want = {d["id"] for d in evaluate(db, g.match or "all", conditions_of(g), devs)}
            except ValueError:
                log.warning("group %s: conditions don't parse, left as they were", g.name)
                continue
            rows = list(db.scalars(select(DeviceGroup).where(DeviceGroup.name == g.name)))
            have_dyn = {r.device_id for r in rows if r.dynamic}
            manual = {r.device_id for r in rows if not r.dynamic}
            gone = have_dyn - want
            if gone:
                db.execute(delete(DeviceGroup).where(DeviceGroup.name == g.name, DeviceGroup.dynamic.is_(True),
                                                     DeviceGroup.device_id.in_(gone)))
            for did in want - have_dyn - manual:
                db.add(DeviceGroup(device_id=did, name=g.name, dynamic=True))
            g.member_count, g.refreshed = len(want | manual), utcnow()
            counts[g.name] = g.member_count
        db.commit()
        if not only:
            _last_refresh = time.time()
        return counts


def refresh_if_stale(db, max_age: float = 300) -> None:
    if time.time() - _last_refresh > max_age:
        try:
            refresh(db)
        except Exception:
            db.rollback()
            log.exception("group refresh")


def hosts(db, name: str) -> list[str]:
    """Every computer in a group (static or rule-based), with rule-based members brought up to date first."""
    if db.scalar(select(GroupDef.id).where(GroupDef.name == name)):
        refresh(db, only=name)
    return list(db.scalars(select(Device.hostname).join(DeviceGroup, DeviceGroup.device_id == Device.id)
                           .where(DeviceGroup.name == name).order_by(Device.hostname)))


def names(db) -> list[str]:
    return sorted({g for (g,) in db.execute(select(DeviceGroup.name).distinct())}
                  | {g for (g,) in db.execute(select(GroupDef.name))})


def describe(match: str, conditions: list[dict]) -> str:
    parts = [f"{c['column']} {OTHER_OPS.get(c.get('op') or 'is', 'is')}{' ' + c['value'] if c.get('value') else ''}"
             if c["field"] == "other" else
             f"{SHORT.get(c['field'], c['field'])} {'is not' if c.get('not') else 'is'} {c['value']}"
             for c in conditions]
    return (" and " if match == "all" else " or ").join(parts)
