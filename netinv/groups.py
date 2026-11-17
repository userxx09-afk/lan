"""Computer groups and user groups.

A group holds computers or AD users (GroupDef.kind). Either way it is
- static: computers added by hand (Computers > Add to group, or a PC's page), or
- rule-based ("dynamic"): defined by conditions, and its members follow the inventory. A PC that moves OU, gets a
  new IP or is renamed joins or leaves the group on the next refresh (after every scan, every few minutes, and
  whenever the group is saved or used as a target).

Computer members live in device_groups, so the Groups column, report filters, scripts, pushes and scan jobs
all see them the same way; rule-based rows carry dynamic = true and are rewritten on each refresh. Computers added
by hand to a rule-based group stay in it whatever the rules say ("also include"). User members live in user_groups
the same way. A user group used as a target for computers (scripts, Configure, scan jobs) means the computers its
users signed in to in the last USER_PC_DAYS days. A user group can also decide who may sign in (auth.py).

Conditions (all of them must match, or any one of them):
  hostname      LAB-*, KIOSK??       wildcards * and ?; without one, "contains"
  ip            10.1.20.0/24, 10.1.20.10-80, 10.1.20.5     any of the PC's addresses
  model         OptiPlex 70*         contains / wildcards
  manufacturer  Dell*
  os            *Windows 11*
  ou            corp.example.com/Sites/Office or OU=Office,OU=Sites,DC=corp,...     at or below that OU
  adgroup       Finance Staff, IT-*, CN=VPN Users,OU=Groups,DC=corp,...     member of that AD group, nested included
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

from .db import AdGroup, AdUser, Device, DeviceGroup, DeviceNic, GroupDef, UserGroup, utcnow

log = logging.getLogger(__name__)

FIELDS = {
    "hostname": "Host name",
    "ip": "IP address or range",
    "model": "Hardware model",
    "manufacturer": "Manufacturer",
    "ou": "AD OU",
    "adgroup": "AD group (security group)",
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
    "adgroup": "Finance Staff, IT-* or CN=VPN Users,OU=Groups,DC=corp,... (groups inside groups count)",
    "os": "Windows 11, *Server 2019*",
    "state": "Active, Stock, Retired",
    "other": "a value; wildcards * and ?, or a number or date (2026-01-31) for less / more than",
}
USER_FIELDS = {
    "username": "User name",
    "name": "Display name",
    "department": "Department",
    "title": "Job title",
    "office": "Office",
    "company": "Company",
    "ou": "AD OU",
    "adgroup": "AD group (security group)",
    "status": "Account",
    "other": "Other field...",
}
USER_HINTS = {
    "username": "jsmith, svc-* (wildcards * and ?; plain text = contains)",
    "name": "Smith, J*",
    "department": "Finance, Sales",
    "title": "*Manager*",
    "office": "HQ floor 1",
    "company": "Example Corp",
    "ou": "corp.example.com/Staff/Finance or OU=Finance,OU=Staff,DC=corp,DC=example,DC=com (includes sub-OUs)",
    "adgroup": "Finance Staff, IT-* or CN=VPN Users,OU=Groups,DC=corp,... (groups inside groups count)",
    "status": "Enabled, Disabled, Locked",
    "other": "a value; wildcards * and ?, or a number or date (2026-01-31) for less / more than",
}
KINDS = ("computers", "users")
USER_PC_DAYS = 30     # a user group as a computer target: the PCs its users signed in to lately
SHORT = {"hostname": "host name", "ip": "IP", "model": "model", "manufacturer": "manufacturer", "ou": "OU", "os": "OS",
         "state": "state", "other": "field", "adgroup": "AD group", "username": "user name", "name": "display name",
         "department": "department", "title": "title", "office": "office", "company": "company", "status": "account"}
MAX_CONDITIONS = 20
_lock = threading.Lock()
_last_refresh = 0.0


def _split(value: str) -> list[str]:
    """Comma-separated values. A DN keeps its commas: "OU=PCs,DC=corp,DC=com, Lab*" is two values."""
    out: list[str] = []
    for part in (value or "").split(","):
        p = part.strip()
        if not p:
            continue
        if out and "=" in out[-1] and re.match(r"(?i)(ou|dc|cn|o|l|c|st)=", p):
            out[-1] += "," + p
        else:
            out.append(p)
    return out


def _ou_dn(v: str) -> str:
    from .scanning import normalize_dn
    dn = normalize_dn(v)
    return re.sub(r"\s*,\s*", ",", dn.strip()).lower()


def _dn(v: str) -> str:
    return re.sub(r"\s*,\s*", ",", (v or "").strip()).lower()


def device_columns(db) -> list[str]:
    from .reports import columns
    # groups is left out: a group defined by group membership could depend on itself and flip on every refresh
    return [c for c in columns(db, "v_devices") if c not in ("id", "device_id", "groups")]


def user_columns(db) -> list[str]:
    from .reports import columns
    return [c for c in columns(db, "v_users") if c not in ("id", "groups")]


def fields_of(kind: str) -> dict:
    return USER_FIELDS if kind == "users" else FIELDS


def validate(match: str, conditions: list[dict], db=None, kind: str = "computers") -> list[dict]:
    """Returns cleaned conditions, or raises ValueError with a message for the user."""
    from .exclusions import parse_ip
    if match not in ("all", "any"):
        raise ValueError("match must be all or any")
    if kind not in KINDS:
        raise ValueError("a group holds computers or users")
    allowed = fields_of(kind)
    out = []
    cols = None
    for c in conditions or []:
        field, value, neg = c.get("field"), str(c.get("value") or "").strip(), bool(c.get("not"))
        if field not in allowed:
            raise ValueError("unknown condition type")
        if field == "other":
            col, op = str(c.get("column") or ""), str(c.get("op") or ("not" if neg else "is"))
            if cols is None:
                cols = (user_columns(db) if kind == "users" else device_columns(db)) if db is not None else None
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
            raise ValueError(f"{allowed[field]}: value too long")
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
            elif field == "status" and v.lower() not in ("enabled", "disabled", "locked"):
                raise ValueError(f"Account: {v}: use Enabled, Disabled or Locked")
        if field == "adgroup" and db is not None:
            unknown = [v for v in _split(value) if not _known_group(db, v)]
            if unknown:
                raise ValueError(f"AD group: no group called {', '.join(unknown[:5])} in the last AD import "
                                 "(check the spelling, or run the AD import if the group is new)")
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
        elif self.field == "adgroup":
            self.gdns = {_dn(v) for v in vals if "=" in v}
            self.gpats = [v.lower() for v in vals if "=" not in v]
        elif self.field == "status":
            self.words = {v.lower() for v in vals}
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
        if self.field == "adgroup":
            return bool(self.gdns & d["gdns"]) or any(fnmatch.fnmatchcase(n, p) for n in d["gnames"] for p in self.gpats)
        if self.field == "status":
            return bool(self.words & set(d["status"]))
        v = d.get(self.field)
        if self.field == "hostname":
            names = [x for x in (d["hostname"], d["fqdn"]) if x]
            return any(fnmatch.fnmatchcase(n.lower(), p) for n in names for p in self.pats)
        if self.field == "username":
            names = [x for x in (d["username"], d.get("upn")) if x]
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


def _known_group(db, v: str) -> bool:
    """Is there an AD group by that name (wildcards allowed) or DN? True before the first AD import has stored groups."""
    from sqlalchemy import func
    if not db.scalar(select(func.count()).select_from(AdGroup)):
        return True
    if "=" in v:
        return bool(db.scalar(select(AdGroup.id).where(AdGroup.dn == _dn(v))))
    p = v.lower()
    if fnmatch.fnmatchcase("domain users", p) or fnmatch.fnmatchcase("domain computers", p):
        return True
    return any(fnmatch.fnmatchcase((n or "").lower(), p) or fnmatch.fnmatchcase((m or "").lower(), p)
               for n, m in db.execute(select(AdGroup.name, AdGroup.sam)))


class _GroupTree:
    """AD groups from the last import: the groups each group is in (all the way up) and their names."""
    def __init__(self, db):
        self.parents, self.names = {}, {}
        for dn, name, sam, mo in db.execute(select(AdGroup.dn, AdGroup.name, AdGroup.sam, AdGroup.member_of)):
            self.parents[dn] = _json_list(mo)
            self.names[dn] = {x.lower() for x in (name, sam) if x}
        self._up: dict[str, frozenset] = {}

    def up(self, dn: str) -> frozenset:
        if dn in self._up:
            return self._up[dn]
        seen, todo = {dn}, [dn]
        while todo:
            for p in self.parents.get(todo.pop(), []):
                if p not in seen:
                    seen.add(p)
                    todo.append(p)
        self._up[dn] = frozenset(seen)
        return self._up[dn]

    def expand(self, direct, primary: str) -> tuple[set, set]:
        """(every group DN, every group name) for an object directly in the groups `direct`."""
        dns = set()
        for d in direct:
            dns |= self.up(d)
        names = {primary}
        for d in dns:
            names |= self.names.get(d) or {d.split(",")[0].removeprefix("cn=")}
        return dns, names


def _json_list(v) -> list:
    try:
        x = json.loads(v or "[]")
        return x if isinstance(x, list) else []
    except ValueError:
        return []


def _extra(db, cols: set[str], kind: str = "computers") -> dict[str, dict]:
    """hostname (or username) -> {column: value} from v_devices (v_users), for "Other field" conditions."""
    from sqlalchemy import text
    view, key = ("v_users", "username") if kind == "users" else ("v_devices", "hostname")
    allowed = set(user_columns(db) if kind == "users" else device_columns(db))
    cols = sorted(c for c in cols if c in allowed and c != key)
    if not cols:
        return {}
    q = f"SELECT {key}, " + ", ".join(f'"{c}"' for c in cols) + f" FROM {view}"
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
    tree = _GroupTree(db)
    out = []
    for d in db.execute(select(Device.id, Device.hostname, Device.fqdn, Device.model, Device.manufacturer, Device.ad_dn,
                               Device.os_caption, Device.ad_os, Device.state, Device.ad_groups)):
        gdns, gnames = tree.expand(_json_list(d.ad_groups), "domain computers") if d.ad_dn else (set(), set())
        out.append({"id": d.id, "hostname": d.hostname, "fqdn": d.fqdn, "model": d.model, "manufacturer": d.manufacturer,
                    "dn": _dn(d.ad_dn) if d.ad_dn else None, "gdns": gdns, "gnames": gnames,
                    "os": d.os_caption or d.ad_os, "state": d.state or "Active", "ips": ips.get(d.id, [])})
    return out


def user_entity(username: str, dn: str | None, group_dns, *, upn=None, name=None, department=None, title=None,
                office=None, company=None, enabled=True, locked=False, uid=None, tree: _GroupTree | None = None,
                nested: bool = False) -> dict:
    """One user as group conditions see it. nested=True: group_dns already holds every group, nested ones too
    (a live AD lookup at sign-in); otherwise they are the direct groups and the import's group tree adds the rest."""
    if nested:
        gdns = {_dn(x) for x in group_dns}
        gnames = {"domain users"} | {x.split(",")[0].removeprefix("cn=") for x in gdns}
        if tree:
            for x in gdns:
                gnames |= tree.names.get(x, set())
    else:
        gdns, gnames = (tree.expand([_dn(x) for x in group_dns], "domain users") if tree else (set(), {"domain users"}))
    return {"id": uid, "username": username, "upn": upn, "name": name, "department": department, "title": title,
            "office": office, "company": company, "dn": _dn(dn) if dn else None, "gdns": gdns, "gnames": gnames,
            "status": (["enabled"] if enabled is not False else ["disabled"]) + (["locked"] if locked else [])}


def _users(db) -> list[dict]:
    tree = _GroupTree(db)
    return [user_entity(u.username, u.dn, _json_list(u.group_dns), upn=u.upn, name=u.display_name,
                        department=u.department, title=u.title, office=u.office, company=u.company,
                        enabled=u.enabled, locked=u.locked, uid=u.id, tree=tree)
            for u in db.scalars(select(AdUser))]


def evaluate(db, match: str, conditions: list[dict], devices: list[dict] | None = None,
             kind: str = "computers") -> list[dict]:
    conds = [_Cond(c) for c in conditions]
    if not conds:
        return []
    devs = devices if devices is not None else (_users(db) if kind == "users" else _devices(db))
    need = {c.column for c in conds if c.field == "other"}
    if need:
        key = "username" if kind == "users" else "hostname"
        ext = _extra(db, need, kind)
        devs = [{**d, "x": {**ext.get(d[key], {}), key: d[key]}} for d in devs]
    agg = all if match == "all" else any
    return [d for d in devs if agg(c.test(d) for c in conds)]


def conditions_of(g: GroupDef) -> list[dict]:
    try:
        return json.loads(g.conditions or "[]")
    except ValueError:
        return []


def kind_of(db, name: str) -> str | None:
    """computers | users | None (no such group)."""
    g = db.scalar(select(GroupDef).where(GroupDef.name == name))
    if g:
        return g.kind or "computers"
    if db.scalar(select(UserGroup.id).where(UserGroup.name == name).limit(1)):
        return "users"
    if db.scalar(select(DeviceGroup.id).where(DeviceGroup.name == name).limit(1)):
        return "computers"
    return None


def refresh(db, only: str | None = None) -> dict[str, int]:
    """Rewrites the rule-based members of every group (or one). Returns {group name: members}."""
    global _last_refresh
    with _lock:
        defs = list(db.scalars(select(GroupDef).where(GroupDef.name == only) if only else select(GroupDef)))
        if not defs:
            return {}
        cache: dict[str, list[dict]] = {}
        counts = {}
        for g in defs:
            kind = g.kind or "computers"
            Row, col = (UserGroup, UserGroup.user_id) if kind == "users" else (DeviceGroup, DeviceGroup.device_id)
            if kind not in cache:
                cache[kind] = _users(db) if kind == "users" else _devices(db)
            try:
                want = {d["id"] for d in evaluate(db, g.match or "all", conditions_of(g), cache[kind], kind)}
            except ValueError:
                log.warning("group %s: conditions don't parse, left as they were", g.name)
                continue
            rows = list(db.scalars(select(Row).where(Row.name == g.name)))
            key = (lambda r: r.user_id) if kind == "users" else (lambda r: r.device_id)
            have_dyn = {key(r) for r in rows if r.dynamic}
            manual = {key(r) for r in rows if not r.dynamic}
            gone = have_dyn - want
            if gone:
                db.execute(delete(Row).where(Row.name == g.name, Row.dynamic.is_(True), col.in_(gone)))
            for oid in want - have_dyn - manual:
                db.add(UserGroup(user_id=oid, name=g.name, dynamic=True) if kind == "users"
                       else DeviceGroup(device_id=oid, name=g.name, dynamic=True))
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


def users(db, name: str) -> list[str]:
    """Every user in a user group, with rule-based members brought up to date first."""
    if db.scalar(select(GroupDef.id).where(GroupDef.name == name)):
        refresh(db, only=name)
    return list(db.scalars(select(AdUser.username).join(UserGroup, UserGroup.user_id == AdUser.id)
                           .where(UserGroup.name == name).order_by(AdUser.username)))


def hosts(db, name: str) -> list[str]:
    """Every computer in a group (static or rule-based), with rule-based members brought up to date first.
    For a user group: the computers its users signed in to in the last USER_PC_DAYS days."""
    if kind_of(db, name) == "users":
        from datetime import timedelta
        from sqlalchemy import text
        who = users(db, name)
        if not who:
            return []
        since = utcnow() - timedelta(days=USER_PC_DAYS)
        found: set[str] = set()
        for i in range(0, len(who), 500):
            from sqlalchemy import bindparam
            q = text("SELECT DISTINCT ud.hostname FROM v_user_devices ud JOIN devices d ON d.hostname = ud.hostname "
                     "WHERE ud.username IN :u AND ud.last_logon >= :since").bindparams(bindparam("u", expanding=True))
            found |= {h for (h,) in db.execute(q, {"u": who[i:i + 500], "since": since})}
        return sorted(found)
    if db.scalar(select(GroupDef.id).where(GroupDef.name == name)):
        refresh(db, only=name)
    return list(db.scalars(select(Device.hostname).join(DeviceGroup, DeviceGroup.device_id == Device.id)
                           .where(DeviceGroup.name == name).order_by(Device.hostname)))


def names(db, kind: str | None = None) -> list[str]:
    """Group names: computer groups, user groups, or both (kind None: anything usable as a computer target)."""
    out: set[str] = set()
    if kind in (None, "computers"):
        out |= {g for (g,) in db.execute(select(DeviceGroup.name).distinct())}
        out |= {g for (g,) in db.execute(select(GroupDef.name).where((GroupDef.kind == "computers") | GroupDef.kind.is_(None)))}
    if kind in (None, "users"):
        out |= {g for (g,) in db.execute(select(UserGroup.name).distinct())}
        out |= {g for (g,) in db.execute(select(GroupDef.name).where(GroupDef.kind == "users"))}
    return sorted(out)


def user_in_group(db, name: str, entity: dict) -> bool:
    """Is this user (user_entity, e.g. looked up live at sign-in) in the user group, by its rules or added by hand?"""
    g = db.scalar(select(GroupDef).where(GroupDef.name == name))
    if g is not None and (g.kind or "computers") != "users":
        return False
    by_hand = db.scalar(select(UserGroup.id).join(AdUser, AdUser.id == UserGroup.user_id)
                        .where(UserGroup.name == name, UserGroup.dynamic.is_not(True), AdUser.username == entity["username"]))
    if by_hand:
        return True
    if g is None:
        return False
    conds = conditions_of(g)
    return bool(conds) and bool(evaluate(db, g.match or "all", conds, [entity], "users"))


def describe(match: str, conditions: list[dict]) -> str:
    parts = [f"{c['column']} {OTHER_OPS.get(c.get('op') or 'is', 'is')}{' ' + c['value'] if c.get('value') else ''}"
             if c["field"] == "other" else
             f"{SHORT.get(c['field'], c['field'])} {'is not' if c.get('not') else 'is'} {c['value']}"
             for c in conditions]
    return (" and " if match == "all" else " or ").join(parts)
