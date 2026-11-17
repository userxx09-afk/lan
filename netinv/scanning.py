"""Ties scan targets and stored credentials to the collectors.

Targets (Settings > Scanning):
  ad_domain         corp.example.com             -> computers, DCs, users of the whole domain
  ad_computer_path  OU=Workstations,DC=corp,...  -> limits computer import + WinRM to that OU
  ad_user_path      OU=Staff,DC=corp,...         -> limits user import to that OU
  ip_range          10.0.0.0/24, 10.0.1.5-80     -> SNMP devices + Windows hosts found by IP

Each target lists credentials to try in order. Windows credentials are used for
LDAP and WinRM, SNMP credentials for network devices. When no targets exist the
legacy [ad]/[winrm]/[snmp] sections of config.toml are used instead.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import logging

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import settings
from .db import Credential, Device, DeviceNic, ScanTarget, get_setting, set_setting, utcnow
from .secrets import decrypt

log = logging.getLogger(__name__)
AD_KINDS = ("ad_domain", "ad_computer_path", "ad_user_path")


# Credential id 0 in a target's (or a push's) credential list = the Windows account NetInventory itself runs as
# (no stored password: WinRM and LDAP sign in with Windows integrated authentication, Kerberos/NTLM via SSPI).
SERVICE_CRED_ID = 0


class NothingToDo(Exception):
    """A scan that had nothing to scan (no target, or its targets are left out of scheduled runs). The run is
    recorded as skipped, not ok."""


def service_account() -> str:
    """The Windows account this process runs as, e.g. CORP\\svc-netinv, or the computer account under SYSTEM."""
    import getpass
    user = os.environ.get("USERNAME") or getpass.getuser()
    dom = os.environ.get("USERDOMAIN") or ""
    if user.upper() == "SYSTEM" or user.endswith("$"):
        host = os.environ.get("COMPUTERNAME") or ""
        return f"SYSTEM (other PCs see the server's computer account {dom + chr(92) if dom else ''}{host}$)"
    return f"{dom}\\{user}" if dom and dom.upper() != user.upper() else user


def service_cfg() -> dict:
    return {"user": None, "password": None, "integrated": True}


def cred_cfg(c: Credential) -> dict:
    if c.kind == "windows":
        return {"user": c.username, "password": decrypt(c.secret)}
    if c.kind == "snmp2":
        return {"version": "2c", "community": decrypt(c.secret)}
    if c.kind == "snmp3":
        return {"version": "3", "v3_user": c.username, "v3_auth_key": decrypt(c.secret), "v3_priv_key": decrypt(c.secret2)}
    raise ValueError(c.kind)


def _creds(db: Session, targets: list[ScanTarget], kinds: tuple[str, ...]) -> list[dict]:
    cid = getattr(SCOPE, "cred_id", None)
    if cid is not None and "windows" in kinds and targets:     # this scan run signs in with one picked account
        if cid == SERVICE_CRED_ID:
            return [service_cfg()]
        c = db.get(Credential, cid)
        if c and c.kind == "windows":
            return [cred_cfg(c)]
        raise RuntimeError("The account picked to sign in with for this scan no longer exists (Settings, Credentials).")
    seen, out = set(), []
    for t in targets:
        for cid in (t.credential_ids or "").split(","):
            if cid.strip() == str(SERVICE_CRED_ID):
                if "windows" in kinds and SERVICE_CRED_ID not in seen:
                    seen.add(SERVICE_CRED_ID)
                    out.append(service_cfg())
                continue
            if cid.strip().isdigit() and int(cid) not in seen:
                c = db.get(Credential, int(cid))
                if c and c.kind in kinds:
                    seen.add(c.id)
                    out.append(cred_cfg(c))
    return out


def short_error(exc: Exception) -> str:
    """Database errors carry the whole SQL statement and its parameters (thousands of lines): keep the reason only."""
    orig = getattr(exc, "orig", None)
    msg = str(orig if orig is not None else exc).strip().split("\n")[0]
    return f"{type(orig if orig is not None else exc).__name__}: {msg}"[:500]


# A scheduled scan job narrows every scan in its thread to its own targets (see jobs.py).
SCOPE = threading.local()


def scoped(target_ids: list[int] | None, parallel: int | None = None, ip_methods: set[str] | None = None,
           group: str | None = None, scheduled: bool = False, cred_id: int | None = None):
    """Context manager: scans in this thread only see these targets (None = all), use this WinRM parallelism,
    on IP ranges run only these methods (None = each target's own), and PC scans only reach this group's computers.
    scheduled=True: a run started by the schedule, which leaves out targets with "Include in scheduled scans"
    unticked. Scan now and Run now scan every target: that box only affects the schedule.
    cred_id: sign in to Windows (LDAP, WinRM) with only this account (0 = the server's own) instead of each
    target's ticked credentials."""
    class _S:
        def __enter__(self):
            SCOPE.ids, SCOPE.parallel = (set(target_ids) if target_ids else None), parallel
            SCOPE.ip_methods = set(ip_methods) if ip_methods else None
            SCOPE.group = group or None
            SCOPE.scheduled = scheduled
            SCOPE.cred_id = cred_id
        def __exit__(self, *a):
            SCOPE.ids = SCOPE.parallel = SCOPE.ip_methods = SCOPE.group = SCOPE.cred_id = None
            SCOPE.scheduled = False
    return _S()


def _scheduled() -> bool:
    return bool(getattr(SCOPE, "scheduled", False))


def _targets(db: Session, *kinds: str, all_scopes: bool = False) -> list[ScanTarget]:
    """The targets a scan works on. all_scopes=True (looking up credentials for an action): every target of these
    kinds. Otherwise the scan job's own targets, minus the ones left out of the schedule on a scheduled run."""
    q = select(ScanTarget).where(ScanTarget.kind.in_(kinds))
    if not all_scopes and _scheduled():
        q = q.where(ScanTarget.enabled.is_(True))
    ids = None if all_scopes else getattr(SCOPE, "ids", None)
    if ids:
        q = q.where(ScanTarget.id.in_(ids))
    return list(db.scalars(q.order_by(ScanTarget.id)))


def _label(t: ScanTarget) -> str:
    v = t.value or ""
    return v if len(v) <= 60 else v[:57] + "..."


def nothing_to_do(db: Session, *kinds: str, what: str) -> NothingToDo:
    """Why a scan of these target kinds has nothing to work on, worded for the Scanning page."""
    q = select(ScanTarget).where(ScanTarget.kind.in_(kinds))
    ids = getattr(SCOPE, "ids", None)
    if ids:
        q = q.where(ScanTarget.id.in_(ids))
    off = [t for t in db.scalars(q.order_by(ScanTarget.id)) if not t.enabled]
    if off and _scheduled():
        names = ", ".join(_label(t) for t in off)
        one = len(off) == 1
        return NothingToDo(f"Skipped: the {what} target{'' if one else 's'} {names} {'is' if one else 'are'} left out "
                           f"of scheduled scans (\"Include in scheduled scans\" is unticked in Settings, Scan targets). "
                           f"Scan now still scans {'it' if one else 'them'}.")
    if ids:
        return NothingToDo(f"Skipped: this scan job has no {what} target ticked (Settings, Scan schedule).")
    return NothingToDo(f"Skipped: no {what} target is set up yet (Settings, Scan targets).")


def _finish(db: Session, targets: list[ScanTarget], ok: bool, msg: str) -> None:
    for t in targets:
        t.last_run, t.last_ok, t.last_result = utcnow(), ok, msg[:2000]
    db.commit()


def dn_domain(dn: str) -> str:
    return ".".join(p.split("=", 1)[1] for p in dn.split(",") if p.strip().upper().startswith("DC="))


def dc_candidates(db: Session, dom: str, ts: list) -> list[str]:
    """Explicit server first, then the domain name (DNS round-robin to DCs), then DCs seen in earlier scans."""
    from .db import DomainController
    out = [t.server for t in ts if t.server] + [dom]
    for dc in db.scalars(select(DomainController).order_by(DomainController.hostname)):
        if dc.fqdn and dc.fqdn.lower().endswith("." + dom):
            out.append(dc.fqdn)
    return list(dict.fromkeys(out))


# ------------------------------------------------------------------ AD scope
def _dn_escape(name: str) -> str:
    s = "".join("\\" + c if c in ',+"\\<>;=' else c for c in name.strip())
    return ("\\" + s) if s.startswith(("#", " ")) else s


def canonical_to_dn(value: str) -> str:
    """'corp.example.com/Sites/Office/PCs' (as ADUC shows it) -> 'OU=PCs,OU=Office,OU=Sites,DC=corp,DC=example,DC=com'.
    The built-in Computers and Users containers right under the domain are CN=, everything else OU=."""
    parts = [p for p in value.strip().strip("/").split("/") if p.strip()]
    if len(parts) < 2 or "." not in parts[0]:
        raise ValueError("start the path with the domain name, e.g. corp.example.com/Sites/Office/PCs")
    dom, ous = parts[0].strip(), parts[1:]
    rdns = []
    for i, name in enumerate(ous):
        attr = "CN" if i == 0 and name.strip().lower() in ("computers", "users") and len(ous) == 1 else "OU"
        rdns.append(f"{attr}={_dn_escape(name)}")
    return ",".join(reversed(rdns)) + "," + ",".join(f"DC={p}" for p in dom.strip(".").split("."))


def normalize_dn(value: str) -> str:
    """Accepts a DN (OU=..,DC=..) or a canonical path (domain/OU/OU) and returns a DN."""
    v = value.strip()
    if "=" in v and "DC=" in v.upper():
        return v
    if "/" in v:
        return canonical_to_dn(v)
    raise ValueError("use a path like corp.example.com/Sites/Office/PCs or a DN like OU=PCs,OU=Office,DC=corp,DC=example,DC=com")


def ad_scope(t: ScanTarget) -> tuple[str, str, str, set[str]]:
    """(effective kind, domain, search base DN, what to collect) for an AD target. An "AD domain" target whose value
    is really an OU path is treated as an OU of computers (older versions accepted that and scanned the whole domain)."""
    kind, v = t.kind, (t.value or "").strip()
    if kind == "ad_domain" and ("/" in v or "=" in v):
        kind = "ad_computer_path"
    if kind == "ad_domain":
        collect = {c for c in (t.collect or "computers,users").split(",") if c}
        return kind, v.lower(), ",".join(f"DC={p}" for p in v.strip(".").lower().split(".")), collect
    base = normalize_dn(v)
    return kind, dn_domain(base).lower(), base, {"users"} if kind == "ad_user_path" else {"computers"}


def fix_ou_targets(db: Session) -> None:
    """Before 0.7 an OU path could be saved as an "AD domain" target, which then scanned the whole domain.
    Turn those into OU-of-computers targets with a proper DN."""
    for t in db.scalars(select(ScanTarget).where(ScanTarget.kind == "ad_domain")):
        v = (t.value or "").strip()
        if "/" in v or "=" in v:
            try:
                t.kind, t.value = "ad_computer_path", normalize_dn(v)
                log.info("scan target %s: OU path %r is now an OU target %r", t.id, v, t.value)
            except ValueError:
                pass
    db.commit()


def has_targets(db: Session) -> bool:
    return db.scalar(select(ScanTarget.id).limit(1)) is not None


# ------------------------------------------------------------------ AD
def run_ad(db: Session) -> str:
    from .collectors import ad
    targets = _targets(db, *AD_KINDS)
    if not targets:
        if settings.ad.get("server"):
            return ad.collect(db, {**settings.ad, "domain": dn_domain(settings.ad.get("base_dn", ""))})
        raise nothing_to_do(db, *AD_KINDS, what="Active Directory")
    domains: dict[str, list[ScanTarget]] = {}
    scopes: dict[int, tuple] = {}
    msgs, failed = [], 0
    for t in targets:
        try:
            scopes[t.id] = ad_scope(t)
        except ValueError as exc:
            _finish(db, [t], False, str(exc))
            msgs.append(f"{t.value}: failed ({exc})")
            failed += 1
            continue
        domains.setdefault(scopes[t.id][1], []).append(t)
    for dom, ts in domains.items():
        creds = _creds(db, ts, ("windows",)) or _creds(db, _targets(db, "ad_domain", all_scopes=True), ("windows",))
        if not creds:
            names = ", ".join(_label(t) for t in ts)
            _finish(db, ts, False, "No Windows credential is ticked on this target (Edit, Credentials to try).")
            msgs.append(f"{dom}: failed (no Windows credential is ticked on the target {names})")
            failed += 1
            continue
        servers = dc_candidates(db, dom, ts)
        sc = [scopes[t.id] for t in ts]
        whole = [s for s in sc if s[0] == "ad_domain"]
        want_computers = any("computers" in s[3] for s in sc)
        cfg = {"server": servers[0], "servers": servers, "domain": dom,
               # a whole-domain target wins over OU targets of the same domain
               "computer_bases": None if any("computers" in s[3] for s in whole) else
                                 ([s[2] for s in sc if s[0] == "ad_computer_path"] or None),
               "user_bases": None if any("users" in s[3] for s in whole) else ([s[2] for s in sc if s[0] == "ad_user_path"] or None),
               "users": any("users" in s[3] for s in sc), "computers": want_computers}
        err = None
        for c in creds:
            try:
                msg = ad.collect(db, {**cfg, **c})
                db.commit()
                _finish(db, ts, True, msg)
                msgs.append(f"{dom}: {msg}")
                err = None
                break
            except Exception as exc:
                db.rollback()
                err = exc
        if err:
            _finish(db, ts, False, short_error(err))
            msgs.append(f"{dom}: failed ({short_error(err)})")
            failed += 1
    if failed and failed == len(msgs):
        raise RuntimeError("; ".join(msgs))
    return "; ".join(msgs)


def ad_action_cfg(db: Session, user_dn: str) -> dict:
    """Credentials + server for writing to the domain that holds user_dn."""
    dom = dn_domain(user_dn).lower()
    ts = []
    for t in _targets(db, *AD_KINDS, all_scopes=True):
        try:
            if ad_scope(t)[1] == dom:
                ts.append(t)
        except ValueError:
            pass
    creds = _creds(db, ts, ("windows",))
    if creds:
        servers = dc_candidates(db, dom, ts)
        return {"server": servers[0], "servers": servers, "domain": dom, **creds[0]}
    if settings.ad.get("server"):
        return dict(settings.ad)
    raise RuntimeError(f"No Windows credential configured for domain {dom}.")


# ------------------------------------------------------------------ IP ranges: SNMP + discovery
async def _probe(ips: list[str], port: int, timeout: float = 1.0, parallel: int = 256) -> list[str]:
    sem = asyncio.Semaphore(parallel)

    async def one(ip):
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
                w.close()
                return ip
            except Exception:
                return None
    return [ip for ip in await asyncio.gather(*(one(i) for i in ips)) if ip]


IP_METHODS = ("ping", "snmp", "winrm")


def ip_methods(db: Session, t: ScanTarget) -> set[str]:
    """What runs on an IP range: the target's ticked methods (older targets: whatever their credentials allow),
    narrowed by the scan job's own IP method boxes when the job sets them."""
    if t.collect:
        m = {x for x in t.collect.split(",") if x in IP_METHODS}
    else:
        m = {"ping"} | ({"snmp"} if _creds(db, [t], ("snmp2", "snmp3")) else set()) | \
            ({"winrm"} if _creds(db, [t], ("windows",)) else set())
    job = getattr(SCOPE, "ip_methods", None)
    return m & job if job else m


def run_ip(db: Session) -> str:
    from .collectors import snmp
    from .correlate import track_port_moves
    from . import progress, reach
    from .exclusions import Exclusions
    targets = _targets(db, "ip_range")
    msgs, failed = [], 0
    if not targets and settings.snmp.get("targets"):
        msgs.append(snmp.collect(db, settings.snmp))
    elif not targets:
        raise nothing_to_do(db, "ip_range", what="IP range")
    for t in targets:
        if progress.stopped():
            break
        try:
            excl = Exclusions.load(db)
            ips = [ip for ip in snmp.expand_targets([x for x in t.value.replace(";", ",").split(",")]) if not excl.ip(ip)]
            methods = ip_methods(db, t)
            parts = []
            if "ping" in methods:
                alive = [ip for ip, (up, _) in reach.sweep(ips, parallel=128).items() if up]
                set_setting(db, f"ip_alive:{t.id}", json.dumps(alive))
                byip = {}
                for n in db.scalars(select(DeviceNic).where(DeviceNic.ip.in_(ips))) if len(ips) <= 4096 else []:
                    byip.setdefault(n.ip, set()).add(n.device_id)
                now, alive_set = utcnow(), set(alive)
                for ip, dev_ids in byip.items():
                    for did in dev_ids:
                        d = db.get(Device, did)
                        if d and not (ip not in alive_set and d.online_via == "agent" and d.online):
                            reach.mark(d, ip in alive_set, "ping" if ip in alive_set else "", now)
                parts.append(f"{len(alive)} of {len(ips)} addresses answer")
            if "snmp" in methods:
                snmp_creds = _creds(db, [t], ("snmp2", "snmp3"))
                parts.append(snmp.collect(db, {**settings.snmp, "targets": ips, "creds": snmp_creds}) if snmp_creds
                             else "SNMP ticked but no SNMP credential on this target")
            if "winrm" in methods:
                if _creds(db, [t], ("windows",)):
                    winrm_ips = asyncio.run(_probe(ips, 5985))
                    set_setting(db, f"ip_scan:{t.id}", json.dumps(winrm_ips))
                    parts.append(f"{len(winrm_ips)} hosts answer on WinRM" + (
                        "" if winrm_ips else " (port 5985 closed or filtered on every address: WinRM is off on those PCs, "
                        "or a firewall blocks it. Turn it on with 'winrm quickconfig' or the WinRM GPO, and allow TCP 5985 "
                        "from this server)"))
                else:
                    parts.append("WinRM sweep ticked but no Windows credential on this target")
            else:
                set_setting(db, f"ip_scan:{t.id}", "[]")   # PC inventory won't reach into this range over WinRM
            db.commit()
            msg = "; ".join(parts) or "nothing ticked to run on this range"
            _finish(db, [t], True, msg)
            msgs.append(f"{t.value}: {msg}")
        except Exception as exc:
            db.rollback()
            _finish(db, [t], False, short_error(exc))
            msgs.append(f"{t.value}: failed ({short_error(exc)})")
            failed += 1
    moved = track_port_moves(db)
    if failed and failed == len(msgs):
        raise RuntimeError("; ".join(msgs))
    return "; ".join(msgs) + (f" {moved} PCs moved port." if moved else "")


# ------------------------------------------------------------------ WinRM endpoints
def winrm_cfg(db: Session) -> dict | None:
    targets = _targets(db, *AD_KINDS, "ip_range")
    if not targets:
        if not settings.winrm.get("user"):
            return None
        creds = None
    else:
        # the scanned targets' own credentials first, then any target's (a target with none of its own)
        creds = _creds(db, targets, ("windows",)) or \
            _creds(db, _targets(db, *AD_KINDS, "ip_range", all_scopes=True), ("windows",))
        if not creds:
            return None
    par = getattr(SCOPE, "parallel", None)
    group = getattr(SCOPE, "group", None)
    if group:       # a scan job limited to a computer group: exactly those PCs, whatever the AD targets say
        from . import groups
        names = groups.hosts(db, group)
        fq = dict(db.execute(select(Device.hostname, Device.fqdn).where(Device.hostname.in_(names))).all()) if names else {}
        return {**settings.winrm, **({"parallel": par} if par else {}), **({"creds": creds} if creds else {}),
                "group": group, "hosts": [fq.get(n) or n for n in names], "include_ad": False, "computer_bases": None}
    if not targets:
        return dict(settings.winrm)
    known_ips = {r[0] for r in db.execute(text("SELECT ip FROM device_nics WHERE ip IS NOT NULL"))}
    hosts = []
    for t in _targets(db, "ip_range"):
        if "winrm" not in ip_methods(db, t):
            continue
        hosts += [ip for ip in json.loads(get_setting(db, f"ip_scan:{t.id}", "[]")) if ip not in known_ips]
    bases, whole = [], False
    for t in _targets(db, *AD_KINDS):
        try:
            k, _, base, coll = ad_scope(t)
        except ValueError:
            continue
        if k == "ad_domain" and "computers" in coll:
            whole = True
        elif k == "ad_computer_path":
            bases.append(base)
    return {**settings.winrm, **({"parallel": par} if par else {}), "creds": creds, "hosts": hosts,
            "include_ad": whole or bool(bases), "computer_bases": None if whole else (bases or None)}


def why_no_winrm(db: Session) -> NothingToDo:
    """winrm_cfg gave nothing: say why (no targets in this run, or no target has a Windows credential)."""
    targets = _targets(db, *AD_KINDS, "ip_range")
    if not targets:
        return nothing_to_do(db, *AD_KINDS, "ip_range", what="Active Directory or IP range")
    names = ", ".join(_label(t) for t in targets)
    return NothingToDo(f"Skipped: no Windows credential is ticked on the target{'s' if len(targets) > 1 else ''} {names} "
                       "(Settings, Scan targets, Edit, Credentials to try).")


def run_pcs(db: Session, check_pending: bool) -> str:
    from .collectors import winrm
    cfg = winrm_cfg(db)
    if cfg is None:
        raise why_no_winrm(db)
    if cfg.get("group") and not cfg.get("hosts"):
        raise NothingToDo(f"Skipped: the group {cfg['group']} has no computers.")
    if not cfg.get("hosts") and not cfg.get("include_ad", True) and not settings.winrm.get("user"):
        raise NothingToDo("Skipped: no computers to scan. Tick Computers on an AD target, add an AD OU of computers, "
                          "or tick WinRM sweep on an IP range.")
    msg = winrm.collect_endpoints(db, cfg, check_pending=check_pending, raise_if_all_failed=True)
    _reconcile(db)
    return msg


def _reconcile(db) -> None:
    from . import catalog
    try:
        catalog.reconcile(db, only_new=True)
    except Exception:
        log.exception("app catalog reconcile")


def run_dc_logons(db: Session) -> str:
    from .collectors import winrm
    from .correlate import resolve_logon_hosts
    cfg = winrm_cfg(db)
    if cfg is None:
        raise why_no_winrm(db)
    msg = winrm.collect_dc_logons(db, cfg)
    return msg + f", {resolve_logon_hosts(db)} matched to the computer they came from"
