"""One-time scans (Scanning tab, "One-time scan"): scan an IP, a range, a computer, a user, an OU or a domain once,
with the scans and the sign-in account picked for this run, without saving a scan target or a scan job.

What is typed is turned into unsaved ScanTarget objects (kinds as in scanning.py, plus "host" for a computer by name
and "ad_user" for a user by name) and the usual collectors run on them inside scanning.scoped(adhoc=...), so the
results land in the inventory exactly like a scheduled scan's. Each run is a CollectorRun ("once"), shows live in
the Scanning view (it can be cancelled there) and is in the audit log when it starts and when it ends.
"""
from __future__ import annotations

import ipaddress
import itertools
import logging
import re
import socket
import threading
import time

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .db import AdUser, AuditLog, CollectorRun, Credential, Device, DomainController, ScanTarget, SessionLocal, \
    norm_host, utcnow
from . import instance, progress, scanning

log = logging.getLogger(__name__)

# What a typed value is. "auto" works it out (see classify).
KINDS = {"auto": "Work it out from what I typed", "ip": "IP address, range or CIDR", "host": "Computer name",
         "user": "Username", "ou_computers": "AD OU of computers", "ou_users": "AD OU of users", "domain": "Whole AD domain"}
SCANS = {"ping": "Ping (is it up)", "snmp": "SNMP (switches, printers, other network devices)",
         "pcs": "PC inventory over WinRM", "updates": "Pending Windows updates too (slower)",
         "ad": "Active Directory details", "dc_logons": "Logons from domain controllers (whole domain)"}
DEFAULT_SCANS = ["ping", "snmp", "pcs", "ad"]
MAX_ADDRESSES = 65536
USER_PCS = 5            # a username + PC inventory: the computers that user signed in to most recently

_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2}|-\d{1,3}(\.\d{1,3}){3}|-\d{1,3})?$")
_n = itertools.count(1)
ACTIVE: dict[str, dict] = {}          # "once:<n>" -> {"name", "who"} while it runs


# ------------------------------------------------------------------ what was typed
def known_domains(db: Session) -> list[str]:
    """AD domains NetInventory knows: from the saved AD targets, then from DCs seen in scans."""
    out = []
    for t in db.scalars(select(ScanTarget).where(ScanTarget.kind.in_(scanning.AD_KINDS)).order_by(ScanTarget.id)):
        try:
            out.append(scanning.ad_scope(t)[1])
        except ValueError:
            pass
    for (fqdn,) in db.execute(select(DomainController.fqdn)):
        if fqdn and "." in fqdn:
            out.append(fqdn.split(".", 1)[1].lower())
    return [d for d in dict.fromkeys(out) if d]


def _netbios(domains: list[str], short: str) -> str | None:
    s = short.strip().lower()
    return next((d for d in domains if d.split(".")[0] == s or d == s), None)


def _one_domain(domains: list[str]) -> str | None:
    return domains[0] if len(domains) == 1 else None


def classify(db: Session, value: str, kind: str = "auto", domains: list[str] | None = None) -> dict:
    """One typed value -> {"kind": scan target kind, "value", "domain", "label", "error"}."""
    v = value.strip().strip(",;")
    domains = known_domains(db) if domains is None else domains
    out = {"input": v, "kind": None, "value": v, "domain": None, "label": "", "error": None}

    def ip():
        from .collectors.snmp import expand_targets
        try:
            n = len(expand_targets([v]))
        except ValueError as exc:
            return {**out, "error": str(exc)}
        if n > MAX_ADDRESSES:
            return {**out, "error": f"{n} addresses is more than {MAX_ADDRESSES} for one scan"}
        return {**out, "kind": "ip_range", "label": f"{n} address{'es' if n != 1 else ''}" if n != 1 else "IP address"}

    def host():
        name = v.split("\\")[-1]
        dom = name.split(".", 1)[1].lower() if "." in name else None
        dev = db.scalar(select(Device).where(Device.hostname == norm_host(name.split(".")[0])))
        if not dom and dev and dev.fqdn and "." in dev.fqdn:
            dom = dev.fqdn.split(".", 1)[1].lower()
        return {**out, "kind": "host", "value": (dev.fqdn if dev and dev.fqdn and "." not in name else name),
                "domain": dom or _one_domain(domains),
                "label": "Computer" + (" (in the inventory)" if dev else " (not in the inventory yet)")}

    def user():
        dom, sam = None, v
        if "\\" in v:
            short, sam = v.split("\\", 1)
            dom = _netbios(domains, short) or (short.lower() if "." in short else None)
        elif "@" in v:
            sam, dom = v.split("@", 1)
            dom = dom.lower()
        sam = sam.strip().lower()
        u = db.scalar(select(AdUser).where(AdUser.username == sam))
        if not dom and u and u.domain:
            dom = _netbios(domains, u.domain)
        return {**out, "kind": "ad_user", "value": sam, "domain": dom or _one_domain(domains),
                "label": "User" + (" (in the inventory)" if u else " (not in the inventory yet)")}

    def ou(k):
        try:
            dn = scanning.normalize_dn(v)
        except ValueError as exc:
            return {**out, "error": str(exc)}
        return {**out, "kind": k, "value": dn, "domain": scanning.dn_domain(dn).lower(),
                "label": "AD OU of computers" if k == "ad_computer_path" else "AD OU of users"}

    def domain():
        if not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", v):
            return {**out, "error": "a domain looks like corp.example.com"}
        return {**out, "kind": "ad_domain", "value": v.lower(), "domain": v.lower(), "label": "Whole AD domain"}

    if not v:
        return {**out, "error": "empty"}
    if kind == "ip":
        return ip()
    if kind == "host":
        return host()
    if kind == "user":
        return user()
    if kind == "ou_computers":
        return ou("ad_computer_path")
    if kind == "ou_users":
        return ou("ad_user_path")
    if kind == "domain":
        return domain()
    # auto
    if _IP.match(v):
        return ip()
    try:
        ipaddress.ip_address(v)          # IPv6
        return ip()
    except ValueError:
        pass
    if "=" in v and "DC=" in v.upper():
        return ou("ad_computer_path")
    if "/" in v:
        return ou("ad_computer_path")
    if "@" in v:
        return user()
    if "\\" in v:
        short, name = v.split("\\", 1)
        if db.scalar(select(AdUser.id).where(AdUser.username == name.strip().lower())) or \
                not db.scalar(select(Device.id).where(Device.hostname == norm_host(name))):
            return user()
        return host()
    if v.lower() in domains:
        return domain()
    if "." in v:
        return host()
    is_pc = db.scalar(select(Device.id).where(Device.hostname == norm_host(v))) is not None
    is_user = db.scalar(select(AdUser.id).where(AdUser.username == v.lower())) is not None
    return user() if is_user and not is_pc else host()


def parse(db: Session, targets: str, kind: str = "auto") -> list[dict]:
    """Several values, one per line or separated by commas, semicolons or spaces."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind}")
    domains = known_domains(db)
    parts = [p for p in re.split(r"[\s,;]+", targets or "") if p.strip()]
    if kind in ("ou_computers", "ou_users"):     # an OU name can have spaces in it: one per line
        parts = [p.strip() for p in re.split(r"[\r\n;]+", targets or "") if p.strip()]
    seen, out = set(), []
    for p in parts:
        if p.lower() in seen:
            continue
        seen.add(p.lower())
        out.append(classify(db, p, kind, domains))
    return out


# ------------------------------------------------------------------ credentials
def _saved_cred_ids(db: Session, kinds: tuple[str, ...]) -> list[int]:
    """The credentials ticked on the saved scan targets (in order), else every stored one of these kinds."""
    ids, out = [], []
    for t in db.scalars(select(ScanTarget).order_by(ScanTarget.id)):
        ids += [int(x) for x in (t.credential_ids or "").split(",") if x.strip().isdigit()]
    for i in dict.fromkeys(ids):
        if i == scanning.SERVICE_CRED_ID:
            if "windows" in kinds:
                out.append(i)
            continue
        c = db.get(Credential, i)
        if c and c.kind in kinds:
            out.append(i)
    if not out:
        out = [c.id for c in db.scalars(select(Credential).where(Credential.kind.in_(kinds)).order_by(Credential.name))]
    return out


def _check_cred(db: Session, cid: int | None) -> None:
    if cid not in (None, scanning.SERVICE_CRED_ID):
        c = db.get(Credential, cid)
        if not c or c.kind != "windows":
            raise ValueError("the account picked to sign in with no longer exists")


# ------------------------------------------------------------------ running it
def steps_for(entries: list[dict], scans: set[str]) -> list[str]:
    kinds = {e["kind"] for e in entries}
    ad_like = kinds & {"ad_domain", "ad_computer_path", "ad_user_path", "host", "ad_user"}
    steps = []
    if "ad" in scans and ad_like:
        steps.append("ad")
    if "ping" in scans and "host" in kinds:
        steps.append("ping")
    if "ip_range" in kinds and scans & {"ping", "snmp", "pcs"}:
        steps.append("snmp")
    if "pcs" in scans and kinds & {"ip_range", "host", "ad_user", "ad_domain", "ad_computer_path"}:
        steps.append("pcs_updates" if "updates" in scans else "pcs")
    if "dc_logons" in scans:
        steps.append("dc_logons")
    return steps


def _user_pcs(db: Session, username: str) -> list[str]:
    rows = db.execute(text("SELECT hostname FROM v_user_devices WHERE username = :u AND hostname IS NOT NULL "
                           "ORDER BY last_logon DESC LIMIT :n"), {"u": username, "n": USER_PCS}).all()
    return [r[0] for r in rows]


def build_targets(db: Session, entries: list[dict], scans: set[str], cred_id: int | None,
                  snmp_ids: list[int] | None) -> list[ScanTarget]:
    win = [cred_id] if cred_id is not None else _saved_cred_ids(db, ("windows",))
    snmp = list(snmp_ids) if snmp_ids is not None else _saved_cred_ids(db, ("snmp2", "snmp3"))
    creds = ",".join(str(i) for i in win + snmp)
    ipm = ",".join(m for m, on in (("ping", "ping" in scans), ("snmp", "snmp" in scans), ("winrm", "pcs" in scans)) if on)
    out, names = [], set()
    for e in entries:
        t = ScanTarget(kind=e["kind"], value=e["value"], credential_ids=creds, enabled=True,
                       collect=ipm if e["kind"] == "ip_range" else
                       ("computers,users" if e["kind"] == "ad_domain" else None))
        t.domain = e.get("domain")
        out.append(t)
        if e["kind"] == "host":
            names.add(norm_host(e["value"].split(".")[0]))
    if "pcs" in scans:          # a user: also scan the PCs they signed in to lately
        for e in entries:
            if e["kind"] != "ad_user":
                continue
            for h in _user_pcs(db, e["value"]):
                if h in names:
                    continue
                names.add(h)
                dev = db.scalar(select(Device).where(Device.hostname == h))
                t = ScanTarget(kind="host", value=(dev.fqdn if dev and dev.fqdn else h), credential_ids=creds, enabled=True)
                t.domain = dev.fqdn.split(".", 1)[1].lower() if dev and dev.fqdn and "." in dev.fqdn else e.get("domain")
                t.for_user = e["value"]
                out.append(t)
    for i, t in enumerate(out, 1):
        t.id = -i               # never saved; the IP sweep keys its results by target id
    return out


def ping_hosts(db: Session) -> str:
    """Ping step for computers entered by name (IP ranges are pinged by the IP range step)."""
    from . import reach
    hosts = scanning._targets(db, "host")
    if not hosts:
        raise scanning.NothingToDo("Skipped: no computer names to ping.")
    addrs = {}
    for t in hosts:
        try:
            addrs[t.value] = socket.gethostbyname(t.value)
        except OSError:
            addrs[t.value] = None
    res = reach.sweep([a for a in addrs.values() if a]) if any(addrs.values()) else {}
    now, parts = utcnow(), []
    for name, a in addrs.items():
        up = bool(a and res.get(a, (False, ""))[0])
        dev = db.scalar(select(Device).where(Device.hostname == norm_host(name.split(".")[0])))
        if dev and a:
            reach.mark(dev, up, "ping" if up else "", now)
        parts.append(f"{name} {'answers' if up else 'does not answer'} ({a})" if a else f"{name}: name not found in DNS")
    db.commit()
    return "; ".join(parts)


def describe(entries: list[dict]) -> str:
    s = ", ".join(e["input"] for e in entries)
    return s if len(s) <= 80 else s[:77] + "..."


def start(db: Session, who: str, targets: str, kind: str = "auto", scans: list[str] | None = None,
          cred_id: int | None = None, snmp_ids: list[int] | None = None, max_parallel: int | None = None) -> dict:
    """Checks the request and starts the scan in its own thread. Raises ValueError with a message for the user."""
    entries = parse(db, targets, kind)
    if not entries:
        raise ValueError("Type at least one IP address, range, computer name, username, OU or domain.")
    bad = [e for e in entries if e["error"]]
    if bad:
        raise ValueError("; ".join(f"{e['input']}: {e['error']}" for e in bad))
    scans = {s for s in (scans or DEFAULT_SCANS) if s in SCANS}
    if "updates" in scans:
        scans.add("pcs")
    steps = steps_for(entries, scans)
    if not steps:
        raise ValueError("None of the ticked scans applies to what was typed (for example SNMP needs an IP address "
                         "or range, Active Directory needs a name, OU or domain).")
    _check_cred(db, cred_id)
    for s in snmp_ids or []:
        c = db.get(Credential, s)
        if not c or c.kind not in ("snmp2", "snmp3"):
            raise ValueError("an SNMP credential picked no longer exists")
    from .fixes import cred_name
    signin = cred_name(db, cred_id) or "the scanning credentials"
    par = max(1, min(64, int(max_parallel))) if max_parallel else None
    n = next(_n)
    key = f"once:{n}"
    what = describe(entries)
    db.add(AuditLog(actor=who, action="scan.once", target=what[:120],
                    result=f"started: {', '.join(steps)}, signing in as {signin}"))
    db.commit()
    threading.Thread(target=_run, args=(key, entries, scans, steps, cred_id, snmp_ids, par, who, signin),
                     daemon=True, name=key).start()
    return {"ok": True, "key": key, "steps": steps, "targets": entries,
            "output": f"One-time scan of {what} started ({', '.join(STEP_NAMES.get(s, s) for s in steps)}), "
                      f"signing in as {signin}. Follow it on the Scanning tab."}


STEP_NAMES = {"ad": "Active Directory", "ping": "ping", "snmp": "IP addresses", "pcs": "PC inventory",
              "pcs_updates": "PC inventory and updates", "dc_logons": "DC logons"}


def _run(key, entries, scans, steps, cred_id, snmp_ids, par, who, signin) -> None:
    from . import jobs
    what = describe(entries)
    name = f"One-time scan: {what}"
    ACTIVE[key] = {"name": name, "who": who}
    jobs.RUNNING[name] = time.time()
    prog = progress.start(key, name, steps=steps, who=who)
    parts, ok, skipped = [], True, 0
    try:
        with SessionLocal() as db:
            run = CollectorRun(collector="once", started=utcnow())
            db.add(run)
            db.commit()
            targets = build_targets(db, entries, scans, cred_id, snmp_ids)
            extra = [t.value for t in targets if getattr(t, "for_user", None)]
            with scanning.scoped(None, par, None, None, scheduled=False, cred_id=cred_id, adhoc=targets):
                for s in steps:
                    if prog.stop.is_set():
                        break
                    prog.begin_step(s)
                    try:
                        res = ping_hosts(db) if s == "ping" else jobs.JOBS[s](db)
                        parts.append(f"{s}: {res}")
                        db.commit()
                    except scanning.NothingToDo as exc:
                        db.rollback()
                        skipped += 1
                        parts.append(f"{s}: {exc}")
                    except Exception as exc:
                        db.rollback()
                        log.exception("one-time scan %s, %s failed", what, s)
                        ok = False
                        parts.append(f"{s}: failed ({scanning.short_error(exc)})")
            msg = f"{what}: " + "; ".join(parts) + (f" (also the PCs the user signed in to: {', '.join(extra)})" if extra else "") \
                + f" (started by {who}) (signed in as {signin})"
            if skipped and skipped == len(parts):
                ok, msg = False, "Skipped: nothing to scan. " + msg
            if prog.stop.is_set():
                ok, msg = False, f"Cancelled by {prog.cancelled_by or 'someone'}. " + msg
            run.ok, run.message, run.finished, run.ran_by = ok, msg[:4000], utcnow(), instance.ran_by()
            db.add(run)
            db.add(AuditLog(actor=who, action="scan.once.done", target=what[:120],
                            result=("ok: " if ok else "") + msg[:1900]))
            db.commit()
            jobs._refresh_groups(db)
    except Exception:
        log.exception("one-time scan %s", what)
    finally:
        progress.end(prog)
        jobs.RUNNING.pop(name, None)
        ACTIVE.pop(key, None)


def cancel(key: str, who: str) -> bool:
    return key in ACTIVE and progress.cancel(key, who)
