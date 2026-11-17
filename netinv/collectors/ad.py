"""Active Directory collector (agentless, LDAP).

Pulls computers (OS, lastLogonTimestamp, enabled, description, location), domain
controllers (site, GC, FSMO roles) and users (identity, organisation, lockout and
password state, group membership). Reading needs only a normal domain account.

Connection: LDAPS (636) first; if that fails, plain LDAP 389 with NTLM. DCs that
enforce LDAP signing (the default from Windows Server 2025) need LDAPS, and password
resets always need LDAPS.

The same module performs the user actions (unlock, reset password, must change
password) - those need an account with the matching delegated rights.
"""
from __future__ import annotations

import json
import logging
import ssl
from datetime import datetime, timedelta, timezone

from ldap3 import ALL, KERBEROS, MODIFY_REPLACE, NTLM, SASL, SUBTREE, Connection, Server, Tls
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import AdGroup, AdUser, DomainController, norm_host, utcnow
from ..ingest import get_or_create_device

log = logging.getLogger(__name__)
UAC_DISABLED = 0x2
UAC_LOCKOUT = 0x10
UAC_DONT_EXPIRE = 0x10000
UAC_SERVER_TRUST = 0x2000  # domain controller


def filetime_to_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.year < 1990:
            return None
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    if v <= 0 or v >= 0x7FFFFFFFFFFFFFFF:
        return None
    return datetime(1601, 1, 1) + timedelta(microseconds=v // 10)


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.strip(".").split("."))


def connect(cfg: dict) -> Connection:
    """cfg: server (or servers: list tried in order), user (DOMAIN\\user or UPN), password, verify_tls, ca_file."""
    errors = []
    servers = [s for s in (cfg.get("servers") or [cfg["server"]]) if s]
    for host in dict.fromkeys(servers):
        try:
            return _connect_one(cfg, host)
        except Exception as exc:
            errors.append(f"{host}: {exc}" if len(servers) > 1 else str(exc))
    raise RuntimeError("; ".join(errors) or "No domain controller to connect to.")


def _integrated(host: str, cfg: dict) -> Connection:
    """Bind as the Windows account this server runs as: Kerberos (SASL GSSAPI) through winkerberos on Windows.
    LDAPS first, then plain LDAP 389 (refused by DCs that require LDAP signing)."""
    errors = []
    for port, use_ssl in ((636, True), (389, False)):
        try:
            tls = Tls(validate=ssl.CERT_NONE) if use_ssl else None
            server = Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL, connect_timeout=8)
            return Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True, receive_timeout=60)
        except Exception as exc:
            errors.append(f"{'LDAPS' if use_ssl else 'LDAP'} as this server's account (Kerberos): {exc}")
    raise RuntimeError("; ".join(errors) + ". Kerberos needs the DC's full DNS name (not an IP), and the server "
                       "must run as a domain account or SYSTEM on a domain-joined machine.")


def _connect_one(cfg: dict, host: str) -> Connection:
    if cfg.get("integrated"):
        return _integrated(host, cfg)
    user = cfg["user"]
    auth = NTLM if "\\" in user else "SIMPLE"
    errors = []
    if cfg.get("use_ssl", True):
        try:
            tls = Tls(validate=ssl.CERT_REQUIRED if cfg.get("verify_tls", False) else ssl.CERT_NONE,
                      ca_certs_file=cfg.get("ca_file") or None)
            server = Server(host, port=636, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=8)
            try:
                return Connection(server, user=user, password=cfg["password"], authentication=auth,
                                  auto_bind=True, receive_timeout=60)
            except Exception as exc:
                if auth != NTLM:
                    raise
                # NTLM can fail where a simple bind works (NTLM disabled by policy, or no MD4 support).
                # Over LDAPS the password is encrypted, so a simple bind with DOMAIN\user is safe to try.
                try:
                    return Connection(server, user=user, password=cfg["password"], authentication="SIMPLE",
                                      auto_bind=True, receive_timeout=60)
                except Exception as exc2:
                    raise RuntimeError(f"NTLM: {exc}; simple bind: {exc2}") from exc2
        except Exception as exc:
            errors.append(f"LDAPS: {exc}")
    try:
        server = Server(host, port=389, get_info=ALL, connect_timeout=8)
        return Connection(server, user=user, password=cfg["password"], authentication=auth,
                          auto_bind=True, receive_timeout=60)
    except Exception as exc:
        errors.append(f"LDAP: {exc}")
    raise RuntimeError("; ".join(errors))


def _attr(entry, name):
    v = entry["attributes"].get(name)
    if isinstance(v, list):
        return v[0] if v else None
    return v if v not in ("", []) else None


def _search(conn, base, flt, attrs):
    return [e for e in conn.extend.standard.paged_search(base, flt, SUBTREE, attributes=attrs, paged_size=500,
                                                         generator=True) if e.get("type") == "searchResEntry"]


COMPUTER_ATTRS = ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp",
                  "whenCreated", "userAccountControl", "distinguishedName", "description", "location", "managedBy",
                  "memberOf"]
USER_ATTRS = ["sAMAccountName", "displayName", "givenName", "sn", "initials", "userPrincipalName", "mail", "description",
              "title", "department", "company", "physicalDeliveryOfficeName", "telephoneNumber", "mobile", "manager",
              "distinguishedName", "objectSid", "scriptPath", "homeDirectory", "userAccountControl", "lockoutTime",
              "pwdLastSet", "lastLogonTimestamp", "badPwdCount", "whenCreated", "whenChanged", "memberOf",
              "msDS-User-Account-Control-Computed"]


def collect(db: Session, cfg: dict) -> str:
    """cfg: server, user, password, base_dn, domain, computer_bases[], user_bases[], users (bool), computers (bool)."""
    from ..exclusions import Exclusions
    excl = Exclusions.load(db)
    conn = connect(cfg)
    base = cfg.get("base_dn") or domain_to_dn(cfg["domain"])
    domain_short = (cfg.get("domain") or "").split(".")[0].upper() or None
    now = utcnow()

    computers = 0
    dcs = []
    want_computers = cfg.get("computers", True)
    for cbase in (cfg.get("computer_bases") or [base]) if want_computers else []:
        for e in _search(conn, cbase, "(objectClass=computer)", COMPUTER_ATTRS):
            name = norm_host(_attr(e, "name"))
            if not name or excl.target(hostname=name, fqdn=_attr(e, "dNSHostName"), dn=_attr(e, "distinguishedName")):
                continue
            uac = int(_attr(e, "userAccountControl") or 0)
            if uac & UAC_SERVER_TRUST:
                dcs.append(e)
            dev = get_or_create_device(db, name)
            dev.fqdn = _attr(e, "dNSHostName") or dev.fqdn
            dev.ad_dn = _attr(e, "distinguishedName")
            dev.ad_enabled = not (uac & UAC_DISABLED)
            dev.ad_os = _attr(e, "operatingSystem")
            dev.ad_os_version = _attr(e, "operatingSystemVersion")
            dev.ad_last_logon = filetime_to_dt(_attr(e, "lastLogonTimestamp"))
            dev.ad_created = filetime_to_dt(_attr(e, "whenCreated"))
            dev.ad_description = _attr(e, "description")
            dev.ad_location = _attr(e, "location")
            dev.ad_managed_by = _attr(e, "managedBy")
            dev.ad_groups = json.dumps([str(g).lower() for g in (e["attributes"].get("memberOf") or [])])
            dev.ad_seen = now
            if dev.first_seen is None or (dev.ad_created and dev.ad_created < dev.first_seen):
                dev.first_seen = dev.ad_created or now
            computers += 1
    # DCs live in OU=Domain Controllers, which may be outside a restricted computer path.
    if cfg.get("computer_bases") or not want_computers:
        dcs = _search(conn, base, "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", COMPUTER_ATTRS)

    fsmo = _fsmo_roles(conn, base)
    gcs = _global_catalogs(conn, base)
    for e in dcs:
        host = norm_host(_attr(e, "name"))
        dc = db.scalar(select(DomainController).where(DomainController.hostname == host)) or DomainController(hostname=host)
        db.add(dc)
        dc.fqdn = _attr(e, "dNSHostName")
        dc.os = _attr(e, "operatingSystem")
        dc.os_version = _attr(e, "operatingSystemVersion")
        dc.site = gcs.get(host, {}).get("site")
        dc.is_gc = gcs.get(host, {}).get("gc", False)
        dc.fsmo_roles = ", ".join(r for r, h in fsmo.items() if h == host) or None
        dc.last_seen = now

    users = 0
    groups = {}
    if want_computers or cfg.get("users", True):
        # Every AD group, with the groups it is itself in: group conditions (Groups tab, sign-in) follow nesting.
        for g in _search(conn, base, "(objectClass=group)", ["distinguishedName", "cn", "sAMAccountName", "groupType",
                                                            "description", "memberOf"]):
            gt = int(_attr(g, "groupType") or 0)
            scope = "Universal" if gt & 8 else "Domain local" if gt & 4 else "Global" if gt & 2 else "Builtin"
            kind = "Security" if gt & 0x80000000 else "Distribution"
            groups[_attr(g, "distinguishedName").lower()] = {"name": _attr(g, "cn"), "type": f"{kind} - {scope.lower()}",
                                                             "description": _attr(g, "description"),
                                                             "sam": _attr(g, "sAMAccountName"),
                                                             "member_of": [str(x).lower() for x in g["attributes"].get("memberOf") or []]}
        _save_groups(db, groups, now)
    if cfg.get("users", True):
        for ubase in cfg.get("user_bases") or [base]:
            for e in _search(conn, ubase, "(&(objectCategory=person)(objectClass=user))", USER_ATTRS):
                sam = (_attr(e, "sAMAccountName") or "").lower()
                if not sam or excl.dn(_attr(e, "distinguishedName")):
                    continue
                u = db.scalar(select(AdUser).where(AdUser.username == sam)) or AdUser(username=sam)
                db.add(u)
                uac = int(_attr(e, "userAccountControl") or 0)
                computed = int(_attr(e, "msDS-User-Account-Control-Computed") or 0)
                lockout = filetime_to_dt(_attr(e, "lockoutTime"))
                manager = _attr(e, "manager")
                member_of = e["attributes"].get("memberOf") or []
                u.domain = domain_short
                u.display_name, u.first_name, u.last_name = _attr(e, "displayName"), _attr(e, "givenName"), _attr(e, "sn")
                u.initials, u.upn, u.email = _attr(e, "initials"), _attr(e, "userPrincipalName"), _attr(e, "mail")
                u.description, u.title, u.department = _attr(e, "description"), _attr(e, "title"), _attr(e, "department")
                u.company, u.office = _attr(e, "company"), _attr(e, "physicalDeliveryOfficeName")
                u.phone, u.mobile = _attr(e, "telephoneNumber"), _attr(e, "mobile")
                u.manager = manager.split(",")[0].removeprefix("CN=") if manager else None
                u.dn, u.sid = _attr(e, "distinguishedName"), str(_attr(e, "objectSid") or "") or None
                u.logon_script, u.home_directory = _attr(e, "scriptPath"), _attr(e, "homeDirectory")
                u.enabled = not (uac & UAC_DISABLED)
                u.locked = bool(computed & UAC_LOCKOUT) if computed else bool(lockout)
                u.password_never_expires = bool(uac & UAC_DONT_EXPIRE)
                u.password_last_set = filetime_to_dt(_attr(e, "pwdLastSet"))
                u.last_logon = filetime_to_dt(_attr(e, "lastLogonTimestamp"))
                u.bad_pwd_count = int(_attr(e, "badPwdCount") or 0)
                u.created, u.changed = filetime_to_dt(_attr(e, "whenCreated")), filetime_to_dt(_attr(e, "whenChanged"))
                u.groups = json.dumps([{k: v for k, v in groups.get(dn.lower(), {"name": dn.split(",")[0].removeprefix("CN="),
                                                                                 "type": ""}).items()
                                        if k in ("name", "type", "description")} for dn in member_of])
                u.group_dns = json.dumps([str(dn).lower() for dn in member_of])
                u.last_scanned = now
                users += 1
    conn.unbind()
    return f"{computers} computers, {len(dcs)} domain controllers, {users} users"


def _save_groups(db: Session, groups: dict, now) -> None:
    """Upserts the AD groups seen in this import. Groups gone from AD are dropped once no import has seen them for a week."""
    have = {g.dn: g for g in db.scalars(select(AdGroup))}
    for dn, g in groups.items():
        row = have.get(dn) or AdGroup(dn=dn)
        row.name, row.sam, row.type, row.description = g["name"], g.get("sam"), g["type"], g.get("description")
        row.member_of, row.seen = json.dumps(g.get("member_of") or []), now
        db.add(row)
    for dn, row in have.items():
        if dn not in groups and row.seen and row.seen < now - timedelta(days=7):
            db.delete(row)
    db.flush()


def _config_dn(base: str) -> str:
    return "CN=Configuration," + base


def _global_catalogs(conn: Connection, base: str) -> dict:
    out: dict = {}
    try:
        conn.search("CN=Sites," + _config_dn(base), "(objectClass=nTDSDSA)", SUBTREE, attributes=["options"])
    except Exception:
        return out
    for e in conn.response:
        if e.get("type") != "searchResEntry":
            continue
        parts = e["dn"].split(",")
        host = norm_host(parts[1].split("=", 1)[1])
        out[host] = {"site": parts[3].split("=", 1)[1], "gc": bool(int(_attr(e, "options") or 0) & 1)}
    return out


def _fsmo_roles(conn: Connection, base: str) -> dict:
    targets = {
        "PDC": (base, "(objectClass=domainDNS)"),
        "RID": ("CN=RID Manager$,CN=System," + base, "(objectClass=*)"),
        "Infrastructure": ("CN=Infrastructure," + base, "(objectClass=*)"),
        "Schema": ("CN=Schema," + _config_dn(base), "(objectClass=dMD)"),
        "DomainNaming": ("CN=Partitions," + _config_dn(base), "(objectClass=crossRefContainer)"),
    }
    roles = {}
    for role, (dn, flt) in targets.items():
        try:
            conn.search(dn, flt, "BASE", attributes=["fSMORoleOwner"])
            owner = _attr(conn.response[0], "fSMORoleOwner") if conn.response else None
            if owner:
                roles[role] = norm_host(owner.split(",")[1].split("=", 1)[1])
        except Exception as exc:
            log.debug("FSMO lookup %s failed: %s", role, exc)
    return roles


# ------------------------------------------------------------------ user actions
def user_action(cfg: dict, dn: str, action: str, new_password: str | None = None, must_change: bool = True) -> str:
    conn = connect(cfg)
    try:
        if action == "unlock":
            ok = conn.extend.microsoft.unlock_account(dn)
        elif action == "must_change":
            ok = conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        elif action == "reset_password":
            if not new_password:
                raise ValueError("new password required")
            ok = conn.extend.microsoft.modify_password(dn, new_password)
            if ok and must_change:
                conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        elif action in ("enable", "disable"):
            conn.search(dn, "(objectClass=*)", "BASE", attributes=["userAccountControl"])
            uac = int(conn.entries[0].userAccountControl.value)
            uac = uac & ~UAC_DISABLED if action == "enable" else uac | UAC_DISABLED
            ok = conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]})
        else:
            raise ValueError("unknown action")
        if not ok:
            raise RuntimeError(conn.result.get("message") or conn.result.get("description") or "AD refused the change")
        return "done"
    finally:
        conn.unbind()


# ------------------------------------------------------------------ computer objects
def bitlocker_keys(cfg: dict, computer_dn: str) -> list[dict]:
    """BitLocker recovery passwords stored in AD under the computer object (needs read access to msFVE-RecoveryPassword)."""
    conn = connect(cfg)
    try:
        conn.search(computer_dn, "(objectClass=msFVE-RecoveryInformation)", SUBTREE,
                    attributes=["msFVE-RecoveryPassword", "msFVE-VolumeGuid", "whenCreated", "name"])
        out = []
        for e in conn.entries:
            d = e.entry_attributes_as_dict
            pw = (d.get("msFVE-RecoveryPassword") or [None])[0]
            name = (d.get("name") or [""])[0]
            out.append({"created": str((d.get("whenCreated") or [""])[0])[:19], "key_id": name.split("{")[-1].rstrip("}") if "{" in name else name,
                        "password": pw, "readable": bool(pw)})
        return sorted(out, key=lambda x: x["created"], reverse=True)
    finally:
        conn.unbind()


def _base(cfg: dict, dn: str) -> str:
    return ",".join(p for p in dn.split(",") if p.strip().upper().startswith("DC="))


def computer_info(cfg: dict, dn: str) -> dict:
    conn = connect(cfg)
    try:
        conn.search(dn, "(objectClass=computer)", "BASE", attributes=["description", "userAccountControl", "memberOf", "location", "managedBy", "name"])
        if not conn.entries:
            raise RuntimeError("The computer object wasn't found in AD (moved or deleted?).")
        d = conn.entries[0].entry_attributes_as_dict
        uac = int((d.get("userAccountControl") or [0])[0] or 0)
        return {"dn": dn, "name": (d.get("name") or [""])[0], "description": (d.get("description") or [""])[0] or "",
                "location": (d.get("location") or [""])[0] or "", "managed_by": (d.get("managedBy") or [""])[0] or "",
                "enabled": not (uac & UAC_DISABLED), "groups": sorted(d.get("memberOf") or [], key=str.lower)}
    finally:
        conn.unbind()


def list_ous(cfg: dict, any_dn: str) -> list[str]:
    conn = connect(cfg)
    try:
        base = _base(cfg, any_dn)
        rows = _search(conn, base, "(|(objectClass=organizationalUnit)(objectClass=container))", ["distinguishedName"])
        skip = ("CN=System,", "CN=Program Data,", "CN=ForeignSecurityPrincipals,", "CN=Managed Service Accounts,", "CN=LostAndFound,",
                "CN=NTDS Quotas,", "CN=TPM Devices,", "CN=Keys,", "CN=Infrastructure,", "CN=Builtin,")
        out = [e["dn"] for e in rows if not any(s.lower() in e["dn"].lower() + "," for s in skip)]
        return sorted(out, key=lambda x: list(reversed(x.lower().split(","))))
    finally:
        conn.unbind()


def find_groups(cfg: dict, any_dn: str, q: str) -> list[dict]:
    from ldap3.utils.conv import escape_filter_chars
    conn = connect(cfg)
    try:
        q = escape_filter_chars((q or "").strip()[:64])
        flt = f"(&(objectClass=group)(|(cn=*{q}*)(sAMAccountName=*{q}*)))" if q else "(objectClass=group)"
        conn.search(_base(cfg, any_dn), flt, SUBTREE, attributes=["cn", "description"], size_limit=50)
        return [{"dn": e.entry_dn, "name": str(e.cn), "description": str(e.description) if e.description else ""} for e in conn.entries]
    finally:
        conn.unbind()


def computer_action(cfg: dict, dn: str, op: str, value: str = "") -> str:
    """op: description, location, enable, disable, move (value = target OU DN), add_group / remove_group (value = group DN).
    Returns the computer's DN afterwards (it changes when moved)."""
    from ldap3 import MODIFY_ADD, MODIFY_DELETE
    conn = connect(cfg)
    try:
        new_dn = dn
        if op in ("description", "location"):
            ok = conn.modify(dn, {op: [(MODIFY_REPLACE, [value] if value else [])]})
        elif op in ("enable", "disable"):
            conn.search(dn, "(objectClass=*)", "BASE", attributes=["userAccountControl"])
            uac = int(conn.entries[0].userAccountControl.value)
            uac = uac & ~UAC_DISABLED if op == "enable" else uac | UAC_DISABLED
            ok = conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]})
        elif op == "move":
            rdn = dn.split(",", 1)[0]
            ok = conn.modify_dn(dn, rdn, new_superior=value)
            new_dn = f"{rdn},{value}"
        elif op in ("add_group", "remove_group"):
            ok = conn.modify(value, {"member": [((MODIFY_ADD if op == "add_group" else MODIFY_DELETE), [dn])]})
        else:
            raise ValueError("unknown action")
        if not ok:
            raise RuntimeError(conn.result.get("message") or conn.result.get("description") or "AD refused the change")
        return new_dn
    finally:
        conn.unbind()
