"""Dashboard sign-in: the local admin account, Active Directory accounts in one AD group, sessions and lockout.

- Local admin: [server] ui_user / ui_password in config.toml. The password may be stored as a hash
  (``pbkdf2_sha256$<iterations>$<salt>$<hash>``, written by the installer) or, for older configs, in plain text.
- AD sign-in: set the domain and group in Settings > Sign-in. Users sign in with their own AD username
  and password (``user``, ``DOMAIN\\user`` or ``user@domain``); NetInventory binds to a DC as them and checks
  they are in the group, nested membership included. The password is never stored.
  Instead of (or as well as) the AD group, a NetInventory user group (Groups tab: by OU, AD security group,
  department...) can be allowed. Its conditions are checked against the user's live AD entry at each sign-in.
- Break-glass: after the first successful AD sign-in NetInventory writes ``local-login.disabled`` next to
  config.toml, which turns the local admin off. Delete that file to turn the local admin back on (for
  example when AD or the group is unavailable). It is written again on the next AD sign-in.
- Admins (0.44): Settings > Sign-in names who may open Settings and change server-wide settings: admin usernames,
  an AD group and/or a NetInventory user group. Until one of those is set, everyone who can sign in is an admin (so
  an upgrade changes nothing). The local admin account is always an admin, so the break-glass file above is also
  the way back in if the admin list is wrong. Admin rights are worked out at sign-in; when the admin settings change,
  other sessions are checked again (live in AD with the scan credential) on their next request.
- Lockout: 5 failed attempts for a username, or 20 from one address, within 15 minutes block further
  attempts for 15 minutes.
- Sessions: random token in an HttpOnly, SameSite=Strict browser-session cookie (Secure over HTTPS; gone when the
  browser closes); 12 hours, or 2 hours idle. Sign-ins, failures, sign-outs and timeouts go to the audit log.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ldap3.utils.conv import escape_filter_chars

from .config import settings

log = logging.getLogger(__name__)
COOKIE = "netinv_session"
SESSION_MAX = 12 * 3600
SESSION_IDLE = 2 * 3600
FAIL_WINDOW = 15 * 60
MAX_USER_FAILS = 5
MAX_IP_FAILS = 20
_lock = threading.Lock()
_sessions: dict[str, "Session"] = {}
_fails: dict[str, list[float]] = {}


@dataclass
class Session:
    user: str
    source: str            # "local" or "ad"
    created: float
    seen: float
    admin: bool = True     # may open Settings (see is_admin)
    admin_stamp: str = ""  # the admin settings this was worked out for


# ------------------------------------------------------------------ password hashing (local admin)
def hash_password(pw: str, iterations: int = 390_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def check_password(pw: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, it, salt, want = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
            return hmac.compare_digest(dk, base64.b64decode(want))
        except Exception:
            return False
    return hmac.compare_digest(pw.encode(), stored.encode())


# ------------------------------------------------------------------ break-glass file
def data_dir() -> Path:
    return Path(os.environ.get("NETINV_CONFIG", "config.toml")).resolve().parent


def local_disabled_file() -> Path:
    return data_dir() / "local-login.disabled"


def local_enabled() -> bool:
    return bool(settings.ui_user) and not local_disabled_file().exists()


def auth_required() -> bool:
    """False only for an unconfigured dev setup (no ui_user and no AD sign-in)."""
    from .db import SessionLocal, get_setting
    if settings.ui_user:
        return True
    with SessionLocal() as db:
        return bool(get_setting(db, "auth:ad_group") or get_setting(db, "auth:access_group"))


# ------------------------------------------------------------------ lockout
def _recent(key: str) -> list[float]:
    now = time.time()
    lst = [t for t in _fails.get(key, []) if now - t < FAIL_WINDOW]
    _fails[key] = lst
    return lst


def locked_out(user: str, ip: str) -> bool:
    with _lock:
        return len(_recent(f"u:{user.lower()}")) >= MAX_USER_FAILS or len(_recent(f"ip:{ip}")) >= MAX_IP_FAILS


def _fail(user: str, ip: str) -> None:
    with _lock:
        now = time.time()
        _fails.setdefault(f"u:{user.lower()}", []).append(now)
        _fails.setdefault(f"ip:{ip}", []).append(now)


def _clear(user: str) -> None:
    with _lock:
        _fails.pop(f"u:{user.lower()}", None)


# ------------------------------------------------------------------ AD sign-in
def ad_config(db) -> dict | None:
    from .db import get_setting
    group = get_setting(db, "auth:ad_group")
    access = get_setting(db, "auth:access_group")
    domain = get_setting(db, "auth:ad_domain")
    if not (group or access) or not domain:
        return None
    return {"group": group, "access_group": access, "domain": domain.lower(), "server": get_setting(db, "auth:ad_server")}


def _split_user(username: str, domain: str) -> tuple[str, str]:
    """Return (bind user for NTLM, sAMAccountName)."""
    u = username.strip()
    if "\\" in u:
        dom, sam = u.split("\\", 1)
        return f"{dom}\\{sam}", sam
    if "@" in u:
        sam, dom = u.split("@", 1)
        return f"{dom}\\{sam}", sam
    return f"{domain}\\{u}", u


def ad_login(db, username: str, password: str) -> str | None:
    """Bind as the user and check group membership. Returns the sAMAccountName, or None."""
    r = ad_login_admin(db, username, password)
    return r[0] if r else None


def ad_login_admin(db, username: str, password: str) -> tuple[str, bool] | None:
    """Like ad_login, and also whether the user is a NetInventory admin: (sAMAccountName, admin) or None."""
    from .collectors import ad as adc
    from .scanning import dc_candidates
    from .collectors.ad import domain_to_dn
    cfg = ad_config(db)
    if not cfg or not password:
        return None
    bind_user, sam = _split_user(username, cfg["domain"])
    ts = [type("T", (), {"server": cfg["server"]})()] if cfg["server"] else []
    try:
        conn = adc.connect({"servers": dc_candidates(db, cfg["domain"], ts), "server": cfg["server"] or cfg["domain"],
                            "user": bind_user, "password": password})
    except Exception as exc:
        log.info("AD sign-in failed for %s: %s", sam, str(exc).split(";")[0])
        return None
    try:
        base = domain_to_dn(cfg["domain"])
        if (cfg["group"] and _in_ad_group(conn, base, sam, cfg["group"])) or \
                (cfg.get("access_group") and _in_user_group(db, conn, base, sam, cfg["access_group"])):
            return sam.lower(), _admin_check(db, conn, base, sam)
        log.info("AD sign-in refused for %s: not in %s", sam,
                 " or ".join(x for x in (cfg["group"], cfg.get("access_group") and f"user group {cfg['access_group']}") if x))
        return None
    finally:
        conn.unbind()


def _in_ad_group(conn, base: str, sam: str, group_dn: str) -> bool:
    if "DC=" not in group_dn.upper():
        g = escape_filter_chars(group_dn)
        conn.search(base, f"(&(objectClass=group)(|(cn={g})(sAMAccountName={g})))", attributes=["distinguishedName"])
        if not conn.entries:
            log.warning("AD sign-in: group %s not found", group_dn)
            return False
        group_dn = conn.entries[0].entry_dn
    flt = (f"(&(objectCategory=person)(sAMAccountName={escape_filter_chars(sam)})"
           f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)})"
           f"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
    conn.search(base, flt, attributes=["sAMAccountName"])
    return bool(conn.entries)


def _in_user_group(db, conn, base: str, sam: str, name: str) -> bool:
    """Checks a NetInventory user group's conditions (OU, AD groups, department...) against the user's live AD entry."""
    from . import groups
    conn.search(base, f"(&(objectCategory=person)(sAMAccountName={escape_filter_chars(sam)}))",
                attributes=["distinguishedName", "userPrincipalName", "displayName", "department", "title",
                            "physicalDeliveryOfficeName", "company", "userAccountControl"])
    if not conn.entries:
        return False
    e = conn.entries[0]
    val = lambda a: (e[a].value if a in e.entry_attributes else None)
    if int(val("userAccountControl") or 0) & 2:
        return False
    dn = e.entry_dn
    conn.search(base, f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={escape_filter_chars(dn)}))",
                attributes=["cn"])
    nested = [g.entry_dn for g in conn.entries]
    ent = groups.user_entity(sam.lower(), dn, nested, upn=val("userPrincipalName"), name=val("displayName"),
                             department=val("department"), title=val("title"), office=val("physicalDeliveryOfficeName"),
                             company=val("company"), tree=groups._GroupTree(db), nested=True)
    return groups.user_in_group(db, name, ent)


# ------------------------------------------------------------------ admins (who may open Settings)
def admin_config(db) -> dict:
    from .db import get_setting
    users = [u.strip().lower().split("\\")[-1].split("@")[0] for u in (get_setting(db, "auth:admin_users") or "").replace(";", ",").split(",")]
    return {"users": sorted({u for u in users if u}), "ad_group": get_setting(db, "auth:admin_group") or "",
            "user_group": get_setting(db, "auth:admin_user_group") or ""}


def admin_configured(cfg: dict) -> bool:
    return bool(cfg["users"] or cfg["ad_group"] or cfg["user_group"])


def admin_stamp(cfg: dict) -> str:
    return hashlib.sha256(repr((cfg["users"], cfg["ad_group"], cfg["user_group"])).encode()).hexdigest()[:16]


def _admin_check(db, conn, base: str, sam: str, cfg: dict | None = None) -> bool:
    """Is this AD user an admin under cfg (default: the saved admin settings)? conn is any bound AD connection."""
    cfg = cfg or admin_config(db)
    if not admin_configured(cfg) or sam.lower() in cfg["users"]:
        return True
    try:
        if cfg["ad_group"] and _in_ad_group(conn, base, sam, cfg["ad_group"]):
            return True
        if cfg["user_group"] and _in_user_group(db, conn, base, sam, cfg["user_group"]):
            return True
    except Exception as exc:
        log.warning("checking whether %s is an admin failed: %s", sam, exc)
    return False


def admin_live(db, sam: str, cfg: dict | None = None) -> bool:
    """Admin check outside sign-in: the username list, else live in AD with the scan credential for the sign-in
    domain. Raises when AD has to be asked and can't be."""
    cfg = cfg or admin_config(db)
    if not admin_configured(cfg) or sam.lower() in cfg["users"]:
        return True
    if not (cfg["ad_group"] or cfg["user_group"]):
        return False
    from .collectors import ad as adc
    from .collectors.ad import domain_to_dn
    from .db import get_setting
    from .scanning import ad_action_cfg
    domain = (get_setting(db, "auth:ad_domain") or "").lower()
    if not domain:
        raise RuntimeError("no AD sign-in domain set")
    base = domain_to_dn(domain)
    conn = adc.connect(ad_action_cfg(db, base))
    try:
        if cfg["ad_group"] and _in_ad_group(conn, base, sam, cfg["ad_group"]):
            return True
        return bool(cfg["user_group"] and _in_user_group(db, conn, base, sam, cfg["user_group"]))
    finally:
        conn.unbind()


def is_admin(s: Session | None) -> bool:
    """May this session open Settings? The local admin always may; with no admins set up, everyone may."""
    from .db import SessionLocal
    if s is None:
        return not auth_required()
    if s.source == "local":
        return True
    with SessionLocal() as db:
        cfg = admin_config(db)
        stamp = admin_stamp(cfg)
        if s.admin_stamp == stamp:
            return s.admin
        if not admin_configured(cfg):
            ok = True
        else:
            try:
                ok = admin_live(db, s.user, cfg)
            except Exception as exc:
                log.warning("admin settings changed; couldn't check %s in AD (%s): not an admin until they sign in again",
                            s.user, str(exc)[:200])
                ok = False
    s.admin, s.admin_stamp = ok, stamp
    return ok


# ------------------------------------------------------------------ login / sessions
class LoginError(Exception):
    pass


def login(db, username: str, password: str, ip: str) -> Session:
    username = (username or "").strip()
    if not username or not password:
        raise LoginError("Enter a username and password.")
    if locked_out(username, ip):
        raise LoginError("Too many failed sign-ins. Try again in 15 minutes.")
    user, source, admin = None, None, True
    if settings.ui_user and hmac.compare_digest(username.lower(), settings.ui_user.lower()):
        if local_enabled() and check_password(password, settings.ui_password):
            user, source = settings.ui_user, "local"
        elif not local_enabled():
            _fail(username, ip)
            raise LoginError("The local admin account is turned off because AD sign-in is set up. Sign in with your "
                             f"AD account, or delete {local_disabled_file()} on the server to turn it back on.")
    elif ad_config(db):
        r = ad_login_admin(db, username, password)
        if r:
            (user, admin), source = r, "ad"
            f = local_disabled_file()
            if settings.ui_user and not f.exists():
                f.write_text("The local admin sign-in is turned off because AD sign-in works.\n"
                             "Delete this file to turn the local admin back on (it is written again at the next AD sign-in).\n")
                log.info("AD sign-in works: local admin turned off (%s)", f)
    if not user:
        _fail(username, ip)
        raise LoginError("Wrong username or password, or the account isn't allowed to use NetInventory.")
    _clear(username)
    s = Session(user=user, source=source, created=time.time(), seen=time.time(), admin=admin,
                admin_stamp=admin_stamp(admin_config(db)))
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = s
    s.token = token  # type: ignore[attr-defined]
    return s


def session_user(token: str | None) -> Session | None:
    if not token:
        return None
    with _lock:
        s = _sessions.get(token)
        now = time.time()
        why = None
        if s and now - s.created > SESSION_MAX:
            why = f"session ended after {SESSION_MAX // 3600} hours"
        elif s and now - s.seen > SESSION_IDLE:
            why = f"signed out after {SESSION_IDLE // 3600} hours without use"
        elif s and s.source == "local" and not local_enabled():
            why = "local admin sign-in was turned off"
        if not s or why:
            _sessions.pop(token, None)
        else:
            s.seen = now
            return s
    if s and why:
        _audit_end(s, why)
    return None


def sweep() -> None:
    """End timed-out sessions nobody came back to, so their end shows in the audit log too."""
    with _lock:
        tokens = list(_sessions)
    for t in tokens:
        if _expired(t):
            session_user(t)


def _expired(token: str) -> bool:
    with _lock:
        s = _sessions.get(token)
        now = time.time()
        return bool(s) and (now - s.created > SESSION_MAX or now - s.seen > SESSION_IDLE)


def _audit_end(s: Session, why: str) -> None:
    try:
        from . import logs
        logs.audit(s.user, "session.expired", "session", why)
    except Exception:
        log.exception("writing the session timeout to the audit log")


def logout(token: str | None) -> None:
    with _lock:
        _sessions.pop(token or "", None)
