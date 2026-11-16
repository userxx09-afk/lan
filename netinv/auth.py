"""Dashboard sign-in: the local admin account, Active Directory accounts in one AD group, sessions and lockout.

- Local admin: [server] ui_user / ui_password in config.toml. The password may be stored as a hash
  (``pbkdf2_sha256$<iterations>$<salt>$<hash>``, written by the installer) or, for older configs, in plain text.
- AD sign-in: set the domain and group in Settings > Sign-in. Users sign in with their own AD username
  and password (``user``, ``DOMAIN\\user`` or ``user@domain``); NetInventory binds to a DC as them and checks
  they are in the group, nested membership included. The password is never stored.
- Break-glass: after the first successful AD sign-in NetInventory writes ``local-login.disabled`` next to
  config.toml, which turns the local admin off. Delete that file to turn the local admin back on (for
  example when AD or the group is unavailable). It is written again on the next AD sign-in.
- Lockout: 5 failed attempts for a username, or 20 from one address, within 15 minutes block further
  attempts for 15 minutes.
- Sessions: random token in an HttpOnly, SameSite=Strict cookie (Secure over HTTPS); 12 hours, or 2 hours idle.
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
        return bool(get_setting(db, "auth:ad_group"))


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
    domain = get_setting(db, "auth:ad_domain")
    if not group or not domain:
        return None
    return {"group": group, "domain": domain.lower(), "server": get_setting(db, "auth:ad_server")}


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
        group_dn = cfg["group"]
        if "DC=" not in group_dn.upper():
            g = escape_filter_chars(group_dn)
            conn.search(base, f"(&(objectClass=group)(|(cn={g})(sAMAccountName={g})))", attributes=["distinguishedName"])
            if not conn.entries:
                log.warning("AD sign-in: group %s not found", group_dn)
                return None
            group_dn = conn.entries[0].entry_dn
        flt = (f"(&(objectCategory=person)(sAMAccountName={escape_filter_chars(sam)})"
               f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)})"
               f"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
        conn.search(base, flt, attributes=["sAMAccountName"])
        if not conn.entries:
            log.info("AD sign-in refused for %s: not in %s", sam, cfg["group"])
            return None
        return str(conn.entries[0].sAMAccountName).lower()
    finally:
        conn.unbind()


# ------------------------------------------------------------------ login / sessions
class LoginError(Exception):
    pass


def login(db, username: str, password: str, ip: str) -> Session:
    username = (username or "").strip()
    if not username or not password:
        raise LoginError("Enter a username and password.")
    if locked_out(username, ip):
        raise LoginError("Too many failed sign-ins. Try again in 15 minutes.")
    user, source = None, None
    if settings.ui_user and hmac.compare_digest(username.lower(), settings.ui_user.lower()):
        if local_enabled() and check_password(password, settings.ui_password):
            user, source = settings.ui_user, "local"
        elif not local_enabled():
            _fail(username, ip)
            raise LoginError("The local admin account is turned off because AD sign-in is set up. Sign in with your "
                             f"AD account, or delete {local_disabled_file()} on the server to turn it back on.")
    elif ad_config(db):
        sam = ad_login(db, username, password)
        if sam:
            user, source = sam, "ad"
            f = local_disabled_file()
            if settings.ui_user and not f.exists():
                f.write_text("The local admin sign-in is turned off because AD sign-in works.\n"
                             "Delete this file to turn the local admin back on (it is written again at the next AD sign-in).\n")
                log.info("AD sign-in works: local admin turned off (%s)", f)
    if not user:
        _fail(username, ip)
        raise LoginError("Wrong username or password, or the account isn't allowed to use NetInventory.")
    _clear(username)
    s = Session(user=user, source=source, created=time.time(), seen=time.time())
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
        if not s or now - s.created > SESSION_MAX or now - s.seen > SESSION_IDLE:
            _sessions.pop(token, None)
            return None
        if s.source == "local" and not local_enabled():
            _sessions.pop(token, None)     # local admin was just turned off
            return None
        s.seen = now
        return s


def logout(token: str | None) -> None:
    with _lock:
        _sessions.pop(token or "", None)
