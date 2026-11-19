"""Remote control: the server side of NetInventory Remote, the second (remote control) agent (rcagent/ in the repo).

The inventory agent stays report-only. This agent does nothing but remote control sessions, and the server is the
only party it talks to:

    browser  --wss (dashboard sign-in cookie)-->  NetInventory server  <--wss (outbound from the PC, pinned TLS)--  PC

- Nothing listens on the PC. Its service keeps one outbound control connection, signed with its own secret
  (HMAC-SHA256, the inventory agent's scheme: agentapi.check_sig), and the server's certificate is pinned.
- Enrollment like the inventory agent: a one-time push ticket ("nrp_...") from the dashboard (approved at once), or
  the remote control site token (Settings > Remote control), with approval by mode (known in AD / all / manual).
  A second agent claiming a hostname that already has one always waits for approval.
- Who may connect: anyone who can sign in to NetInventory, or only members of rc:allowed_group (an AD security
  group) when set. Members of rc:direct_group connect without asking; everyone else's request is shown to the
  signed-in user at the PC, who must accept it (default answer No, after rc:ask_seconds). Group membership is checked
  live in AD at each request with the scan credential; if that check fails, the answer is the safe one (ask, or refuse
  when an allowed group is set). The local admin account always asks. A PC's own policy (AlwaysAsk=1) forces the
  question; Disabled=1 turns sessions off there.
- Each session has two random one-time tokens (viewer, PC helper), good for 2 minutes. The viewer's WebSocket also
  needs the same signed-in user and a same-origin request (no cross-site WebSocket hijacking).
- The server relays and checks everything: only mouse, keyboard and display messages pass from the viewer to the PC,
  with bounds; view-only sessions pass no input at all. No clipboard, no files, no commands.
- Sessions end after rc:max_hours, after rc:idle_minutes without input, from the dashboard, or from the End button
  on the bar the PC shows during the whole session. Every request, answer, start and end is in the audit log and in
  the rc_sessions table (Settings > Remote control, and the PC's page); the PC writes them to its own event log too.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets as pysecrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from . import auth, logs
from .db import AuditLog, Device, RcAgent, RcSession, SessionLocal, get_setting, norm_host, set_setting, utcnow
from .secrets import decrypt, encrypt

log = logging.getLogger(__name__)
router = APIRouter()

APPROVE = ("ad", "all", "manual")
NOUSER = ("allow", "deny")
TOKEN_TTL = 120              # seconds a session's one-time tokens are good for
CONNECT_TTL = 90             # after the answer, the PC's helper has this long to connect
MAX_FRAME = 16 << 20
INPUT_RATE = 600             # viewer messages per second, at most
SID_RE = re.compile(r"^[A-Za-z0-9_\-]{16,64}$")
CODE_RE = re.compile(r"^[A-Za-z0-9]{1,24}$")
_fails: dict[str, list[float]] = {}
_starts: dict[str, list[float]] = {}

ALLOWED_RESULTS = {"accepted": "accepted by {u}", "direct": "connected without asking (allowed group)",
                   "nouser-allowed": "nobody signed in at the PC", "denied": "refused by {u}",
                   "timeout": "no answer from {u}", "nouser-denied": "nobody signed in at the PC (refused by setting)",
                   "busy": "another session is already running on the PC", "disabled": "turned off on the PC by its policy",
                   "error": "error on the PC"}


# ------------------------------------------------------------------ settings
def _int(db, key: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(get_setting(db, key, None) or default)))
    except ValueError:
        return default


def config(db) -> dict:
    a = get_setting(db, "rc:approve", None) or "ad"
    n = get_setting(db, "rc:nouser", None) or "allow"
    return {"enabled": (get_setting(db, "rc:enabled", None) or "1") == "1",
            "allowed_group": get_setting(db, "rc:allowed_group", None) or "",
            "direct_group": get_setting(db, "rc:direct_group", None) or "",
            "ask_seconds": _int(db, "rc:ask_seconds", 30, 10, 300),
            "nouser": n if n in NOUSER else "allow",
            "max_hours": _int(db, "rc:max_hours", 8, 1, 24),
            "idle_minutes": _int(db, "rc:idle_minutes", 30, 5, 480),
            "approve": a if a in APPROVE else "ad",
            "require_reason": (get_setting(db, "rc:require_reason", None) or "0") == "1"}


def token_hash(tok: str) -> str:
    return hashlib.sha256(tok.strip().encode()).hexdigest()


def new_token(db) -> str:
    tok = "nra_" + pysecrets.token_urlsafe(24)
    set_setting(db, "rc:token_hash", token_hash(tok))
    set_setting(db, "rc:token_created", utcnow().isoformat(sep=" ", timespec="minutes"))
    set_setting(db, "rc:token_hint", tok[-4:])
    return tok


def msi_path() -> Path | None:
    """NetInventory-Remote.msi shipped with the server installer ({app}\\agent-msi), if there is one."""
    cands = []
    if os.environ.get("NETINV_RC_MSI"):
        cands.append(Path(os.environ["NETINV_RC_MSI"]))
    from .updater import install_dir
    root = install_dir()
    if root:
        cands.append(root / "agent-msi" / "NetInventory-Remote.msi")
    for p in cands:
        if p.is_file() and 100_000 < p.stat().st_size < 60_000_000:
            return p
    return None


# ------------------------------------------------------------------ who may connect, and how
def _member(db, sam: str, group: str) -> bool:
    """Live check in AD (nested groups too) with the scan credential for the sign-in domain. Raises when AD can't
    be asked."""
    from .collectors import ad as adc
    from .collectors.ad import domain_to_dn
    from .scanning import ad_action_cfg
    domain = (get_setting(db, "auth:ad_domain") or "").lower()
    if not domain:
        raise RuntimeError("no AD sign-in domain set (Settings > Sign-in)")
    base = domain_to_dn(domain)
    conn = adc.connect(ad_action_cfg(db, base))
    try:
        return auth._in_ad_group(conn, base, sam, group)
    finally:
        conn.unbind()


def rights(db, user: str, source: str) -> dict:
    """{'allowed': bool, 'direct': bool, 'why': str} for a signed-in user."""
    cfg = config(db)
    if not cfg["enabled"]:
        return {"allowed": False, "direct": False, "why": "Remote control is turned off (Settings > Remote control)."}
    allowed, direct, notes = True, False, []
    if cfg["allowed_group"]:
        if source != "ad":
            return {"allowed": False, "direct": False, "why": f"Only members of {cfg['allowed_group']} can use remote control, "
                                                              "and this account isn't an AD account."}
        try:
            allowed = _member(db, user, cfg["allowed_group"])
        except Exception as exc:
            log.warning("remote control: checking %s in %s failed: %s", user, cfg["allowed_group"], exc)
            return {"allowed": False, "direct": False,
                    "why": f"Couldn't check your membership of {cfg['allowed_group']} in AD ({str(exc)[:150]}), so remote control is refused."}
        if not allowed:
            return {"allowed": False, "direct": False, "why": f"Only members of {cfg['allowed_group']} can use remote control."}
    if cfg["direct_group"] and source == "ad":
        try:
            direct = _member(db, user, cfg["direct_group"])
        except Exception as exc:
            log.warning("remote control: checking %s in %s failed: %s", user, cfg["direct_group"], exc)
            notes.append(f"couldn't check {cfg['direct_group']} in AD, so the user is asked")
    return {"allowed": allowed, "direct": direct, "why": "; ".join(notes)}


# ------------------------------------------------------------------ live state (one server process)
@dataclass
class Control:
    agent_id: int
    hostname: str
    ws: WebSocket
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    user: str | None = None
    always_ask: bool = False
    disabled: bool = False
    since: float = field(default_factory=time.time)

    async def send(self, msg: dict) -> None:
        async with self.lock:
            await self.ws.send_text(json.dumps(msg))


@dataclass
class Live:
    sid: str
    hostname: str
    tech: str
    view_only: bool
    viewer_token: str
    agent_token: str
    created: float = field(default_factory=time.time)
    state: str = "asking"
    viewer: WebSocket | None = None
    vlock: asyncio.Lock = field(default_factory=asyncio.Lock)
    agent: WebSocket | None = None
    alock: asyncio.Lock = field(default_factory=asyncio.Lock)
    answered: float = 0.0
    started: float = 0.0
    last_input: float = field(default_factory=time.time)
    bytes: int = 0
    info: dict | None = None
    ended: bool = False

    async def to_viewer(self, msg: dict | bytes) -> None:
        ws = self.viewer
        if ws is None:
            return
        try:
            async with self.vlock:
                if isinstance(msg, bytes):
                    await ws.send_bytes(msg)
                else:
                    await ws.send_text(json.dumps(msg))
        except Exception:
            pass

    async def to_agent(self, msg: dict) -> None:
        ws = self.agent
        if ws is None:
            return
        try:
            async with self.alock:
                await ws.send_text(json.dumps(msg))
        except Exception:
            pass


controls: dict[str, Control] = {}     # hostname -> its agent's control connection
live: dict[str, Live] = {}            # sid -> session


def online(host: str) -> bool:
    return norm_host(host) in controls


def _audit(actor: str, action: str, host: str, result: str, ip: str | None = None) -> None:
    logs.audit(actor, action, f"computer:{host}", result[:1000], ip=ip)


def _row(db, sid: str) -> RcSession | None:
    return db.scalar(select(RcSession).where(RcSession.sid == sid))


async def end(s: Live, why: str, by: str = "server") -> None:
    """End a session everywhere (viewer, helper, the PC's service) and record it once."""
    if s.ended:
        return
    s.ended = True
    live.pop(s.sid, None)
    await s.to_viewer({"t": "status", "s": "ended", "msg": why})
    await s.to_agent({"t": "end"})
    c = controls.get(s.hostname)
    if c:
        try:
            await c.send({"t": "end", "sid": s.sid})
        except Exception:
            pass
    for ws in (s.viewer, s.agent):
        if ws is not None:
            try:
                await ws.close(code=1000)
            except Exception:
                pass

    def store():
        with SessionLocal() as db:
            r = _row(db, s.sid)
            if r:
                if r.status in ("asking", "connecting", "connected"):
                    r.status = "ended" if r.started else "failed"
                r.ended = r.ended or utcnow()
                r.end_reason = r.end_reason or why[:255]
                r.bytes_sent = s.bytes
                db.commit()
        dur = f" after {int((time.time() - s.started) // 60)} min" if s.started else ""
        _audit(s.tech, "rc.end", s.hostname, f"{why}{dur} ({s.bytes // 1024} KB sent)" if s.started else why)
    await run_in_threadpool(store)


async def watchdog() -> None:
    """Token expiry, answer and connect timeouts, the session time limit and the idle limit."""
    while True:
        await asyncio.sleep(5)
        try:
            with SessionLocal() as db:
                cfg = config(db)
            now = time.time()
            for s in list(live.values()):
                if s.state == "asking" and now - s.created > cfg["ask_seconds"] + 45:
                    await end(s, "no answer from the PC")
                elif s.state == "connecting" and now - s.answered > CONNECT_TTL:
                    await end(s, "the PC didn't start the session")
                elif s.state == "connected" and now - s.started > cfg["max_hours"] * 3600:
                    await end(s, f"time limit ({cfg['max_hours']} h)")
                elif s.state == "connected" and now - s.last_input > cfg["idle_minutes"] * 60:
                    await end(s, f"no input for {cfg['idle_minutes']} min")
                elif s.viewer is None and now - s.created > TOKEN_TTL:
                    await end(s, "the viewer never opened")
        except Exception:
            log.exception("remote control watchdog")


_watch: asyncio.Task | None = None


def _ensure_watchdog() -> None:
    global _watch
    if _watch is None or _watch.done():
        _watch = asyncio.get_running_loop().create_task(watchdog())


# ------------------------------------------------------------------ PC agent: enrollment and control connection
class EnrollIn(BaseModel):
    token: str
    hostname: str
    fqdn: str | None = None
    machine_guid: str | None = None
    version: str | None = None


def _throttle(ip: str) -> None:
    now = time.time()
    recent = [t for t in _fails.get(ip, []) if now - t < 600]
    _fails[ip] = recent
    if len(recent) >= 20:
        raise HTTPException(429, "too many failed enrollments from this address; try again later")


@router.post("/api/rc/agent/enroll")
def enroll(body: EnrollIn, request: Request):
    from . import agentpush
    ip = request.client.host if request.client else "?"
    _throttle(ip)
    host = norm_host(body.hostname)
    if not host or len(host) > 64 or not re.match(r"^[A-Z0-9][A-Z0-9\-_]*$", host):
        raise HTTPException(400, "bad hostname")
    with SessionLocal() as db:
        pushed = agentpush.use_ticket(db, host, body.token, kind="rc")
        want = get_setting(db, "rc:token_hash", None)
        if not pushed and (not want or not hmac.compare_digest(token_hash(body.token), want)):
            _fails.setdefault(ip, []).append(time.time())
            db.rollback()
            raise HTTPException(403, "enrollment token not accepted (wrong, rotated, already used or turned off)")
        guid = (body.machine_guid or "")[:64] or None
        others = list(db.scalars(select(RcAgent).where(RcAgent.hostname == host, RcAgent.status != "revoked")))
        status, note = "active", None
        same = [a for a in others if guid and a.machine_guid == guid]
        for a in same:          # the same PC enrolling again (reinstalled): its old secret stops working
            a.status, a.note = "revoked", "replaced by a new enrollment of the same PC"
        if same and not pushed and not all(a.status == "active" for a in same):
            status = "pending"
        others = [a for a in others if a not in same]
        if others:
            status, note = "pending", "another remote control agent already uses this computer name"
        elif pushed:
            status = "active"
        else:
            mode = config(db)["approve"]
            known_ad = db.scalar(select(Device.id).where(Device.hostname == host, Device.ad_dn.is_not(None)))
            if mode == "manual" or (mode == "ad" and not known_ad):
                status, note = "pending", "not in Active Directory" if mode == "ad" else "approval required"
        secret = pysecrets.token_bytes(32)
        a = RcAgent(agent_id=str(uuid.uuid4()), hostname=host, fqdn=(body.fqdn or "")[:255] or None, machine_guid=guid,
                    secret_enc=encrypt(base64.b64encode(secret).decode()), status=status, note=note, enrolled=utcnow(),
                    last_seen=utcnow(), last_ip=ip, version=(body.version or "")[:32] or None)
        db.add(a)
        db.add(AuditLog(actor=f"rcagent:{host}", action="rc.agent.enroll", target=f"computer:{host}",
                        result=f"{status} from {ip}" + (" (pushed)" if pushed else "") + (f": {note}" if note else ""), ip=ip))
        db.commit()
        return {"agent_id": a.agent_id, "secret": base64.b64encode(secret).decode(), "status": status, "note": note}


async def _deny(ws: WebSocket, code: int, msg: str) -> None:
    """Refuse a WebSocket before accepting it: an HTTP error the agent can log."""
    from starlette.responses import JSONResponse
    try:
        await ws.send_denial_response(JSONResponse({"detail": msg}, status_code=code))
    except Exception:
        await ws.close(code=1008)


@router.websocket("/api/rc/agent/control")
async def agent_control(ws: WebSocket):
    from .agentapi import check_sig
    ip = ws.client.host if ws.client else None
    h = ws.headers
    aid = h.get("x-agent-id", "")
    try:
        def lookup():
            with SessionLocal() as db:
                a = db.scalar(select(RcAgent).where(RcAgent.agent_id == aid)) if aid else None
                if a is None:
                    raise HTTPException(401, "unknown agent")
                if a.status == "revoked":
                    raise HTTPException(401, "agent revoked")
                key = base64.b64decode(decrypt(a.secret_enc))
                check_sig(key, h.get("x-agent-ts", ""), h.get("x-agent-nonce", ""), "/api/rc/agent/control", b"", h.get("x-agent-sig", ""))
                a.last_seen, a.last_ip, a.version = utcnow(), ip, (h.get("x-agent-version") or a.version or "")[:32] or None
                db.commit()
                if a.status != "active":
                    raise HTTPException(403, f"waiting for approval in NetInventory (Settings > Remote control): {a.note or ''}")
                return a.id, a.hostname
        agent_db_id, host = await run_in_threadpool(lookup)
    except HTTPException as exc:
        await _deny(ws, exc.status_code, exc.detail)
        return
    await ws.accept()
    _ensure_watchdog()
    c = Control(agent_db_id, host, ws)
    old = controls.get(host)
    controls[host] = c
    if old:
        try:
            await old.ws.close(code=1000)
        except Exception:
            pass
    try:
        while True:
            raw = await ws.receive_text()
            if len(raw) > 8192:
                continue
            try:
                m = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(m, dict):
                continue
            t = m.get("t")
            if t == "hello":
                c.user = str(m.get("user") or "")[:128] or None
                c.always_ask, c.disabled = bool(m.get("always_ask")), bool(m.get("disabled"))

                def hello():
                    with SessionLocal() as db:
                        a = db.get(RcAgent, agent_db_id)
                        if a:
                            a.console_user, a.always_ask, a.disabled = c.user, c.always_ask, c.disabled
                            a.version = str(m.get("version") or a.version or "")[:32] or None
                            db.commit()
                await run_in_threadpool(hello)
            elif t in ("consent", "ended"):
                s = live.get(str(m.get("sid") or ""))
                if s is None or s.hostname != host:
                    continue
                if t == "ended":
                    await end(s, str(m.get("why") or "ended on the PC")[:200], by="pc")
                else:
                    await _consent(s, str(m.get("result") or ""), str(m.get("user") or "")[:128], str(m.get("detail") or "")[:200])
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        if controls.get(host) is c:
            controls.pop(host, None)
            for s in list(live.values()):
                if s.hostname == host and s.state != "connected":
                    await end(s, "the PC went offline")

        def seen():
            with SessionLocal() as db:
                a = db.get(RcAgent, agent_db_id)
                if a:
                    a.last_seen = utcnow()
                    db.commit()
        await run_in_threadpool(seen)


async def _consent(s: Live, result: str, user: str, detail: str) -> None:
    if s.state != "asking" or result not in ALLOWED_RESULTS:
        return
    ok = result in ("accepted", "direct", "nouser-allowed")
    text = ALLOWED_RESULTS[result].format(u=user or "the user")
    s.answered = time.time()
    s.state = "connecting" if ok else "denied"     # now: the PC's helper connects right after its answer

    def store():
        with SessionLocal() as db:
            r = _row(db, s.sid)
            if r:
                r.consent, r.pc_user = result, user or None
                if r.status == "asking":
                    r.status = "connecting" if ok else "denied"
                if not ok:
                    r.ended, r.end_reason = utcnow(), (text + (f": {detail}" if detail and result == "error" else ""))[:255]
                db.commit()
        _audit(s.tech, "rc.consent" if ok else "rc.denied", s.hostname, text + (f" ({detail})" if detail else ""))
    await run_in_threadpool(store)
    if ok:
        if s.agent is None and not s.ended:
            await s.to_viewer({"t": "status", "s": "connecting", "msg": f"{text[0].upper()}{text[1:]}. Starting the session…"})
    else:
        s.ended = True
        live.pop(s.sid, None)
        await s.to_viewer({"t": "status", "s": "denied", "msg": text[0].upper() + text[1:] + (f": {detail}" if detail and result == "error" else ".")})
        if s.viewer is not None:
            try:
                await s.viewer.close(code=1000)
            except Exception:
                pass


@router.websocket("/api/rc/agent/stream")
async def agent_stream(ws: WebSocket):
    """The helper on the PC, for one session: screen out, input in."""
    sid, tok = ws.headers.get("x-rc-session", ""), ws.headers.get("x-rc-token", "")
    s = live.get(sid) if SID_RE.match(sid) else None
    c = controls.get(s.hostname) if s else None
    if (s is None or s.state != "connecting" or not s.agent_token or not tok or c is None
            or not hmac.compare_digest(s.agent_token, tok)):
        await _deny(ws, 403, "no such session, or its token was used or expired")
        return
    s.agent_token = ""               # one use
    await ws.accept()
    s.agent, s.state, s.started, s.last_input = ws, "connected", time.time(), time.time()

    def store():
        with SessionLocal() as db:
            r = _row(db, sid)
            if r:
                r.status, r.started = "connected", utcnow()
                db.commit()
        _audit(s.tech, "rc.start", s.hostname, "session started" + (" (view only)" if s.view_only else ""))
    await run_in_threadpool(store)
    await s.to_viewer({"t": "status", "s": "connected", "msg": "Connected."})
    why = "the PC closed the connection"
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            if msg.get("bytes") is not None:
                b = msg["bytes"]
                if len(b) > MAX_FRAME or b[:1] != b"F":
                    continue
                s.bytes += len(b)
                await s.to_viewer(b)
            elif msg.get("text"):
                try:
                    m = json.loads(msg["text"][:65536])
                except ValueError:
                    continue
                if not isinstance(m, dict):
                    continue
                if m.get("t") == "info":
                    mons = [{k: int(x.get(k) or 0) for k in ("x", "y", "w", "h")} | {"primary": bool(x.get("primary"))}
                            for x in (m.get("mons") or [])[:16] if isinstance(x, dict)]
                    s.info = {"t": "info", "mons": mons, "mon": int(m.get("mon") or 0), "desk": str(m.get("desk") or "")[:32]}
                    await s.to_viewer(s.info)
                elif m.get("t") == "bye":
                    why = str(m.get("why") or "ended at the PC")[:200]
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        s.agent = None
        await end(s, why, by="pc")


# ------------------------------------------------------------------ dashboard: start, view, end, history
def _session_of(conn) -> auth.Session | None:
    s = auth.session_user(conn.cookies.get(auth.COOKIE))
    if s:
        return s
    if not auth.auth_required():
        return auth.Session(user="admin", source="local", created=time.time(), seen=time.time())
    return None


class StartIn(BaseModel):
    hostname: str
    reason: str | None = None
    view_only: bool = False


@router.post("/api/rc/sessions")
async def start(body: StartIn, request: Request):
    """Ask a PC for a session. Returns the session id and the viewer's one-time token."""
    who = _session_of(request)
    if who is None:
        raise HTTPException(401, "Sign in required (remote control needs a dashboard sign-in, not basic auth)")
    _ensure_watchdog()
    host = norm_host(body.hostname)
    now = time.time()
    recent = [t for t in _starts.get(who.user, []) if now - t < 60]
    if len(recent) >= 10:
        raise HTTPException(429, "Too many remote control requests; wait a minute.")
    _starts[who.user] = recent + [now]
    reason = " ".join((body.reason or "").split())[:200]
    ip = request.client.host if request.client else None

    def check():
        with SessionLocal() as db:
            cfg = config(db)
            if cfg["require_reason"] and not reason:
                raise HTTPException(400, "Enter a reason: it's shown to the user and kept in the log.")
            r = rights(db, who.user, who.source)
            if not r["allowed"]:
                _audit(who.user, "rc.refused", host or "?", r["why"], ip)
                raise HTTPException(403, r["why"])
            return cfg, r
    cfg, r = await run_in_threadpool(check)
    c = controls.get(host or "")
    if c is None:
        raise HTTPException(409, f"{host}'s remote control agent isn't connected. Install it (Push remote control agent) "
                                 "or check that the PC is on.")
    if c.disabled:
        raise HTTPException(409, f"Remote control is turned off on {host} by its own policy.")
    if any(x.hostname == host for x in live.values()):
        raise HTTPException(409, f"A remote control session to {host} is already open or being asked for.")
    direct = r["direct"] and not c.always_ask
    s = Live(sid=pysecrets.token_urlsafe(24), hostname=host, tech=who.user, view_only=body.view_only,
             viewer_token=pysecrets.token_urlsafe(32), agent_token=pysecrets.token_urlsafe(32))

    def store():
        with SessionLocal() as db:
            db.add(RcSession(sid=s.sid, hostname=host, tech=who.user, tech_ip=ip, reason=reason or None, direct=direct,
                             view_only=body.view_only, status="asking"))
            db.commit()
        how = "without asking (allowed group)" if direct else "asking the user at the PC"
        if r["direct"] and c.always_ask:
            how = "asking the user (the PC's policy always asks)"
        _audit(who.user, "rc.request", host, how + (" · view only" if body.view_only else "") + (f" · reason: {reason}" if reason else "")
               + (f" · {r['why']}" if r["why"] else ""), ip)
    await run_in_threadpool(store)
    live[s.sid] = s
    try:
        await c.send({"t": "session", "sid": s.sid, "tech": who.user, "ask": not direct, "wait": cfg["ask_seconds"],
                      "nouser": cfg["nouser"], "token": s.agent_token, "reason": reason})
    except Exception:
        await end(s, "couldn't reach the PC's agent")
        raise HTTPException(409, f"Couldn't reach {host}'s remote control agent.")
    return {"sid": s.sid, "token": s.viewer_token, "direct": direct, "ask_seconds": cfg["ask_seconds"], "hostname": host,
            "pc_user": c.user}


def _same_origin(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin")
    host = ws.headers.get("host")
    return bool(origin and host and urlparse(origin).netloc.lower() == host.lower())


def clean_input(m) -> dict | None:
    """What a viewer may send to the PC, re-built from checked values (anything else is dropped)."""
    if not isinstance(m, dict):
        return None
    t = m.get("t")
    num = lambda k, lo, hi: (lambda v: v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else None)(m.get(k))  # noqa: E731
    if t == "mm" or t in ("md", "mu"):
        x, y = num("x", 0, 32767), num("y", 0, 32767)
        if x is None or y is None:
            return None
        if t == "mm":
            return {"t": t, "x": x, "y": y}
        b = num("b", 0, 2)
        return None if b is None else {"t": t, "x": x, "y": y, "b": b}
    if t == "wh":
        dx, dy = num("dx", -1200, 1200) or 0, num("dy", -1200, 1200) or 0
        return {"t": t, "dx": dx, "dy": dy} if dx or dy else None
    if t in ("kd", "ku"):
        c = m.get("c")
        return {"t": t, "c": c} if isinstance(c, str) and CODE_RE.match(c) else None
    if t == "mon":
        i = num("i", 0, 15)
        return None if i is None else {"t": t, "i": i}
    if t == "q":
        v = num("v", 20, 95)
        return None if v is None else {"t": t, "v": v}
    if t in ("ack", "full", "rel", "cad", "end"):
        return {"t": t}
    return None


INPUT_TYPES = {"mm", "md", "mu", "wh", "kd", "ku", "cad"}


@router.websocket("/api/rc/view/{sid}")
async def view(ws: WebSocket, sid: str):
    who = _session_of(ws)
    s = live.get(sid) if SID_RE.match(sid) else None
    tok = ws.query_params.get("t", "")
    if who is None or not _same_origin(ws):
        await _deny(ws, 403, "sign in to NetInventory first")
        return
    if (s is None or s.viewer is not None or not s.viewer_token or not tok or s.tech != who.user
            or not hmac.compare_digest(s.viewer_token, tok) or time.time() - s.created > TOKEN_TTL):
        await _deny(ws, 403, "no such session, or its link was used or expired")
        return
    s.viewer_token = ""              # one use
    await ws.accept()
    s.viewer = ws
    if s.state == "asking":
        await s.to_viewer({"t": "status", "s": "asking", "msg": "Waiting for the user at the PC to accept…"})
    elif s.state == "connecting":
        await s.to_viewer({"t": "status", "s": "connecting", "msg": "Starting the session…"})
    elif s.state == "connected":
        await s.to_viewer({"t": "status", "s": "connected", "msg": "Connected."})
        if s.info:
            await s.to_viewer(s.info)
    window, count = time.time(), 0
    why = "closed by the technician"
    try:
        while True:
            raw = await ws.receive_text()
            now = time.time()
            if now - window >= 1:
                window, count = now, 0
            count += 1
            if count > INPUT_RATE or len(raw) > 512:
                continue
            try:
                m = clean_input(json.loads(raw))
            except ValueError:
                continue
            if m is None:
                continue
            if m["t"] == "end":
                why = "ended by the technician"
                break
            if m["t"] in INPUT_TYPES:
                if s.view_only:
                    continue
                s.last_input = now
            if m["t"] == "cad":
                c = controls.get(s.hostname)
                if c and s.state == "connected":
                    await c.send({"t": "cad", "sid": s.sid})
                    logs.audit(s.tech, "rc.cad", f"computer:{s.hostname}", "Ctrl+Alt+Del sent")
                continue
            if s.state == "connected":
                await s.to_agent(m)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        s.viewer = None
        await end(s, why, by="tech")


def _t(v):
    from .jobs import _local
    return _local(v).isoformat(sep=" ", timespec="seconds") if v else None


def session_out(r: RcSession) -> dict:
    dur = int(((r.ended or utcnow()) - r.started).total_seconds()) if r.started else None
    return {"sid": r.sid[:8], "hostname": r.hostname, "tech": r.tech, "tech_ip": r.tech_ip, "reason": r.reason, "direct": r.direct,
            "view_only": r.view_only, "status": r.status, "consent": r.consent, "pc_user": r.pc_user, "created": _t(r.created),
            "started": _t(r.started), "ended": _t(r.ended), "end_reason": r.end_reason, "minutes": round(dur / 60, 1) if dur is not None else None,
            "kb": (r.bytes_sent or 0) // 1024, "live": r.sid in live}


def history(db, host: str | None = None, limit: int = 200) -> list[dict]:
    q = select(RcSession)
    if host:
        q = q.where(RcSession.hostname == norm_host(host))
    return [session_out(r) for r in db.scalars(q.order_by(RcSession.created.desc()).limit(min(limit, 2000)))]


@router.post("/api/rc/sessions/{sid}/end")
async def end_session(sid: str, request: Request):
    """Any signed-in user can end any live session (sid: the full id, or the 8-character prefix shown in the list)."""
    who = _session_of(request)
    if who is None:
        raise HTTPException(401, "Sign in required")
    s = live.get(sid) or next((x for x in live.values() if len(sid) >= 8 and x.sid.startswith(sid)), None)
    if s is None:
        raise HTTPException(404, "That session isn't open.")
    await end(s, f"ended by {who.user} from the dashboard" if who.user != s.tech else "ended by the technician", by="tech")
    return {"ok": True}


def agent_out(a: RcAgent) -> dict:
    return {"id": a.id, "hostname": a.hostname, "status": a.status, "note": a.note, "enrolled": _t(a.enrolled),
            "last_seen": _t(a.last_seen), "last_ip": a.last_ip, "version": a.version, "online": controls.get(a.hostname) is not None
            and controls[a.hostname].agent_id == a.id, "user": a.console_user, "always_ask": a.always_ask, "disabled": a.disabled}


def status_for(db, host: str) -> dict:
    """What the PC page shows next to the Remote control button."""
    host = norm_host(host)
    a = db.scalars(select(RcAgent).where(RcAgent.hostname == host, RcAgent.status != "revoked").order_by(RcAgent.enrolled.desc())).first()
    c = controls.get(host)
    return {"installed": a is not None, "status": a.status if a else None, "online": c is not None,
            "user": c.user if c else (a.console_user if a else None), "always_ask": bool(c.always_ask if c else (a and a.always_ask)),
            "disabled": bool(c.disabled if c else (a and a.disabled)), "version": a.version if a else None,
            "live": [session_out(r) for r in db.scalars(select(RcSession).where(RcSession.hostname == host,
                                                                                RcSession.sid.in_(list(live) or [""])))]}


# ------------------------------------------------------------------ push from the dashboard (fixes.py: rc_install / rc_remove)
INSTALL = r"""
$ErrorActionPreference = 'Stop'
$res = @{ ok = $false; stage = 'install' }
$dir = Join-Path $env:ProgramData 'NetInventory\fix'
$self = Join-Path $dir '__NAME__.ps1'
$logf = Join-Path $env:ProgramData 'NetInventory Remote\agent.log'
try {
  $t0 = (Get-Date).ToUniversalTime()
  $msi = Join-Path $dir 'NetInventory-Remote.msi'
  $mlog = Join-Path $dir 'rc-install.log'
  [IO.File]::WriteAllBytes($msi, [Convert]::FromBase64String('__BITS__'))
  $sig = Get-AuthenticodeSignature -LiteralPath $msi
  $res.signature = "$($sig.Status)"
  $a = "/i `"$msi`" /qn /norestart /l*v `"$mlog`" SERVER=__SERVER__ TOKEN=__TOKEN__ PIN=__PIN__"
  $p = Start-Process msiexec.exe -ArgumentList $a -Wait -PassThru
  $res.exit = $p.ExitCode
  Remove-Item $msi -ErrorAction SilentlyContinue
  if ($p.ExitCode -notin 0, 3010, 1641) {
    $why = switch ($p.ExitCode) { 1618 { 'another installation is running; it is tried again later' } 1603 { 'the installation failed (1603)' } 1638 { 'a newer remote control agent is already installed' } default { "msiexec exit code $($p.ExitCode)" } }
    $tail = (Get-Content $mlog -ErrorAction SilentlyContinue | Select-String 'error|failed|return value 3' | Select-Object -Last 6 | ForEach-Object { "$_".Trim() }) -join "`n"
    throw ("MSI: $why" + $(if ($tail) { "`n$tail" } else { '' }))
  }
  Remove-Item $mlog -ErrorAction SilentlyContinue
  # Wait for the service to enroll and connect: success means the PC reached this server.
  $res.stage = 'first connection'
  $deadline = (Get-Date).AddSeconds(90)
  $lines = @()
  do {
    Start-Sleep -Seconds 3
    $lines = @(Get-Content $logf -ErrorAction SilentlyContinue | Where-Object {
      $_ -match '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ) (.*)$' -and [datetime]::ParseExact($Matches[1], "yyyy-MM-dd HH:mm:ss'Z'", $null).AddSeconds(5) -ge $t0 } |
      ForEach-Object { ($_ -split ' ', 3)[2] })
  } while (-not ($lines | Where-Object { $_ -like 'connected to *' -or $_ -like 'error: *' }) -and (Get-Date) -lt $deadline)
  $res.log = ($lines | Select-Object -Last 6) -join "`n"
  if ($lines | Where-Object { $_ -like 'connected to *' }) { $res.ok = $true; $res.message = 'Installed and connected' }
  else {
    $err = ($lines | Where-Object { $_ -like 'error: *' } | Select-Object -Last 1)
    $res.message = "Installed, but it couldn't connect to the server: " + $(if ($err) { $err.Substring(7) } else { 'no answer within 90 seconds' })
  }
} catch { $res.message = "$_" }
Remove-Item $self -ErrorAction SilentlyContinue
$res
"""

REMOVE = r"""
$ErrorActionPreference = 'Stop'
$res = @{ ok = $false }
try {
  $k = $null
  foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
    $k = Get-ChildItem $root -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -eq 'NetInventory Remote' } | Select-Object -First 1
    if ($k) { break } }
  if ($k) {
    $p = Start-Process msiexec.exe -ArgumentList "/x $($k.PSChildName) /qn /norestart" -Wait -PassThru
    $res.exit = $p.ExitCode
    if ($p.ExitCode -notin 0, 3010, 1641, 1605) { throw "msiexec exit code $($p.ExitCode)" }
    $res.message = 'Remote control agent uninstalled'
  } else { $res.message = 'The remote control agent was not installed' }
  $res.ok = $true
} catch { $res.message = "$_" }
$res
"""


def install_script(db, host: str, task: str) -> str:
    from . import agentpush
    url = agentpush.check_url(agentpush.server_url(db))
    if not get_setting(db, "agent:server_url", None):
        raise ValueError("Set the server address for agents first (Push remote control agent dialog).")
    fp = agentpush.pin()
    if not fp:
        raise ValueError("This server isn't on HTTPS: the remote control agent only talks HTTPS with a pinned certificate.")
    p = msi_path()
    if not p:
        raise ValueError("This server has no NetInventory-Remote.msi (agent-msi folder); update the server.")
    tok = agentpush.new_ticket(db, host, kind="rc")
    return (INSTALL.replace("__NAME__", task).replace("__SERVER__", url).replace("__TOKEN__", tok).replace("__PIN__", fp)
            .replace("__BITS__", base64.b64encode(p.read_bytes()).decode()))


def after_remove(db, host: str, who: str) -> None:
    for a in db.scalars(select(RcAgent).where(RcAgent.hostname == norm_host(host), RcAgent.status != "revoked")):
        a.status, a.note = "revoked", f"removed by {who}"


async def close_control(host: str) -> None:
    """Drop a PC's control connection (its agent was revoked or deleted), ending its sessions."""
    host = norm_host(host)
    for s in [x for x in live.values() if x.hostname == host]:
        await end(s, "the PC's remote control agent was revoked")
    c = controls.pop(host, None)
    if c:
        try:
            await c.ws.close(code=1008)
        except Exception:
            pass
