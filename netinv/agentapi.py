"""Server side of the optional NetInventory Agent (agent/NetInventoryAgent.ps1).

Enrollment: the agent sends the site enrollment token (Settings > Agent), or a one-time ticket from a push from the
dashboard (agentpush.py), once and gets its own random secret.
The token is stored only as a SHA-256 hash; each agent's secret is stored encrypted (secrets.py).
Who gets in on their own (Settings): PCs already known from Active Directory (default), every PC, or nobody
(an admin approves each). A second agent for a hostname that already has one, or a PC whose agent was revoked,
always waits for approval, so a stolen token can't take over an existing PC's identity.

Every later request is signed: HMAC-SHA256(secret, "<unix time>\\n<nonce>\\n<path>\\n<sha256 hex of the body>"),
checked within 5 minutes, and each nonce is accepted once. An agent only ever reports for its own enrolled hostname.
The server never sends code to run: the heartbeat answer is only "inventory due: yes/no".
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets as pysecrets
import threading
import time
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from .db import Agent, AuditLog, Device, SessionLocal, get_setting, norm_host, set_setting, utcnow
from .secrets import decrypt, encrypt

router = APIRouter()
SKEW = 300
_nonces: dict[str, float] = {}
_nlock = threading.Lock()
_fails: dict[str, list[float]] = {}
APPROVE = ("ad", "all", "manual")


def _db():
    with SessionLocal() as db:
        yield db


def token_hash(token: str) -> str:
    return hashlib.sha256(token.strip().encode()).hexdigest()


def new_token(db) -> str:
    tok = "nia_" + pysecrets.token_urlsafe(24)
    set_setting(db, "agent:token_hash", token_hash(tok))
    set_setting(db, "agent:token_created", utcnow().isoformat(sep=" ", timespec="minutes"))
    set_setting(db, "agent:token_hint", tok[-4:])
    return tok


def approve_mode(db) -> str:
    m = get_setting(db, "agent:approve", None) or "ad"
    return m if m in APPROVE else "ad"


def inventory_hours(db) -> int:
    try:
        return max(1, min(24 * 14, int(get_setting(db, "agent:inventory_hours", None) or 24)))
    except ValueError:
        return 24


def _throttle(ip: str) -> None:
    now = time.time()
    recent = [t for t in _fails.get(ip, []) if now - t < 600]
    _fails[ip] = recent
    if len(recent) >= 20:
        raise HTTPException(429, "too many failed enrollments from this address; try again later")


# ------------------------------------------------------------------ agent endpoints
class EnrollIn(BaseModel):
    token: str
    hostname: str
    fqdn: str | None = None
    machine_guid: str | None = None
    version: str | None = None
    run_as: str | None = None


@router.post("/api/agent/enroll")
def enroll(body: EnrollIn, request: Request, db=Depends(_db)):
    ip = request.client.host if request.client else "?"
    _throttle(ip)
    host = norm_host(body.hostname)
    if not host or len(host) > 64:
        raise HTTPException(400, "bad hostname")
    from . import agentpush
    pushed = agentpush.use_ticket(db, host, body.token)      # one-time ticket from a push from the dashboard
    want = get_setting(db, "agent:token_hash", None)
    if not pushed and (not want or not hmac.compare_digest(token_hash(body.token), want)):
        _fails.setdefault(ip, []).append(time.time())
        db.rollback()
        raise HTTPException(403, "enrollment token not accepted (wrong, rotated, already used or turned off)")
    guid = (body.machine_guid or "")[:64] or None
    others = list(db.scalars(select(Agent).where(Agent.hostname == host, Agent.status != "revoked")))
    revoked = db.scalar(select(Agent).where(Agent.hostname == host, Agent.status == "revoked"))
    status, note = "active", None
    same = [a for a in others if guid and a.machine_guid == guid]
    if same:                      # the same PC enrolling again (reinstalled agent): replace its old secret
        for a in same:
            a.status, a.note = "revoked", "replaced by a new enrollment of the same PC"
        others = [a for a in others if a not in same]
        status = "active" if all(a.status == "active" for a in same) else "pending"
    if others:
        status, note = "pending", "another agent already reports as this computer"
    elif pushed:
        status, note = "active", None        # an admin pushed it to this PC: approved, even if it was revoked before
    elif revoked and not same:
        status, note = "pending", "this computer's agent was revoked before"
    elif status == "active":
        mode = approve_mode(db)
        known_ad = db.scalar(select(Device.id).where(Device.hostname == host, Device.ad_dn.is_not(None)))
        if mode == "manual" or (mode == "ad" and not known_ad):
            status, note = "pending", "not in Active Directory" if mode == "ad" else "approval required"
    secret = pysecrets.token_bytes(32)
    import base64
    a = Agent(agent_id=str(uuid.uuid4()), hostname=host, fqdn=(body.fqdn or "")[:255] or None, machine_guid=guid,
              secret_enc=encrypt(base64.b64encode(secret).decode()), status=status, note=note, enrolled=utcnow(),
              last_seen=utcnow(), last_ip=ip, version=(body.version or "")[:16] or None, run_as=(body.run_as or "")[:64] or None,
              want_inventory=True)
    db.add(a)
    agentpush.settle(db, host, "enrolled" + (" by the push" if pushed else ", installed by hand or GPO") +
                     ("" if status == "active" else f"; waiting for approval in Settings > Agent: {note}"))
    db.add(AuditLog(actor=f"agent:{host}", action="agent.enroll", target=f"computer:{host}", result=f"{status} from {ip}" + (" (pushed)" if pushed else "")))
    db.commit()
    return {"agent_id": a.agent_id, "secret": base64.b64encode(secret).decode(), "status": status, "note": note}


async def signed(request: Request) -> tuple[str, bytes]:
    """Checks the signature; returns (agent_id, body)."""
    body = await request.body()
    aid = request.headers.get("x-agent-id", "")
    ts, nonce, sig = (request.headers.get(h, "") for h in ("x-agent-ts", "x-agent-nonce", "x-agent-sig"))
    if not (aid and ts.isdigit() and 16 <= len(nonce) <= 64 and len(sig) == 64):
        raise HTTPException(401, "unsigned request")
    if abs(time.time() - int(ts)) > SKEW:
        raise HTTPException(401, "clock skew: the PC's clock is more than 5 minutes off")
    with SessionLocal() as db:
        a = db.scalar(select(Agent).where(Agent.agent_id == aid))
        if a is None:
            raise HTTPException(401, "unknown agent")
        if a.status == "revoked":
            raise HTTPException(401, "agent revoked")
        import base64
        key = base64.b64decode(decrypt(a.secret_enc))
    msg = f"{ts}\n{nonce}\n{request.url.path}\n{hashlib.sha256(body).hexdigest()}".encode()
    if not hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).hexdigest(), sig.lower()):
        raise HTTPException(401, "bad signature")
    now = time.time()
    with _nlock:
        if nonce in _nonces:
            raise HTTPException(401, "replayed request")
        _nonces[nonce] = now
        if len(_nonces) > 50000:
            for k in [k for k, v in _nonces.items() if now - v > 2 * SKEW]:
                _nonces.pop(k, None)
    return aid, body


def _agent(db, aid: str, request: Request) -> Agent:
    a = db.scalar(select(Agent).where(Agent.agent_id == aid))
    a.last_seen, a.last_ip = utcnow(), (request.client.host if request.client else None)
    if a.status == "pending":
        db.commit()
        raise HTTPException(403, f"waiting for approval in NetInventory (Settings > Agent): {a.note or ''}")
    return a


class HeartbeatIn(BaseModel):
    hostname: str | None = None
    last_boot: str | None = None
    current_user: str | None = None
    ips: list[str] = []
    version: str | None = None


@router.post("/api/agent/heartbeat")
async def heartbeat(request: Request, auth=Depends(signed)):
    from datetime import datetime
    from .ingest import _naive, get_or_create_device
    from .reach import mark
    aid, raw = auth
    hb = HeartbeatIn.model_validate_json(raw or b"{}")
    with SessionLocal() as db:
        a = _agent(db, aid, request)
        a.version = (hb.version or a.version or "")[:16] or None
        dev = get_or_create_device(db, a.hostname)
        mark(dev, True, "agent")
        if hb.last_boot:
            try:
                dev.last_boot = _naive(datetime.fromisoformat(hb.last_boot.replace("Z", "+00:00")))
            except ValueError:
                pass
        if hb.current_user is not None:
            dev.current_user = hb.current_user[:128] or None
        if a.status == "active":
            from . import agentpush
            agentpush.settle(db, a.hostname, "heartbeat")
        due = a.want_inventory or not a.last_inventory or a.last_inventory < utcnow() - timedelta(hours=inventory_hours(db))
        db.commit()
        return {"ok": True, "inventory": bool(due), "status": a.status}


@router.post("/api/agent/inventory")
async def inventory(request: Request, auth=Depends(signed)):
    from .ingest import EndpointPayload, apply_endpoint
    from .reach import mark
    aid, raw = auth
    try:
        p = EndpointPayload.model_validate(json.loads(raw.decode("utf-8-sig")))
    except Exception as exc:
        raise HTTPException(400, f"bad inventory: {str(exc)[:300]}")
    from starlette.concurrency import run_in_threadpool
    ip = request.client.host if request.client else None

    def store():
        with SessionLocal() as db:
            a = db.scalar(select(Agent).where(Agent.agent_id == aid))
            a.last_seen, a.last_ip = utcnow(), ip
            if a.status == "pending":
                db.commit()
                raise HTTPException(403, f"waiting for approval in NetInventory (Settings > Agent): {a.note or ''}")
            p.hostname, p.source = a.hostname, "agent"          # an agent only ever reports as itself
            p.agent_version = a.version
            dev = apply_endpoint(db, p)
            mark(dev, True, "agent")
            dev.scan_error = dev.scan_error_kind = dev.scan_error_time = None
            a.last_inventory, a.want_inventory = utcnow(), False
            db.commit()
        from .scanning import _reconcile
        with SessionLocal() as db:
            _reconcile(db)
    await run_in_threadpool(store)
    return {"ok": True}


def request_inventory(db, hostname: str) -> bool:
    """Rescan button: active agents of this PC send an inventory on their next heartbeat (within 5 minutes)."""
    n = 0
    for a in db.scalars(select(Agent).where(Agent.hostname == norm_host(hostname), Agent.status == "active")):
        a.want_inventory = True
        n += 1
    db.commit()
    return bool(n)


def recent_hosts(db, minutes: int) -> set[str]:
    since = utcnow() - timedelta(minutes=minutes)
    return {h for (h,) in db.execute(select(Agent.hostname).where(Agent.status == "active", Agent.last_seen >= since))}
