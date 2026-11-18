"""Audit trail and the server log, both viewable on the Logs page.

Audit log (table audit_log):
- Sign-in, failed sign-in, sign-out and session timeouts are written by main.py / auth.py.
- Endpoints that make a change write their own, descriptive entry (``AuditLog(...)``). The ``AuditMiddleware``
  below makes sure nothing slips through: every POST/PUT/PATCH/DELETE to /api/ by a signed-in user that did not
  write its own entry gets a generic one (method, path, response status and the request body with passwords,
  tokens and keys masked). Every entry made while handling a request gets the caller's IP address.

Server log (table server_log): a logging handler copies the application's log records (netinv.* at INFO and
above, anything else at WARNING and above) into the database from a background thread, so scan, collector and DC
errors can be read in the web app instead of only in the service's log files on the server. Kept 30 days.
The service's own log files (WinSW out/err logs, setup and update logs) in <data folder>/logs can be read too.
"""
from __future__ import annotations

import contextvars
import json
import logging
import queue
import re
import threading
import time
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, event, func, or_, select

from .db import AuditLog, ServerLog, SessionLocal, utcnow

SERVER_LOG_DAYS = 30
SERVER_LOG_MAX_ROWS = 200_000
_ctx: contextvars.ContextVar[dict | None] = contextvars.ContextVar("netinv_request", default=None)

# POSTs that only read or check something; they change nothing, so the generic entry would be noise.
READ_ONLY = [re.compile(p) for p in (
    r"^/api/login$", r"^/api/logout$", r"^/api/prefs/", r"^/api/query$", r"^/api/export/", r"^/api/groups/preview$",
    r"^/api/library/[^/]+/drill$", r"^/api/tls/check$", r"^/api/ingest/", r"^/api/agent/", r"^/api/logs",
)]
SECRET_KEYS = re.compile(r"pass|secret|token|key|pwd|private|pfx|pem|cert_data|api_?token", re.I)
MAX_BODY = 16_384


# ------------------------------------------------------------------ request context
def context() -> dict | None:
    return _ctx.get()


def request_ip() -> str | None:
    c = _ctx.get()
    return c.get("ip") if c else None


@event.listens_for(AuditLog, "before_insert")
def _fill_ip(mapper, connection, target: AuditLog) -> None:
    c = _ctx.get()
    if c is not None:
        c["audited"] = True
        if not target.ip:
            target.ip = c.get("ip")


def redact(v, depth: int = 0):
    """Copy of a request body with anything that looks like a password, token or key replaced by ***."""
    if depth > 6:
        return "…"
    if isinstance(v, dict):
        return {k: ("***" if SECRET_KEYS.search(str(k)) and v[k] not in (None, "") else redact(x, depth + 1)) for k, x in v.items()}
    if isinstance(v, list):
        return [redact(x, depth + 1) for x in v[:50]] + (["…"] if len(v) > 50 else [])
    if isinstance(v, str) and len(v) > 300:
        return v[:300] + "…"
    return v


def describe_body(raw: bytes, content_type: str) -> str:
    if not raw:
        return ""
    if "json" not in content_type:
        return f"({content_type.split(';')[0] or 'body'}, {len(raw)} bytes)"
    try:
        return json.dumps(redact(json.loads(raw)), default=str, ensure_ascii=False)[:1500]
    except ValueError:
        return f"({len(raw)} bytes)"


class AuditMiddleware:
    """Pure ASGI middleware: request context (IP, audited flag) plus the catch-all audit entry for changes."""

    def __init__(self, app, client_ip=None, user_for=None):
        self.app = app
        self.client_ip = client_ip        # (scope) -> str
        self.user_for = user_for          # (scope) -> str | None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path, method = scope.get("path", ""), scope.get("method", "GET")
        ip = self.client_ip(scope) if self.client_ip else ((scope.get("client") or ("?",))[0])
        ctx = {"ip": ip, "audited": False}
        token = _ctx.set(ctx)
        watch = (path.startswith("/api/") and method in ("POST", "PUT", "PATCH", "DELETE")
                 and not any(p.search(path) for p in READ_ONLY))
        body = bytearray()
        status = {"code": 0}
        ctype = dict((k.decode().lower(), v.decode("latin-1")) for k, v in scope.get("headers", [])).get("content-type", "")

        async def recv():
            msg = await receive()
            if watch and msg.get("type") == "http.request" and len(body) < MAX_BODY:
                body.extend(msg.get("body", b"")[: MAX_BODY - len(body)])
            return msg

        async def snd(msg):
            if msg.get("type") == "http.response.start":
                status["code"] = msg.get("status", 0)
                if path.startswith("/api/"):
                    hdrs = list(msg.get("headers", []))
                    if not any(k.lower() == b"cache-control" for k, _ in hdrs):
                        hdrs.append((b"cache-control", b"no-store"))   # nothing of one user's lingers in a shared browser's cache
                    msg["headers"] = hdrs
            await send(msg)

        try:
            await self.app(scope, recv, snd)
        finally:
            _ctx.reset(token)
            if watch and not ctx["audited"] and status["code"] not in (401, 404, 405):
                try:
                    user = self.user_for(scope) if self.user_for else None
                    if user:
                        _write(AuditLog(actor=user[:128], action=f"api.{method.lower()}", target=path[:255], ip=ip,
                                        result=(f"HTTP {status['code']}" + (f": {describe_body(bytes(body), ctype)}" if body else ""))))
                except Exception:
                    logging.getLogger(__name__).exception("writing the audit entry for %s %s", method, path)


def _write(row) -> None:
    with SessionLocal() as db:
        db.add(row)
        db.commit()


def audit(actor: str | None, action: str, target: str | None = None, result: str | None = None, ip: str | None = None) -> None:
    """Write one audit entry in its own transaction (for places with no request database session)."""
    _write(AuditLog(actor=(actor or "")[:128], action=action[:64], target=(target or "")[:255] or None,
                    result=result, ip=ip or request_ip()))


# ------------------------------------------------------------------ server log to the database
_q: queue.Queue = queue.Queue(maxsize=20_000)
_writer_started = False
_local = threading.local()


class DbLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        if getattr(_local, "busy", False) or record.name.startswith(("sqlalchemy", "netinv.logs")):
            return
        if record.levelno < logging.WARNING and not record.name.startswith("netinv"):
            return
        try:
            msg = record.getMessage()
            if record.exc_info:
                msg += "\n" + logging.Formatter().formatException(record.exc_info)
            _q.put_nowait((utcnow(), record.levelname, record.name[:128], msg[:8000]))
        except queue.Full:
            pass
        except Exception:
            self.handleError(record)


def _flush() -> None:
    rows = []
    while len(rows) < 1000:
        try:
            rows.append(_q.get_nowait())
        except queue.Empty:
            break
    if not rows:
        return
    _local.busy = True
    try:
        with SessionLocal() as db:
            db.add_all([ServerLog(time=t, level=lv, logger=n, message=m) for t, lv, n, m in rows])
            db.commit()
    finally:
        _local.busy = False


def prune() -> None:
    _local.busy = True
    try:
        with SessionLocal() as db:
            db.execute(delete(ServerLog).where(ServerLog.time < utcnow() - timedelta(days=SERVER_LOG_DAYS)))
            n = db.scalar(select(func.count(ServerLog.id))) or 0
            if n > SERVER_LOG_MAX_ROWS:
                cut = db.scalar(select(ServerLog.id).order_by(ServerLog.id.desc()).offset(SERVER_LOG_MAX_ROWS).limit(1))
                if cut:
                    db.execute(delete(ServerLog).where(ServerLog.id <= cut))
            db.commit()
    finally:
        _local.busy = False


def _loop(stop: threading.Event) -> None:
    last_prune = last_sweep = 0.0
    while not stop.is_set():
        stop.wait(2)
        try:
            _flush()
            if time.time() - last_sweep > 60:
                from . import auth
                auth.sweep()
                last_sweep = time.time()
            if time.time() - last_prune > 3600:
                prune()
                last_prune = time.time()
        except Exception as exc:       # never log from here: it would feed itself
            _local.busy = True
            try:
                print(f"netinv.logs: could not write the server log: {exc}")
            finally:
                _local.busy = False
    _flush()


def install(stop: threading.Event) -> None:
    """Start copying log records to the database. Call once, after init_db."""
    global _writer_started
    if _writer_started:
        return
    _writer_started = True
    h = DbLogHandler(level=logging.INFO)
    logging.getLogger().addHandler(h)
    for name in ("uvicorn", "uvicorn.error"):        # uvicorn's loggers don't reach the root logger
        lg = logging.getLogger(name)
        if not lg.propagate or name == "uvicorn":
            lg.addHandler(h)
    threading.Thread(target=_loop, args=(stop,), daemon=True, name="server-log").start()


# ------------------------------------------------------------------ queries for the Logs page
def _since(hours: int | None):
    return utcnow() - timedelta(hours=hours) if hours else None


def _like(col, text: str):
    return col.ilike(f"%{text.replace('%', '').replace('_', '')}%")


def audit_rows(db, *, hours: int | None = None, actor: str = "", action: str = "", text: str = "", ip: str = "",
               kind: str = "", limit: int = 500, offset: int = 0) -> dict:
    q = select(AuditLog)
    since = _since(hours)
    if since:
        q = q.where(AuditLog.time >= since)
    if actor:
        q = q.where(_like(AuditLog.actor, actor))
    if action:
        q = q.where(_like(AuditLog.action, action))
    if ip:
        q = q.where(or_(_like(AuditLog.ip, ip), _like(AuditLog.target, ip)))
    if text:
        q = q.where(or_(_like(AuditLog.target, text), _like(AuditLog.result, text), _like(AuditLog.action, text)))
    if kind == "signin":
        q = q.where(or_(AuditLog.action.like("login.%"), AuditLog.action.like("logout%"), AuditLog.action.like("session.%")))
    elif kind == "failed":
        q = q.where(or_(AuditLog.action == "login.failed", _like(AuditLog.result, "fail"), AuditLog.result.like("HTTP 4%"),
                        AuditLog.result.like("HTTP 5%")))
    elif kind == "changes":
        q = q.where(~AuditLog.action.like("login.%"), ~AuditLog.action.like("logout%"), ~AuditLog.action.like("session.%"))
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(AuditLog.time.desc(), AuditLog.id.desc()).offset(offset).limit(min(limit, 5000)))
    return {"total": total, "rows": [{"time": r.time, "actor": r.actor, "action": r.action, "target": r.target, "ip": r.ip,
                                      "result": r.result} for r in rows]}


LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def server_rows(db, *, hours: int | None = None, level: str = "", logger: str = "", text: str = "",
                limit: int = 500, offset: int = 0) -> dict:
    _flush()
    q = select(ServerLog)
    since = _since(hours)
    if since:
        q = q.where(ServerLog.time >= since)
    if level and level.upper() in LEVELS:
        q = q.where(ServerLog.level.in_(LEVELS[LEVELS.index(level.upper()):]))
    if logger:
        q = q.where(_like(ServerLog.logger, logger))
    if text:
        q = q.where(_like(ServerLog.message, text))
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(ServerLog.time.desc(), ServerLog.id.desc()).offset(offset).limit(min(limit, 5000)))
    return {"total": total, "rows": [{"time": r.time, "level": r.level, "logger": r.logger, "message": r.message} for r in rows]}


def loggers(db) -> list[str]:
    return [n for (n,) in db.execute(select(ServerLog.logger).distinct().order_by(ServerLog.logger)) if n]


# ------------------------------------------------------------------ log files on the server
def log_dir() -> Path:
    from .auth import data_dir
    return data_dir() / "logs"


def log_files() -> list[dict]:
    d = log_dir()
    if not d.is_dir():
        return []
    out = []
    for f in sorted(d.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if f.is_file() and (f.suffix.lower() in (".log", ".txt", ".err", ".out", ".old") or ".log" in f.name.lower()):
            st = f.stat()
            out.append({"name": f.name, "size": st.st_size, "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(st.st_mtime))})
    return out


def log_file_path(name: str) -> Path | None:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    if name not in {f["name"] for f in log_files()}:
        return None
    return log_dir() / name


def tail(path: Path, max_bytes: int = 256_000) -> str:
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
            fh.readline()
        data = fh.read()
    for enc in ("utf-8", "utf-16", "cp1252"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")
