"""FastAPI server: dashboard, reports API, report builder and ingest endpoints."""
from __future__ import annotations

import csv
import io
import json
import logging
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import bindparam, select, text

from . import __version__, actions, alerts, auth, catalog, exports, fixes, jobs, library, reports, updater
from .config import settings
from .correlate import create_views
from datetime import datetime

from .db import (AdUser, AuditLog, Credential, ScanTarget, SoftwareRule, get_setting, set_setting)
from .db import (ChangeEvent, CollectorRun, Comment, CustomField, Device, DeviceGroup, SavedReport, SessionLocal,
                 init_db, norm_host, norm_mac)
from .ingest import EndpointPayload, LogonIn, add_logons, apply_endpoint

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
STATIC = Path(__file__).parent / "static"
_stop = threading.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(settings.database_url)
    with SessionLocal() as db:
        create_views(db)
    if settings.schedule.get("enabled", True):
        threading.Thread(target=jobs.scheduler_loop, args=(_stop,), daemon=True).start()
    with SessionLocal() as db:   # a finished update leaves its "installing" note behind
        if get_setting(db, "update:message") and not updater.status(db)["available"]:
            set_setting(db, "update:message", None)
            db.commit()
    threading.Thread(target=updater.loop, args=(_stop,), daemon=True).start()
    threading.Thread(target=catalog.loop, args=(_stop,), daemon=True).start()
    threading.Thread(target=fixes.loop, args=(_stop,), daemon=True).start()
    yield
    _stop.set()


app = FastAPI(title="NetInventory", version=__version__, lifespan=lifespan)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def current_user(request: Request) -> str | None:
    """The signed-in user from the session cookie, or from HTTP basic auth (scripts, BI refreshes)."""
    s = auth.session_user(request.cookies.get(auth.COOKIE))
    if s:
        return s.user
    h = request.headers.get("authorization", "")
    if h.lower().startswith("basic "):
        import base64
        try:
            user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        except Exception:
            return None
        with SessionLocal() as db:
            try:
                sess = auth.login(db, user, pw, _client_ip(request))
            except auth.LoginError:
                return None
        auth.logout(getattr(sess, "token", None))   # basic auth is per request; keep no session
        return sess.user
    return None


def ui_auth(request: Request):
    user = current_user(request)
    if user:
        return user
    if not auth.auth_required():
        return "admin"
    raise HTTPException(401, "Sign in required")


def ingest_auth(x_ingest_token: str = Header(default="")):
    if not settings.ingest_token or not secrets.compare_digest(x_ingest_token, settings.ingest_token):
        raise HTTPException(401, "bad ingest token")


def db_session():
    with SessionLocal() as db:
        yield db


UI = [Depends(ui_auth)]


@app.get("/")
def index(request: Request):
    if not current_user(request) and auth.auth_required():
        return RedirectResponse("/login", status_code=303)
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/login")
def login_page():
    return FileResponse(STATIC / "login.html", headers={"Cache-Control": "no-store"})


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def do_login(body: LoginIn, request: Request, db=Depends(db_session)):
    ip = _client_ip(request)
    try:
        s = auth.login(db, body.username, body.password, ip)
    except auth.LoginError as exc:
        db.add(AuditLog(actor=body.username[:64], action="login.failed", target=f"ip:{ip}", result=str(exc)[:200]))
        db.commit()
        raise HTTPException(401, str(exc))
    db.add(AuditLog(actor=s.user, action=f"login.{s.source}", target=f"ip:{ip}", result="ok"))
    db.commit()
    resp = Response('{"ok": true}', media_type="application/json")
    resp.set_cookie(auth.COOKIE, s.token, httponly=True, samesite="strict", secure=request.url.scheme == "https",
                    max_age=auth.SESSION_MAX, path="/")
    return resp


@app.post("/api/logout")
def do_logout(request: Request):
    auth.logout(request.cookies.get(auth.COOKIE))
    resp = Response('{"ok": true}', media_type="application/json")
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.get("/api/me")
def me(user=Depends(ui_auth)):
    return {"user": user, "version": __version__}


# ----------------------------------------------------------------- sign-in settings (AD group, break-glass)
class AuthIn(BaseModel):
    ad_domain: str | None = None
    ad_group: str | None = None
    ad_server: str | None = None


def _auth_out(db) -> dict:
    return {"ad_domain": get_setting(db, "auth:ad_domain"), "ad_group": get_setting(db, "auth:ad_group"),
            "ad_server": get_setting(db, "auth:ad_server"), "local_user": settings.ui_user or None,
            "local_enabled": auth.local_enabled(), "local_disabled_file": str(auth.local_disabled_file()),
            "https": bool(settings.tls_cert)}


@app.get("/api/auth", dependencies=UI)
def get_auth(db=Depends(db_session)):
    return _auth_out(db)


@app.put("/api/auth")
def put_auth(body: AuthIn, actor=Depends(ui_auth), db=Depends(db_session)):
    for k in ("ad_domain", "ad_group", "ad_server"):
        v = (getattr(body, k) or "").strip() or None
        if v and not __import__("re").fullmatch(r"[A-Za-z0-9 ._=,\-]{1,255}", v):
            raise HTTPException(400, f"{k} has characters that aren't allowed")
        set_setting(db, f"auth:{k}", v)
    db.add(AuditLog(actor=actor, action="auth.save", target="sign-in",
                    result=f"domain={body.ad_domain} group={body.ad_group} server={body.ad_server}"))
    db.commit()
    return _auth_out(db)


@app.post("/api/auth/test")
def test_auth(body: LoginIn, request: Request, actor=Depends(ui_auth), db=Depends(db_session)):
    """Try an AD sign-in without signing in (and without turning off the local admin)."""
    if auth.locked_out(body.username, _client_ip(request)):
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")
    sam = auth.ad_login(db, body.username, body.password)
    if not sam:
        auth._fail(body.username, _client_ip(request))
    db.add(AuditLog(actor=actor, action="auth.test", target=f"user:{body.username[:64]}", result="ok" if sam else "refused"))
    db.commit()
    return {"ok": bool(sam), "output": f"{sam} can sign in." if sam else
            "Refused: wrong password, account disabled, not in the group, or no domain controller reachable. "
            "The server log has the reason."}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ----------------------------------------------------------------- overview
@app.get("/api/summary", dependencies=UI)
def summary(db=Depends(db_session)):
    q = lambda sql: db.execute(text(sql)).scalar()  # noqa: E731
    ins = reports.insights(db, settings.insights, settings.outdated_software)
    runs = db.scalars(select(CollectorRun).order_by(CollectorRun.started.desc()).limit(10))
    return {
        "counts": {
            "pcs": q("SELECT COUNT(*) FROM devices WHERE ad_enabled IS NOT FALSE"),
            "inventoried": q("SELECT COUNT(*) FROM devices WHERE agent_last_report IS NOT NULL"),
            "domain_controllers": q("SELECT COUNT(*) FROM domain_controllers"),
            "network_devices": q("SELECT COUNT(*) FROM network_devices"),
            "mapped_to_port": q("SELECT COUNT(DISTINCT hostname) FROM v_port_map WHERE hostname IS NOT NULL"),
            "users": q("SELECT COUNT(DISTINCT username) FROM logon_events"),
        },
        "insight_counts": {k: len(v) for k, v in ins.items()},
        "os_breakdown": [dict(r._mapping) for r in db.execute(text(
            "SELECT COALESCE(os, 'Unknown') AS os, COALESCE(os_display_version, '') AS version, COUNT(*) AS n "
            "FROM v_devices GROUP BY 1, 2 ORDER BY n DESC"))],
        "runs": [{"collector": r.collector, "started": r.started.isoformat(timespec="seconds"),
                  "ok": r.ok, "message": r.message} for r in runs],
    }


@app.get("/api/insights", dependencies=UI)
def get_insights(db=Depends(db_session)):
    return reports.insights(db, settings.insights, settings.outdated_software)


def _device(db, hostname: str) -> Device:
    dev = db.scalar(select(Device).where(Device.hostname == norm_host(hostname)))
    if dev is None:
        raise HTTPException(404, "unknown device")
    return dev


@app.get("/api/devices/{hostname}", dependencies=UI)
def device(hostname: str, db=Depends(db_session)):
    dev = _device(db, hostname)
    h = dev.hostname
    one = lambda ds, f="hostname", **kw: reports.run_query(db, ds, filters=[{"field": f, "op": "eq", "value": h}], limit=5000, **kw)["rows"]  # noqa: E731
    macs = [n.mac for n in dev.nics]
    location = []
    if macs:
        location = _rows_of(db.execute(text(
            "SELECT nd.sysname AS switch_name, sp.name AS port, sp.alias AS port_alias, ms.vlan, ms.mac, "
            "ms.first_seen, ms.last_seen FROM mac_sightings ms JOIN switch_ports sp ON sp.id = ms.port_id "
            "JOIN network_devices nd ON nd.id = sp.switch_id WHERE sp.is_uplink = :f AND ms.mac IN :macs "
            "ORDER BY ms.last_seen DESC").bindparams(bindparam("macs", expanding=True)), {"f": False, "macs": macs}))
    return {"device": one("v_devices")[0], "disks": one("v_disks"), "software": one("v_software", sort="name"),
            "updates": one("v_updates"), "users": one("v_user_devices", sort="last_logon", desc=True),
            "logons": reports.run_query(db, "v_logons", filters=[{"field": "hostname", "op": "eq", "value": h}],
                                        sort="time", desc=True, limit=300)["rows"],
            "fixes_running": fixes.running(h),
            "location": location, "nics": [{"mac": n.mac, "ip": n.ip, "description": n.description} for n in dev.nics],
            "groups": sorted(g.name for g in db.scalars(select(DeviceGroup).where(DeviceGroup.device_id == dev.id))),
            "custom_fields": {c.name: c.value for c in db.scalars(select(CustomField).where(CustomField.device_id == dev.id))},
            "comments": [{"id": c.id, "author": c.author, "text": c.text, "created": c.created.isoformat(sep=" ", timespec="minutes")}
                         for c in db.scalars(select(Comment).where(Comment.device_id == dev.id).order_by(Comment.created.desc()))],
            "history": [{"time": c.time.isoformat(sep=" ", timespec="minutes"), "kind": c.kind, "detail": c.detail}
                        for c in db.scalars(select(ChangeEvent).where(ChangeEvent.device_id == dev.id)
                                            .order_by(ChangeEvent.time.desc()).limit(500))]}


def _rows_of(result):
    return [{k: (v.isoformat(sep=" ", timespec="seconds") if isinstance(v, datetime) else v)
             for k, v in r._mapping.items()} for r in result]


class DevicePatch(BaseModel):
    purchase_date: str | None = None
    warranty_end: str | None = None
    asset_location: str | None = None
    state: str | None = None


@app.patch("/api/devices/{hostname}")
def patch_device(hostname: str, body: DevicePatch, user=Depends(ui_auth), db=Depends(db_session)):
    dev = _device(db, hostname)
    for k, v in body.model_dump(exclude_unset=True).items():
        if k in ("purchase_date", "warranty_end"):
            v = datetime.fromisoformat(v) if v else None
        if getattr(dev, k) != v:
            from .ingest import log_change
            log_change(db, dev, "edit", f"{k.replace('_', ' ')} set to {v or '(empty)'} by {user}")
            setattr(dev, k, v)
    db.commit()
    return {"ok": True}


class NameValue(BaseModel):
    name: str
    value: str | None = None


@app.post("/api/devices/{hostname}/groups", dependencies=UI)
def add_group(hostname: str, body: NameValue, db=Depends(db_session)):
    dev = _device(db, hostname)
    _add_group(db, dev, body.name)
    db.commit()
    return {"ok": True}


def _add_group(db, dev: Device, name: str) -> None:
    name = name.strip()[:128]
    if name and not db.scalar(select(DeviceGroup).where(DeviceGroup.device_id == dev.id, DeviceGroup.name == name)):
        db.add(DeviceGroup(device_id=dev.id, name=name))


@app.delete("/api/devices/{hostname}/groups/{name}", dependencies=UI)
def remove_group(hostname: str, name: str, db=Depends(db_session)):
    dev = _device(db, hostname)
    for g in db.scalars(select(DeviceGroup).where(DeviceGroup.device_id == dev.id, DeviceGroup.name == name)):
        db.delete(g)
    db.commit()
    return {"ok": True}


@app.put("/api/devices/{hostname}/fields", dependencies=UI)
def set_field(hostname: str, body: NameValue, db=Depends(db_session)):
    dev = _device(db, hostname)
    f = db.scalar(select(CustomField).where(CustomField.device_id == dev.id, CustomField.name == body.name))
    if not body.value:
        if f:
            db.delete(f)
    else:
        f = f or CustomField(device_id=dev.id, name=body.name.strip()[:128])
        f.value = body.value
        db.add(f)
    db.commit()
    return {"ok": True}


class CommentIn(BaseModel):
    text: str


@app.post("/api/devices/{hostname}/comments")
def add_comment(hostname: str, body: CommentIn, user=Depends(ui_auth), db=Depends(db_session)):
    dev = _device(db, hostname)
    if body.text.strip():
        db.add(Comment(device_id=dev.id, author=user, text=body.text.strip()[:5000]))
        db.commit()
    return {"ok": True}


@app.post("/api/devices/{hostname}/action/{action}")
def device_action(hostname: str, action: str, user=Depends(ui_auth), db=Depends(db_session)):
    dev = _device(db, hostname)
    if action == "ping":
        return actions.ping(dev)
    if action == "wol":
        return actions.wake_on_lan(dev)
    if action == "rescan":
        return actions.rescan(dev.hostname)
    if action == "reboot":
        return actions.reboot(db, dev, user)
    raise HTTPException(404)


class FixIn(BaseModel):
    action: str
    value: str | None = None


@app.post("/api/devices/{hostname}/fix")
def device_fix(hostname: str, body: FixIn, user=Depends(ui_auth), db=Depends(db_session)):
    return fixes.run(db, _device(db, hostname), body.action, user, body.value)


class BulkFixIn(BaseModel):
    action: str
    hostnames: list[str]
    value: str | None = None


@app.post("/api/fix/bulk")
def bulk_fix(body: BulkFixIn, user=Depends(ui_auth)):
    if body.action not in fixes.ACTIONS:
        raise HTTPException(400, "unknown fix")
    if len(body.hostnames) > 500:
        raise HTTPException(400, "at most 500 computers at a time")
    n = fixes.run_many(body.hostnames, body.action, user, body.value)
    return {"ok": True, "count": n, "output": f"Started on {n} computer{'s' if n != 1 else ''}. Results appear in each PC's History."}


# ------------------------------------------------------------------ app catalog
@app.get("/api/apps", dependencies=UI)
def apps(db=Depends(db_session)):
    """One row per program (name + publisher + catalog package), with how many PCs are behind."""
    raw = db.execute(text(
        "SELECT name, publisher, catalog_id, version, latest_version, sw_status, scope, match_method, "
        "COUNT(DISTINCT device_id) AS n FROM software GROUP BY 1, 2, 3, 4, 5, 6, 7, 8")).all()
    out: dict[tuple, dict] = {}
    for name, pub, cid, ver, latest, st, scope, how, n in raw:
        a = out.setdefault((name, pub, cid), {"name": name, "publisher": pub, "catalog_id": cid, "latest_version": latest,
                                              "installed": 0, "outdated": 0, "outdated_user": 0, "versions": set(),
                                              "status": st or "unknown", "match_method": how})
        a["installed"] += n
        a["versions"].add(ver or "")
        if st == "outdated":
            a["outdated"] += n
            a["status"] = "outdated"
            if scope == "user":
                a["outdated_user"] += n
        elif st == "current" and a["status"] in ("unknown", "ignored"):
            a["status"] = "current"
        if latest and catalog.vt(latest) > catalog.vt(a["latest_version"]):
            a["latest_version"] = latest
    rows = []
    for a in out.values():
        vs = sorted((v for v in a.pop("versions") if v), key=catalog.vt)
        a["oldest"], a["newest"] = (vs[0], vs[-1]) if vs else ("", "")
        rows.append(a)
    rows.sort(key=lambda a: (-a["outdated"], -a["installed"], a["name"].lower()))
    return {"apps": rows, "catalog": catalog.status_info(db)}


@app.get("/api/apps/computers", dependencies=UI)
def app_computers(name: str, status: str | None = None, db=Depends(db_session)):
    q = ("SELECT d.hostname, s.version, s.latest_version, s.sw_status AS status, s.scope, s.catalog_id "
         "FROM software s JOIN devices d ON d.id = s.device_id WHERE s.name = :n")
    if status:
        q += " AND s.sw_status = :st"
    return _rows_of(db.execute(text(q + " ORDER BY d.hostname"), {"n": name, "st": status}))


@app.get("/api/catalog", dependencies=UI)
def catalog_status(db=Depends(db_session)):
    return {**catalog.status_info(db), "rules": [
        {"id": r.id, "match": r.match, "action": r.action, "value": r.value, "note": r.note, "created_by": r.created_by}
        for r in db.scalars(select(SoftwareRule).order_by(SoftwareRule.id))]}


def _catalog_bg(download: bool) -> None:
    def work():
        with SessionLocal() as db:
            try:
                if download:
                    catalog.refresh(db)
                catalog.reconcile(db)
            except Exception as exc:
                set_setting(db, "catalog:error", f"{type(exc).__name__}: {exc}"[:300])
                db.commit()
    threading.Thread(target=work, daemon=True).start()


@app.post("/api/catalog/refresh")
def catalog_refresh(user=Depends(ui_auth)):
    _catalog_bg(True)
    return {"ok": True, "output": "Downloading the app catalog. Statuses update in a minute."}


@app.get("/api/catalog/search", dependencies=UI)
def catalog_search(q: str):
    return catalog.search(q[:100])


class RuleIn(BaseModel):
    match: str
    action: str
    value: str | None = None
    note: str | None = None


@app.post("/api/catalog/rules")
def add_rule(body: RuleIn, user=Depends(ui_auth), db=Depends(db_session)):
    import re as _re
    if body.action not in ("ignore", "package", "target"):
        raise HTTPException(400, "action must be ignore, package or target")
    if not body.match.strip() or len(body.match) > 200:
        raise HTTPException(400, "enter the program name or a pattern")
    try:
        _re.compile(body.match)
    except _re.error as exc:
        raise HTTPException(400, f"pattern: {exc}")
    if body.action == "package" and not catalog.package_exists((body.value or "").strip()):
        raise HTTPException(400, "that package id isn't in the catalog")
    if body.action == "target" and not catalog.vt(body.value):
        raise HTTPException(400, "enter a version number")
    r = SoftwareRule(match=body.match.strip(), action=body.action, value=(body.value or "").strip() or None,
                     note=(body.note or "")[:255] or None, created_by=user[:64])
    db.add(r)
    db.add(AuditLog(actor=user, action="catalog.rule", target=f"software:{r.match[:100]}", result=f"{r.action} {r.value or ''}"))
    db.commit()
    _catalog_bg(False)
    return {"ok": True, "id": r.id}


@app.delete("/api/catalog/rules/{rid}")
def delete_rule(rid: int, user=Depends(ui_auth), db=Depends(db_session)):
    r = db.get(SoftwareRule, rid)
    if r:
        db.add(AuditLog(actor=user, action="catalog.rule.delete", target=f"software:{r.match[:100]}", result=r.action))
        db.delete(r)
        db.commit()
        _catalog_bg(False)
    return {"ok": True}


@app.get("/api/devices/{hostname}/rdp", dependencies=UI)
def rdp(hostname: str, db=Depends(db_session)):
    dev = _device(db, hostname)
    return Response(actions.rdp_file(dev), media_type="application/x-rdp",
                    headers={"Content-Disposition": f'attachment; filename="{dev.hostname}.rdp"'})


class Bulk(BaseModel):
    hostnames: list[str]
    action: str          # rescan | wol | add_group | remove_group | set_state
    value: str | None = None


@app.post("/api/bulk")
def bulk(body: Bulk, user=Depends(ui_auth), db=Depends(db_session)):
    done = 0
    for h in body.hostnames[:2000]:
        dev = db.scalar(select(Device).where(Device.hostname == norm_host(h)))
        if dev is None:
            continue
        if body.action == "rescan":
            actions.rescan(dev.hostname)
        elif body.action == "wol":
            actions.wake_on_lan(dev)
        elif body.action == "add_group" and body.value:
            _add_group(db, dev, body.value)
        elif body.action == "remove_group" and body.value:
            for g in db.scalars(select(DeviceGroup).where(DeviceGroup.device_id == dev.id, DeviceGroup.name == body.value)):
                db.delete(g)
        elif body.action == "set_state" and body.value:
            dev.state = body.value
        else:
            raise HTTPException(400, "unknown action")
        done += 1
    db.commit()
    return {"ok": True, "count": done}


@app.get("/api/status", dependencies=UI)
def status():
    import time as _t
    return {"running": [{"job": k, "seconds": int(_t.time() - v)} for k, v in jobs.RUNNING.items()]}


@app.get("/api/users/{username}", dependencies=UI)
def user(username: str, db=Depends(db_session)):
    u = username.lower()
    info = reports.run_query(db, "v_users", filters=[{"field": "username", "op": "eq", "value": u}], limit=1)["rows"]
    ad = db.scalar(select(AdUser).where(AdUser.username == u))
    computers = _rows_of(db.execute(text(
        "SELECT ud.hostname, d.os, d.os_display_version, ud.last_logon, ud.logon_count, d.ip, d.switch_name, d.switch_port "
        "FROM v_user_devices ud LEFT JOIN v_devices d ON d.hostname = ud.hostname WHERE ud.username = :u "
        "ORDER BY ud.last_logon DESC LIMIT 50"), {"u": u}))
    logons = reports.run_query(db, "v_logons", filters=[{"field": "username", "op": "eq", "value": u}],
                               sort="time", desc=True, limit=200)["rows"]
    audit = reports.run_query(db, "v_audit", filters=[{"field": "target", "op": "eq", "value": f"user:{u}"}],
                              sort="time", desc=True, limit=100)["rows"]
    return {"user": info[0] if info else {"username": u}, "in_ad": ad is not None,
            "groups": json.loads(ad.groups) if ad and ad.groups else [], "computers": computers,
            "logons": logons, "audit": audit, "dn": ad.dn if ad else None}


class UserAction(BaseModel):
    password: str | None = None
    must_change: bool = True


@app.post("/api/users/{username}/action/{action}")
def user_action(username: str, action: str, body: UserAction, actor=Depends(ui_auth), db=Depends(db_session)):
    from .collectors import ad as adc
    from .scanning import ad_action_cfg
    if action not in ("unlock", "reset_password", "must_change", "enable", "disable"):
        raise HTTPException(404)
    u = db.scalar(select(AdUser).where(AdUser.username == username.lower()))
    if not u or not u.dn:
        raise HTTPException(404, "User not found in AD data")
    try:
        adc.user_action(ad_action_cfg(db, u.dn), u.dn, action, body.password, body.must_change)
        ok, msg = True, {"unlock": "Account unlocked.", "reset_password": "Password reset.",
                         "must_change": "User must change password at next logon.",
                         "enable": "Account enabled.", "disable": "Account disabled."}[action]
        if action == "unlock":
            u.locked, u.bad_pwd_count = False, 0
        elif action in ("enable", "disable"):
            u.enabled = action == "enable"
    except Exception as exc:
        ok, msg = False, f"Failed: {exc}"
    db.add(AuditLog(actor=actor, action=f"user.{action}", target=f"user:{u.username}", result=msg))
    db.commit()
    return {"ok": ok, "output": msg}


# ----------------------------------------------------------------- alerts + report library
@app.get("/api/alerts", dependencies=UI)
def alerts_summary(db=Depends(db_session)):
    return alerts.summary(db)


@app.get("/api/alerts/{rid}", dependencies=UI)
def alert_rows(rid: str, db=Depends(db_session)):
    try:
        return alerts.rows(db, rid)
    except KeyError:
        raise HTTPException(404)


@app.get("/api/library", dependencies=UI)
def library_list():
    return library.catalog()


@app.get("/api/library/{rid}", dependencies=UI)
def library_run(rid: str, db=Depends(db_session)):
    try:
        return library.run(db, rid)
    except KeyError:
        raise HTTPException(404)


@app.get("/api/library/{rid}/export/{fmt}", dependencies=UI)
def library_export(rid: str, fmt: str, db=Depends(db_session)):
    res = library.run(db, rid)
    body, mime, ext = exports.FORMATS[fmt](res, rid)
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{rid}.{ext}"'})


@app.get("/api/alerts/{rid}/export/{fmt}", dependencies=UI)
def alert_export(rid: str, fmt: str, db=Depends(db_session)):
    res = alerts.rows(db, rid)
    body, mime, ext = exports.FORMATS[fmt](res, rid)
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{rid}.{ext}"'})


# ----------------------------------------------------------------- credentials, scan targets, settings
class CredIn(BaseModel):
    name: str
    kind: str                      # windows | snmp2 | snmp3
    username: str | None = None
    secret: str | None = None      # blank on update = keep the stored one
    secret2: str | None = None


def _cred_out(c: Credential) -> dict:
    return {"id": c.id, "name": c.name, "kind": c.kind, "username": c.username,
            "has_secret": bool(c.secret), "has_secret2": bool(c.secret2)}


@app.get("/api/credentials", dependencies=UI)
def list_creds(db=Depends(db_session)):
    return [_cred_out(c) for c in db.scalars(select(Credential).order_by(Credential.name))]


@app.post("/api/credentials")
def save_cred(body: CredIn, cid: int | None = None, actor=Depends(ui_auth), db=Depends(db_session)):
    from .secrets import encrypt
    if body.kind not in ("windows", "snmp2", "snmp3"):
        raise HTTPException(400, "kind must be windows, snmp2 or snmp3")
    c = db.get(Credential, cid) if cid else Credential()
    if c is None:
        raise HTTPException(404)
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Give the credential a name")
    clash = db.scalar(select(Credential).where(Credential.name == name))
    if clash and clash.id != c.id:
        raise HTTPException(400, f"A credential named {name} already exists")
    c.name, c.kind, c.username = body.name.strip(), body.kind, (body.username or "").strip() or None
    if body.secret:
        c.secret = encrypt(body.secret)
    if body.secret2:
        c.secret2 = encrypt(body.secret2)
    db.add(c)
    db.add(AuditLog(actor=actor, action="credential.save", target=f"credential:{c.name}", result=c.kind))
    db.commit()
    return _cred_out(c)


@app.delete("/api/credentials/{cid}")
def delete_cred(cid: int, actor=Depends(ui_auth), db=Depends(db_session)):
    c = db.get(Credential, cid)
    if c:
        db.add(AuditLog(actor=actor, action="credential.delete", target=f"credential:{c.name}"))
        db.delete(c)
        db.commit()
    return {"ok": True}


class CredTest(BaseModel):
    host: str


@app.post("/api/credentials/{cid}/test", dependencies=UI)
def test_cred(cid: int, body: CredTest, db=Depends(db_session)):
    """Try a credential against one host: LDAP bind + WinRM for Windows, sysName get for SNMP."""
    import asyncio
    from .scanning import cred_cfg
    c = db.get(Credential, cid)
    if not c:
        raise HTTPException(404)
    host = body.host.strip()
    if not actions.HOST_RE.match(host):
        raise HTTPException(400, "invalid host")
    cfg = cred_cfg(c)
    results = []
    if c.kind == "windows":
        from .collectors import ad as adc
        from .collectors.winrm import run_ps
        try:
            conn = adc.connect({**cfg, "server": host})
            results.append(f"LDAP: OK ({'LDAPS' if conn.server.ssl else 'LDAP 389, not encrypted: set up LDAPS for password resets'})")
            conn.unbind()
        except Exception as exc:
            results.append(f"LDAP: {exc}")
        try:
            name = run_ps(host, {**settings.winrm, **cfg, "timeout": 30}, "$env:COMPUTERNAME | ConvertTo-Json")
            results.append(f"WinRM: OK ({name})")
        except Exception as exc:
            results.append(f"WinRM: {exc}")
    else:
        from .collectors.snmp import SYS, Snmp
        try:
            r = asyncio.run(Snmp(host, {**cfg, "timeout": 3}).get({"name": SYS["name"]}))
            results.append(f"SNMP: OK ({r['name']})")
        except Exception as exc:
            results.append(f"SNMP: {exc}")
    return {"ok": all(": OK" in r for r in results), "output": "\n".join(results)}


class TargetIn(BaseModel):
    kind: str
    value: str
    server: str | None = None
    credential_ids: list[int] = []
    enabled: bool = True


def _target_out(t: ScanTarget) -> dict:
    return {"id": t.id, "kind": t.kind, "value": t.value, "server": t.server, "enabled": t.enabled,
            "credential_ids": [int(x) for x in (t.credential_ids or "").split(",") if x.strip().isdigit()],
            "last_run": t.last_run.isoformat(sep=" ", timespec="minutes") if t.last_run else None,
            "last_ok": t.last_ok, "last_result": t.last_result}


@app.get("/api/targets", dependencies=UI)
def list_targets(db=Depends(db_session)):
    return [_target_out(t) for t in db.scalars(select(ScanTarget).order_by(ScanTarget.kind, ScanTarget.id))]


@app.post("/api/targets")
def save_target(body: TargetIn, tid: int | None = None, actor=Depends(ui_auth), db=Depends(db_session)):
    if body.kind not in ("ad_domain", "ad_computer_path", "ad_user_path", "ip_range"):
        raise HTTPException(400, "bad kind")
    if body.kind == "ip_range":
        from .collectors.snmp import expand_targets
        try:
            n = len(expand_targets(body.value.replace(";", ",").split(",")))
        except Exception as exc:
            raise HTTPException(400, f"Invalid IP range: {exc}")
        if n > 65536:
            raise HTTPException(400, "IP range too large (max 65,536 addresses)")
    elif body.kind != "ad_domain" and "DC=" not in body.value.upper():
        raise HTTPException(400, "Use a distinguished name such as OU=Workstations,DC=corp,DC=example,DC=com")
    t = db.get(ScanTarget, tid) if tid else ScanTarget()
    if t is None:
        raise HTTPException(404)
    t.kind, t.value, t.server, t.enabled = body.kind, body.value.strip(), (body.server or "").strip() or None, body.enabled
    t.credential_ids = ",".join(str(i) for i in body.credential_ids)
    db.add(t)
    db.add(AuditLog(actor=actor, action="target.save", target=f"{t.kind}:{t.value}"))
    db.commit()
    return _target_out(t)


@app.delete("/api/targets/{tid}")
def delete_target(tid: int, actor=Depends(ui_auth), db=Depends(db_session)):
    t = db.get(ScanTarget, tid)
    if t:
        db.add(AuditLog(actor=actor, action="target.delete", target=f"{t.kind}:{t.value}"))
        db.delete(t)
        db.commit()
    return {"ok": True}


@app.post("/api/targets/{tid}/scan", dependencies=UI)
def scan_target(tid: int, db=Depends(db_session)):
    t = db.get(ScanTarget, tid)
    if not t:
        raise HTTPException(404)
    order = ["ad", "pcs", "dc_logons"] if t.kind.startswith("ad_") else ["snmp", "pcs"]
    threading.Thread(target=lambda: [jobs.run_job(n) for n in order], daemon=True).start()
    return {"started": order}


@app.post("/api/scan/all", dependencies=UI)
def scan_all():
    threading.Thread(target=jobs.run_all, daemon=True).start()
    return {"started": jobs.ALL_ORDER}


# ----------------------------------------------------------------- software updates (see updater.py)
@app.get("/api/update", dependencies=UI)
def update_status(db=Depends(db_session)):
    return updater.status(db)


@app.post("/api/update/check", dependencies=UI)
def update_check(db=Depends(db_session)):
    return updater.check(db)


@app.post("/api/update/install")
def update_install(actor=Depends(ui_auth), db=Depends(db_session)):
    target = updater.status(db).get("latest")
    try:
        msg = updater.install(db)
        ok = True
    except Exception as exc:
        ok, msg = False, str(exc)
    db.add(AuditLog(actor=actor, action="update.install", target=f"version:{target}", result=msg[:500]))
    db.commit()
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "output": msg}


SETTING_KEYS = {"dameware_mode": "windows", "interval:ad": "", "interval:snmp": "",
                "interval:pcs": "", "interval:pcs_updates": "", "interval:dc_logons": "",
                "fix:reboot_hour": "2"}


@app.get("/api/settings", dependencies=UI)
def get_settings(db=Depends(db_session)):
    out = {k: get_setting(db, k, v) for k, v in SETTING_KEYS.items()}
    out["intervals"] = jobs.intervals(db)
    return out


@app.put("/api/settings")
def put_settings(body: dict, actor=Depends(ui_auth), db=Depends(db_session)):
    for k, v in body.items():
        if k in SETTING_KEYS:
            if k == "dameware_mode" and v not in ("windows", "saved"):
                raise HTTPException(400, "dameware_mode must be windows or saved")
            if k.startswith("interval:") and v not in ("", None) and not str(v).isdigit():
                raise HTTPException(400, f"{k} must be minutes")
            if k == "fix:reboot_hour" and not (str(v).isdigit() and 0 <= int(v) <= 23):
                raise HTTPException(400, "reboot hour must be 0-23")
            set_setting(db, k, None if v in ("", None) else str(v))
    db.add(AuditLog(actor=actor, action="settings.save", target="settings", result=json.dumps(body)[:500]))
    db.commit()
    return get_settings(db)


@app.get("/api/search", dependencies=UI)
def search(q: str, db=Depends(db_session)):
    """Find a PC, user, MAC or IP."""
    mac = norm_mac(q)
    out = {}
    if mac:
        out["port_map"] = reports.run_query(db, "v_port_map", filters=[{"field": "mac", "op": "eq", "value": mac}])["rows"]
    out["devices"] = reports.run_query(db, "v_devices", ["hostname", "os", "last_user", "ip", "switch_name", "switch_port"],
                                       [{"field": "hostname", "op": "contains", "value": q}], limit=50)["rows"]
    out["devices"] += reports.run_query(db, "v_devices", ["hostname", "os", "last_user", "ip", "switch_name", "switch_port"],
                                        [{"field": "ip", "op": "eq", "value": q}], limit=50)["rows"]
    out["users"] = reports.run_query(db, "v_user_devices", filters=[{"field": "username", "op": "contains", "value": q}],
                                     sort="last_logon", desc=True, limit=50)["rows"]
    return out


# ----------------------------------------------------------------- reports
@app.get("/api/datasets", dependencies=UI)
def datasets(db=Depends(db_session)):
    return [{"name": k, "label": v, "columns": reports.columns(db, k)} for k, v in reports.DATASETS.items()]


class QuerySpec(BaseModel):
    dataset: str
    fields: list[str] = []
    filters: list[dict] = []
    sort: str | None = None
    desc: bool = False
    limit: int = 1000
    offset: int = 0
    count: bool = False


@app.post("/api/query", dependencies=UI)
def query(spec: QuerySpec, db=Depends(db_session)):
    try:
        return reports.run_query(db, **spec.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/export/{fmt}", dependencies=UI)
def export(fmt: str, spec: QuerySpec, db=Depends(db_session)):
    res = reports.run_query(db, **{**spec.model_dump(), "limit": 100000, "offset": 0, "count": False})
    if fmt not in exports.FORMATS:
        raise HTTPException(404)
    body, mime, ext = exports.FORMATS[fmt](res, spec.dataset)
    return Response(body, media_type=mime,
                    headers={"Content-Disposition": f'attachment; filename="{spec.dataset.removeprefix("v_")}.{ext}"'})


@app.get("/api/reports", dependencies=UI)
def list_reports(db=Depends(db_session)):
    built = [{"id": k, "name": v[0], "builtin": True,
              "spec": {"dataset": v[1], "fields": v[2], "filters": v[3], "sort": v[4]}}
             for k, v in reports.PREBUILT.items()]
    saved = [{"id": f"saved:{r.id}", "name": r.name, "builtin": False, "spec": json.loads(r.spec)}
             for r in db.scalars(select(SavedReport).order_by(SavedReport.name))]
    return built + saved


class SaveReport(BaseModel):
    name: str
    spec: QuerySpec


@app.post("/api/reports", dependencies=UI)
def save_report(body: SaveReport, db=Depends(db_session)):
    r = db.scalar(select(SavedReport).where(SavedReport.name == body.name)) or SavedReport(name=body.name)
    r.spec = body.spec.model_dump_json()
    db.add(r)
    db.commit()
    return {"id": f"saved:{r.id}"}


@app.delete("/api/reports/{rid}", dependencies=UI)
def delete_report(rid: str, db=Depends(db_session)):
    r = db.get(SavedReport, int(rid.split(":")[-1]))
    if r:
        db.delete(r)
        db.commit()
    return {"ok": True}


# ----------------------------------------------------------------- collectors
@app.post("/api/collect/{name}", dependencies=UI)
def collect_now(name: str):
    if name not in jobs.JOBS:
        raise HTTPException(404)
    threading.Thread(target=jobs.run_job, args=(name,), daemon=True).start()
    return {"started": name}


# Ingest endpoints for a future endpoint agent or scripts (same payload as the WinRM pull).
@app.post("/api/ingest/endpoint", dependencies=[Depends(ingest_auth)])
def ingest_endpoint(p: EndpointPayload, db=Depends(db_session)):
    apply_endpoint(db, p)
    db.commit()
    return {"ok": True}


@app.post("/api/ingest/logons", dependencies=[Depends(ingest_auth)])
def ingest_logons(rows: list[LogonIn], db=Depends(db_session)):
    n = add_logons(db, rows)
    db.commit()
    return {"ok": True, "stored": n}
