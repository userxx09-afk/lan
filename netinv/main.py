"""FastAPI server: dashboard, reports API, report builder and ingest endpoints."""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, select, text

from . import __version__, actions, alerts, auth, catalog, exclusions, exports, fixes, groups, jobs, library, reports, scanning, updater
from .config import settings
from .correlate import create_views
from datetime import datetime

from .db import (AdUser, AuditLog, Credential, Deployment, Script, ScanExclusion, ScanJob, ScanTarget, SoftwareRule, get_setting, set_setting)
from .db import (ChangeEvent, CollectorRun, Comment, CustomField, Device, DeviceGroup, GroupDef, SavedReport, SessionLocal, UserGroup,
                 init_db, norm_host, norm_mac, utcnow)
from .ingest import EndpointPayload, LogonIn, add_logons, apply_endpoint, log_change

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
STATIC = Path(__file__).parent / "static"
_stop = threading.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(settings.database_url)
    with SessionLocal() as db:
        create_views(db)
        exclusions.seed(db)
        scanning.fix_ou_targets(db)
        try:   # quick SQL-only pass; reverse DNS runs with each DC logon import
            from .correlate import resolve_logon_hosts
            resolve_logon_hosts(db, dns=False)
        except Exception:
            db.rollback()
            logging.getLogger(__name__).exception("matching logons to computers")
    if settings.schedule.get("enabled", True):
        threading.Thread(target=jobs.scheduler_loop, args=(_stop,), daemon=True).start()
    from . import reach
    threading.Thread(target=reach.loop, args=(_stop,), daemon=True).start()
    with SessionLocal() as db:   # a finished update leaves its "installing" note behind
        if get_setting(db, "update:message") and not updater.status(db)["available"]:
            set_setting(db, "update:message", None)
            db.commit()
    from . import instance
    threading.Thread(target=instance.loop, args=(_stop,), daemon=True).start()
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
    access_group: str | None = None     # a NetInventory user group (Groups tab) whose members may sign in


def _auth_out(db) -> dict:
    return {"ad_domain": get_setting(db, "auth:ad_domain"), "ad_group": get_setting(db, "auth:ad_group"),
            "access_group": get_setting(db, "auth:access_group"), "user_groups": groups.names(db, "users"),
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
    access = (body.access_group or "").strip() or None
    if access and access not in groups.names(db, "users"):
        raise HTTPException(400, f"there's no user group called {access} (Groups tab)")
    set_setting(db, "auth:access_group", access)
    db.add(AuditLog(actor=actor, action="auth.save", target="sign-in",
                    result=f"domain={body.ad_domain} group={body.ad_group} user group={access} server={body.ad_server}"))
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
from . import agentapi, agentpush  # noqa: E402
app.include_router(agentapi.router)


# ----------------------------------------------------------------- overview
def _run_name(db, collector: str) -> str:
    if collector.startswith("job:") and collector[4:].isdigit():
        j = db.get(ScanJob, int(collector[4:]))
        return f"job: {j.name}" if j else "job (deleted)"
    return collector



@app.get("/api/summary", dependencies=UI)
def summary(db=Depends(db_session)):
    q = lambda sql: db.execute(text(sql)).scalar()  # noqa: E731
    ins = reports.insights(db, settings.insights, settings.outdated_software)
    runs = db.scalars(select(CollectorRun).order_by(CollectorRun.started.desc()).limit(10))
    return {
        "counts": {
            "pcs": q("SELECT COUNT(*) FROM devices WHERE ad_enabled IS NOT FALSE"),
            "inventoried": q("SELECT COUNT(*) FROM devices WHERE agent_last_report IS NOT NULL"),
            "not_inventoried": q("SELECT COUNT(*) FROM devices WHERE agent_last_report IS NULL"),
            "domain_controllers": q("SELECT COUNT(*) FROM domain_controllers"),
            "network_devices": q("SELECT COUNT(*) FROM network_devices"),
            "mapped_to_port": q("SELECT COUNT(DISTINCT hostname) FROM v_port_map WHERE hostname IS NOT NULL"),
            "users": q("SELECT COUNT(DISTINCT username) FROM logon_events"),
        },
        "insight_counts": {k: len(v) for k, v in ins.items()},
        "os_breakdown": [dict(r._mapping) for r in db.execute(text(
            "SELECT COALESCE(os, 'Unknown') AS os, COALESCE(os_display_version, '') AS version, COUNT(*) AS n "
            "FROM v_devices GROUP BY 1, 2 ORDER BY n DESC"))],
        "runs": [{"collector": _run_name(db, r.collector), "started": r.started.isoformat(timespec="seconds"),
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
            "deployments": [_dep_out(x) for x in db.scalars(select(Deployment).where(Deployment.hostname == h)
                                                               .order_by(Deployment.created.desc()).limit(200))],
            "location": location, "nics": [{"mac": n.mac, "ip": n.ip, "description": n.description} for n in dev.nics],
            "groups": sorted(g.name for g in db.scalars(select(DeviceGroup).where(DeviceGroup.device_id == dev.id))),
            "rule_groups": sorted(g.name for g in db.scalars(select(DeviceGroup).where(DeviceGroup.device_id == dev.id,
                                                                                         DeviceGroup.dynamic.is_(True)))),
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
    if not name:
        return
    row = db.scalar(select(DeviceGroup).where(DeviceGroup.device_id == dev.id, DeviceGroup.name == name))
    if row is None:
        db.add(DeviceGroup(device_id=dev.id, name=name, dynamic=False))
    elif row.dynamic:
        row.dynamic = False     # added by hand to a rule-based group: stays whatever the rules say


def _remove_group(db, dev: Device, name: str) -> bool:
    """False when the PC is in the group only because of the group's rules (removing it would be undone)."""
    rows = list(db.scalars(select(DeviceGroup).where(DeviceGroup.device_id == dev.id, DeviceGroup.name == name)))
    if rows and all(r.dynamic for r in rows):
        return False
    for g in rows:
        if db.scalar(select(GroupDef.id).where(GroupDef.name == name)) and groups.evaluate(
                db, *_gdef_rules(db, name), devices=[d for d in groups._devices(db) if d["id"] == dev.id]):
            g.dynamic = True    # added by hand, but the rules match it too: it stays as a rule-based member
        else:
            db.delete(g)
    return True


def _gdef_rules(db, name: str) -> tuple[str, list]:
    g = db.scalar(select(GroupDef).where(GroupDef.name == name))
    return (g.match or "all", groups.conditions_of(g)) if g else ("all", [])


@app.delete("/api/devices/{hostname}/groups/{name}", dependencies=UI)
def remove_group(hostname: str, name: str, db=Depends(db_session)):
    dev = _device(db, hostname)
    if not _remove_group(db, dev, name):
        raise HTTPException(400, f"{dev.hostname} is in {name} because of the group's rules. To leave it out, "
                                 f"edit the group under Groups and add a condition such as \"host name is not {dev.hostname}\".")
    db.commit()
    return {"ok": True}


# ----------------------------------------------------------------- groups page (static and rule-based groups)
class Condition(BaseModel):
    field: str
    value: str = ""
    column: str | None = None       # "other": a v_devices column
    op: str | None = None           # "other": is | not | lt | gt | empty | not_empty
    not_: bool = Field(False, alias="not")
    model_config = {"populate_by_name": True}


class GroupIn(BaseModel):
    name: str
    description: str | None = None
    kind: str = "computers"          # computers | users
    match: str = "all"
    conditions: list[Condition] = []
    hostnames: list[str] = []        # always in the group, whatever the conditions say (computer groups)
    usernames: list[str] = []        # the same for user groups


def _conds(body) -> list[dict]:
    return [{"field": c.field, "value": c.value, "not": c.not_,
             **({"column": c.column, "op": c.op} if c.field == "other" else {})} for c in body.conditions]


def _clean_conds(match: str, conds: list[dict], allow_empty: bool, db=None, kind: str = "computers") -> list[dict]:
    if allow_empty and not any(str(c.get("value") or "").strip() or c.get("op") in ("empty", "not_empty") for c in conds):
        return []
    try:
        return groups.validate(match, conds, db, kind)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


def _norm_user(u: str) -> str:
    return (u or "").strip().replace("/", "\\").split("\\")[-1].split("@")[0].lower()


@app.get("/api/groups", dependencies=UI)
def groups_list(db=Depends(db_session)):
    from sqlalchemy import func
    groups.refresh_if_stale(db)
    counts = dict(db.execute(select(DeviceGroup.name, func.count()).group_by(DeviceGroup.name)).all())
    manual = dict(db.execute(select(DeviceGroup.name, func.count()).where(DeviceGroup.dynamic.is_not(True))
                             .group_by(DeviceGroup.name)).all())
    ucounts = dict(db.execute(select(UserGroup.name, func.count()).group_by(UserGroup.name)).all())
    umanual = dict(db.execute(select(UserGroup.name, func.count()).where(UserGroup.dynamic.is_not(True))
                              .group_by(UserGroup.name)).all())
    defs = {g.name: g for g in db.scalars(select(GroupDef))}
    used: dict[str, list[str]] = {}
    for j in db.scalars(select(ScanJob).where(ScanJob.group_name.is_not(None))):
        used.setdefault(j.group_name, []).append(j.name)
    signin = get_setting(db, "auth:access_group")
    out = []
    for of in groups.KINDS:
        for name in groups.names(db, of):
            g, conds = defs.get(name), groups.conditions_of(defs[name]) if name in defs else []
            n, m = (ucounts, umanual) if of == "users" else (counts, manual)
            out.append({"name": name, "of": of, "description": g.description if g else None,
                        "kind": "rules" if conds else "manual",
                        "match": g.match if g else "all", "conditions": conds,
                        "rule": groups.describe(g.match or "all", conds) if conds else "",
                        "members": n.get(name, 0), "manual": m.get(name, 0), "scan_jobs": used.get(name, []),
                        "signin": of == "users" and name == signin,
                        "updated": jobs._local(g.updated).isoformat(sep=" ", timespec="minutes") if g and g.updated else None,
                        "who": g.who if g else None})
    from sqlalchemy import func as _f
    from .db import AdGroup
    return {"groups": out, "fields": groups.FIELDS, "hints": groups.HINTS, "other_ops": groups.OTHER_OPS,
            "columns": groups.device_columns(db), "user_fields": groups.USER_FIELDS, "user_hints": groups.USER_HINTS,
            "user_columns": groups.user_columns(db), "user_pc_days": groups.USER_PC_DAYS,
            "ad_groups": db.scalar(select(_f.count()).select_from(AdGroup)) or 0}


@app.get("/api/ad-groups", dependencies=UI)
def ad_groups_search(q: str = "", db=Depends(db_session)):
    """AD groups from the last import, for the group condition picker."""
    from .db import AdGroup
    st = select(AdGroup).order_by(AdGroup.name).limit(50)
    if q.strip():
        like = f"%{q.strip().lower()}%"
        from sqlalchemy import func, or_
        st = st.where(or_(func.lower(AdGroup.name).like(like), func.lower(AdGroup.sam).like(like)))
    return [{"name": g.name, "dn": g.dn, "type": g.type, "description": g.description} for g in db.scalars(st)]


@app.post("/api/groups/preview", dependencies=UI)
def groups_preview(body: GroupIn, db=Depends(db_session)):
    conds = _clean_conds(body.match, _conds(body), allow_empty=True, db=db, kind=body.kind)
    hits = groups.evaluate(db, body.match, conds, kind=body.kind) if conds else []
    if body.kind == "users":
        names = sorted({d["username"] for d in hits} | {_norm_user(u) for u in body.usernames if _norm_user(u)})
    else:
        names = sorted({d["hostname"] for d in hits} | {norm_host(h) for h in body.hostnames if norm_host(h)})
    return {"count": len(names), "rule_count": len(hits), "hostnames": names[:500], "names": names[:500]}


@app.get("/api/groups/{name}/members", dependencies=UI)
def group_members(name: str, db=Depends(db_session)):
    if groups.kind_of(db, name) == "users":
        groups.users(db, name)
        rows = db.execute(select(AdUser.username, UserGroup.dynamic).join(UserGroup, UserGroup.user_id == AdUser.id)
                          .where(UserGroup.name == name).order_by(AdUser.username)).all()
        info = {}
        if rows:
            info = {r["username"]: r for r in reports.run_query(
                db, "v_users", fields=["username", "display_name", "department", "title", "ou", "enabled", "locked",
                                       "last_computer"],
                filters=[{"field": "username", "op": "in", "value": [u for u, _ in rows]}], limit=100000)["rows"]}
        return {"of": "users", "members": [{**{k: v for k, v in (info.get(u) or {}).items()}, "username": u,
                                            "how": "rules" if dyn else "added by hand"} for u, dyn in rows],
                "computers": groups.hosts(db, name)}
    groups.hosts(db, name)
    rows = db.execute(select(Device.hostname, DeviceGroup.dynamic).join(DeviceGroup, DeviceGroup.device_id == Device.id)
                      .where(DeviceGroup.name == name).order_by(Device.hostname)).all()
    info = {}
    if rows:
        info = {r["hostname"]: r for r in reports.run_query(
            db, "v_devices", fields=["hostname", "os", "ip", "model", "ou", "last_user"],
            filters=[{"field": "hostname", "op": "in", "value": [h for h, _ in rows]}], limit=100000)["rows"]}
    return {"of": "computers",
            "members": [{"hostname": h, "os": (info.get(h) or {}).get("os"), "ip": (info.get(h) or {}).get("ip"),
                         "model": (info.get(h) or {}).get("model"), "ou": (info.get(h) or {}).get("ou"),
                         "last_user": (info.get(h) or {}).get("last_user"), "how": "rules" if dyn else "added by hand"}
                        for h, dyn in rows]}


@app.post("/api/groups")
def group_save(body: GroupIn, old: str | None = None, actor=Depends(ui_auth), db=Depends(db_session)):
    name = body.name.strip()
    kind = body.kind
    if kind not in groups.KINDS:
        raise HTTPException(400, "a group holds computers or users")
    if not name or len(name) > 128 or "," in name:
        raise HTTPException(400, "give the group a name (up to 128 characters, no commas)")
    if body.match not in ("all", "any"):
        raise HTTPException(400, "match must be all or any")
    conds = _clean_conds(body.match, _conds(body), allow_empty=True, db=db, kind=kind)
    if kind == "users":
        want = {_norm_user(u) for u in body.usernames if _norm_user(u)}
        found = dict(db.execute(select(AdUser.username, AdUser.id).where(AdUser.username.in_(want))).all()) if want else {}
        what = "users"
    else:
        want = {norm_host(h) for h in body.hostnames if norm_host(h)}
        found = dict(db.execute(select(Device.hostname, Device.id).where(Device.hostname.in_(want))).all()) if want else {}
        what = "computers"
    if not conds and not want:
        raise HTTPException(400, f"add at least one condition, or list the {what} that belong in the group")
    missing = sorted(want - set(found))
    if missing:
        raise HTTPException(400, f"not in the {'AD user list' if kind == 'users' else 'inventory'}: "
                                 f"{', '.join(missing[:20])}{' ...' if len(missing) > 20 else ''}")
    existing = set(groups.names(db))
    if old and old not in existing:
        raise HTTPException(404, "that group no longer exists")
    if old and groups.kind_of(db, old) != kind:
        raise HTTPException(400, f"that group holds {groups.kind_of(db, old)}; make a new group for {kind}")
    if name != old and name in existing:
        raise HTTPException(400, "another group already has that name")
    Row = UserGroup if kind == "users" else DeviceGroup
    if old and old != name:     # rename: memberships, scan jobs, sign-in and the definition follow
        for r in db.scalars(select(Row).where(Row.name == old)):
            r.name = name
        for j in db.scalars(select(ScanJob).where(ScanJob.group_name == old)):
            j.group_name = name
        if kind == "users" and get_setting(db, "auth:access_group") == old:
            set_setting(db, "auth:access_group", name)
    g = db.scalar(select(GroupDef).where(GroupDef.name == (old or name))) or GroupDef()
    g.name, g.kind, g.description, g.match = name, kind, (body.description or "").strip()[:1000] or None, body.match
    g.conditions, g.who, g.updated = json.dumps(conds), actor, utcnow()
    db.add(g)
    db.flush()
    key = (lambda r: r.user_id) if kind == "users" else (lambda r: r.device_id)
    # The list is the full set of hand-added members: drop the others, add the new ones.
    for r in db.scalars(select(Row).where(Row.name == name, Row.dynamic.is_not(True))):
        if key(r) not in found.values():
            db.delete(r)
    db.flush()
    have = {key(r): r for r in db.scalars(select(Row).where(Row.name == name))}
    for oid in found.values():
        if oid in have:
            have[oid].dynamic = False
        else:
            db.add(UserGroup(user_id=oid, name=name, dynamic=False) if kind == "users"
                   else DeviceGroup(device_id=oid, name=name, dynamic=False))
    db.commit()
    n = groups.refresh(db, only=name).get(name, 0)
    db.add(AuditLog(actor=actor, action="group.save", target=f"group:{name[:100]}",
                    result=(groups.describe(body.match, conds) if conds else "by hand")[:1000] + f"; {n} {what}"))
    db.commit()
    return {"ok": True, "members": n, "of": kind}


@app.delete("/api/groups/{name}")
def group_delete(name: str, actor=Depends(ui_auth), db=Depends(db_session)):
    jobs_using = [j.name for j in db.scalars(select(ScanJob).where(ScanJob.group_name == name))]
    if jobs_using:
        raise HTTPException(400, f"the scan job{'s' if len(jobs_using) > 1 else ''} {', '.join(jobs_using)} "
                                 f"scan{'' if len(jobs_using) > 1 else 's'} this group: change or delete {'them' if len(jobs_using) > 1 else 'it'} first")
    if get_setting(db, "auth:access_group") == name:
        raise HTTPException(400, "this group decides who can sign in (Settings > Sign-in): pick another there first")
    from sqlalchemy import delete as sql_delete
    n = db.execute(sql_delete(DeviceGroup).where(DeviceGroup.name == name)).rowcount
    n += db.execute(sql_delete(UserGroup).where(UserGroup.name == name)).rowcount
    db.execute(sql_delete(GroupDef).where(GroupDef.name == name))
    db.add(AuditLog(actor=actor, action="group.delete", target=f"group:{name[:100]}", result=f"{n} memberships removed"))
    db.commit()
    return {"ok": True}


@app.post("/api/groups/{name}/users/{action}")
def group_user_action(name: str, action: str, actor=Depends(ui_auth), db=Depends(db_session)):
    """Unlock, enable, disable or 'must change password' for every user in a user group (AD writes, one by one)."""
    from .collectors import ad as adc
    from .scanning import ad_action_cfg
    if action not in ("unlock", "must_change", "enable", "disable"):
        raise HTTPException(404)
    if groups.kind_of(db, name) != "users":
        raise HTTPException(400, "that isn't a user group")
    who = groups.users(db, name)
    if len(who) > 500:
        raise HTTPException(400, f"{len(who)} users: at most 500 at once")
    ok = failed = 0
    errors = []
    for u in db.scalars(select(AdUser).where(AdUser.username.in_(who))):
        if not u.dn or (action == "unlock" and not u.locked):
            continue
        try:
            adc.user_action(ad_action_cfg(db, u.dn), u.dn, action)
            ok += 1
            if action == "unlock":
                u.locked, u.bad_pwd_count = False, 0
            elif action in ("enable", "disable"):
                u.enabled = action == "enable"
            res = "done"
        except Exception as exc:
            failed += 1
            res = f"Failed: {exc}"
            errors.append(f"{u.username}: {exc}")
        db.add(AuditLog(actor=actor, action=f"user.{action}", target=f"user:{u.username}", result=f"{res} (group {name})"[:1000]))
    db.commit()
    verb = {"unlock": "unlocked", "must_change": "set to change password at next logon", "enable": "enabled",
            "disable": "disabled"}[action]
    msg = f"{ok} user{'s' if ok != 1 else ''} {verb}." + (f" {failed} failed: {'; '.join(errors[:3])}" if failed else "")
    if action == "unlock" and not ok and not failed:
        msg = "Nobody in the group is locked out."
    return {"ok": not failed, "output": msg}


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


# ----------------------------------------------------------------- live PC tools (see pctools.py)
def _tool(fn):
    from .collectors.winrm import classify_error
    try:
        return fn()
    except PermissionError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        kind = classify_error(exc)
        msg = str(exc).split("\n")[0][:300]
        raise HTTPException(502, ("The PC isn't reachable over WinRM right now: " if kind == "unreachable" else
                                  "Access denied by the PC: " if kind == "access_denied" else "") + msg)


@app.get("/api/devices/{hostname}/processes", dependencies=UI)
def device_processes(hostname: str, db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    return _tool(lambda: pctools.processes(db, dev))


@app.get("/api/devices/{hostname}/services", dependencies=UI)
def device_services(hostname: str, db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    return _tool(lambda: pctools.services(db, dev))


class KillIn(BaseModel):
    pid: int
    name: str = ""


@app.post("/api/devices/{hostname}/processes/kill")
def device_kill(hostname: str, body: KillIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    return _tool(lambda: pctools.kill(db, dev, body.pid, body.name, user))


class ServiceIn(BaseModel):
    name: str
    action: str


@app.post("/api/devices/{hostname}/services/action")
def device_service(hostname: str, body: ServiceIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    return _tool(lambda: pctools.service(db, dev, body.name, body.action, user))


class AdhocIn(BaseModel):
    language: str = "powershell"
    body: str
    timeout: int = 10


@app.get("/api/devices/{hostname}/registry", dependencies=UI)
def device_registry(hostname: str, path: str = "HKLM\\SOFTWARE", db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    try:
        pctools.reg_split(path)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return _tool(lambda: pctools.registry(db, dev, path))


class RegIn(BaseModel):
    op: str
    path: str
    name: str = ""
    kind: str = "String"
    data: str = ""


@app.post("/api/devices/{hostname}/registry")
def device_registry_change(hostname: str, body: RegIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    try:
        return _tool(lambda: pctools.reg_change(db, dev, user, body.op, body.path, body.name, body.kind, body.data))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/devices/{hostname}/printers", dependencies=UI)
def device_printers(hostname: str, db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    return {"printers": _tool(lambda: pctools.printers(db, dev)), "drives": _tool(lambda: pctools.drives(db, dev))}


class NameOpIn(BaseModel):
    op: str
    name: str


@app.post("/api/devices/{hostname}/printers")
def device_printer_change(hostname: str, body: NameOpIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    return _tool(lambda: pctools.printer_change(db, dev, user, body.op, body.name))


@app.get("/api/devices/{hostname}/accounts", dependencies=UI)
def device_accounts(hostname: str, db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    return _tool(lambda: pctools.local_accounts(db, dev))


@app.post("/api/devices/{hostname}/accounts")
def device_account_change(hostname: str, body: NameOpIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import pctools
    dev = _device(db, hostname)
    return _tool(lambda: pctools.local_change(db, dev, user, body.op, body.name))


# ----------------------------------------------------------------- remote tools (see remote.py)
def _remote(fn):
    """_tool, plus: a ValueError is a bad request (checked before anything reaches the PC)."""
    def checked():
        try:
            return fn()
        except ValueError as exc:
            raise PermissionError(str(exc))
    return _tool(checked)


class PowerIn(BaseModel):
    op: str
    minutes: int = 0
    message: str = ""


@app.post("/api/devices/{hostname}/power")
def device_power(hostname: str, body: PowerIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.power(db, dev, user, body.op, body.minutes, body.message))


@app.get("/api/devices/{hostname}/sessions", dependencies=UI)
def device_sessions(hostname: str, db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.sessions(db, dev))


class SessionIn(BaseModel):
    op: str
    id: int


@app.post("/api/devices/{hostname}/sessions")
def device_session_op(hostname: str, body: SessionIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.session_op(db, dev, user, body.op, body.id))


class MessageIn(BaseModel):
    text: str
    title: str = ""
    user: str = ""
    session: int = 0
    seconds: int = 300


@app.post("/api/devices/{hostname}/message")
def device_message(hostname: str, body: MessageIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.message(db, dev, user, body.text, body.title, body.user, body.session, body.seconds))


class CommandIn(BaseModel):
    command: str
    shell: str = "powershell"
    timeout: int = 60


@app.post("/api/devices/{hostname}/command")
def device_command(hostname: str, body: CommandIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.command(db, dev, user, body.command, body.shell, body.timeout))


@app.get("/api/devices/{hostname}/wmi", dependencies=UI)
def device_wmi(hostname: str, ns: str = "root\\cimv2", cls: str = "", limit: int = 500, db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    if cls:
        return _remote(lambda: remote.wmi_class(db, dev, ns, cls, limit))
    return _remote(lambda: remote.wmi_browse(db, dev, ns))


class WqlIn(BaseModel):
    ns: str = "root\\cimv2"
    query: str
    limit: int = 1000


@app.post("/api/devices/{hostname}/wmi")
def device_wql(hostname: str, body: WqlIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.wmi_query(db, dev, body.ns, body.query, body.limit))


@app.get("/api/devices/{hostname}/view/{name}", dependencies=UI)
def device_view(hostname: str, name: str, request: Request, db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    if name not in remote.VIEWS:
        raise HTTPException(404)
    p = {k: v for k, v in request.query_params.items() if k not in ("name", "db", "dev")}
    return _remote(lambda: remote.view(db, dev, name, **p))


class ChangeIn(BaseModel):
    kind: str
    op: str
    args: dict = {}


@app.post("/api/devices/{hostname}/change")
def device_change(hostname: str, body: ChangeIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.change(db, dev, user, body.kind, body.op, body.args))


@app.get("/api/devices/{hostname}/files", dependencies=UI)
def device_files(hostname: str, path: str = "C:\\", db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.files(db, dev, path))


@app.get("/api/devices/{hostname}/files/text", dependencies=UI)
def device_file_text(hostname: str, path: str, tail: bool = False, db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.file_text(db, dev, path, tail))


class FileOpIn(BaseModel):
    op: str
    path: str
    name: str = ""


@app.post("/api/devices/{hostname}/files")
def device_file_op(hostname: str, body: FileOpIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.file_op(db, dev, user, body.op, body.path, body.name))


@app.get("/api/devices/{hostname}/files/download")
def device_file_download(hostname: str, path: str, user=Depends(ui_auth), db=Depends(db_session)):
    import tempfile
    from starlette.background import BackgroundTask
    from . import remote
    dev = _device(db, hostname)
    fd, tmp = tempfile.mkstemp(prefix="netinv-dl-")
    os.close(fd)
    try:
        info = _remote(lambda: remote.download(db, dev, user, path, tmp))
    except BaseException:
        os.unlink(tmp)
        raise
    return FileResponse(tmp, filename=info["name"], media_type="application/octet-stream",
                        background=BackgroundTask(lambda: os.path.exists(tmp) and os.unlink(tmp)))


@app.put("/api/devices/{hostname}/files/upload")
async def device_file_upload(hostname: str, path: str, name: str, request: Request, user=Depends(ui_auth), db=Depends(db_session)):
    import tempfile
    from starlette.concurrency import run_in_threadpool
    from . import remote
    dev = _device(db, hostname)
    fd, tmp = tempfile.mkstemp(prefix="netinv-ul-")
    size = 0
    try:
        with os.fdopen(fd, "wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > remote.MAX_TRANSFER:
                    return {"ok": False, "output": f"Files over {remote.MAX_TRANSFER // 1048576} MB aren't copied from here."}
                f.write(chunk)
        return await run_in_threadpool(lambda: _remote(lambda: remote.upload(db, dev, user, path, name, tmp, size)))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@app.get("/api/devices/{hostname}/bitlocker-keys")
def device_bitlocker_keys(hostname: str, user=Depends(ui_auth), db=Depends(db_session)):
    """BitLocker recovery keys from AD. Every look is written to the audit log."""
    from .collectors import ad as adc
    from .scanning import ad_action_cfg
    dev = _device(db, hostname)
    if not dev.ad_dn:
        raise HTTPException(400, "This PC isn't in the AD data.")
    try:
        keys = adc.bitlocker_keys(ad_action_cfg(db, dev.ad_dn), dev.ad_dn)
        msg = f"{len(keys)} key(s) shown" + ("" if all(k["readable"] for k in keys) else "; some unreadable (no permission)")
    except Exception as exc:
        keys, msg = None, f"Failed: {exc}"
    db.add(AuditLog(actor=user, action="pc.bitlocker_keys", target=f"computer:{dev.hostname}", result=msg[:500]))
    db.commit()
    if keys is None:
        raise HTTPException(502, msg)
    return keys


def _ad_cfg(db, dev):
    from .scanning import ad_action_cfg
    if not dev.ad_dn:
        raise HTTPException(400, "This PC isn't in the AD data.")
    try:
        return ad_action_cfg(db, dev.ad_dn)
    except Exception as exc:
        raise HTTPException(400, str(exc))


def _ad_call(fn):
    try:
        return fn()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Active Directory: {str(exc)[:300]}")


@app.get("/api/devices/{hostname}/ad", dependencies=UI)
def device_ad(hostname: str, db=Depends(db_session)):
    from .collectors import ad as adc
    dev = _device(db, hostname)
    cfg = _ad_cfg(db, dev)
    return _ad_call(lambda: adc.computer_info(cfg, dev.ad_dn))


@app.get("/api/devices/{hostname}/ad/ous", dependencies=UI)
def device_ad_ous(hostname: str, db=Depends(db_session)):
    from .collectors import ad as adc
    dev = _device(db, hostname)
    cfg = _ad_cfg(db, dev)
    return _ad_call(lambda: adc.list_ous(cfg, dev.ad_dn))


@app.get("/api/devices/{hostname}/ad/groups", dependencies=UI)
def device_ad_groups(hostname: str, q: str = "", db=Depends(db_session)):
    from .collectors import ad as adc
    dev = _device(db, hostname)
    cfg = _ad_cfg(db, dev)
    return _ad_call(lambda: adc.find_groups(cfg, dev.ad_dn, q))


class AdOpIn(BaseModel):
    op: str
    value: str = ""


@app.post("/api/devices/{hostname}/ad")
def device_ad_change(hostname: str, body: AdOpIn, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    _ad_cfg(db, dev)
    return _remote(lambda: remote.ad_change(db, dev, user, body.op, body.value))


@app.post("/api/devices/{hostname}/screenshot")
def device_screenshot(hostname: str, user=Depends(ui_auth), db=Depends(db_session)):
    from . import remote
    dev = _device(db, hostname)
    return _remote(lambda: remote.screenshot(db, dev, user))


@app.get("/api/devices/{hostname}/audit")
def device_audit(hostname: str, live: bool = False, user=Depends(ui_auth), db=Depends(db_session)):
    """One printable page with everything known about the PC (and, with live=1, a few checks run on it now)."""
    from . import audit
    data = device(hostname, db)
    return Response(audit.render(db, _device(db, hostname), data, live, user), media_type="text/html")


class FixIn(BaseModel):
    action: str
    value: str | None = None
    adhoc: AdhocIn | None = None     # action "script" without a saved script: a one-off command
    tool: dict | None = None         # action "tool": {"tool": ..., "args": {...}} (remote.BULK)


@app.post("/api/devices/{hostname}/fix")
def device_fix(hostname: str, body: FixIn, user=Depends(ui_auth), db=Depends(db_session)):
    return fixes.run(db, _device(db, hostname), body.action, user, body.value, body.tool if body.action == "tool" else body.adhoc.model_dump() if body.adhoc else None)


class BulkFixIn(BaseModel):
    action: str
    hostnames: list[str] = []
    group: str | None = None           # every computer in this group, as well as hostnames
    value: str | None = None
    adhoc: AdhocIn | None = None
    tool: dict | None = None


@app.post("/api/fix/bulk")
def bulk_fix(body: BulkFixIn, user=Depends(ui_auth)):
    if body.action not in fixes.ACTIONS:
        raise HTTPException(400, "unknown fix")
    hosts = list(body.hostnames)
    if body.group:
        with SessionLocal() as db:
            hosts += groups.hosts(db, body.group)
    if not hosts:
        raise HTTPException(400, "pick at least one computer")
    if len(set(hosts)) > 2000:
        raise HTTPException(400, "at most 2,000 computers at a time")
    try:
        n = fixes.run_many(hosts, body.action, user, body.value, body.tool if body.action == "tool" else body.adhoc.model_dump() if body.adhoc else None)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "count": n, "output": f"Queued for {n} computer{'s' if n != 1 else ''}. Track it in Software > Deployments; "
                                               "PCs that are offline get it when they come back online."}


def _dep_out(x) -> dict:
    t = lambda v: jobs._local(v).isoformat(sep=" ", timespec="minutes") if v else None  # noqa: E731
    return {"id": x.id, "hostname": x.hostname, "action": x.action, "value": x.value, "label": x.label, "who": x.who,
            "status": x.status, "message": x.message, "created": t(x.created), "started": t(x.started),
            "finished": t(x.finished), "attempts": x.attempts, "next_try": t(x.next_try), "expires": t(x.expires),
            "waiting_offline": x.status == "queued" and (x.attempts or 0) > 0}


@app.get("/api/deployments", dependencies=UI)
def deployments(status: str | None = None, host: str | None = None, days: int = 30, db=Depends(db_session)):
    from datetime import timedelta
    from sqlalchemy import func
    since = utcnow() - timedelta(days=max(1, min(days, 365)))
    q = select(Deployment).where((Deployment.created >= since) | Deployment.status.in_(("queued", "sending", "running")))
    if status:
        q = q.where(Deployment.status.in_(status.split(",")))
    if host:
        q = q.where(Deployment.hostname.ilike(f"%{host}%"))
    rows = [_dep_out(x) for x in db.scalars(q.order_by(Deployment.created.desc(), Deployment.id.desc()).limit(5000))]
    counts = dict(db.execute(select(Deployment.status, func.count()).where(
        (Deployment.created >= since) | Deployment.status.in_(("queued", "sending", "running"))).group_by(Deployment.status)).all())
    return {"rows": rows, "counts": counts, "queue_days": fixes.queue_days(db), "parallel": fixes.parallel(db)}


@app.post("/api/deployments/{did}/cancel")
def deployment_cancel(did: int, actor=Depends(ui_auth), db=Depends(db_session)):
    d = db.get(Deployment, did)
    if not d or d.status != "queued":
        raise HTTPException(400, "only a deployment still waiting in the queue can be cancelled")
    d.status, d.finished, d.message = "cancelled", utcnow(), f"Cancelled by {actor}"
    db.add(AuditLog(actor=actor, action="fix.cancel", target=f"computer:{d.hostname}", result=d.label))
    db.commit()
    return {"ok": True, "output": f"{d.label} on {d.hostname} cancelled."}


@app.post("/api/deployments/{did}/retry")
def deployment_retry(did: int, actor=Depends(ui_auth), db=Depends(db_session)):
    d = db.get(Deployment, did)
    if not d or d.status not in ("failed", "expired", "cancelled"):
        raise HTTPException(400, "only a failed, expired or cancelled deployment can be retried")
    snap = (d.label, d.payload) if d.action in ("script", "tool") and d.payload else None
    try:
        n = fixes.run_many([d.hostname], d.action, actor, d.value, snapshot=snap)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "output": f"{d.label} on {d.hostname} queued again." if n else "That computer no longer exists."}


@app.get("/api/deployments/{did}", dependencies=UI)
def deployment_one(did: int, db=Depends(db_session)):
    d = db.get(Deployment, did)
    if not d:
        raise HTTPException(404, "not found")
    out = _dep_out(d)
    if d.payload:
        p = json.loads(d.payload)
        out["script"] = {"language": p.get("language"), "body": p.get("body"), "timeout": p.get("timeout")}
    return out


# ------------------------------------------------------------------ script library (run on one PC or many)
class ScriptIn(BaseModel):
    name: str
    description: str | None = None
    language: str = "powershell"
    body: str
    timeout_min: int = 30


def _script_out(x: Script, runs: dict) -> dict:
    t = lambda v: jobs._local(v).isoformat(sep=" ", timespec="minutes") if v else None  # noqa: E731
    return {"id": x.id, "name": x.name, "description": x.description, "language": x.language, "body": x.body,
            "timeout_min": x.timeout_min, "updated": t(x.updated), "who": x.who, **runs.get(str(x.id), {"runs": 0, "ok": 0, "failed": 0})}


@app.get("/api/scripts", dependencies=UI)
def scripts_list(db=Depends(db_session)):
    from sqlalchemy import func
    runs: dict = {}
    for v, st, n in db.execute(select(Deployment.value, Deployment.status, func.count()).where(Deployment.action == "script",
                                                                                              Deployment.value.is_not(None))
                               .group_by(Deployment.value, Deployment.status)):
        r = runs.setdefault(v, {"runs": 0, "ok": 0, "failed": 0})
        r["runs"] += n
        if st == "success":
            r["ok"] += n
        elif st in ("failed", "expired"):
            r["failed"] += n
    return {"scripts": [_script_out(x, runs) for x in db.scalars(select(Script).order_by(Script.name))],
            "languages": fixes.LANGS, "groups": groups.names(db)}


def _script_save(db, x: Script, body: ScriptIn, actor: str) -> dict:
    name = body.name.strip()
    if not name or len(name) > 128:
        raise HTTPException(400, "give the script a name (up to 128 characters)")
    try:
        fixes.check_script(body.language, body.body, body.timeout_min)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    clash = db.scalar(select(Script.id).where(Script.name == name))
    if clash and clash != x.id:
        raise HTTPException(400, "another script already has that name")
    x.name, x.description, x.language, x.body = name, (body.description or "").strip() or None, body.language, body.body
    x.timeout_min, x.updated, x.who = body.timeout_min, utcnow(), actor[:64]
    db.add(x)
    db.flush()
    db.add(AuditLog(actor=actor, action="script.save", target=f"script:{x.id}", result=f"{name} ({fixes._digest(json.dumps({'language': x.language, 'body': x.body}))})"))
    db.commit()
    return {"ok": True, "id": x.id}


@app.post("/api/scripts")
def script_create(body: ScriptIn, actor=Depends(ui_auth), db=Depends(db_session)):
    return _script_save(db, Script(created=utcnow()), body, actor)


@app.put("/api/scripts/{sid}")
def script_update(sid: int, body: ScriptIn, actor=Depends(ui_auth), db=Depends(db_session)):
    x = db.get(Script, sid)
    if not x:
        raise HTTPException(404, "not found")
    return _script_save(db, x, body, actor)


@app.delete("/api/scripts/{sid}")
def script_delete(sid: int, actor=Depends(ui_auth), db=Depends(db_session)):
    x = db.get(Script, sid)
    if not x:
        raise HTTPException(404, "not found")
    db.add(AuditLog(actor=actor, action="script.delete", target=f"script:{sid}", result=x.name))
    db.delete(x)      # pushes already queued keep their own copy of the text
    from sqlalchemy import update
    db.execute(update(Deployment).where(Deployment.action == "script", Deployment.value == str(sid)).values(value=None))
    db.commit()
    return {"ok": True}


class DeploySettingsIn(BaseModel):
    queue_days: int
    parallel: int


@app.put("/api/deployments/settings")
def deployment_settings(body: DeploySettingsIn, actor=Depends(ui_auth), db=Depends(db_session)):
    if not 1 <= body.queue_days <= 60 or not 1 <= body.parallel <= 32:
        raise HTTPException(400, "keep waiting 1-60 days, and send to 1-32 PCs at once")
    set_setting(db, "fix:queue_days", str(body.queue_days))
    set_setting(db, "fix:parallel", str(body.parallel))
    db.add(AuditLog(actor=actor, action="fix.settings", target="deployments", result=f"days={body.queue_days} parallel={body.parallel}"))
    db.commit()
    return {"ok": True}


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


# ------------------------------------------------------------------ HTTPS certificate
def _tls_folder() -> Path:
    return Path(settings.tls_cert).parent if settings.tls_cert else auth.data_dir()


@app.get("/api/tls", dependencies=UI)
def tls_info():
    from . import tlscert
    return tlscert.info(settings.tls_cert)


@app.get("/api/tls/cert.cer", dependencies=UI)
def tls_download():
    """The certificate the dashboard serves, to trust on PCs (GPO: Trusted Root Certification Authorities)."""
    if not settings.tls_cert or not Path(settings.tls_cert).exists():
        raise HTTPException(404, "HTTPS isn't turned on")
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    leaf = x509.load_pem_x509_certificates(Path(settings.tls_cert).read_bytes())[0]
    return Response(leaf.public_bytes(Encoding.PEM), media_type="application/x-x509-ca-cert",
                    headers={"Content-Disposition": 'attachment; filename="NetInventory.cer"'})


@app.post("/api/tls/csr")
def tls_csr(user=Depends(ui_auth), db=Depends(db_session)):
    from . import tlscert
    csr = tlscert.make_csr(str(_tls_folder()))
    db.add(AuditLog(actor=user, action="tls.request", target="https", result="certificate request created"))
    db.commit()
    return Response(csr, media_type="application/pkcs10",
                    headers={"Content-Disposition": 'attachment; filename="NetInventory.req"'})


class TlsIn(BaseModel):
    data: str                 # base64 of the uploaded file
    password: str | None = None


def _restart_soon() -> None:
    """Exit so the service wrapper (WinSW, restart on failure) starts the app again with the new certificate."""
    import os, time
    def go():
        time.sleep(2)
        os._exit(3)
    threading.Thread(target=go, daemon=True).start()


@app.post("/api/tls/import")
def tls_import(body: TlsIn, user=Depends(ui_auth), db=Depends(db_session)):
    import base64, os
    from . import tlscert
    if not settings.tls_cert:
        raise HTTPException(400, "HTTPS isn't turned on in config.toml")
    try:
        subject = tlscert.install(str(_tls_folder()), base64.b64decode(body.data), body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.add(AuditLog(actor=user, action="tls.install", target="https", result=subject[:200]))
    db.commit()
    as_service = os.name == "nt" and os.environ.get("NETINV_CONFIG")
    if as_service:
        _restart_soon()
    return {"ok": True, "output": f"Installed {subject}. " + (
        "NetInventory restarts in a few seconds; reload the page in about 30 seconds." if as_service
        else "Restart NetInventory to use it.")}


# ------------------------------------------------------------------ scanning exclusions
class ExclusionIn(BaseModel):
    kind: str
    value: str
    note: str | None = None


@app.get("/api/exclusions", dependencies=UI)
def list_exclusions(db=Depends(db_session)):
    rows = db.scalars(select(ScanExclusion).order_by(ScanExclusion.kind, ScanExclusion.value))
    return {"kinds": exclusions.KINDS, "rows": [{"id": r.id, "kind": r.kind, "value": r.value, "note": r.note,
                                                 "created": r.created, "created_by": r.created_by} for r in rows]}


@app.post("/api/exclusions")
def add_exclusion(body: ExclusionIn, user=Depends(ui_auth), db=Depends(db_session)):
    try:
        value = exclusions.validate(body.kind, body.value)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if db.scalar(select(ScanExclusion).where(ScanExclusion.kind == body.kind, ScanExclusion.value == value)):
        raise HTTPException(400, "that exclusion already exists")
    r = ScanExclusion(kind=body.kind, value=value, note=(body.note or "").strip()[:255] or None, created_by=user[:64])
    db.add(r)
    db.add(AuditLog(actor=user, action="exclusion.add", target=f"{body.kind}:{value[:200]}", result=r.note or "ok"))
    db.commit()
    return {"ok": True, "id": r.id}


@app.delete("/api/exclusions/{eid}")
def delete_exclusion(eid: int, user=Depends(ui_auth), db=Depends(db_session)):
    r = db.get(ScanExclusion, eid)
    if r:
        db.add(AuditLog(actor=user, action="exclusion.delete", target=f"{r.kind}:{r.value[:200]}", result="ok"))
        db.delete(r)
        db.commit()
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
    done = ruled = 0
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
            if not _remove_group(db, dev, body.value):
                ruled += 1
                continue
        elif body.action == "set_state" and body.value:
            dev.state = body.value
        else:
            raise HTTPException(400, "unknown action")
        done += 1
    db.commit()
    out = {"ok": True, "count": done}
    if ruled:
        out["note"] = (f"{ruled} computer{'s are' if ruled != 1 else ' is'} in {body.value} because of the group's rules "
                       "and stayed. Edit the group's conditions under Groups to leave them out.")
    return out


@app.get("/api/status", dependencies=UI)
def status():
    import time as _t
    return {"running": [{"job": k, "seconds": int(_t.time() - v)} for k, v in jobs.RUNNING.items()],
            "queued": len(jobs.QUEUE)}


@app.get("/api/scanning", dependencies=UI)
def scanning_view(db=Depends(db_session)):
    """The Scanning view: what runs now (with progress), what waits and when it should start, what finished lately."""
    import heapq
    import time as _t
    from . import progress
    now = _t.time()
    alljobs = {j.id: j for j in db.scalars(select(ScanJob))}
    running = progress.snapshot()
    cap = jobs.max_concurrent(db)
    # When does each queued job start? Fill the slots in queue order: a running job frees its slot at its ETA
    # (5 min if unknown), a queued job then holds it for as long as its last run took.
    free = [now + (r["eta"] if r["eta"] is not None else 300) for r in running if r["job_id"]]
    free = sorted(free)[:cap] + [now] * max(0, cap - len(free))
    heapq.heapify(free)
    queued = []
    for pos, (jid, since, who) in enumerate(jobs.queue_snapshot()):
        j = alljobs.get(jid)
        start = heapq.heappop(free)
        heapq.heappush(free, start + ((j.last_seconds if j and j.last_seconds else 300)))
        queued.append({"job_id": jid, "name": j.name if j else f"#{jid}", "position": pos + 1, "who": who,
                       "waiting": int(now - since), "starts_in": max(0, int(start - now)),
                       "expected": j.last_seconds if j else None})
    upcoming = []
    for j in alljobs.values():
        if j.enabled and not jobs.JOB_STATE.get(j.id):
            nxt = jobs.next_run(j)
            if nxt:
                upcoming.append({"job_id": j.id, "name": j.name, "next_run": nxt.isoformat(sep=" ", timespec="minutes"),
                                 "schedule": jobs.describe(j), "expected": j.last_seconds})
    upcoming.sort(key=lambda u: u["next_run"])
    recent = []
    for r in db.scalars(select(CollectorRun).where(CollectorRun.finished.is_not(None))
                        .order_by(CollectorRun.finished.desc()).limit(20)):
        recent.append({"name": _run_name(db, r.collector), "job_id": int(r.collector[4:]) if r.collector.startswith("job:") and r.collector[4:].isdigit() else None,
                       "finished": jobs._local(r.finished).isoformat(sep=" ", timespec="minutes"),
                       "seconds": int((r.finished - r.started).total_seconds()), "ok": r.ok,
                       "cancelled": (r.message or "").startswith("Cancelled by"), "result": r.message})
    return {"max_concurrent": cap, "running": running, "queued": queued, "upcoming": upcoming[:8], "recent": recent}


@app.post("/api/scanning/{jid}/cancel")
def scanning_cancel(jid: int, actor=Depends(ui_auth), db=Depends(db_session)):
    what = jobs.cancel_job(jid, actor)
    if what is None:
        raise HTTPException(400, "that job isn't queued or running")
    j = db.get(ScanJob, jid)
    db.add(AuditLog(actor=actor, action="job.cancel", target=f"job:{(j.name if j else jid)}"[:120], result=what))
    db.commit()
    return {"ok": True, "output": f"{j.name if j else 'Job'}: {what}."}


@app.post("/api/scanning/{jid}/front", dependencies=UI)
def scanning_front(jid: int):
    if not jobs.move_to_front(jid):
        raise HTTPException(400, "that job isn't waiting in the queue")
    return {"ok": True, "output": "Moved to the front of the queue."}


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
            "logons": logons, "audit": audit, "dn": ad.dn if ad else None,
            "ni_groups": sorted(n for (n,) in db.execute(select(UserGroup.name).where(UserGroup.user_id == ad.id))) if ad else []}


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


class DrillRow(BaseModel):
    row: dict


@app.post("/api/library/{rid}/drill", dependencies=UI)
def library_drill(rid: str, body: DrillRow, db=Depends(db_session)):
    try:
        return library.drill(db, rid, body.row)
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


@app.get("/api/service-account", dependencies=UI)
def service_account():
    """The Windows account NetInventory runs as: offered as the credential "This server's own account" (id 0)."""
    return {"id": scanning.SERVICE_CRED_ID, "account": scanning.service_account()}


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
    from .scanning import SERVICE_CRED_ID, cred_cfg, service_cfg
    c = None if cid == SERVICE_CRED_ID else db.get(Credential, cid)
    if not c and cid != SERVICE_CRED_ID:
        raise HTTPException(404)
    host = body.host.strip()
    if not actions.HOST_RE.match(host):
        raise HTTPException(400, "invalid host")
    cfg = cred_cfg(c) if c else service_cfg()
    results = []
    if not c or c.kind == "windows":
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
    collect: list[str] | None = None     # whole-domain targets: "computers", "users"; IP ranges: "ping", "snmp", "winrm"


def _target_out(t: ScanTarget) -> dict:
    base, collect, err = None, None, None
    if t.kind == "ip_range":
        collect = [m for m in scanning.IP_METHODS if m in (t.collect or "").split(",")] or None
    else:
        try:
            _, _, base, cs = scanning.ad_scope(t)
            collect = [c for c in ("computers", "users") if c in cs]
        except ValueError as exc:
            err = str(exc)
    return {"id": t.id, "kind": t.kind, "value": t.value, "server": t.server, "enabled": t.enabled,
            "search_base": base, "collect": collect, "scope_error": err,
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
    kind, value = body.kind, body.value.strip()
    if kind == "ad_domain" and ("/" in value or "=" in value):   # an OU typed into "whole domain": scan just that OU
        kind = "ad_user_path" if body.collect == ["users"] else "ad_computer_path"
    if kind in ("ad_computer_path", "ad_user_path"):
        try:
            value = scanning.normalize_dn(value)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    elif kind == "ad_domain":
        import re as _re
        value = value.lower().strip(".")
        if not _re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", value):
            raise HTTPException(400, "Type the domain's DNS name, e.g. corp.example.com")
    collect = None
    if kind == "ip_range":
        collect = [m for m in scanning.IP_METHODS if m in (body.collect if body.collect is not None else scanning.IP_METHODS)]
        if not collect:
            raise HTTPException(400, "Tick at least one of ping, SNMP or WinRM")
    if kind == "ad_domain":
        collect = [c for c in ("computers", "users") if c in (body.collect if body.collect is not None else ["computers", "users"])]
        if not collect:
            raise HTTPException(400, "Tick computers, users or both")
    t = db.get(ScanTarget, tid) if tid else ScanTarget()
    if t is None:
        raise HTTPException(404)
    t.kind, t.value, t.server, t.enabled = kind, value, (body.server or "").strip() or None, body.enabled
    t.collect = ",".join(collect) if collect else None
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


# ----------------------------------------------------------------- scan schedule (see jobs.py)
JOB_COLLECTORS = {"ad": "Active Directory import (computers, users, DCs)", "snmp": "IP ranges (ping, SNMP, WinRM sweep: see below)",
                  "pcs": "PC inventory over WinRM", "pcs_updates": "PC inventory plus pending Windows updates",
                  "dc_logons": "Logons from domain controllers"}


def _job_out(j: ScanJob, tnames: dict) -> dict:
    ids = [int(x) for x in (j.target_ids or "").split(",") if x.strip().isdigit()]
    nxt = jobs.next_run(j)
    return {"id": j.id, "name": j.name, "enabled": j.enabled, "target_ids": ids,
            "scope": (", ".join(tnames.get(i, f"#{i}") for i in ids) or "all scan targets")
                     + (f"; PCs: only group {j.group_name}" if j.group_name else ""),
            "collectors": [c for c in (j.collectors or "").split(",") if c], "every_min": j.every_min, "at_time": j.at_time,
            "days": j.days or "0123456", "window_start": j.window_start, "window_end": j.window_end,
            "max_parallel": j.max_parallel, "ip_methods": [m for m in (j.ip_methods or "").split(",") if m],
            "group_name": j.group_name,
            "schedule": jobs.describe(j), "state": jobs.JOB_STATE.get(j.id),
            "next_run": nxt.isoformat(sep=" ", timespec="minutes") if nxt else None,
            "last_run": jobs._local(j.last_run).isoformat(sep=" ", timespec="minutes") if j.last_run else None,
            "last_ok": j.last_ok, "last_result": j.last_result, "last_seconds": j.last_seconds,
            "ran_by": j.ran_by if j.ran_at and (not j.last_run or j.ran_at >= j.last_run) else None}


@app.get("/api/jobs", dependencies=UI)
def list_jobs(db=Depends(db_session)):
    jobs.migrate_schedule(db)
    tnames = {t.id: f"{t.value}" for t in db.scalars(select(ScanTarget))}
    from . import reach
    return {"max_concurrent": jobs.max_concurrent(db), "collectors": JOB_COLLECTORS, "reach_interval": reach.interval(db),
            "groups": groups.names(db),
            "jobs": [_job_out(j, tnames) for j in db.scalars(select(ScanJob).order_by(ScanJob.name))]}


class JobIn(BaseModel):
    name: str
    enabled: bool = True
    target_ids: list[int] = []
    collectors: list[str]
    every_min: int | None = None
    at_time: str | None = None
    days: str = "0123456"
    window_start: int | None = None
    window_end: int | None = None
    max_parallel: int | None = None
    ip_methods: list[str] = []          # empty = each IP range target's own ticks
    group_name: str | None = None       # PC scans reach only this group's computers


def _check_job(body: JobIn, db) -> None:
    import re as _re
    if not body.name.strip() or len(body.name) > 120:
        raise HTTPException(400, "give the job a name")
    if not body.collectors or any(c not in JOB_COLLECTORS for c in body.collectors):
        raise HTTPException(400, "pick at least one thing to scan")
    if body.at_time and not _re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", body.at_time):
        raise HTTPException(400, "time of day must look like 02:30")
    if body.every_min is not None and not body.at_time and not 5 <= body.every_min <= 10080:
        raise HTTPException(400, "repeat every 5 minutes to 7 days")
    if not _re.fullmatch(r"[0-6]{1,7}", body.days or ""):
        raise HTTPException(400, "pick at least one day")
    for h in (body.window_start, body.window_end):
        if h is not None and not 0 <= h <= 23:
            raise HTTPException(400, "time window hours are 0-23")
    if body.max_parallel is not None and not 1 <= body.max_parallel <= 64:
        raise HTTPException(400, "PCs at once: 1 to 64")
    known = {i for (i,) in db.execute(select(ScanTarget.id))}
    if any(i not in known for i in body.target_ids):
        raise HTTPException(400, "a chosen scan target no longer exists")
    if body.group_name and body.group_name not in groups.names(db):
        raise HTTPException(400, "the chosen group no longer exists")
    if body.group_name and not {"pcs", "pcs_updates"} & set(body.collectors):
        raise HTTPException(400, "a group limits PC scans: tick PCs (inventory) or Windows updates, or clear the group")


@app.post("/api/jobs")
def save_job(body: JobIn, jid: int | None = None, actor=Depends(ui_auth), db=Depends(db_session)):
    _check_job(body, db)
    j = db.get(ScanJob, jid) if jid else ScanJob()
    if j is None:
        raise HTTPException(404)
    dup = db.scalar(select(ScanJob).where(ScanJob.name == body.name.strip()))
    if dup and dup.id != j.id:
        raise HTTPException(400, "another job has that name")
    j.name, j.enabled = body.name.strip(), body.enabled
    j.target_ids = ",".join(str(i) for i in sorted(set(body.target_ids))) or None
    j.collectors = ",".join(c for c in jobs.COLLECTOR_ORDER if c in body.collectors)
    j.at_time = body.at_time or None
    j.every_min = None if j.at_time else body.every_min
    j.days = "".join(sorted(set(body.days)))
    j.window_start, j.window_end = body.window_start, body.window_end
    j.max_parallel = body.max_parallel
    j.ip_methods = ",".join(m for m in scanning.IP_METHODS if m in body.ip_methods) or None
    j.group_name = (body.group_name or "").strip() or None
    db.add(j)
    db.add(AuditLog(actor=actor, action="job.save", target=f"job:{j.name[:100]}", result=jobs.describe(j)))
    db.commit()
    return {"ok": True, "id": j.id}


@app.delete("/api/jobs/{jid}")
def delete_job(jid: int, actor=Depends(ui_auth), db=Depends(db_session)):
    j = db.get(ScanJob, jid)
    if j:
        db.add(AuditLog(actor=actor, action="job.delete", target=f"job:{j.name[:100]}", result="ok"))
        db.delete(j)
        db.commit()
    return {"ok": True}


@app.post("/api/jobs/{jid}/run")
def run_job_now(jid: int, actor=Depends(ui_auth), db=Depends(db_session)):
    j = db.get(ScanJob, jid)
    if not j:
        raise HTTPException(404)
    if jobs.JOB_STATE.get(jid):
        raise HTTPException(400, f"{j.name} is already {jobs.JOB_STATE[jid]}")
    db.add(AuditLog(actor=actor, action="job.run", target=f"job:{j.name[:100]}", result="started"))
    db.commit()
    threading.Thread(target=jobs.run_scan_job, args=(jid, actor), daemon=True).start()
    return {"ok": True, "output": f"{j.name} started (or queued if other jobs are running)."}


@app.get("/api/jobs/{jid}/history", dependencies=UI)
def job_history(jid: int, db=Depends(db_session)):
    rows = db.scalars(select(CollectorRun).where(CollectorRun.collector == f"job:{jid}")
                      .order_by(CollectorRun.started.desc()).limit(30))
    return [{"started": jobs._local(r.started).isoformat(sep=" ", timespec="minutes"),
             "seconds": int((r.finished - r.started).total_seconds()) if r.finished else None,
             "ok": r.ok, "result": r.message} for r in rows]


class JobSettingsIn(BaseModel):
    max_concurrent: int
    reach_interval: int | None = None


@app.put("/api/jobs/settings")
def job_settings(body: JobSettingsIn, actor=Depends(ui_auth), db=Depends(db_session)):
    if not 1 <= body.max_concurrent <= 8:
        raise HTTPException(400, "1 to 8 jobs at once")
    set_setting(db, "jobs:max_concurrent", str(body.max_concurrent))
    if body.reach_interval is not None:
        if not 0 <= body.reach_interval <= 1440:
            raise HTTPException(400, "status check: 0 (off) to 1440 minutes")
        set_setting(db, "reach:interval_min", str(body.reach_interval))
    db.add(AuditLog(actor=actor, action="job.settings", target="schedule", result=f"max_concurrent={body.max_concurrent} reach_interval={body.reach_interval}"))
    db.commit()
    return {"ok": True}


# ----------------------------------------------------------------- NetInventory Agent (see agentapi.py)
AGENT_MSI = "https://github.com/userxx09-afk/prod/releases/download/lan-latest/NetInventory-Agent.msi"


def _agent_out(a) -> dict:
    t = lambda v: jobs._local(v).isoformat(sep=" ", timespec="minutes") if v else None  # noqa: E731
    return {"id": a.id, "hostname": a.hostname, "status": a.status, "note": a.note, "enrolled": t(a.enrolled),
            "last_seen": t(a.last_seen), "last_inventory": t(a.last_inventory), "last_ip": a.last_ip, "version": a.version,
            "run_as": a.run_as, "inventory_requested": a.want_inventory}


@app.get("/api/agents", dependencies=UI)
def agents_list(request: Request, db=Depends(db_session)):
    from . import tlscert
    from .db import Agent
    tls = tlscert.info(settings.tls_cert)
    return {"token": {"set": bool(get_setting(db, "agent:token_hash", None)), "created": get_setting(db, "agent:token_created", None),
                      "hint": get_setting(db, "agent:token_hint", None)},
            "approve": agentapi.approve_mode(db), "inventory_hours": agentapi.inventory_hours(db),
            "pin": tls.get("sha256"), "https": tls.get("https", False), "server": str(request.base_url).rstrip("/"),
            "msi_url": "/api/agents/msi" if agentpush.msi_path() else AGENT_MSI, "msi_local": bool(agentpush.msi_path()),
            "msi_folder": str(agentpush.msi_path().parent) if agentpush.msi_path() else None,
            "agents": [_agent_out(a) for a in db.scalars(select(Agent).order_by(Agent.status != "pending", Agent.hostname))]}


@app.post("/api/agents/token")
def agents_token(actor=Depends(ui_auth), db=Depends(db_session)):
    tok = agentapi.new_token(db)
    db.add(AuditLog(actor=actor, action="agent.token", target="enrollment", result="new token"))
    db.commit()
    return {"token": tok}


@app.delete("/api/agents/token")
def agents_token_off(actor=Depends(ui_auth), db=Depends(db_session)):
    for k in ("agent:token_hash", "agent:token_hint", "agent:token_created"):
        set_setting(db, k, "")
    db.add(AuditLog(actor=actor, action="agent.token", target="enrollment", result="turned off"))
    db.commit()
    return {"ok": True}


class AgentSettingsIn(BaseModel):
    approve: str
    inventory_hours: int


@app.put("/api/agents/settings")
def agents_settings(body: AgentSettingsIn, actor=Depends(ui_auth), db=Depends(db_session)):
    if body.approve not in agentapi.APPROVE or not 1 <= body.inventory_hours <= 336:
        raise HTTPException(400, "bad settings")
    set_setting(db, "agent:approve", body.approve)
    set_setting(db, "agent:inventory_hours", str(body.inventory_hours))
    db.add(AuditLog(actor=actor, action="agent.settings", target="agent", result=f"approve={body.approve} hours={body.inventory_hours}"))
    db.commit()
    return {"ok": True}


@app.post("/api/agents/{aid}/{what}")
def agents_action(aid: int, what: str, actor=Depends(ui_auth), db=Depends(db_session)):
    from .db import Agent
    a = db.get(Agent, aid)
    if not a or what not in ("approve", "revoke", "inventory", "delete"):
        raise HTTPException(404)
    if what == "approve":
        for other in db.scalars(select(Agent).where(Agent.hostname == a.hostname, Agent.status == "active", Agent.id != a.id)):
            other.status, other.note = "revoked", f"replaced by agent {a.agent_id[:8]} (approved by {actor})"
        a.status, a.note, a.want_inventory = "active", None, True
    elif what == "revoke":
        a.status, a.note = "revoked", f"revoked by {actor}"
    elif what == "inventory":
        a.want_inventory = True
    else:
        db.delete(a)
    db.add(AuditLog(actor=actor, action=f"agent.{what}", target=f"computer:{a.hostname}", result="ok"))
    db.commit()
    return {"ok": True, "output": {"approve": f"{a.hostname} approved.", "revoke": f"{a.hostname}'s agent revoked: it can't report any more.",
                                   "inventory": f"{a.hostname} sends its inventory within 5 minutes.", "delete": "Removed."}[what]}


@app.get("/api/agents/msi", dependencies=UI)
def agents_msi():
    """The agent MSI that came with this server, so nobody has to fetch it from the internet."""
    p = agentpush.msi_path()
    if not p:
        raise HTTPException(404, "This server has no agent MSI; download it from the prod release.")
    return FileResponse(p, media_type="application/x-msi", filename="NetInventory-Agent.msi",
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.get("/api/agents/push", dependencies=UI)
def agents_push_info(request: Request, db=Depends(db_session)):
    return agentpush.status(db, str(request.base_url))


class AgentPushIn(BaseModel):
    hostnames: list[str] = []
    group: str | None = None
    run_as: str = "LOCALSERVICE"
    server_url: str
    remove: bool = False
    credential_id: int | None = None      # sign in to the PCs with: None = scan targets' credentials, 0 = this server's account


@app.post("/api/agents/push")
def agents_push(body: AgentPushIn, user=Depends(ui_auth)):
    """Install (or remove) the agent on PCs over WinRM through the deployment queue (agentpush.py)."""
    with SessionLocal() as db:
        if not body.remove:
            try:
                url = agentpush.check_url(body.server_url)
            except ValueError as exc:
                raise HTTPException(400, str(exc))
            if not agentpush.pin():
                raise HTTPException(400, "This server isn't on HTTPS. Agents only talk HTTPS: set up the certificate in Settings first.")
            if body.run_as not in agentpush.RUN_AS:
                raise HTTPException(400, "bad account")
            if get_setting(db, "agent:server_url", None) != url:
                set_setting(db, "agent:server_url", url)
                db.add(AuditLog(actor=user, action="agent.settings", target="agent", result=f"server address for pushes: {url}"))
            db.commit()
        if body.credential_id is not None:
            try:
                fixes.cred_for_push(db, body.credential_id)
            except PermissionError as exc:
                raise HTTPException(400, str(exc))
        hosts = list(body.hostnames)
        if body.group:
            hosts += groups.hosts(db, body.group)
    if not hosts:
        raise HTTPException(400, "pick at least one computer")
    if len(set(hosts)) > 2000:
        raise HTTPException(400, "at most 2,000 computers at a time")
    try:
        n = fixes.run_many(hosts, "agent_remove" if body.remove else "agent_install", user, None if body.remove else body.run_as,
                           **({"cred_id": body.credential_id} if body.credential_id is not None else {}))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "count": n, "output": f"{'Removal' if body.remove else 'Agent install'} queued for {n} computer{'s' if n != 1 else ''}. "
                                               "Each PC's result shows in Software > Deployments and in the Agent column; "
                                               "offline PCs get it when they come back online."}


# ----------------------------------------------------------------- software updates (see updater.py)
@app.get("/api/update", dependencies=UI)
def update_status(db=Depends(db_session)):
    from . import instance
    return {**updater.status(db), "instances": instance.status(db)}


@app.post("/api/update/check", dependencies=UI)
def update_check(db=Depends(db_session)):
    from . import instance
    return {**updater.check(db), "instances": instance.status(db)}


class UpdateIn(BaseModel):
    force: bool = False       # reinstall the newest version even if already up to date (repair)


@app.post("/api/update/install")
def update_install(body: UpdateIn | None = None, actor=Depends(ui_auth), db=Depends(db_session)):
    force = bool(body and body.force)
    try:
        msg = updater.install(db, force=force)
        ok = True
    except Exception as exc:
        ok, msg = False, str(exc)
    target = updater.status(db).get("latest")
    db.add(AuditLog(actor=actor, action="update.reinstall" if force else "update.install",
                    target=f"version:{target}", result=msg[:500]))
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
