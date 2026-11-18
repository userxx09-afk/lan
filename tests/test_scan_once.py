"""One-time scans (0.30): type an IP, range, computer, user, OU or domain, pick scans and the sign-in account, run once.
Nothing is saved as a target or job; results land like any scan, the run is in Recently finished and the audit log.
LDAP, WinRM, SNMP and ping are faked. Run: python tests/test_scan_once.py (DATABASE_URL set, demo loaded)."""
import asyncio, logging, sys, time
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import func, select
import netinv.main as m
from netinv import oneshot, scanning
from netinv.collectors import ad, snmp, winrm
from netinv.db import AuditLog, CollectorRun, Credential, ScanJob, ScanTarget, SessionLocal

ad_cfgs, snmp_cfgs, pcs_cfgs, swept = [], [], [], []
ad.collect = lambda db, cfg: ad_cfgs.append(cfg) or "1 computers, 0 domain controllers, 1 users"
snmp.collect = lambda db, cfg: snmp_cfgs.append(cfg) or f"{len(cfg['targets'])} addresses polled"
winrm.collect_endpoints = lambda db, cfg, **kw: pcs_cfgs.append(cfg) or f"{len(cfg['hosts'])}/{len(cfg['hosts'])} computers collected"
import netinv.reach as reach
reach.sweep = lambda ips, parallel=128: swept.extend(ips) or {ip: (True, "icmp") for ip in ips}


async def fake_probe(ips, port, timeout=1.0, parallel=256):
    return list(ips)[:2]
scanning._probe = fake_probe
oneshot.socket.gethostbyname = lambda name: "10.9.9.9"


def wait(c, n_before):
    for _ in range(100):
        with SessionLocal() as db:
            rows = list(db.scalars(select(CollectorRun).where(CollectorRun.collector == "once").order_by(CollectorRun.id)))
        if len(rows) > n_before and rows[-1].finished:
            return rows[-1]
        time.sleep(0.05)
    raise AssertionError("one-time scan did not finish")


def runs():
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(CollectorRun).where(CollectorRun.collector == "once"))


with TestClient(m.app) as c:
    with SessionLocal() as db:
        n_targets = db.scalar(select(func.count()).select_from(ScanTarget))
        n_jobs = db.scalar(select(func.count()).select_from(ScanJob))
        pc = db.execute(m.text("SELECT hostname FROM devices WHERE fqdn LIKE '%.corp.example.com' ORDER BY hostname LIMIT 1")).scalar()
        user = db.execute(m.text("SELECT username FROM v_user_devices LIMIT 1")).scalar()
    cid = c.post("/api/credentials", json={"name": "Once admin", "kind": "windows", "username": "CORP\\once", "secret": "pw"}).json()["id"]
    sid = c.post("/api/credentials", json={"name": "Once SNMP", "kind": "snmp2", "secret": "public"}).json()["id"]

    o = c.get("/api/scan/once").json()
    assert "user" in o["kinds"] and "pcs" in o["scans"] and "corp.example.com" in o["domains"], o
    assert any(s["id"] == sid for s in o["snmp"])

    # preview: each value is recognised
    p = c.post("/api/scan/once/preview", json={"targets": f"10.0.0.5, 10.0.1.0/30 10.0.2.10-12\n{pc}\n{user}\nCORP\\{user}\n"
                                               "corp.example.com/Sites/PCs, corp.example.com, nope/", "scans": ["ping", "snmp", "pcs", "ad"]}).json()
    kinds = {e["input"]: (e["kind"], e["error"]) for e in p["targets"]}
    assert kinds["10.0.0.5"] == ("ip_range", None) and kinds["10.0.1.0/30"][0] == "ip_range" and kinds["10.0.2.10-12"][0] == "ip_range", kinds
    assert kinds[pc] == ("host", None) and kinds[user] == ("ad_user", None) and kinds[f"CORP\\{user}"] == ("ad_user", None), kinds
    assert kinds["corp.example.com/Sites/PCs"][0] == "ad_computer_path" and kinds["corp.example.com"][0] == "ad_domain", kinds
    assert kinds["nope/"][1], kinds
    assert p["steps"] == ["ad", "ping", "snmp", "pcs"], p["steps"]
    u = next(e for e in p["targets"] if e["input"] == f"CORP\\{user}")
    assert u["domain"] == "corp.example.com" and u["value"] == user, u

    # bad input is refused with the reason; nothing runs
    r = c.post("/api/scan/once", json={"targets": "10.0.0.0/8", "scans": ["ping"]})
    assert r.status_code == 400 and "more than" in r.json()["detail"], r.text
    r = c.post("/api/scan/once", json={"targets": "10.0.0.5", "scans": ["ad"]})
    assert r.status_code == 400 and "None of the ticked scans" in r.json()["detail"], r.text
    r = c.post("/api/scan/once", json={"targets": "10.0.0.5", "credential_id": 999999})
    assert r.status_code == 400, r.text

    # an IP range: ping + SNMP with the picked SNMP credential + WinRM inventory of what answers on 5985
    n0 = runs()
    r = c.post("/api/scan/once", json={"targets": "10.0.3.1-4", "scans": ["ping", "snmp", "pcs"], "credential_id": cid,
                                       "snmp_ids": [sid]}).json()
    assert r["ok"] and r["steps"] == ["snmp", "pcs"] and "signing in as" in r["output"], r
    run = wait(c, n0)
    assert run.ok, run.message
    assert snmp_cfgs[-1]["targets"] == ["10.0.3.1", "10.0.3.2", "10.0.3.3", "10.0.3.4"] and \
        snmp_cfgs[-1]["creds"] == [{"version": "2c", "community": "public"}], snmp_cfgs[-1]
    cfg = pcs_cfgs[-1]
    assert cfg["hosts"] == ["10.0.3.1", "10.0.3.2"] and cfg["creds"] == [{"user": "CORP\\once", "password": "pw"}], cfg
    assert not cfg["include_ad"], cfg
    assert "10.0.3.1-4" in run.message and "started by" in run.message and "Once admin" in run.message, run.message

    # a computer and a user by name: AD looks up just those two, ping and WinRM reach the PC and the user's PCs
    n0 = runs()
    r = c.post("/api/scan/once", json={"targets": f"{pc}, {user}", "scans": ["ping", "pcs", "ad"], "credential_id": 0}).json()
    assert r["steps"] == ["ad", "ping", "pcs"], r
    run = wait(c, n0)
    assert run.ok, run.message
    a = ad_cfgs[-1]
    assert a["domain"] == "corp.example.com" and a["computer_names"][0].upper() == pc.upper() and len(a["computer_names"]) > 1 and a["user_names"] == [user], a
    assert a["computers"] is False and a["users"] is False and a.get("integrated"), a     # no whole-domain import
    hosts = pcs_cfgs[-1]["hosts"]
    assert hosts and hosts[0].upper().startswith(pc.upper()) and len(hosts) >= 2, hosts       # + the user's PCs
    assert "also the PCs the user signed in to" in run.message, run.message

    # an OU: AD import of that OU and the PC inventory of its computers
    n0 = runs()
    c.post("/api/scan/once", json={"targets": "corp.example.com/Sites/PCs", "scans": ["ad", "pcs"]})
    run = wait(c, n0)
    assert ad_cfgs[-1]["computer_bases"] == ["OU=PCs,OU=Sites,DC=corp,DC=example,DC=com"], ad_cfgs[-1]
    assert pcs_cfgs[-1]["include_ad"] and pcs_cfgs[-1]["computer_bases"] == ["OU=PCs,OU=Sites,DC=corp,DC=example,DC=com"], pcs_cfgs[-1]

    # nothing was saved; the runs show in the Scanning view and the audit log
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(ScanTarget)) == n_targets
        assert db.scalar(select(func.count()).select_from(ScanJob)) == n_jobs
        acts = [x.action for x in db.scalars(select(AuditLog).where(AuditLog.action.like("scan.once%")))]
    assert acts.count("scan.once") == 3 and acts.count("scan.once.done") == 3, acts
    rec = c.get("/api/scanning").json()["recent"]
    assert any(x["name"] == "One-time scan" for x in rec), rec

    # the LDAP filters the AD collector builds for names
    searches = []

    class FakeConn:
        def unbind(self): pass
    import importlib
    import netinv.collectors.ad as adm
    importlib.reload(adm)
    adm.connect = lambda cfg: FakeConn()
    adm._search = lambda conn, base, flt, attrs: searches.append((base, flt)) or []
    adm._fsmo_roles = lambda conn, base: {}
    adm._global_catalogs = lambda conn, base: {}
    with SessionLocal() as db:
        adm.collect(db, {"domain": "corp.example.com", "computers": False, "users": False,
                         "computer_names": ["PC1"], "user_names": ["j*smith"]})
    flts = [f for _, f in searches]
    assert "(&(objectClass=computer)(|(name=PC1)))" in flts, flts
    assert "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=j\\2asmith)))" in flts, flts
    assert "(objectClass=computer)" not in flts and "(&(objectCategory=person)(objectClass=user))" not in flts, flts

print("one-time scan OK")
