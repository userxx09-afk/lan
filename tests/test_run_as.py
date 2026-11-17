"""Run modes (0.24): who a deployment signs in as and runs as on the PC, and the sign-in account for a scan run.
WinRM is faked. Run: python tests/test_run_as.py (DATABASE_URL set, demo loaded)."""
import base64, logging, re, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import fixes, scanning
from netinv.collectors import winrm

calls = []          # (addr, cfg, script)
NOBODY = set()      # PCs where nobody is signed in


def fake_run_ps(addr, cfg, script):
    calls.append((addr, cfg, script))
    if "NetInventory fix" in script and "Register-ScheduledTask" in script:
        if "LogonType Interactive" in script and addr in NOBODY:
            raise RuntimeError(f"{fixes.NOUSER}: nobody is signed in to this PC")
        return {"ok": True, "runs_as": "x"}
    return {"ok": True, "output": "done"}


winrm.run_ps = fake_run_ps
SCAN = {"user": "CORP\\scan", "password": "scanpw"}
scanning.winrm_cfg = lambda db: {"creds": [dict(SCAN)]}
d64 = lambda s: base64.b64decode(s).decode()  # noqa: E731


def last_launch():
    return next(c for c in reversed(calls) if "Register-ScheduledTask" in c[2])


def dep(c, host):
    return next(x for x in c.get(f"/api/deployments?host={host}").json()["rows"])


with TestClient(m.app) as c:
    hosts = [r["hostname"] for r in c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "limit": 4}).json()["rows"]]
    from netinv.db import Device, SessionLocal
    from netinv.actions import _addr
    with SessionLocal() as db:
        from sqlalchemy import select
        addrs = {h: _addr(db.scalar(select(Device).where(Device.hostname == h))) for h in hosts}
    ra = c.get("/api/run-as").json()
    assert list(ra["modes"]) == ["user", "account", "system"] and ra["script_modes"]["select"] == "Select on deployment", ra
    cid = c.post("/api/credentials", json={"name": "Helpdesk admin", "kind": "windows", "username": "CORP\\helpdesk", "secret": "hdpw"}).json()["id"]
    assert any(a["id"] == cid for a in c.get("/api/run-as").json()["accounts"])

    # a new script asks at deployment: refused without a choice
    sid = c.post("/api/scripts", json={"name": "Kill Chrome", "body": "taskkill /im chrome.exe /f", "language": "cmd"}).json()["id"]
    assert next(s for s in c.get("/api/scripts").json()["scripts"] if s["id"] == sid)["run_mode"] == "select"
    r = c.post(f"/api/devices/{hosts[0]}/fix", json={"action": "script", "value": str(sid)}).json()
    assert not r["ok"] and "Pick who" in r["output"], r
    assert c.post("/api/fix/bulk", json={"action": "script", "value": str(sid), "hostnames": hosts}).status_code == 400

    # logged-on user: an interactive task with limited rights; label says so
    r = c.post(f"/api/devices/{hosts[0]}/fix", json={"action": "script", "value": str(sid), "run_mode": "user"}).json()
    assert r["ok"], r
    s = last_launch()[2]
    assert "LogonType Interactive" in s and "RunLevel Limited" in s and "'user'" in s and "SYSTEM" not in s.split("__REG__")[0][-10:], s[-600:]
    d = dep(c, hosts[0])
    assert d["label"].endswith("(as Currently logged on user)") and d["run_as"] == "Currently logged on user", d

    # nobody signed in: waits (queued), like an offline PC
    NOBODY.add(addrs[hosts[1]])
    r = c.post(f"/api/devices/{hosts[1]}/fix", json={"action": "script", "value": str(sid), "run_mode": "user"}).json()
    assert r["ok"] and "Nobody is signed in" in r["output"], r
    d = dep(c, hosts[1])
    assert d["status"] == "queued" and "sign in" in d["message"], d

    # scanning credentials: the task runs as the scan account, with its password (network access)
    c.post(f"/api/devices/{hosts[2]}/fix", json={"action": "script", "value": str(sid), "run_mode": "account"})
    cfg, s = last_launch()[1:]
    u = re.search(r"-User \(D '([^']+)'\)", s)
    assert u and d64(u.group(1)) == "CORP\\scan" and cfg["creds"][0]["user"] == "CORP\\scan", s[-500:]

    # a saved account picked at deployment: signs in and runs as it
    c.post(f"/api/devices/{hosts[2]}/fix", json={"action": "script", "value": str(sid), "run_mode": "account", "credential_id": cid})
    cfg, s = last_launch()[1:]
    assert cfg["creds"] == [{"user": "CORP\\helpdesk", "password": "hdpw"}] and d64(re.search(r"-User \(D '([^']+)'\)", s).group(1)) == "CORP\\helpdesk"
    d = dep(c, hosts[2])
    assert d["run_as"] == "Helpdesk admin" and d["label"].endswith("(as Helpdesk admin)"), d
    # the server's own account has no password: S4U
    c.post(f"/api/devices/{hosts[2]}/fix", json={"action": "script", "value": str(sid), "run_mode": "account", "credential_id": 0})
    cfg, s = last_launch()[1:]
    assert "LogonType S4U" in s and cfg["creds"][0].get("integrated"), s[-400:]
    # System
    c.post(f"/api/devices/{hosts[2]}/fix", json={"action": "script", "value": str(sid), "run_mode": "system"})
    assert "-UserId 'SYSTEM'" in last_launch()[2]
    # a deleted / non-Windows account is refused
    assert not c.post(f"/api/devices/{hosts[2]}/fix", json={"action": "script", "value": str(sid), "run_mode": "account", "credential_id": 99999}).json()["ok"]

    # a predefined run mode on the script wins over what the request says
    c.put(f"/api/scripts/{sid}", json={"name": "Kill Chrome", "body": "taskkill /im chrome.exe /f", "language": "cmd", "run_mode": "user"})
    assert next(s for s in c.get("/api/scripts").json()["scripts"] if s["id"] == sid)["run_mode"] == "user"
    assert c.put(f"/api/scripts/{sid}", json={"name": "Kill Chrome", "body": "x", "run_mode": "admin"}).status_code == 400
    c.post(f"/api/devices/{hosts[3]}/fix", json={"action": "script", "value": str(sid), "run_mode": "system"})
    assert "LogonType Interactive" in last_launch()[2]

    # Retry keeps the account and run mode
    from netinv.db import Deployment
    with SessionLocal() as db:
        x = db.scalars(select(Deployment).where(Deployment.cred_id == cid)).first()
        x.status = "failed"
        db.commit()
        xid = x.id
    assert c.post(f"/api/deployments/{xid}/retry").json()["ok"]
    with SessionLocal() as db:
        y = db.scalars(select(Deployment).order_by(Deployment.id.desc())).first()
        assert (y.cred_id, y.run_mode) == (cid, "account"), (y.cred_id, y.run_mode)

    # Configure tools and power actions sign in with the picked account
    n = len(calls)
    c.post(f"/api/devices/{hosts[3]}/fix", json={"action": "tool", "tool": {"tool": "net", "args": {"op": "flushdns"}}, "credential_id": cid})
    assert any(cl[1]["creds"][0]["user"] == "CORP\\helpdesk" for cl in calls[n:]), [cl[1] for cl in calls[n:]]
    n = len(calls)
    c.post(f"/api/devices/{hosts[3]}/fix", json={"action": "cancel_reboot", "credential_id": cid})
    assert calls[n][1]["creds"][0]["user"] == "CORP\\helpdesk"
    d = dep(c, hosts[3])
    assert "Helpdesk admin" in d["run_as"], d
    # without a pick: the scan credentials
    n = len(calls)
    c.post(f"/api/devices/{hosts[3]}/fix", json={"action": "cancel_reboot"})
    assert calls[n][1]["creds"][0]["user"] == "CORP\\scan"

    # scan runs: a job's sign-in account, and a one-run override
    from netinv.db import ScanTarget
    with SessionLocal() as db:
        t = ScanTarget(kind="ip_range", value="10.9.9.0/30", credential_ids="")
        db.add(t)
        db.commit()
        with scanning.scoped([t.id], cred_id=cid):
            assert scanning._creds(db, [t], ("windows",)) == [{"user": "CORP\\helpdesk", "password": "hdpw"}]
            assert scanning._creds(db, [t], ("snmp2", "snmp3")) == []
        with scanning.scoped([t.id], cred_id=0):
            assert scanning._creds(db, [t], ("windows",))[0].get("integrated")
        assert scanning._creds(db, [t], ("windows",)) == []
    body = {"name": "Run-as job", "collectors": ["pcs"], "credential_id": cid}
    assert c.post("/api/jobs", json=body).json()["ok"]
    j = next(x for x in c.get("/api/jobs").json()["jobs"] if x["name"] == "Run-as job")
    assert j["credential_id"] == cid and j["sign_in"] == "Helpdesk admin", j
    assert c.post("/api/jobs", json={**body, "name": "bad", "credential_id": 99999}).status_code == 400
    assert c.post(f"/api/jobs/{j['id']}/run", json={"job_account": False, "credential_id": 99999}).status_code == 400
    import netinv.jobs as jobs
    started = []
    jobs.run_scan_job = lambda jid, who="schedule", cred_id=None: started.append((jid, cred_id))
    r = c.post(f"/api/jobs/{j['id']}/run", json={"job_account": False, "credential_id": 0}).json()
    assert "own account" in r["output"], r
    r = c.post(f"/api/jobs/{j['id']}/run").json()
    assert "Helpdesk admin" in r["output"], r
    import time; time.sleep(0.5)
    assert started == [(j["id"], 0), (j["id"], cid)], started
    print("run as OK")
