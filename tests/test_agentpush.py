"""Pushing the agent from the dashboard, with WinRM and the PC faked: queue, ticket, enrollment, result, Agent column.
Run: python tests/test_agentpush.py (DATABASE_URL set, demo loaded)."""
import base64, json, logging, re, sys, time
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import agentpush, fixes, scanning
from netinv.collectors import winrm

sent = []          # (address, inner script) that reached a "PC"
result = {"ok": True, "message": "Installed (scripts, runs as LOCALSERVICE) and reporting", "log": "enrolled as x (active)"}


def fake_run_ps(addr, cfg, script):
    if "NetInventory fix" in script and "__B64__" not in script and "FromBase64String('" in script:
        b64 = re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
        sent.append((addr, base64.b64decode(b64).decode()))
        return {"ok": True}
    if "done = $true" in script:
        return {"done": True, "state": "Ready", "result": result}
    return {}


winrm.run_ps = fake_run_ps
scanning.winrm_cfg = lambda db: {"username": "x", "password": "y"}
fixes._cfg = lambda db: {"username": "x", "password": "y"}
agentpush.pin = lambda: "AB" * 32           # pretend the server is on HTTPS


def due_now():
    from netinv.db import Deployment, SessionLocal, utcnow
    with SessionLocal() as db:
        for d in db.query(Deployment).filter(Deployment.status.in_(("running", "queued"))):
            d.next_try = utcnow()
        db.commit()


with TestClient(m.app) as c:
    hosts = [r["hostname"] for r in c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "limit": 2}).json()["rows"]]
    info = c.get("/api/agents/push").json()
    assert info["package"] == "scripts" and info["https"] and not info["saved"], info
    assert c.post("/api/agents/push", json={"hostnames": hosts, "server_url": "http://x"}).status_code == 400
    assert c.post("/api/agents/push", json={"hostnames": hosts, "server_url": "https://localhost:8080"}).status_code == 400
    assert c.post("/api/agents/push", json={"hostnames": [], "server_url": "https://netinv.corp.local:8080"}).status_code == 400
    r = c.post("/api/agents/push", json={"hostnames": hosts, "server_url": "https://netinv.corp.local:8080/", "run_as": "SYSTEM"}).json()
    assert r["count"] == 2, r
    assert c.get("/api/agents/push").json()["server"] == "https://netinv.corp.local:8080"
    rows = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname", "agent_status"],
                                     "filters": [{"field": "hostname", "op": "in", "value": hosts}]}).json()["rows"]
    assert all(x["agent_status"] in ("waiting", "installing") for x in rows), rows      # the dispatcher may already be sending

    fixes.poll_once(); time.sleep(1.5)
    assert len(sent) == 2, sent
    inner = sent[0][1]
    tok = re.search(r"\$tok = '(nip_[^']+)'", inner).group(1)
    assert "https://netinv.corp.local:8080" in inner and "'SYSTEM'" in inner and "'scripts'" in inner
    files = json.loads(base64.b64decode(re.search(r"\$bits = \[Convert\]::FromBase64String\('([^']+)'\)", inner).group(1)))
    assert {"NetInventoryAgent.ps1", "Install-Agent.ps1", "Uninstall-Agent.ps1"} <= set(files), files.keys()
    host = next(h for h in hosts if h.split(".")[0].upper() in sent[0][0].upper())

    # the ticket only works for that PC, once; it enrolls as active even with approval set to manual
    c.put("/api/agents/settings", json={"approve": "manual", "inventory_hours": 24})
    assert c.post("/api/agent/enroll", json={"token": tok, "hostname": "SOMEONE-ELSE"}).status_code == 403
    e = c.post("/api/agent/enroll", json={"token": tok, "hostname": host, "machine_guid": "g1"}).json()
    assert e["status"] == "active", e
    assert c.post("/api/agent/enroll", json={"token": tok, "hostname": host}).status_code == 403, "ticket reused"

    due_now(); fixes.poll_once()
    deps = [d for d in c.get("/api/deployments").json()["rows"] if d["action"] == "agent_install"]
    assert all(d["status"] == "success" for d in deps), deps
    row = c.post("/api/query", json={"dataset": "v_devices", "fields": ["agent_status"],
                                    "filters": [{"field": "hostname", "op": "eq", "value": host}]}).json()["rows"][0]
    assert row["agent_status"] == "active", row

    # a failure on the PC shows the agent's own error; removal revokes the server-side record
    result = {"ok": False, "message": "Installed, but the agent couldn't reach the server: pin mismatch", "log": "error: pin mismatch"}
    c.post("/api/agents/push", json={"hostnames": [host], "server_url": "https://netinv.corp.local:8080"})
    fixes.poll_once(); time.sleep(1); due_now(); fixes.poll_once()
    last = [d for d in c.get(f"/api/deployments?host={host}").json()["rows"] if d["action"] == "agent_install"][0]
    assert last["status"] == "failed" and "pin mismatch" in last["message"], last
    # pushed, but installed by hand before the push ran: the queued push is settled, the column shows the real state
    other = next(h for h in hosts if h != host)
    par, fixes.parallel = fixes.parallel, (lambda db: 0)     # keep it in the queue, as for an unreachable PC
    c.post("/api/agents/push", json={"hostnames": [other], "server_url": "https://netinv.corp.local:8080"})
    col = lambda h: c.post("/api/query", json={"dataset": "v_devices", "fields": ["agent_status", "agent_note"],  # noqa: E731
                                               "filters": [{"field": "hostname", "op": "eq", "value": h}]}).json()["rows"][0]
    assert col(other)["agent_status"] == "waiting", col(other)
    site = c.post("/api/agents/token").json()["token"]
    e = c.post("/api/agent/enroll", json={"token": site, "hostname": other, "machine_guid": "g2"}).json()
    assert e["status"] == "pending", e          # approval mode is manual
    row = col(other)
    assert row["agent_status"] == "pending" and row["agent_note"], row
    q = [d for d in c.get(f"/api/deployments?host={other}").json()["rows"] if d["action"] == "agent_install"][0]
    assert q["status"] == "success" and "Not needed" in q["message"], q
    fixes.parallel = par

    result = {"ok": True, "message": "Agent uninstalled (MSI)"}
    c.post("/api/agents/push", json={"hostnames": [host], "server_url": "https://netinv.corp.local:8080", "remove": True})
    fixes.poll_once(); time.sleep(1); due_now(); fixes.poll_once()
    ag = [a for a in c.get("/api/agents").json()["agents"] if a["hostname"] == host]
    assert ag and all(a["status"] == "revoked" for a in ag), ag
    assert c.get("/api/agents/msi").status_code == 404
    print("agent push OK:", len(sent), "sent")
