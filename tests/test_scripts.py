"""Script library and running scripts through the deployment queue, with WinRM faked.
Run: python tests/test_scripts.py (DATABASE_URL set, demo loaded)."""
import base64, json, logging, re, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import fixes, scanning
from netinv.collectors import winrm

sent = []          # scripts that reached a "PC"


def fake_run_ps(addr, cfg, script):
    if "NetInventory fix" in script and "__B64__" not in script and "FromBase64String('" in script:
        b64 = re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
        inner = base64.b64decode(b64).decode()
        user = base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)", inner).group(1)).decode()
        sent.append((addr, user, inner))
        return {"ok": True}
    if "done = $true" in script:        # the result check
        return {"done": True, "state": "Ready", "result": {"ok": True, "exit": 0, "message": "Exit code 0", "output": "hello from the PC"}}
    return {}


winrm.run_ps = fake_run_ps
scanning.winrm_cfg = lambda db: {"username": "x", "password": "y"}
fixes._cfg = lambda db: {"username": "x", "password": "y"}

with TestClient(m.app) as c:
    host = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "limit": 3}).json()["rows"]
    hosts = [r["hostname"] for r in host]
    # library: validation, create, edit, list
    assert c.post("/api/scripts", json={"name": "x", "body": "  "}).status_code == 400
    assert c.post("/api/scripts", json={"name": "x", "body": "dir", "language": "bash"}).status_code == 400
    assert c.post("/api/scripts", json={"name": "x", "body": "dir", "timeout_min": 999}).status_code == 400
    sid = c.post("/api/scripts", json={"name": "Flush DNS", "body": "ipconfig /flushdns", "language": "cmd", "timeout_min": 5}).json()["id"]
    assert c.post("/api/scripts", json={"name": "Flush DNS", "body": "x"}).status_code == 400, "duplicate name"
    assert c.put(f"/api/scripts/{sid}", json={"name": "Flush DNS", "body": "ipconfig /flushdns\r\necho done", "language": "cmd", "timeout_min": 5}).json()["ok"]
    lst = c.get("/api/scripts").json()
    assert lst["scripts"][0]["name"] == "Flush DNS" and lst["languages"]["cmd"]

    # one PC from its page: sent at once, then the result comes back with the output
    r = c.post(f"/api/devices/{hosts[0]}/fix", json={"action": "script", "value": str(sid)}).json()
    assert r["ok"], r
    assert sent and sent[-1][1] == "ipconfig /flushdns\r\necho done" and "'.cmd'" in sent[-1][2], sent[-1][2][:300]
    deps = c.get(f"/api/deployments?host={hosts[0]}").json()["rows"]
    d = next(x for x in deps if x["action"] == "script")
    assert d["status"] == "running" and d["label"] == "Run script Flush DNS", d
    from netinv.db import Deployment, SessionLocal, utcnow
    with SessionLocal() as db:
        db.get(Deployment, d["id"]).next_try = utcnow()
        db.commit()
    fixes.poll_once()
    one = c.get(f"/api/deployments/{d['id']}").json()
    assert one["status"] == "success" and "hello from the PC" in one["message"], one
    assert one["script"]["body"].startswith("ipconfig") and one["script"]["language"] == "cmd"

    # an edit later doesn't change what was queued; Retry runs the same text again
    c.put(f"/api/scripts/{sid}", json={"name": "Flush DNS", "body": "echo changed", "language": "cmd", "timeout_min": 5})
    with SessionLocal() as db:
        db.get(Deployment, d["id"]).status = "failed"
        db.commit()
    assert c.post(f"/api/deployments/{d['id']}/retry").json()["ok"]
    with SessionLocal() as db:
        from sqlalchemy import select
        again = db.scalars(select(Deployment).where(Deployment.action == "script").order_by(Deployment.id.desc())).first()
        assert json.loads(again.payload)["body"].startswith("ipconfig"), again.payload

    # one-off command on many PCs, and on a group
    r = c.post("/api/fix/bulk", json={"action": "script", "hostnames": hosts, "adhoc": {"language": "powershell", "body": "Get-Date", "timeout": 3}}).json()
    assert r["count"] == len(hosts), r
    assert c.post("/api/fix/bulk", json={"action": "script", "hostnames": hosts, "adhoc": {"body": "", "timeout": 3}}).status_code == 400
    assert c.post("/api/fix/bulk", json={"action": "script", "hostnames": []}).status_code == 400
    c.post(f"/api/devices/{hosts[1]}/groups", json={"name": "Lab"})
    r = c.post("/api/fix/bulk", json={"action": "script", "group": "Lab", "value": str(sid)}).json()
    assert r["count"] == 1, r
    q = c.get("/api/deployments").json()["rows"]
    assert sum(x["label"] == "Run command: Get-Date" for x in q) == len(hosts), [x["label"] for x in q]

    # deleting a script keeps queued pushes runnable
    assert c.delete(f"/api/scripts/{sid}").json()["ok"]
    fixes.poll_once()
    import time; time.sleep(1)
    assert any(s[1] == "echo changed" for s in sent), "the group push should still run after the script was deleted"
    print("scripts OK:", len(sent), "sent")
