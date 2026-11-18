"""Audit log (sign-in/out, every change, IP, masked secrets), server log, Logs page APIs, per-user settings.
Run: python tests/test_audit_logs.py (DATABASE_URL set, demo loaded)."""
import logging, sys, time
from pathlib import Path
logging.disable(logging.NOTSET)
logging.getLogger("httpx").setLevel(logging.WARNING)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import auth, logs
from netinv.config import settings

settings.ui_user, settings.ui_password = "admin", auth.hash_password("correct horse battery")
assert not auth.local_disabled_file().exists(), "remove local-login.disabled before running this test"


def audit(c, **q):
    r = c.get("/api/logs/audit", params={"hours": 1, **q})
    assert r.status_code == 200, r.text
    return r.json()["rows"]


with TestClient(m.app) as c:
    assert c.get("/api/logs/audit").status_code == 401                     # signed out: nothing to see
    assert c.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    r = c.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    assert r.status_code == 200, r.text
    assert "max-age" not in r.headers["set-cookie"].lower(), "session cookie must end with the browser"

    rows = audit(c, kind="signin")
    acts = [x["action"] for x in rows]
    assert "login.failed" in acts and "login.local" in acts, acts
    assert all(x["ip"] for x in rows), rows
    assert c.get("/api/settings").headers.get("cache-control") == "no-store"

    # a change with its own audit entry: shows what changed, and the IP
    c.put("/api/settings", json={"fix:reboot_hour": "4"})
    x = audit(c, action="settings.save")[0]
    assert "2 -> 4" in x["result"] and x["ip"] and x["actor"] == "admin", x

    # a change with no entry of its own gets the generic one, with secrets masked
    r = c.post("/api/credentials", json={"name": "t1", "kind": "winrm", "username": "CORP\\scan", "password": "Sup3rSecret!"})
    rows = [x for x in audit(c) if "credential" in (x["target"] or "")]
    assert rows, audit(c)
    assert not any("Sup3rSecret" in (x["result"] or "") for x in audit(c, hours=0)), "password leaked into the audit log"
    n_before = len(audit(c, hours=0))
    c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "limit": 1})   # read-only POST: no entry
    assert len(audit(c, hours=0)) == n_before
    assert logs.redact({"password": "x", "nested": {"api_token": "y", "name": "n"}}) == {"password": "***", "nested": {"api_token": "***", "name": "n"}}

    # per-user setting: DameWare mode is the user's own
    assert c.put("/api/settings", json={"dameware_mode": "saved"}).json()["dameware_mode"] == "saved"
    with m.SessionLocal() as db:
        assert m.get_setting(db, "user:admin:dameware_mode") == "saved"
        assert m.get_setting(db, "dameware_mode") in (None, "windows")       # the shared default is untouched

    # server log
    logging.getLogger("netinv.scanning").warning("DC dc99.corp.example.com did not answer (test)")
    r = c.get("/api/logs/server", params={"level": "warning", "text": "dc99"}).json()
    assert r["rows"] and r["rows"][0]["logger"] == "netinv.scanning", r
    assert "netinv.scanning" in r["loggers"]
    assert c.get("/api/logs/server", params={"level": "error", "text": "dc99"}).json()["rows"] == []
    assert c.get("/api/logs/runs").status_code == 200
    assert c.get("/api/logs/runs", params={"failed": True}).status_code == 200

    # log files: only names from the folder, no paths
    logs.log_dir().mkdir(exist_ok=True)
    (logs.log_dir() / "NetInventory.err.log").write_text("line one\nTraceback: boom\n")
    names = [f["name"] for f in c.get("/api/logs/files").json()["files"]]
    assert "NetInventory.err.log" in names, names
    assert "boom" in c.get("/api/logs/files/NetInventory.err.log").json()["text"]
    assert c.get("/api/logs/files/..%2Fconfig.toml").status_code == 404
    assert c.get("/api/logs/files/config.toml").status_code == 404
    assert c.get("/api/logs/audit.csv").text.startswith("time (UTC),who,action")

    # sign-out is logged, and the session is gone
    r = c.post("/api/logout")
    assert "storage" in r.headers.get("clear-site-data", "")
    assert c.get("/api/logs/audit").status_code == 401
    c.post("/api/login", json={"username": "admin", "password": "correct horse battery"})
    assert "logout" in [x["action"] for x in audit(c, kind="signin")]

    # an idle session that times out is logged when swept
    s = auth.login(m.SessionLocal(), "admin", "correct horse battery", "10.0.0.9")
    s.seen -= auth.SESSION_IDLE + 5
    auth.sweep()
    assert any(x["action"] == "session.expired" for x in audit(c, kind="signin")), audit(c, kind="signin")
    (logs.log_dir() / "NetInventory.err.log").unlink()
print("Audit log, server log, Logs page and per-user settings OK")
