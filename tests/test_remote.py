"""Remote tools (power, sessions, messages, command, WMI) with WinRM faked: validation and what reaches the PC.
Run: python tests/test_remote.py (DATABASE_URL set, demo loaded)."""
import base64, logging, re, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import scanning
from netinv.collectors import winrm

sent = []


def decoded(script):
    return [base64.b64decode(x).decode() for x in re.findall(r"D '([A-Za-z0-9+/=]*)'", script) if x]


def fake(addr, cfg, script):
    sent.append(script)
    if "Start-Job" in script:
        return {"ok": True, "timed_out": False, "exit_code": 0, "output": "Windows IP Configuration", "user": "CORP\\svc"}
    if "__NAMESPACE" in script:
        return {"namespaces": "root\\cimv2\\mdm", "classes": [{"name": "Win32_BIOS", "dynamic": True}]}
    if "Get-CimClass -Namespace $ns -ClassName" in script:
        return {"properties": [{"name": "Name", "type": "String", "key": True}], "methods": [], "rows": {"Name": "BIOS"}}
    if "-Query $q" in script:
        return {"rows": [{"Name": "a"}, {"Name": "b"}]}
    if "boot =" in script:
        return {"sessions": {"user": "alee", "session": "console", "id": 1, "state": "Active", "idle": "none", "logon": "x"}, "console": "CORP\\alee"}
    return {"ok": True, "message": "done"}


winrm.run_ps = fake
scanning.winrm_cfg = lambda db: {"creds": [{"user": "CORP\\svc-netinv", "password": "x"}]}

with TestClient(m.app) as c:
    h = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "limit": 1}).json()["rows"][0]["hostname"]
    u = f"/api/devices/{h}"
    n = len(sent)
    for body in ({"op": "format"}, {"op": "shutdown", "minutes": 9999}, {"op": "restart", "minutes": -1}):
        assert not c.post(f"{u}/power", json=body).json()["ok"], body
    assert len(sent) == n, "refused power actions must not reach the PC"
    for op in ("shutdown", "restart", "abort", "hibernate", "sleep", "lock", "logoff_all"):
        r = c.post(f"{u}/power", json={"op": op, "minutes": 5 if op == "restart" else 0, "message": "'; calc; '"}).json()
        assert r["ok"], (op, r)
        assert "'; calc; '" not in sent[-1]
    assert "'; calc; '" in decoded(sent[-1])

    r = c.get(f"{u}/sessions").json()
    assert r["sessions"][0]["user"] == "alee", r
    n = len(sent)
    assert not c.post(f"{u}/sessions", json={"op": "kill", "id": 1}).json()["ok"]
    assert not c.post(f"{u}/sessions", json={"op": "logoff", "id": 0}).json()["ok"]
    assert len(sent) == n
    assert c.post(f"{u}/sessions", json={"op": "logoff", "id": 2}).json()["ok"] and "$id = 2" in sent[-1]

    evil = 'Hi "there" $(Remove-Item C:\\) `n'
    assert not c.post(f"{u}/message", json={"text": " "}).json()["ok"]
    assert not c.post(f"{u}/message", json={"text": "x", "user": "a;b|c"}).json()["ok"]
    assert c.post(f"{u}/message", json={"text": evil, "user": "CORP\\alee"}).json()["ok"]
    assert evil in decoded(sent[-1]) and evil not in sent[-1] and "alee" in decoded(sent[-1])

    n = len(sent)
    assert not c.post(f"{u}/command", json={"command": ""}).json()["ok"]
    assert not c.post(f"{u}/command", json={"command": "dir", "shell": "bash"}).json()["ok"]
    assert len(sent) == n
    cmd = "Get-Process | Where-Object { $_.Name -eq 'x' }; '$(calc)'"
    r = c.post(f"{u}/command", json={"command": cmd, "timeout": 999}).json()
    assert r["ok"] and r["output"].startswith("Windows IP") and r["status"] == "exit code 0", r
    assert cmd in decoded(sent[-1]) and cmd not in sent[-1] and "Wait-Job $j -Timeout 100" in sent[-1]

    r = c.get(f"{u}/wmi").json()
    assert r["namespace"] == "root\\cimv2" and r["namespaces"] == ["root\\cimv2\\mdm"], r
    assert c.get(f"{u}/wmi", params={"ns": "root\\cimv2", "cls": "Win32_BIOS"}).json()["rows"] == [{"Name": "BIOS"}]
    n = len(sent)
    assert c.get(f"{u}/wmi", params={"cls": "Win32_BIOS; calc"}).status_code == 400
    assert c.get(f"{u}/wmi", params={"ns": "C:\\Windows"}).status_code == 400
    assert c.post(f"{u}/wmi", json={"query": "DELETE FROM Win32_Process"}).status_code == 400
    assert len(sent) == n
    assert len(c.post(f"{u}/wmi", json={"query": "SELECT * FROM Win32_Service", "ns": "root/cimv2"}).json()["rows"]) == 2

    hist = c.get(u).json()
    hist = hist.get("history") or hist.get("changes") or []
    assert any("Command (powershell)" in (x.get("detail") or x.get("text") or str(x)) for x in hist), hist[:3]
print("remote tools OK")
