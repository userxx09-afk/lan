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

    # read-only views
    for name in ("shares", "env", "startup", "tasks", "eventlogs", "devices", "network", "connections", "performance"):
        assert c.get(f"{u}/view/{name}").status_code == 200, name
    assert c.get(f"{u}/view/bogus").status_code == 404
    c.get(f"{u}/view/events", params={"log": "System", "levels": "error,warning", "hours": 48, "text": "disk*", "id": 7, "name": "x"})
    assert "Level = @(2,3)" in sent[-1] and ".AddHours(-48)" in sent[-1] and "disk" in decoded(sent[-1]) and "Id = 7" in sent[-1]
    assert c.get(f"{u}/view/events", params={"log": "Sys'tem"}).status_code == 400
    c.get(f"{u}/view/tasks", params={"all": 1})
    assert "$true -or" in sent[-1]

    # changes: refused ones never reach the PC
    n = len(sent)
    for kind, op, args in (("share", "add", {"name": "a/b", "path": "D:\\x", "access": "Read", "account": "Everyone"}),
                           ("share", "add", {"name": "Scans", "path": "\\\\srv\\x", "access": "Read", "account": "Everyone"}),
                           ("share", "add", {"name": "Scans", "path": "D:\\Scans", "access": "Owner", "account": "Everyone"}),
                           ("share", "remove", {"name": "ADMIN$"}), ("env", "delete", {"name": "Path"}),
                           ("env", "set", {"name": "Path", "value": "C:\\Tools"}), ("env", "set", {"name": "1bad", "value": "x"}),
                           ("startup", "remove", {"name": "x", "kind": "registry", "location": "HKLM\\SOFTWARE\\Evil"}),
                           ("task", "disable", {"path": "\\Microsoft\\Windows\\Defrag\\", "name": "ScheduledDefrag"}),
                           ("task", "run", {"path": "no-slash", "name": "x"}), ("net", "format", {}), ("disk", "wipe", {})):
        assert not c.post(f"{u}/change", json={"kind": kind, "op": op, "args": args}).json()["ok"], (kind, op, args)
    assert len(sent) == n
    ok = lambda kind, op, args: c.post(f"{u}/change", json={"kind": kind, "op": op, "args": args}).json()["ok"]  # noqa: E731
    assert ok("share", "add", {"name": "Scans", "path": "D:\\Scans", "desc": "'; calc '", "access": "Change", "account": "CORP\\Scanner Users"})
    assert "'; calc '" in decoded(sent[-1]) and "'; calc '" not in sent[-1] and "New-SmbShare" in sent[-1]
    assert ok("env", "set", {"name": "JAVA_HOME", "value": "C:\\Java\\jdk$(calc)"}) and "C:\\Java\\jdk$(calc)" in decoded(sent[-1])
    assert ok("env", "delete", {"name": "OLDVAR", "sid": "S-1-5-21-1-2-3-1001"}) and "HKEY_USERS\\S-1-5-21-1-2-3-1001" in sent[-1]
    assert ok("startup", "remove", {"name": "Updater", "kind": "registry", "location": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"})
    assert ok("startup", "remove", {"name": "App.lnk", "kind": "folder", "location": "C:\\Users\\alee\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"})
    assert ok("task", "run", {"path": "\\Vendor\\", "name": "Nightly sync"}) and "Start-ScheduledTask" in sent[-1]
    for op in ("flushdns", "registerdns", "renew", "gpupdate"):
        assert ok("net", op, {}), op

    # files
    n = len(sent)
    for bad in ("..\\x", "C:\\a\\..\\Windows", "\\\\srv\\c$", "C:relative", "C:\\a|b"):
        assert c.get(f"{u}/files", params={"path": bad}).status_code == 400, bad
    for body in ({"op": "delete", "path": "C:\\Windows"}, {"op": "delete", "path": "C:\\"}, {"op": "rename", "path": "C:\\Program Files", "name": "x"},
                 {"op": "delete", "path": "C:\\Windows\\System32\\drivers"}, {"op": "mkdir", "path": "C:\\Temp", "name": "a/b"}, {"op": "format", "path": "C:\\Temp"}):
        assert not c.post(f"{u}/files", json=body).json()["ok"], body
    assert len(sent) == n
    c.get(f"{u}/files", params={"path": "C:"})
    assert "C:\\" in decoded(sent[-1])
    assert c.post(f"{u}/files", json={"op": "delete", "path": "C:\\Users\\Public\\x.txt"}).json()["ok"]
    assert c.post(f"{u}/files", json={"op": "mkdir", "path": "C:\\Temp", "name": "new $(calc)"}).json()["ok"] and "new $(calc)" in decoded(sent[-1])
    from netinv import remote
    calls = []

    class FakeClient:
        def execute_ps(self, s): return "ok", None, False
        def fetch(self, src, dest): calls.append(("fetch", src)); Path(dest).write_bytes(b"hello")
        def copy(self, src, dest): calls.append(("copy", dest, Path(src).read_bytes()))
    winrm._client = lambda host, cfg: FakeClient()
    real = sent.append
    r = c.put(f"{u}/files/upload", params={"path": "C:\\Temp", "name": "a.txt"}, content=b"data123")
    assert r.json()["ok"] and calls[-1] == ("copy", "C:\\Temp\\a.txt", b"data123"), (r.text, calls)
    assert not c.put(f"{u}/files/upload", params={"path": "C:\\Windows", "name": "a.txt"}, content=b"x").json()["ok"]
    assert not c.put(f"{u}/files/upload", params={"path": "C:\\Temp", "name": "..\\a.txt"}, content=b"x").json()["ok"]
    remote.MAX_TRANSFER = 4
    assert not c.put(f"{u}/files/upload", params={"path": "C:\\Temp", "name": "a.txt"}, content=b"too long").json()["ok"]
    remote.MAX_TRANSFER = 200 * 1024 * 1024
    winrm.run_ps = lambda a, cfg, s: {"size": 5, "name": "x.log"} if "Get-Item -LiteralPath $p" in s and "ReadAllBytes" not in s else fake(a, cfg, s)
    r = c.get(f"{u}/files/download", params={"path": "C:\\Temp\\x.log"})
    assert r.status_code == 200 and r.content == b"hello" and "x.log" in r.headers["content-disposition"], r.text
    winrm.run_ps = lambda a, cfg, s: {"size": 300 * 1024 * 1024, "name": "big.iso"}
    assert c.get(f"{u}/files/download", params={"path": "C:\\Temp\\big.iso"}).status_code == 400
    winrm.run_ps = fake

    # security, group policy, Defender, BitLocker keys from AD, Windows Update restart choice
    assert c.get(f"{u}/view/security").status_code == 200 and c.get(f"{u}/view/gpresult").status_code == 200
    for op in ("quickscan", "fullscan", "signatures"):
        assert ok("defender", op, {}), op
    assert "MpCmdRun.exe" in sent[-3] and "-ScanType 2" in sent[-2]
    from netinv.collectors import ad as adc
    from netinv import fixes
    import netinv.scanning as sc
    from netinv.db import SessionLocal, Device, AuditLog
    from sqlalchemy import select
    with SessionLocal() as db:
        dn = db.scalar(select(Device.ad_dn).where(Device.hostname == h))
    sc.ad_action_cfg = lambda db, dn: {"server": "dc1", "user": "CORP\\svc", "password": "x"}
    adc.bitlocker_keys = lambda cfg, dn: [{"created": "2026-01-01", "key_id": "ABCD", "password": "111111-222222", "readable": True}]
    r = c.get(f"{u}/bitlocker-keys")
    if dn:
        assert r.json()[0]["password"] == "111111-222222", r.text
        with SessionLocal() as db:
            assert db.scalar(select(AuditLog).where(AuditLog.action == "pc.bitlocker_keys").order_by(AuditLog.id.desc())).actor
    else:
        assert r.status_code == 400
    assert fixes._validate("windows_updates", "restart")[1] == "restart"
    assert fixes._validate("windows_updates", "bogus") == ("Install pending Windows updates", None)
    assert "'notify' -eq 'notify'" in fixes.WU_SCRIPT.replace("__AFTER__", "notify")

    hist = c.get(u).json()
    hist = hist.get("history") or hist.get("changes") or []
    assert any("Command (powershell)" in (x.get("detail") or x.get("text") or str(x)) for x in hist), hist[:3]
print("remote tools OK")
