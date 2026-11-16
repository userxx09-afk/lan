"""PC tools (registry, printers, drives, local accounts) API with WinRM faked: validation and what reaches the PC.
Run: python tests/test_pctools.py (DATABASE_URL set, demo loaded)."""
import base64, logging, re, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import pctools, scanning
from netinv.collectors import winrm

sent = []


def decoded(script):
    return [base64.b64decode(x).decode() for x in re.findall(r"D '([A-Za-z0-9+/=]*)'", script) if x]


def fake(addr, cfg, script):
    sent.append(script)
    if "GetSubKeyNames" in script and "SetValue" not in script:
        return {"subkeys": ["Microsoft", "Vendor"], "values": {"name": "", "type": "String", "data": "x"}}
    if "Win32_Printer" in script and "$n = D" not in script:
        return [{"name": "HP LaserJet", "status": "3", "jobs": 2, "machine_wide": False, "network": False}]
    if "MountPoints2" in script:
        return {"user": "CORP\\alee", "drive": "H:", "path": "\\\\fs01\\home\\alee", "kind": "mapped (persistent)"}
    if "WinNT://./$g,group" in script and "$n = D" not in script:
        return {"group": "Administrators", "computer": "PC1", "members": [{"name": "PC1\\Administrator", "builtin": True}],
                "users": {"name": "Administrator", "enabled": False}}
    return {"ok": True, "message": "done"}


winrm.run_ps = fake
scanning.winrm_cfg = lambda db: {"creds": [{"user": "CORP\\svc-netinv", "password": "x"}]}

with TestClient(m.app) as c:
    h = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "limit": 1}).json()["rows"][0]["hostname"]
    u = f"/api/devices/{h}"
    r = c.get(f"{u}/registry", params={"path": "HKEY_LOCAL_MACHINE\\SOFTWARE"}).json()
    assert r["path"] == "HKLM\\SOFTWARE" and r["subkeys"] == ["Microsoft", "Vendor"] and len(r["values"]) == 1, r
    assert c.get(f"{u}/registry", params={"path": "HKCU\\Software"}).status_code == 400
    # registry changes: refusals never reach the PC
    n = len(sent)
    for body in ({"op": "set", "path": "HKLM\\SAM\\SAM", "name": "x", "data": "1"},
                 {"op": "set", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "name": "RunAsPPL", "kind": "DWord", "data": "0"},
                 {"op": "delete_key", "path": "HKLM\\SOFTWARE\\Microsoft"},
                 {"op": "set", "path": "HKLM\\SOFTWARE\\X", "name": "n", "kind": "DWord", "data": "abc"},
                 {"op": "set", "path": "HKLM\\SOFTWARE\\X", "name": "n", "kind": "DWord", "data": "4294967296"},
                 {"op": "set", "path": "HKLM\\SOFTWARE\\X", "name": "n", "kind": "Binary", "data": "00"},
                 {"op": "new_key", "path": "HKLM\\SOFTWARE\\X", "name": "a\\b"},
                 {"op": "set", "path": "HKLM", "name": "n", "data": "1"}):
        assert not c.post(f"{u}/registry", json=body).json()["ok"], body
    assert len(sent) == n, "refused changes must not reach the PC"
    # a value with quotes and $() goes over as data, not code
    evil = "'; Remove-Item C:\\ -Recurse; '$(calc)"
    assert c.post(f"{u}/registry", json={"op": "set", "path": "HKLM\\SOFTWARE\\Vendor\\App", "name": "Path", "data": evil}).json()["ok"]
    assert evil in decoded(sent[-1]) and evil not in sent[-1]
    assert c.post(f"{u}/registry", json={"op": "set", "path": "HKLM\\SOFTWARE\\Vendor\\App", "name": "n", "kind": "DWord", "data": "0xFFFFFFFF"}).json()["ok"]
    assert "4294967295" in decoded(sent[-1])
    assert c.post(f"{u}/registry", json={"op": "delete_key", "path": "HKLM\\SOFTWARE\\Vendor\\App"}).json()["ok"]

    # printers and drives
    r = c.get(f"{u}/printers").json()
    assert r["printers"][0]["status"] == "ready" and r["drives"][0]["drive"] == "H:", r
    assert not c.post(f"{u}/printers", json={"op": "add", "name": "fs01\\HP"}).json()["ok"]
    assert c.post(f"{u}/printers", json={"op": "add", "name": "\\\\print01\\HP-2F"}).json()["ok"]
    assert c.post(f"{u}/printers", json={"op": "clear", "name": "HP LaserJet"}).json()["ok"]
    assert not c.post(f"{u}/printers", json={"op": "format", "name": "HP LaserJet"}).json()["ok"]

    # local accounts
    r = c.get(f"{u}/accounts").json()
    assert r["members"][0]["builtin"] and r["users"][0]["name"] == "Administrator", r
    n = len(sent)
    for op, name in (("add_admin", "helpdesk"), ("add_admin", "CORP\\a;b"), ("remove_admin", "CORP\\Domain Admins"),
                     ("remove_admin", "CORP\\svc-netinv"), ("disable", "svc-netinv"), ("enable", "bad\\name"), ("wipe", "x")):
        assert not c.post(f"{u}/accounts", json={"op": op, "name": name}).json()["ok"], (op, name)
    assert len(sent) == n
    assert c.post(f"{u}/accounts", json={"op": "add_admin", "name": "CORP\\Helpdesk"}).json()["ok"]
    assert "CORP\\Helpdesk" in decoded(sent[-1])
    hist = c.get(u).json()["history"]
    assert any("Add to local Administrators" in (x.get("detail") or x.get("summary") or str(x)) for x in hist), hist[:3]
    print("pc tools OK")
