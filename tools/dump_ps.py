"""Writes every PowerShell script the server sends to PCs (PC tools, fixes, scripts) to a folder, so CI can parse
them with the real PowerShell parser on Windows. Usage: python tools/dump_ps.py <out dir>"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netinv import fixes, pctools  # noqa: E402

out = Path(sys.argv[1] if len(sys.argv) > 1 else "psparse")
out.mkdir(parents=True, exist_ok=True)
seen: list[str] = []


def keep(script: str) -> dict:
    seen.append(script)
    return {"ok": True, "message": "x", "subkeys": [], "values": [], "members": [], "users": []}


pctools._run = lambda db, dev, script: keep(pctools.D + script)
pctools._record = lambda *a, **k: None
pctools._cfg = lambda db: {"creds": [{"user": "CORP\\svc-netinv"}]}
dev = SimpleNamespace(hostname="PC1")

pctools.registry(None, dev, "HKLM\\SOFTWARE\\Vendor")
for kind in pctools.REG_TYPES:
    pctools.reg_change(None, dev, "t", "set", "HKLM\\SOFTWARE\\Vendor\\App", "v", kind, "1")
for op in ("delete_value", "new_key", "delete_key"):
    pctools.reg_change(None, dev, "t", op, "HKLM\\SOFTWARE\\Vendor\\App", "v")
pctools.printers(None, dev)
for op in ("test", "clear", "remove"):
    pctools.printer_change(None, dev, "t", op, "HP LaserJet")
pctools.printer_change(None, dev, "t", "add", "\\\\print01\\HP-2F")
pctools.drives(None, dev)
pctools.local_accounts(None, dev)
for op, n in (("add_admin", "CORP\\helpdesk"), ("remove_admin", "CORP\\helpdesk"), ("enable", "kiosk"), ("disable", "kiosk")):
    pctools.local_change(None, dev, "t", op, n)
seen += [pctools.PROCESSES, pctools.SERVICES]
for name in ("WU_SCRIPT", "WINGET_SCRIPT", "REMOVE_SCRIPT", "LAUNCH", "RESULT", "SCRIPT_RUNNER"):
    s = getattr(fixes, name)
    for k, v in {"__TIMEOUT__": "10", "__EXT__": ".ps1", "__NAME__": "x", "__SB64__": "", "__B64__": "", "__PKG__": "Vendor.App",
                 "__KEY__": "{00000000-0000-0000-0000-000000000000}", "__MODE__": "remove", "__AFTER__": "notify"}.items():
        s = s.replace(k, v)          # filled in the same way before a script is sent
    seen.append(s)

from netinv import remote  # noqa: E402
remote._run = pctools._run
remote._record = pctools._record
for op in remote.POWER:
    remote.power(None, dev, "t", op, 5 if op in ("shutdown", "restart") else 0, "Save your work")
seen.append(pctools.D + remote.SESSIONS)
for op in remote.SESSION_OPS:
    remote.session_op(None, dev, "t", op, 2)
remote.message(None, dev, "t", "Hello", "IT", "alee")
remote.command(None, dev, "t", "ipconfig /all", "cmd")
remote.wmi_browse(None, dev, "root\\cimv2")
remote.wmi_class(None, dev, "root\\cimv2", "Win32_BIOS")
remote.wmi_query(None, dev, "root\\cimv2", "SELECT * FROM Win32_BIOS")
for name in remote.VIEWS:
    remote.view(None, dev, name, log="System", levels="error", all=1)
for kind, op, a in (("share", "add", {"name": "Scans", "path": r"D:\Scans", "access": "Read", "account": "Everyone"}),
                    ("share", "remove", {"name": "Scans"}), ("env", "set", {"name": "X", "value": "1"}), ("env", "delete", {"name": "X"}),
                    ("startup", "remove", {"name": "x", "kind": "registry", "location": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}),
                    ("startup", "remove", {"name": "x.lnk", "kind": "folder", "location": r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"}),
                    ("task", "run", {"path": "\\Vendor\\", "name": "x"}), ("net", "flushdns", {}), ("net", "registerdns", {}),
                    ("net", "renew", {}), ("net", "gpupdate", {}), ("defender", "quickscan", {}), ("defender", "signatures", {})):
    r = remote.change(None, dev, "t", kind, op, a)
    assert r["ok"], (kind, op, r)
remote.files(None, dev, "C:\\Users")
remote.file_text(None, dev, "C:\\Windows\\Logs\\x.log", True)
seen.append(pctools.D + remote.FILE_INFO.replace("__PATH__", ""))
for op in remote.FILE_OPS:
    remote.file_op(None, dev, "t", op, "C:\\Temp\\x", "y")

from netinv import agentpush  # noqa: E402
for s in (agentpush.INSTALL, agentpush.REMOVE):
    for k, v in {"__NAME__": "agent-install", "__SERVER__": "https://netinv.corp.local:8080", "__TOKEN__": "nip_x",
                 "__PIN__": "AB" * 32, "__RUNAS__": "LOCALSERVICE", "__KIND__": "msi", "__BITS__": ""}.items():
        s = s.replace(k, v)
    seen.append(s)

for i, s in enumerate(seen):
    (out / f"script{i:02d}.ps1").write_text(s, encoding="utf-8-sig")
print(f"{len(seen)} scripts written to {out}")
