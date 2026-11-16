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
    seen.append(getattr(fixes, name))

for i, s in enumerate(seen):
    (out / f"script{i:02d}.ps1").write_text(s, encoding="utf-8-sig")
print(f"{len(seen)} scripts written to {out}")
