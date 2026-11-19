"""The DameWare launcher for technician PCs, served from Settings > DameWare.

Files live in netinv/dameware/ (shipped with the app, so every install, Docker included, can serve them).
The zip adds Install.cmd / Uninstall.cmd (double-click, they ask for admin) and a plain README, and fills in
DameWareAllowedSuffixes with the DNS domains this server knows, so full names like ws-031.corp.local work too.
"""
from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

from sqlalchemy import text

from .db import get_setting

DIR = Path(__file__).resolve().parent / "dameware"
FILES = ("Install-DameWareHandler.ps1", "Open-DameWare.ps1", "dameware-handler.reg")
FOLDER = "NetInventory-DameWare"
_DNS = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$")
_SUFFIX_LINE = '; "DameWareAllowedSuffixes"=".corp.example.com"'


def suffixes(db) -> list[str]:
    """DNS domains (with a dot, safe characters only) from the sign-in domain and the computers' domains."""
    found: list[str] = []
    cands = [get_setting(db, "auth:ad_domain") or ""]
    try:
        cands += [d for (d,) in db.execute(text("SELECT DISTINCT domain FROM v_devices WHERE domain IS NOT NULL AND domain <> ''"))]
    except Exception:       # view not built yet
        pass
    for d in cands:
        d = str(d).strip().strip(".").lower()
        if _DNS.match(d) and d not in found:
            found.append(d)
    return sorted(found)[:20]


def file_bytes(name: str, sfx: list[str]) -> bytes:
    if name not in FILES:
        raise KeyError(name)
    data = (DIR / name).read_bytes()
    if name == "dameware-handler.reg" and sfx:
        line = '"DameWareAllowedSuffixes"="' + ";".join("." + s for s in sfx) + '"'
        data = data.replace(_SUFFIX_LINE.encode(), line.encode())
    return data


def _crlf(s: str) -> bytes:
    return s.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")


def _cmd(uninstall: bool, sfx: list[str]) -> bytes:
    args = "-Uninstall" if uninstall else (f'-AllowedSuffixes "{";".join("." + s for s in sfx)}"' if sfx else "")
    what = "Removing" if uninstall else "Installing"
    return _crlf(f"""@echo off
rem NetInventory DameWare launcher: {what.lower()} the dameware:// link handler on this PC.
rem Double-click it. Windows asks for administrator rights once.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
echo {what} the NetInventory DameWare launcher...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-DameWareHandler.ps1" {args}
echo.
pause
""")


def readme(sfx: list[str], server: str) -> bytes:
    allowed = ", ".join("." + s for s in sfx) if sfx else "none found yet (only short names like WS-031 and private IPs work)"
    return _crlf(f"""NetInventory DameWare launcher
==============================

What it does
------------
The "Remote control (DameWare)" buttons in NetInventory open a dameware:// link. Windows needs to be told what
to do with that kind of link. These files tell it: "open DameWare Mini Remote Control and connect to that PC",
using your own Windows logon (or the saved host entry, if you chose that in NetInventory Settings).
Install it on each technician PC that has DameWare Mini Remote Control. Nothing is needed on the PCs you connect to.

  Install.cmd                  Double-click to install on this PC (asks for administrator rights).
  Uninstall.cmd                Double-click to remove it again.
  Install-DameWareHandler.ps1  Does the work: copies Open-DameWare.ps1 to C:\\ProgramData\\NetInventory\\
                               and registers dameware:// links in the registry (HKLM\\SOFTWARE\\Classes\\dameware).
  Open-DameWare.ps1            The launcher Windows runs when you click the button. It checks the computer name
                               (short names, private IPs and allowed domains only, so another web site can't misuse
                               it), finds DWRCC.exe and starts it with -c: -m:<PC> -a:1 -x (your Windows logon).
  dameware-handler.reg         The same registry settings as a .reg file, for Group Policy.

Allowed domains for full names: {allowed}

One PC
------
1. Unzip this folder (right-click the zip > Extract All). Don't run it from inside the zip.
2. Double-click Install.cmd and click Yes when Windows asks.
3. In NetInventory ({server}), open a computer and click "Remote control (DameWare)".
   The browser asks once whether to open the link: tick "Always allow" and click Open.

Many PCs by Group Policy (pick one)
-----------------------------------
A) Startup script (simplest)
   1. Copy this folder to a share every PC can read, for example \\\\yourdomain\\NETLOGON\\{FOLDER}
   2. In a GPO linked to the technicians' computers: Computer Configuration > Policies > Windows Settings >
      Scripts > Startup > PowerShell Scripts > Add:
        Script name:  \\\\yourdomain\\NETLOGON\\{FOLDER}\\Install-DameWareHandler.ps1
        Parameters:   {('-AllowedSuffixes "' + ";".join("." + s for s in sfx) + '"') if sfx else "(leave empty)"}
   3. It runs at the next restart (as SYSTEM) and again at every start, which is harmless.
   If PowerShell scripts are blocked by execution policy, add it under the "Scripts" tab instead with
        Script name:  powershell.exe
        Parameters:   -NoProfile -ExecutionPolicy Bypass -File "\\\\yourdomain\\NETLOGON\\{FOLDER}\\Install-DameWareHandler.ps1"

B) Group Policy Preferences (no script runs)
   In a GPO linked to the technicians' computers, under Computer Configuration > Preferences > Windows Settings:
   1. Files > New > File: Source \\\\yourdomain\\NETLOGON\\{FOLDER}\\Open-DameWare.ps1,
      Destination C:\\ProgramData\\NetInventory\\Open-DameWare.ps1
   2. Registry > New > Registry Item (Action Update, Hive HKEY_LOCAL_MACHINE), three items:
        Key SOFTWARE\\Classes\\dameware                     value (Default)       = URL:DameWare Remote Control (NetInventory)
        Key SOFTWARE\\Classes\\dameware                     value URL Protocol    = (empty)
        Key SOFTWARE\\Classes\\dameware\\shell\\open\\command   value (Default)       =
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\\ProgramData\\NetInventory\\Open-DameWare.ps1" "%1"
      (dameware-handler.reg holds exactly these values, if you'd rather run "reg import" from a script.)

Optional settings per PC (HKLM\\SOFTWARE\\NetInventory)
-----------------------------------------------------
  DameWarePath             full path to DWRCC.exe, if it isn't found automatically
  DameWareAllowedSuffixes  domains allowed in full names, for example .corp.example.com
  DameWareExtraArgs        extra DWRCC switches added to every connection

Something not working?
----------------------
  Nothing happens on click: the launcher isn't installed on this PC, or the browser prompt was dismissed.
  "DWRCC.exe was not found": install DameWare Mini Remote Control, or set DameWarePath.
  "Refusing to connect": the name isn't a short name, private IP or allowed domain; set DameWareAllowedSuffixes.
  Test without the browser:  powershell -File C:\\ProgramData\\NetInventory\\Open-DameWare.ps1 "dameware://connect/?host=PCNAME&mode=windows" -DryRun
""")


def zip_bytes(sfx: list[str], server: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{FOLDER}/Install.cmd", _cmd(False, sfx))
        z.writestr(f"{FOLDER}/Uninstall.cmd", _cmd(True, sfx))
        z.writestr(f"{FOLDER}/README.txt", readme(sfx, server))
        for n in FILES:
            z.writestr(f"{FOLDER}/{n}", file_bytes(n, sfx))
    return buf.getvalue()
