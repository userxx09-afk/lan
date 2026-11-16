"""Live tools on one PC over WinRM (the asset page's Processes and Services tabs).

Read-only views run on demand. Changes (end a process, start/stop/restart a service, change its start type) are
confirmed in the UI, written to the audit log and the PC's history. Process IDs and service names are validated
before they go into a script, so nothing typed in the browser reaches PowerShell unchecked.
"""
from __future__ import annotations

import re

from .actions import _addr
from .db import AuditLog, Device
from .ingest import log_change

SERVICE_RE = re.compile(r"^[A-Za-z0-9_.\-$ ]{1,128}$")
# Never touched from here: stopping these breaks the PC or our own access to it
PROTECTED = {"winrm", "rpcss", "lsass", "csrss", "wininit", "services", "smss", "eventlog", "dcomlaunch", "plugplay",
             "samss", "lsm", "power", "brokerinfrastructure", "systemeventsbroker", "termservice"}
PROTECTED_PROC = {"system", "idle", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
                  "svchost.exe", "wsmprovhost.exe", "registry", "memory compression", "fontdrvhost.exe", "dwm.exe"}

PROCESSES = r'''
$ErrorActionPreference = 'SilentlyContinue'
$cpu = @{}
Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | ForEach-Object { $cpu[[int]$_.IDProcess] = [int]$_.PercentProcessorTime }
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$sess = @{}
Get-CimInstance Win32_Process | ForEach-Object {
  $o = $null
  if ($_.ProcessId -gt 4) { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner }
  [pscustomobject]@{ pid = [int]$_.ProcessId; name = $_.Name; path = $_.ExecutablePath
    user = if ($o -and $o.User) { "$($o.Domain)\$($o.User)" } else { '' }
    mem_mb = [math]::Round($_.WorkingSetSize / 1MB, 1); cpu_pct = [math]::Round(($cpu[[int]$_.ProcessId]) / [math]::Max(1, $cores), 1)
    started = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('s') } else { '' }
    session = [int]$_.SessionId; threads = [int]$_.ThreadCount; cmd = "$($_.CommandLine)".Substring(0, [math]::Min(400, "$($_.CommandLine)".Length)) }
} | ConvertTo-Json -Compress -Depth 2
'''

SERVICES = r'''
$ErrorActionPreference = 'SilentlyContinue'
Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; display = $_.DisplayName; state = $_.State; start = $_.StartMode
    delayed = [bool]$_.DelayedAutoStart; account = $_.StartName; pid = [int]$_.ProcessId; path = $_.PathName; description = $_.Description }
} | ConvertTo-Json -Compress -Depth 2
'''


def _cfg(db):
    from .scanning import winrm_cfg
    cfg = winrm_cfg(db)
    if not cfg:
        raise PermissionError("No Windows credential is configured (Settings > Credentials).")
    return cfg


def _list(x):
    return x if isinstance(x, list) else ([x] if x else [])


def processes(db, dev: Device) -> list[dict]:
    from .collectors.winrm import run_ps
    rows = _list(run_ps(_addr(dev), _cfg(db), PROCESSES))
    for r in rows:
        r["protected"] = (r.get("name") or "").lower() in PROTECTED_PROC or r.get("pid", 0) <= 4
    return sorted(rows, key=lambda r: -(r.get("mem_mb") or 0))


def services(db, dev: Device) -> list[dict]:
    from .collectors.winrm import run_ps
    rows = _list(run_ps(_addr(dev), _cfg(db), SERVICES))
    for r in rows:
        r["protected"] = (r.get("name") or "").lower() in PROTECTED
    return sorted(rows, key=lambda r: (r.get("display") or r.get("name") or "").lower())


def _record(db, dev: Device, who: str, action: str, detail: str, ok: bool) -> None:
    db.add(AuditLog(actor=who[:64], action=f"pc.{action}", target=f"computer:{dev.hostname}", result=detail[:500]))
    log_change(db, dev, "tool", f"{detail} (by {who})" + ("" if ok else " failed"))
    db.commit()


def kill(db, dev: Device, pid: int, name: str, who: str) -> dict:
    from .collectors.winrm import run_ps
    if not isinstance(pid, int) or pid <= 4:
        return {"ok": False, "output": "That process can't be ended from here."}
    if (name or "").lower() in PROTECTED_PROC:
        return {"ok": False, "output": f"{name} is a Windows system process; ending it would crash or lock the PC."}
    r = run_ps(_addr(dev), _cfg(db), f"""
$p = Get-CimInstance Win32_Process -Filter "ProcessId={pid}"
if (-not $p) {{ '{{"ok": false, "message": "not running any more"}}'; return }}
$n = $p.Name
$r = Invoke-CimMethod -InputObject $p -MethodName Terminate
@{{ ok = ($r.ReturnValue -eq 0); message = "$n (PID {pid}): " + $(if ($r.ReturnValue -eq 0) {{ 'ended' }} else {{ "Windows refused (code $($r.ReturnValue))" }}) }} | ConvertTo-Json -Compress""")
    ok, msg = bool(r.get("ok")), r.get("message") or "?"
    _record(db, dev, who, "kill", f"End process {msg}", ok)
    return {"ok": ok, "output": msg}


SERVICE_ACTIONS = {"start", "stop", "restart", "auto", "delayed", "manual", "disabled"}


def service(db, dev: Device, name: str, action: str, who: str) -> dict:
    from .collectors.winrm import run_ps
    if action not in SERVICE_ACTIONS or not SERVICE_RE.match(name or ""):
        return {"ok": False, "output": "Unknown service or action."}
    if name.lower() in PROTECTED and action in ("stop", "restart", "disabled", "manual"):
        return {"ok": False, "output": f"{name} is needed by Windows or by NetInventory's own access; it isn't changed from here."}
    q = name.replace("'", "''")
    body = {
        "start": "Start-Service -Name $n",
        "stop": "Stop-Service -Name $n -Force",
        "restart": "Restart-Service -Name $n -Force",
        "auto": "Set-Service -Name $n -StartupType Automatic; & sc.exe config $n start= auto | Out-Null",
        "delayed": "& sc.exe config $n start= delayed-auto | Out-Null",
        "manual": "Set-Service -Name $n -StartupType Manual",
        "disabled": "Set-Service -Name $n -StartupType Disabled",
    }[action]
    r = run_ps(_addr(dev), _cfg(db), f"""
$ErrorActionPreference = 'Stop'
$n = '{q}'
try {{
  if (-not (Get-Service -Name $n -ErrorAction SilentlyContinue)) {{ throw 'service not found' }}
  {body}
  Start-Sleep -Milliseconds 800
  $s = Get-CimInstance Win32_Service -Filter "Name='$($n -replace "'", "''")'"
  @{{ ok = $true; message = "$($s.DisplayName): $($s.State), start $($s.StartMode)" + $(if ($s.DelayedAutoStart) {{ ' (delayed)' }} else {{ '' }}) }} | ConvertTo-Json -Compress
}} catch {{ @{{ ok = $false; message = "$_" }} | ConvertTo-Json -Compress }}""")
    ok, msg = bool(r.get("ok")), r.get("message") or "?"
    label = {"start": "Start", "stop": "Stop", "restart": "Restart", "auto": "Set to Automatic", "delayed": "Set to Automatic (delayed)",
             "manual": "Set to Manual", "disabled": "Disable"}[action]
    _record(db, dev, who, f"service.{action}", f"{label} service {name}: {msg}", ok)
    return {"ok": ok, "output": msg}
