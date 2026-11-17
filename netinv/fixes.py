"""One-click fixes on a PC, run over WinRM with the scan credential. Each one is confirmed in the UI and
written to the audit log and the PC's history.

- windows_updates: install the pending software updates Windows Update offers this PC (its WSUS server if a GPO
  sets one, otherwise Microsoft Update). Never reboots; the PC shows "reboot pending" afterwards if one is needed.
- app_update: ``winget upgrade --id <package> --exact`` for a machine-wide install.
- start_service: start Microsoft Defender Antivirus, Windows Update or BITS if it is stopped (never changes a
  service that a policy disabled).
- reboot / cancel_reboot: restart in 5 minutes or tonight at the configured hour, with a notice to the signed-in user.
- script: a saved script (Software > Scripts) or a one-off command, PowerShell or command prompt, run as SYSTEM.
  The exact text is stored with the deployment when it's queued, so an edit later never changes what an approved
  push runs; its output and exit code are the result.

Windows refuses to install updates or MSI/winget packages directly from a remote session, so the first two run
as SYSTEM from a one-off scheduled task ("NetInventory fix ...") that writes its result to
C:\\ProgramData\\NetInventory\\fix\\<name>.json on the PC. A background thread checks those results and adds them to
the PC's history.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select

from .db import AuditLog, Device, SessionLocal, get_setting
from .config import settings
from .ingest import log_change

log = logging.getLogger(__name__)
SERVICES = {"WinDefend": "Microsoft Defender Antivirus", "wuauserv": "Windows Update", "BITS": "Background Intelligent Transfer"}
ACTIONS = {"tool", "windows_updates", "app_update", "start_service", "reboot", "cancel_reboot", "app_uninstall", "app_repair", "script",
           "agent_install", "agent_remove"}
LANGS = {"powershell": "PowerShell", "cmd": "Command prompt"}
MAX_SCRIPT = 100_000
KEY_RE = re.compile(r"^[A-Za-z0-9{}\-_. ]{1,128}$")      # an Uninstall registry key name (MSI product code or app id)
_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="fix")
_plock = threading.Lock()

# ------------------------------------------------------------------ scripts that run on the PC
WU_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$res = @{ ok = $false; installed = 0; failed = 0; reboot_required = $false; titles = @() }
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $s.ClientApplicationID = 'NetInventory'
  $found = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
  if ($found.Count -eq 0) { $res.ok = $true; $res.message = 'No pending updates' }
  else {
    $todo = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $found) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$todo.Add($u) }
    $d = $s.CreateUpdateDownloader(); $d.Updates = $todo; [void]$d.Download()
    $i = $s.CreateUpdateInstaller(); $i.Updates = $todo; $i.ForceQuiet = $true
    $r = $i.Install()
    for ($n = 0; $n -lt $todo.Count; $n++) {
      $code = $r.GetUpdateResult($n).ResultCode      # 2 = succeeded, 3 = succeeded with errors
      if ($code -eq 2 -or $code -eq 3) { $res.installed++ } else { $res.failed++ }
      $res.titles += $todo.Item($n).Title
    }
    $res.reboot_required = [bool]$r.RebootRequired
    $res.ok = ($res.failed -eq 0)
    $res.message = "$($res.installed) installed, $($res.failed) failed" + $(if ($res.reboot_required) { ', reboot needed' } else { '' })
    # what to do when a restart is needed: 'none' (just report it), 'restart' (in 5 minutes, with a notice), 'notify' (ask the user)
    if ($res.reboot_required -and '__AFTER__' -eq 'restart') {
      & shutdown.exe /r /t 300 /d p:2:17 /c 'Windows updates were installed. This PC restarts in 5 minutes: please save your work.' 2>&1 | Out-Null
      $res.message += '; restarting in 5 minutes'
    } elseif ($res.reboot_required -and '__AFTER__' -eq 'notify') {
      & msg.exe * /time:86400 'Windows updates were installed on this PC. Please save your work and restart it when you can.' 2>&1 | Out-Null
      $res.message += '; the user was asked to restart'
    }
  }
} catch { $res.message = "$_" }
$res
'''

WINGET_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$res = @{ ok = $false; package = '__PKG__' }
try {
  # winget lives in the App Installer package; as SYSTEM it has to be called by its full path
  $wg = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
        Sort-Object { [version]($_.Directory.Name -split '_')[1] } | Select-Object -Last 1
  if (-not $wg) { throw 'winget (App Installer) is not installed on this PC' }
  # Installed programs before and after, so the server can confirm the new version is really there
  $snap = { @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
    ForEach-Object { @{ name = "$($_.DisplayName)"; version = "$($_.DisplayVersion)"; publisher = "$($_.Publisher)"; product_code = $_.PSChildName } }) }
  $res.before = & $snap
  $out = & $wg.FullName upgrade --id '__PKG__' --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-String
  $res.exit = $LASTEXITCODE
  $res.output = ($out -replace '[^\x20-\x7E\r\n]', '').Trim()
  if ($res.output.Length -gt 1500) { $res.output = $res.output.Substring($res.output.Length - 1500) }
  # 0 = updated; 0x8A15002B = no newer version applies to this install
  $res.ok = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189)
  $res.message = if ($LASTEXITCODE -eq 0) { 'winget finished' } elseif ($LASTEXITCODE -eq -1978335189) { 'winget found no applicable upgrade' } else { "winget exit code $LASTEXITCODE" }
  Start-Sleep -Seconds 5          # some installers return before they finish writing their uninstall entry
  $res.after = & $snap
} catch { $res.message = "$_" }
$res
'''

# Uninstall or repair one program by its Uninstall registry key: MSI products with msiexec, others with their
# QuietUninstallString (or a known silent switch). Refuses rather than pop up an uninstaller nobody can click.
REMOVE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$res = @{ ok = $false; key = '__KEY__'; mode = '__MODE__' }
try {
  $k = $null
  foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
    if (Test-Path "$root\__KEY__") { $k = Get-ItemProperty "$root\__KEY__"; break } }
  if (-not $k) { throw 'not installed on this PC any more (or installed for one user only)' }
  $res.name = $k.DisplayName
  $isMsi = ('__KEY__' -match '^\{[0-9A-Fa-f\-]{36}\}$') -and ($k.WindowsInstaller -eq 1 -or "$($k.UninstallString)" -match 'msiexec')
  if ($isMsi) {
    $margs = if ('__MODE__' -eq 'repair') { "/fa __KEY__ /qn /norestart" } else { "/x __KEY__ /qn /norestart" }
    $p = Start-Process msiexec.exe -ArgumentList $margs -Wait -PassThru
    $code = $p.ExitCode
  } elseif ('__MODE__' -eq 'repair') {
    throw 'repair only works for Windows Installer (MSI) programs'
  } else {
    $cmd = "$($k.QuietUninstallString)"
    if (-not $cmd) {
      $u = "$($k.UninstallString)"
      if ($u -match 'unins\d+\.exe') { $cmd = "$u /VERYSILENT /SUPPRESSMSGBOXES /NORESTART" }     # Inno Setup
      elseif ($u -match 'uninst(all)?\.exe' -and $u -notmatch ' /') { $cmd = "$u /S" }       # NSIS
      else { throw 'this program has no silent uninstall; remove it by hand or with winget' }
    }
    $p = Start-Process cmd.exe -ArgumentList "/c $cmd" -Wait -PassThru -WindowStyle Hidden
    $code = $p.ExitCode
  }
  $res.exit = $code
  $res.ok = ($code -in 0, 1641, 3010)
  if ('__MODE__' -eq 'remove') {
    Start-Sleep -Seconds 5
    $res.still_installed = [bool](@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') |
      Where-Object { Test-Path "$_\__KEY__" })
  }
  $res.message = switch ($code) { 0 { 'Done' } 1641 { 'Done, the PC is restarting' } 3010 { 'Done, needs a restart' } 1605 { 'Not installed' } 1618 { 'Another installation is running; try again later' } default { "Exit code $code" } }
} catch { $res.message = "$_" }
$res
"""

# Runs a user's script (PowerShell or .cmd) in its own process with a time limit; keeps the end of its output.
SCRIPT_RUNNER = r"""
$res = @{ ok = $false }
try {
  $dir = Join-Path $env:ProgramData 'NetInventory\fix'
  $ext = '__EXT__'
  $f = Join-Path $dir ('__NAME__-script' + $ext)
  $out = Join-Path $dir '__NAME__-out.txt'
  $code = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SB64__'))
  if ($ext -eq '.cmd') { [IO.File]::WriteAllText($f, $code, [Text.Encoding]::Default) }
  else { [IO.File]::WriteAllText($f, $code, (New-Object Text.UTF8Encoding $true)) }
  if ($ext -eq '.cmd') { $exe = "$env:SystemRoot\System32\cmd.exe"; $a = "/d /c `"$f`"" }
  else { $exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"; $a = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$f`"" }
  $p = Start-Process $exe -ArgumentList $a -RedirectStandardOutput $out -RedirectStandardError "$out.err" -PassThru
  if (-not $p.WaitForExit(__TIMEOUT__ * 60000)) {
    try { & taskkill.exe /PID $p.Id /T /F | Out-Null } catch {}
    $res.exit = -1; $res.message = 'Stopped: still running after __TIMEOUT__ minutes'
  } else { $res.exit = $p.ExitCode; $res.ok = ($p.ExitCode -eq 0); $res.message = "Exit code $($p.ExitCode)" }
  Start-Sleep -Milliseconds 300
  $o = ("$(Get-Content $out -Raw -ErrorAction SilentlyContinue)" + "$(Get-Content "$out.err" -Raw -ErrorAction SilentlyContinue)").Trim()
  if ($o.Length -gt 3500) { $o = '...' + $o.Substring($o.Length - 3500) }
  $res.output = $o
  Remove-Item $f, $out, "$out.err" -ErrorAction SilentlyContinue
} catch { $res.message = "$_" }
$res
"""

# Writes the script to the PC, runs it as SYSTEM from a one-off task, and returns at once.
LAUNCH = r'''
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:ProgramData 'NetInventory\fix'
New-Item -ItemType Directory $dir -Force | Out-Null
$name = '__NAME__'
$body = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__B64__'))
$wrap = "`$r = & { $body }`r`n`$r.finished = (Get-Date).ToString('o')`r`n`$r | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 '$dir\$name.json'"
Remove-Item "$dir\$name.json" -ErrorAction SilentlyContinue
Set-Content -LiteralPath "$dir\$name.ps1" -Value $wrap -Encoding UTF8
$task = "NetInventory fix $name"
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$dir\$name.ps1`""
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action $a -Principal $p -Settings $st -Force | Out-Null
Start-ScheduledTask -TaskName $task
'{"ok": true}'
'''

RESULT = r'''
$f = Join-Path $env:ProgramData 'NetInventory\fix\__NAME__.json'
$t = Get-ScheduledTask -TaskName 'NetInventory fix __NAME__' -ErrorAction SilentlyContinue
$state = if ($t) { "$($t.State)" } else { 'missing' }
if (Test-Path $f) {
  $j = Get-Content $f -Raw | ConvertFrom-Json
  if ($t -and $state -ne 'Running') { Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false }
  @{ done = $true; state = $state; result = $j } | ConvertTo-Json -Depth 5 -Compress
} else { @{ done = $false; state = $state } | ConvertTo-Json -Compress }
'''


def _task_name(action: str, pkg: str | None = None) -> str:
    if action == "windows_updates":
        return "windows-updates"
    if action in ("agent_install", "agent_remove"):
        return action.replace("_", "-")
    prefix = {"app_uninstall": "remove-", "app_repair": "repair-"}.get(action, "app-")
    return prefix + re.sub(r"[^A-Za-z0-9.\-]", "_", pkg or "")[:80]


def _cfg(db, dep=None):
    """WinRM settings and credentials for a push. A push made with a chosen account (dep.cred_id) uses only that."""
    from .scanning import winrm_cfg
    base = winrm_cfg(db)
    cid = getattr(dep, "cred_id", None)
    if cid is None:
        return base
    return {**(base or settings.winrm), "creds": [cred_for_push(db, cid)]}


def cred_for_push(db, cid: int) -> dict:
    """The sign-in for 'Run as' on a push: 0 = this server's own Windows account, else a stored Windows credential."""
    from .db import Credential
    from .scanning import SERVICE_CRED_ID, cred_cfg, service_cfg
    if cid == SERVICE_CRED_ID:
        return service_cfg()
    c = db.get(Credential, cid)
    if not c or c.kind != "windows":
        raise PermissionError("The account chosen for this push no longer exists (Settings, Credentials).")
    return cred_cfg(c)


def _audit(db, who: str, action: str, host: str, result: str) -> None:
    db.add(AuditLog(actor=(who or "")[:64], action=f"fix.{action}", target=f"computer:{host}", result=result[:500]))


# ------------------------------------------------------------------ the deployment queue and log
# Every push is a Deployment row: queued -> sending -> running (long jobs on the PC) -> success | failed.
# A PC that can't be reached stays queued and is retried when it's back online, until the deadline
# (Settings, default 7 days): then it's "expired". At most `fix:parallel` pushes are sent at once.
LONG = {"windows_updates": 4, "app_update": 1, "app_uninstall": 1, "app_repair": 1, "agent_install": 0.5, "agent_remove": 0.5}       # hours to wait for the result on the PC
OFFLINE_RETRY_MIN = 10


def queue_days(db) -> int:
    try:
        return max(1, min(60, int(get_setting(db, "fix:queue_days") or 7)))
    except ValueError:
        return 7


def check_script(language: str, body: str, timeout: int) -> None:
    if language not in LANGS:
        raise ValueError("Pick PowerShell or Command prompt.")
    if not (body or "").strip():
        raise ValueError("The script is empty.")
    if len(body) > MAX_SCRIPT:
        raise ValueError(f"Scripts are limited to {MAX_SCRIPT // 1000} KB.")
    if not 1 <= int(timeout) <= 240:
        raise ValueError("The time limit is 1 to 240 minutes.")


def script_payload(db, value: str | None, adhoc: dict | None) -> tuple[str, str, str | None]:
    """(label, payload JSON, value) for a saved script (value = its id) or a one-off command (adhoc)."""
    from .db import Script
    if value:
        sc = db.get(Script, int(value)) if str(value).isdigit() else None
        if sc is None:
            raise ValueError("That script doesn't exist any more.")
        lang, body, timeout, label = sc.language, sc.body, sc.timeout_min or 30, f"Run script {sc.name}"
    else:
        adhoc = adhoc or {}
        lang, body, timeout = adhoc.get("language") or "powershell", adhoc.get("body") or "", int(adhoc.get("timeout") or 10)
        first = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
        label = f"Run command: {first[:80]}" + ("…" if len(first) > 80 or body.strip().count("\n") else "")
    check_script(lang, body, timeout)
    return label[:255], json.dumps({"language": lang, "body": body, "timeout": int(timeout)}), (str(value) if value else None)


def _digest(payload: str) -> str:
    import hashlib
    p = json.loads(payload)
    if "tool" in p:
        return f"tool {p['tool']}: " + json.dumps(p.get("args") or {})[:200]
    return f"{LANGS[p['language']]}, sha256 {hashlib.sha256(p['body'].encode()).hexdigest()[:12]}"


WU_AFTER = {"none": "", "restart": ", then restart if needed", "notify": ", then ask the user to restart"}


def tool_payload(spec: dict | None) -> tuple[str, str]:
    """(label, payload) for a remote tool run through the queue (remote.BULK)."""
    from . import remote
    return remote.bulk_label(spec or {}), json.dumps(spec)


def _validate(action: str, value: str | None) -> tuple[str, str | None]:
    """(label, value) or ValueError."""
    from . import catalog
    if action not in ACTIONS:
        raise ValueError("Unknown fix.")
    if action == "windows_updates":
        v = value if value in WU_AFTER else "none"
        return "Install pending Windows updates" + WU_AFTER[v], (None if v == "none" else v)
    if action == "app_update":
        pkg = (value or "").strip()
        if not catalog.package_exists(pkg):
            raise ValueError("That package isn't in the app catalog.")
        return f"Update {pkg}", pkg
    if action in ("app_uninstall", "app_repair"):
        if not KEY_RE.match(value or ""):
            raise ValueError("That program can't be identified on the PC.")
        return f"{'Uninstall' if action == 'app_uninstall' else 'Repair'} {value}", value
    if action == "script":
        return "Run script", value
    if action == "tool":
        return "Tool", None
    if action == "agent_install":
        from .agentpush import RUN_AS
        run_as = value if value in RUN_AS else "LOCALSERVICE"
        return f"Install NetInventory Agent (runs as {RUN_AS[run_as]})", run_as
    if action == "agent_remove":
        return "Remove NetInventory Agent", None
    if action == "start_service":
        if value not in SERVICES:
            raise ValueError("That service can't be started from here.")
        return f"Start {SERVICES[value]}", value
    if action == "reboot":
        return ("Reboot tonight" if value == "tonight" else "Reboot in 5 minutes"), ("tonight" if value == "tonight" else "soon")
    return "Cancel scheduled reboot", None


def _sw_name(db, hostname: str, code: str) -> str | None:
    from .db import Software
    return db.scalar(select(Software.name).join(Device).where(Device.hostname == hostname, Software.product_code == code))


def enqueue(db, hostname: str, action: str, who: str, value: str | None = None, adhoc: dict | None = None,
            snapshot: tuple[str, str] | None = None, cred_id: int | None = None):
    """snapshot = (label, payload) re-runs exactly what an earlier script push ran (Retry)."""
    from .db import Deployment, utcnow
    from datetime import timedelta
    label, value = _validate(action, value)
    payload = None
    if action == "script":
        label, payload = snapshot if snapshot else script_payload(db, value, adhoc)[:2]
    if action == "tool":
        label, payload = snapshot if snapshot else tool_payload(adhoc)
    if action in ("app_uninstall", "app_repair"):
        name = _sw_name(db, hostname, value)
        if not name:
            raise ValueError("That program isn't in this PC's inventory.")
        label = f"{'Uninstall' if action == 'app_uninstall' else 'Repair'} {name}"
    now = utcnow()
    dep = Deployment(hostname=hostname, action=action, value=value, label=label, who=who, status="queued", payload=payload,
                     created=now, next_try=now, expires=now + timedelta(days=queue_days(db)), cred_id=cred_id)
    db.add(dep)
    _audit(db, who, action, hostname, f"queued: {label}" + (f" ({_digest(payload)})" if payload else ""))
    db.commit()
    return dep


def _execute(db, dev: Device, dep) -> str:
    """Send the push to the PC. Returns the immediate result; raises on failure."""
    from .actions import _addr
    from .collectors.winrm import run_ps
    cfg = _cfg(db, dep)
    if not cfg:
        raise PermissionError("No Windows credential is ticked on any scan target (Settings, Scan targets), "
                              "and no account was chosen for this push.")
    addr = _addr(dev)
    action, value = dep.action, dep.value
    if action == "tool":
        from . import remote
        return remote.bulk_run(db, dev, dep.who or "?", json.loads(dep.payload or "{}"))
    if action == "windows_updates":
        _launch(addr, cfg, _task_name(action), WU_SCRIPT.replace("__AFTER__", value if value in WU_AFTER else "none"))
        return "Started. Windows is downloading and installing the updates."
    if action == "app_update":
        _launch(addr, cfg, _task_name(action, value), WINGET_SCRIPT.replace("__PKG__", value))
        return f"Started winget upgrade of {value}."
    if action in ("app_uninstall", "app_repair"):
        _launch(addr, cfg, _task_name(action, value), REMOVE_SCRIPT.replace("__KEY__", value).replace("__MODE__", "repair" if action == "app_repair" else "remove"))
        return f"Started {'uninstall' if action == 'app_uninstall' else 'repair'}."
    if action == "agent_install":
        from . import agentpush
        _launch(addr, cfg, _task_name(action), agentpush.install_script(db, dev.hostname, _task_name(action), value or "LOCALSERVICE"))
        return "Sent. Installing the agent and waiting for its first report."
    if action == "agent_remove":
        from . import agentpush
        _launch(addr, cfg, _task_name(action), agentpush.REMOVE)
        return "Sent. Removing the agent."
    if action == "script":
        p = json.loads(dep.payload or "{}")
        check_script(p.get("language"), p.get("body") or "", p.get("timeout") or 0)
        body = (SCRIPT_RUNNER.replace("__EXT__", ".cmd" if p["language"] == "cmd" else ".ps1").replace("__NAME__", _dep_task(dep))
                .replace("__TIMEOUT__", str(int(p["timeout"])))
                .replace("__SB64__", base64.b64encode(p["body"].encode("utf-8")).decode()))
        _launch(addr, cfg, _dep_task(dep), body)
        return f"Started ({LANGS[p['language']]}, as SYSTEM, up to {p['timeout']} min)."
    if action == "start_service":
        r = run_ps(addr, cfg, f"""
$s = Get-Service -Name '{value}' -ErrorAction SilentlyContinue
if (-not $s) {{ '{{"ok": false, "message": "service not found"}}'; return }}
$mode = (Get-CimInstance Win32_Service -Filter "Name='{value}'").StartMode
if ($mode -eq 'Disabled') {{ '{{"ok": false, "message": "disabled (by policy or by hand), not changed"}}'; return }}
if ($s.Status -ne 'Running') {{ Start-Service -Name '{value}'; Start-Sleep 3; $s.Refresh() }}
@{{ ok = ($s.Status -eq 'Running'); message = "$($s.Status)" }} | ConvertTo-Json -Compress""")
        out = f"{SERVICES[value]}: {r.get('message')}"
        if not r.get("ok"):
            raise RuntimeError(out)
        return out
    if action == "reboot":
        hour = int(get_setting(db, "fix:reboot_hour") or 2)
        if value == "tonight":
            secs = (f"$n = Get-Date; $t = $n.Date.AddHours({hour}); if ($t -le $n) {{ $t = $t.AddDays(1) }}; "
                    "$s = [int]($t - $n).TotalSeconds")
            label = f"Reboot scheduled for {hour:02d}:00"
        else:
            secs, label = "$s = 300", "Reboot in 5 minutes"
        run_ps(addr, cfg, secs + "; & shutdown.exe /r /t $s /d p:0:0 /c 'Your IT team scheduled a restart of this PC. "
               "Save your work.' 2>&1 | Out-Null; @{ ok = ($LASTEXITCODE -eq 0); seconds = $s } | ConvertTo-Json -Compress")
        return label + ". The signed-in user sees a notice."
    r = run_ps(addr, cfg, "& shutdown.exe /a 2>&1 | Out-Null; @{ ok = ($LASTEXITCODE -eq 0); code = $LASTEXITCODE } | ConvertTo-Json -Compress")
    return "Scheduled reboot cancelled." if r.get("ok") else "No reboot was scheduled."


def _dep_task(dep) -> str:
    return f"script-{dep.id}" if dep.action == "script" else _task_name(dep.action, dep.value)


def _wait_hours(dep) -> float | None:
    if dep.action == "script":
        return (json.loads(dep.payload or "{}").get("timeout") or 30) / 60 + 0.5
    return LONG.get(dep.action)


def attempt(db, dep) -> dict:
    """Try to send one queued deployment now."""
    from .collectors.winrm import classify_error
    from .db import utcnow
    from datetime import timedelta
    from .db import norm_host
    dev = db.scalar(select(Device).where(Device.hostname == norm_host(dep.hostname)))
    now = utcnow()
    if dev is None:
        dep.status, dep.finished, dep.message = "failed", now, "Computer not found"
        db.commit()
        return {"ok": False, "output": dep.message}
    dep.status, dep.attempts = "sending", (dep.attempts or 0) + 1
    dep.started = dep.started or now
    db.commit()
    try:
        out = _execute(db, dev, dep)
    except Exception as exc:
        msg = str(exc).split("\n")[0][:300]
        if classify_error(exc) == "unreachable" and dep.expires and now < dep.expires:
            dep.status, dep.next_try = "queued", now + timedelta(minutes=OFFLINE_RETRY_MIN)
            dep.message = f"PC not reachable ({msg}). Waiting for it to come online; tried {dep.attempts}x."
            db.commit()
            return {"ok": True, "output": f"{dev.hostname} isn't reachable right now. Queued: it runs when the PC is back "
                                          f"online (until {dep.expires:%Y-%m-%d %H:%M} UTC). See Software > Deployments."}
        dep.status, dep.finished, dep.message = "failed", utcnow(), msg
        _audit(db, dep.who, dep.action, dev.hostname, f"failed: {msg}")
        log_change(db, dev, "fix", f"{dep.label} (by {dep.who}) failed: {msg}")
        db.commit()
        return {"ok": False, "output": f"Failed: {msg}"}
    if _wait_hours(dep):
        dep.status, dep.message = "running", out
        dep.task = _dep_task(dep)
        dep.check_until = now + timedelta(hours=_wait_hours(dep))
        dep.next_try = now + timedelta(seconds=20 if dep.action == "script" else 60)
        out += " The result appears in the deployment log and the PC's History."
    else:
        dep.status, dep.finished, dep.message = "success", utcnow(), out
    _audit(db, dep.who, dep.action, dev.hostname, out)
    log_change(db, dev, "fix", f"{dep.label} (by {dep.who}): {out}")
    db.commit()
    return {"ok": True, "output": out}


def run(db, dev: Device, action: str, who: str, value: str | None = None, adhoc: dict | None = None) -> dict:
    """One PC, from its page: queue it and send it right away, so the answer is immediate."""
    try:
        dep = enqueue(db, dev.hostname, action, who, value, adhoc)
    except ValueError as exc:
        return {"ok": False, "output": str(exc)}
    if not _cfg(db):
        dep.status, dep.message = "failed", "No Windows credential is configured (Settings > Credentials)."
        db.commit()
        return {"ok": False, "output": dep.message}
    return attempt(db, dep)


def run_many(hostnames: list[str], action: str, who: str, value: str | None = None, adhoc: dict | None = None,
             snapshot: tuple[str, str] | None = None, cred_id: int | None = None) -> int:
    """Queue a push to many PCs; the dispatcher sends them a few at a time. Returns how many were queued."""
    from .db import norm_host
    hosts = list(dict.fromkeys(norm_host(h) for h in hostnames))
    with SessionLocal() as db:
        _validate(action, value)
        if action == "script" and not snapshot:      # one snapshot for every PC, so they all run the same text
            snapshot = script_payload(db, value, adhoc)[:2]
        if action == "tool" and not snapshot:
            snapshot = tool_payload(adhoc)
        known = {h for (h,) in db.execute(select(Device.hostname).where(Device.hostname.in_(hosts)))}
        queued = 0
        for h in hosts:
            if h in known:
                try:
                    enqueue(db, h, action, who, value, snapshot=snapshot, cred_id=cred_id)
                    queued += 1
                except ValueError:
                    db.rollback()      # e.g. that program isn't on this PC
        known = range(queued)
    _wake.set()
    return len(known)


def _launch(addr: str, cfg: dict, name: str, body: str) -> None:
    from .collectors.winrm import run_ps
    b64 = base64.b64encode(body.encode("utf-8")).decode()
    run_ps(addr, cfg, LAUNCH.replace("__NAME__", name).replace("__B64__", b64))


def check(db, dev: Device, name: str, dep=None) -> dict:
    from .actions import _addr
    from .collectors.winrm import run_ps
    return run_ps(_addr(dev), _cfg(db, dep), RESULT.replace("__NAME__", name))


def parallel(db) -> int:
    try:
        return max(1, min(32, int(get_setting(db, "fix:parallel") or 8)))
    except ValueError:
        return 8


_wake = threading.Event()
_inflight: set[int] = set()


def _send(dep_id: int) -> None:
    from .db import Deployment
    try:
        with SessionLocal() as db:
            dep = db.get(Deployment, dep_id)
            if dep and dep.status == "queued":
                attempt(db, dep)
    except Exception:
        log.exception("deployment %s", dep_id)
    finally:
        with _plock:
            _inflight.discard(dep_id)


RESCAN_AFTER = {"app_update", "app_uninstall", "app_repair", "windows_updates"}
WINGET_CODES = {
    -1978335189: "winget found no applicable upgrade for this install. Common causes: it was installed for one user only, "
                 "with a different installer type than the catalog's, or the newest version doesn't support this PC",
    -1978335212: "winget couldn't find this program installed on the PC",
    -1978334967: "the update needs a restart of the PC to finish",            # 0x8A150109
    -1978334966: "the PC has to restart before this update can install",     # 0x8A15010A
    -1978334975: "the app is in use; close it and try again",                 # 0x8A150101
    -1978334974: "another installation is running; try again later",         # 0x8A150102
    -1978334973: "a file the installer needs is in use; close the app and try again",   # 0x8A150103
}


def verify_update(db, pkg: str, res: dict) -> tuple[bool, str]:
    """Success only if the PC now has the catalog's version (or newer) of pkg, whatever winget's exit code said."""
    from . import catalog
    code = res.get("exit")
    if code is None:                       # the script failed before winget ran
        return False, res.get("message") or "winget didn't run"
    have_after = catalog.installed_versions(db, pkg, res.get("after") or [])
    have_before = catalog.installed_versions(db, pkg, res.get("before") or [])
    target = catalog.target_version(pkg)
    why = WINGET_CODES.get(code) or (f"winget exit code {code} (0x{code & 0xFFFFFFFF:08X})" if code else "")
    out = (res.get("output") or "").strip()
    tail = f"\nwinget output:\n{out[-800:]}" if out else ""
    if not have_after:
        return False, (f"{pkg} isn't in the PC's installed programs after the update" + (f"; {why}" if why else "")
                       + ". It may be installed for one user only." + tail)
    now = max(have_after, key=catalog.vt)
    was = max(have_before, key=catalog.vt) if have_before else None
    if target and catalog.vt(now) >= catalog.vt(target):
        return True, f"Updated {pkg}: {was or '?'} -> {now} (confirmed on the PC)"
    if not target and was and catalog.vt(now) > catalog.vt(was):
        return True, f"Updated {pkg}: {was} -> {now} (confirmed on the PC)"
    still = f"still {now}" + (f", latest is {target}" if target else "")
    if code == 0:
        why = "winget reported success, but the new version isn't installed. The app may have been running, or the update finishes after a restart"
    return False, f"Not updated ({still}): {why}." + tail


_rescan_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rescan")


def _rescan_later(hostname: str, check_pending: bool = False) -> None:
    """Refresh the PC's inventory so the Software tab shows the version that is really installed now
    (four at a time, so a deployment to many PCs doesn't start hundreds of scans at once)."""
    from .actions import rescan

    def go():
        try:
            rescan(hostname, wait=True, check_pending=check_pending)
        except Exception:
            log.exception("rescan after deployment on %s", hostname)
    _rescan_pool.submit(go)


def _check_running(db, dep) -> None:
    from .db import utcnow, norm_host
    from datetime import timedelta
    now = utcnow()
    dev = db.scalar(select(Device).where(Device.hostname == norm_host(dep.hostname)))
    if dev is None:
        dep.status, dep.finished, dep.message = "failed", now, "Computer no longer exists"
        return
    try:
        r = check(db, dev, dep.task, dep)
    except Exception as exc:
        if dep.check_until and now > dep.check_until:
            dep.status, dep.finished = "failed", now
            dep.message = f"No result: the PC stayed unreachable past the time limit ({str(exc)[:200]})"
            log_change(db, dev, "fix", f"{dep.label}: {dep.message}")
        else:
            dep.next_try = now + timedelta(minutes=2)
        return
    if r.get("done") or (dep.check_until and now > dep.check_until):
        res = r.get("result") or {}
        ok = bool(res.get("ok"))
        msg = res.get("message") or ("no result after the time limit" if not r.get("done") else "done")
        if dep.action == "script":
            if res.get("output"):
                msg += f"\n{res['output']}"
        elif dep.action == "agent_install":
            from . import agentpush
            agentpush.drop_ticket(db, dev.hostname)
            st = agentpush.agent_state(db, dev.hostname)
            if ok and st and st != "active":
                msg += f"; {st}"
            if res.get("log") and not ok:
                msg += f"\nAgent log:\n{res['log']}"
        elif dep.action == "agent_remove" and ok:
            from .db import Agent
            for a in db.scalars(select(Agent).where(Agent.hostname == dev.hostname, Agent.status != "revoked")):
                a.status, a.note = "revoked", f"agent removed by {dep.who}"
        elif dep.action == "app_update" and r.get("done"):
            ok, msg = verify_update(db, dep.value, res)
        elif dep.action == "app_uninstall" and ok and res.get("still_installed") and res.get("exit") not in (1641, 3010):
            ok, msg = False, "The uninstaller finished but the program is still installed"
        elif res.get("output") and not ok:
            msg += f": {str(res['output'])[-500:]}"
        if dep.action in RESCAN_AFTER:
            _rescan_later(dev.hostname, check_pending=dep.action == "windows_updates")
        dep.status, dep.finished, dep.message = ("success" if ok else "failed"), now, msg[:4000]
        log_change(db, dev, "fix", f"{dep.label}: {msg.splitlines()[0] if msg else ''} ({'ok' if ok else 'problem'})")
    else:
        dep.next_try = now + timedelta(minutes=2)


def poll_once() -> None:
    from .db import Deployment, utcnow
    now = utcnow()
    with SessionLocal() as db:
        # finished on the PC yet?
        for dep in db.scalars(select(Deployment).where(Deployment.status == "running", Deployment.next_try <= now).limit(50)):
            try:
                _check_running(db, dep)
            except Exception:
                log.exception("deployment check %s", dep.id)
            db.commit()
        # past the deadline while waiting
        for dep in db.scalars(select(Deployment).where(Deployment.status == "queued", Deployment.expires < now)):
            dep.status, dep.finished = "expired", now
            dep.message = (dep.message or "") + " Gave up: the PC wasn't reachable before the deadline."
        db.commit()
        # send what's due, a few at a time; skip PCs known to be offline (they're retried when the dot turns green)
        free = parallel(db) - len(_inflight)
        if free <= 0:
            return
        q = (select(Deployment).where(Deployment.status == "queued", Deployment.next_try <= now)
             .order_by(Deployment.created, Deployment.id).limit(500))
        offline = {h for (h,) in db.execute(select(Device.hostname).where(Device.online.is_(False)))}
        for dep in db.scalars(q):
            if free <= 0:
                break
            if dep.id in _inflight or (dep.hostname in offline and dep.attempts):
                continue
            with _plock:
                _inflight.add(dep.id)
            free -= 1
            _pool.submit(_send, dep.id)


def loop(stop: threading.Event) -> None:
    from .db import Deployment
    try:   # a restart in the middle of sending: send again
        with SessionLocal() as db:
            for dep in db.scalars(select(Deployment).where(Deployment.status == "sending")):
                dep.status = "queued"
            db.commit()
    except Exception:
        log.exception("deployment queue")
    while not stop.is_set():
        try:
            poll_once()
        except Exception:
            log.exception("deployment queue")
        _wake.wait(20)
        _wake.clear()


def running(host: str) -> list[str]:
    from .db import Deployment, norm_host
    with SessionLocal() as db:
        return [d.label for d in db.scalars(select(Deployment).where(
            Deployment.hostname == norm_host(host), Deployment.status.in_(("sending", "running"))))]
