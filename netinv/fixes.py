"""One-click fixes on a PC, run over WinRM with the scan credential. Each one is confirmed in the UI and
written to the audit log and the PC's history.

- windows_updates: install the pending software updates Windows Update offers this PC (its WSUS server if a GPO
  sets one, otherwise Microsoft Update). Never reboots; the PC shows "reboot pending" afterwards if one is needed.
- app_update: ``winget upgrade --id <package> --exact`` for a machine-wide install.
- start_service: start Microsoft Defender Antivirus, Windows Update or BITS if it is stopped (never changes a
  service that a policy disabled).
- reboot / cancel_reboot: restart in 5 minutes or tonight at the configured hour, with a notice to the signed-in user.

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
from .ingest import log_change

log = logging.getLogger(__name__)
SERVICES = {"WinDefend": "Microsoft Defender Antivirus", "wuauserv": "Windows Update", "BITS": "Background Intelligent Transfer"}
ACTIONS = {"windows_updates", "app_update", "start_service", "reboot", "cancel_reboot"}
_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="fix")
_pending: dict[tuple[str, str], dict] = {}     # (hostname, task) -> {"until": ts, "label": ...}
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
  $out = & $wg.FullName upgrade --id '__PKG__' --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-String
  $res.exit = $LASTEXITCODE
  $res.output = ($out -replace '[^\x20-\x7E\r\n]', '').Trim()
  if ($res.output.Length -gt 1500) { $res.output = $res.output.Substring($res.output.Length - 1500) }
  # 0 = updated; 0x8A15002B = no newer version applies to this install
  $res.ok = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189)
  $res.message = if ($LASTEXITCODE -eq 0) { 'Updated' } elseif ($LASTEXITCODE -eq -1978335189) { 'Already up to date for this install' } else { "winget exit code $LASTEXITCODE" }
} catch { $res.message = "$_" }
$res
'''

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
    return "windows-updates" if action == "windows_updates" else "app-" + re.sub(r"[^A-Za-z0-9.\-]", "_", pkg or "")[:80]


def _cfg(db):
    from .scanning import winrm_cfg
    return winrm_cfg(db)


def _audit(db, who: str, action: str, host: str, result: str) -> None:
    db.add(AuditLog(actor=who[:64], action=f"fix.{action}", target=f"computer:{host}", result=result[:500]))


# ------------------------------------------------------------------ actions
def run(db, dev: Device, action: str, who: str, value: str | None = None) -> dict:
    from .actions import _addr
    from .collectors.winrm import run_ps
    from . import catalog
    if action not in ACTIONS:
        return {"ok": False, "output": "Unknown fix."}
    cfg = _cfg(db)
    if not cfg:
        return {"ok": False, "output": "No Windows credential is configured (Settings > Credentials)."}
    addr = _addr(dev)
    try:
        if action == "windows_updates":
            label = "Install pending Windows updates"
            _launch(addr, cfg, _task_name(action), WU_SCRIPT)
            _track(dev.hostname, _task_name(action), label, hours=4)
            out = "Started. Windows is downloading and installing the updates; the result appears in History."
        elif action == "app_update":
            pkg = (value or "").strip()
            if not catalog.package_exists(pkg):
                return {"ok": False, "output": "That package isn't in the app catalog."}
            label = f"Update {pkg}"
            _launch(addr, cfg, _task_name(action, pkg), WINGET_SCRIPT.replace("__PKG__", pkg))
            _track(dev.hostname, _task_name(action, pkg), label, hours=1)
            out = f"Started winget upgrade of {pkg}; the result appears in History."
        elif action == "start_service":
            if value not in SERVICES:
                return {"ok": False, "output": "That service can't be started from here."}
            label = f"Start {SERVICES[value]}"
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
        elif action == "reboot":
            hour = int(get_setting(db, "fix:reboot_hour") or 2)
            if value == "tonight":
                label = f"Reboot scheduled for {hour:02d}:00"
                secs = (f"$n = Get-Date; $t = $n.Date.AddHours({hour}); if ($t -le $n) {{ $t = $t.AddDays(1) }}; "
                        "$s = [int]($t - $n).TotalSeconds")
            else:
                label, secs = "Reboot in 5 minutes", "$s = 300"
            run_ps(addr, cfg, secs + "; & shutdown.exe /r /t $s /d p:0:0 /c 'Your IT team scheduled a restart of this PC. "
                   "Save your work.' 2>&1 | Out-Null; @{ ok = ($LASTEXITCODE -eq 0); seconds = $s } | ConvertTo-Json -Compress")
            out = label + ". The signed-in user sees a notice."
        else:  # cancel_reboot
            label = "Cancel scheduled reboot"
            r = run_ps(addr, cfg, "& shutdown.exe /a 2>&1 | Out-Null; @{ ok = ($LASTEXITCODE -eq 0); code = $LASTEXITCODE } | ConvertTo-Json -Compress")
            out = "Scheduled reboot cancelled." if r.get("ok") else "No reboot was scheduled."
    except Exception as exc:
        msg = str(exc).split("\n")[0][:300]
        _audit(db, who, action, dev.hostname, f"failed: {msg}")
        log_change(db, dev, "fix", f"{action} by {who} failed: {msg}")
        db.commit()
        return {"ok": False, "output": f"Failed: {msg}"}
    _audit(db, who, action, dev.hostname, out)
    log_change(db, dev, "fix", f"{label} (by {who}): {out}")
    db.commit()
    return {"ok": True, "output": out}


def run_many(hostnames: list[str], action: str, who: str, value: str | None = None) -> int:
    """Start a fix on many PCs in the background. Returns how many were queued."""
    from .db import norm_host

    def one(h):
        with SessionLocal() as db:
            dev = db.scalar(select(Device).where(Device.hostname == norm_host(h)))
            if dev:
                run(db, dev, action, who, value)
    hosts = list(dict.fromkeys(hostnames))
    for h in hosts:
        _pool.submit(one, h)
    return len(hosts)


def _launch(addr: str, cfg: dict, name: str, body: str) -> None:
    from .collectors.winrm import run_ps
    b64 = base64.b64encode(body.encode("utf-8")).decode()
    run_ps(addr, cfg, LAUNCH.replace("__NAME__", name).replace("__B64__", b64))


def _track(host: str, name: str, label: str, hours: float) -> None:
    with _plock:
        _pending[(host, name)] = {"until": time.time() + hours * 3600, "label": label, "next": time.time() + 60}


def check(db, dev: Device, name: str) -> dict:
    from .actions import _addr
    from .collectors.winrm import run_ps
    return run_ps(_addr(dev), _cfg(db), RESULT.replace("__NAME__", name))


def poll_once() -> None:
    now = time.time()
    with _plock:
        due = [(k, v) for k, v in _pending.items() if v["next"] <= now]
    for (host, name), info in due:
        try:
            with SessionLocal() as db:
                dev = db.scalar(select(Device).where(Device.hostname == host))
                if dev is None:
                    raise LookupError
                r = check(db, dev, name)
                if r.get("done") or now > info["until"]:
                    res = r.get("result") or {}
                    msg = res.get("message") or ("no result after the time limit" if not r.get("done") else "done")
                    ok = "ok" if res.get("ok") else "problem"
                    log_change(db, dev, "fix", f"{info['label']}: {msg} ({ok})")
                    db.commit()
                    with _plock:
                        _pending.pop((host, name), None)
                    continue
        except LookupError:
            with _plock:
                _pending.pop((host, name), None)
            continue
        except Exception as exc:
            log.info("fix result check %s/%s: %s", host, name, exc)
            if now > info["until"]:     # PC stayed unreachable past the time limit: stop asking
                with _plock:
                    _pending.pop((host, name), None)
                continue
        with _plock:
            if (host, name) in _pending:
                _pending[(host, name)]["next"] = now + 120


def loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            poll_once()
        except Exception:
            log.exception("fix poller")
        stop.wait(30)


def running(host: str) -> list[str]:
    with _plock:
        return [v["label"] for (h, _), v in _pending.items() if h == host]
