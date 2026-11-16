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
ACTIONS = {"windows_updates", "app_update", "start_service", "reboot", "cancel_reboot", "app_uninstall", "app_repair"}
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
  $res.message = switch ($code) { 0 { 'Done' } 1641 { 'Done, the PC is restarting' } 3010 { 'Done, needs a restart' } 1605 { 'Not installed' } 1618 { 'Another installation is running; try again later' } default { "Exit code $code" } }
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
    prefix = {"app_uninstall": "remove-", "app_repair": "repair-"}.get(action, "app-")
    return prefix + re.sub(r"[^A-Za-z0-9.\-]", "_", pkg or "")[:80]


def _cfg(db):
    from .scanning import winrm_cfg
    return winrm_cfg(db)


def _audit(db, who: str, action: str, host: str, result: str) -> None:
    db.add(AuditLog(actor=(who or "")[:64], action=f"fix.{action}", target=f"computer:{host}", result=result[:500]))


# ------------------------------------------------------------------ the deployment queue and log
# Every push is a Deployment row: queued -> sending -> running (long jobs on the PC) -> success | failed.
# A PC that can't be reached stays queued and is retried when it's back online, until the deadline
# (Settings, default 7 days): then it's "expired". At most `fix:parallel` pushes are sent at once.
LONG = {"windows_updates": 4, "app_update": 1, "app_uninstall": 1, "app_repair": 1}       # hours to wait for the result on the PC
OFFLINE_RETRY_MIN = 10


def queue_days(db) -> int:
    try:
        return max(1, min(60, int(get_setting(db, "fix:queue_days") or 7)))
    except ValueError:
        return 7


def _validate(action: str, value: str | None) -> tuple[str, str | None]:
    """(label, value) or ValueError."""
    from . import catalog
    if action not in ACTIONS:
        raise ValueError("Unknown fix.")
    if action == "windows_updates":
        return "Install pending Windows updates", None
    if action == "app_update":
        pkg = (value or "").strip()
        if not catalog.package_exists(pkg):
            raise ValueError("That package isn't in the app catalog.")
        return f"Update {pkg}", pkg
    if action in ("app_uninstall", "app_repair"):
        if not KEY_RE.match(value or ""):
            raise ValueError("That program can't be identified on the PC.")
        return f"{'Uninstall' if action == 'app_uninstall' else 'Repair'} {value}", value
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


def enqueue(db, hostname: str, action: str, who: str, value: str | None = None):
    from .db import Deployment, utcnow
    from datetime import timedelta
    label, value = _validate(action, value)
    if action in ("app_uninstall", "app_repair"):
        name = _sw_name(db, hostname, value)
        if not name:
            raise ValueError("That program isn't in this PC's inventory.")
        label = f"{'Uninstall' if action == 'app_uninstall' else 'Repair'} {name}"
    now = utcnow()
    dep = Deployment(hostname=hostname, action=action, value=value, label=label, who=who, status="queued",
                     created=now, next_try=now, expires=now + timedelta(days=queue_days(db)))
    db.add(dep)
    _audit(db, who, action, hostname, f"queued: {label}")
    db.commit()
    return dep


def _execute(db, dev: Device, dep) -> str:
    """Send the push to the PC. Returns the immediate result; raises on failure."""
    from .actions import _addr
    from .collectors.winrm import run_ps
    cfg = _cfg(db)
    if not cfg:
        raise PermissionError("No Windows credential is configured (Settings > Credentials).")
    addr = _addr(dev)
    action, value = dep.action, dep.value
    if action == "windows_updates":
        _launch(addr, cfg, _task_name(action), WU_SCRIPT)
        return "Started. Windows is downloading and installing the updates."
    if action == "app_update":
        _launch(addr, cfg, _task_name(action, value), WINGET_SCRIPT.replace("__PKG__", value))
        return f"Started winget upgrade of {value}."
    if action in ("app_uninstall", "app_repair"):
        _launch(addr, cfg, _task_name(action, value), REMOVE_SCRIPT.replace("__KEY__", value).replace("__MODE__", "repair" if action == "app_repair" else "remove"))
        return f"Started {'uninstall' if action == 'app_uninstall' else 'repair'}."
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
    if dep.action in LONG:
        dep.status, dep.message = "running", out
        dep.task = _task_name(dep.action, dep.value)
        dep.check_until, dep.next_try = now + timedelta(hours=LONG[dep.action]), now + timedelta(seconds=60)
        out += " The result appears in the deployment log and the PC's History."
    else:
        dep.status, dep.finished, dep.message = "success", utcnow(), out
    _audit(db, dep.who, dep.action, dev.hostname, out)
    log_change(db, dev, "fix", f"{dep.label} (by {dep.who}): {out}")
    db.commit()
    return {"ok": True, "output": out}


def run(db, dev: Device, action: str, who: str, value: str | None = None) -> dict:
    """One PC, from its page: queue it and send it right away, so the answer is immediate."""
    try:
        dep = enqueue(db, dev.hostname, action, who, value)
    except ValueError as exc:
        return {"ok": False, "output": str(exc)}
    if not _cfg(db):
        dep.status, dep.message = "failed", "No Windows credential is configured (Settings > Credentials)."
        db.commit()
        return {"ok": False, "output": dep.message}
    return attempt(db, dep)


def run_many(hostnames: list[str], action: str, who: str, value: str | None = None) -> int:
    """Queue a push to many PCs; the dispatcher sends them a few at a time. Returns how many were queued."""
    from .db import norm_host
    hosts = list(dict.fromkeys(norm_host(h) for h in hostnames))
    with SessionLocal() as db:
        _validate(action, value)
        known = {h for (h,) in db.execute(select(Device.hostname).where(Device.hostname.in_(hosts)))}
        queued = 0
        for h in hosts:
            if h in known:
                try:
                    enqueue(db, h, action, who, value)
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


def check(db, dev: Device, name: str) -> dict:
    from .actions import _addr
    from .collectors.winrm import run_ps
    return run_ps(_addr(dev), _cfg(db), RESULT.replace("__NAME__", name))


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


def _check_running(db, dep) -> None:
    from .db import utcnow, norm_host
    from datetime import timedelta
    now = utcnow()
    dev = db.scalar(select(Device).where(Device.hostname == norm_host(dep.hostname)))
    if dev is None:
        dep.status, dep.finished, dep.message = "failed", now, "Computer no longer exists"
        return
    try:
        r = check(db, dev, dep.task)
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
        if res.get("output") and not ok:
            msg += f": {str(res['output'])[-500:]}"
        dep.status, dep.finished, dep.message = ("success" if ok else "failed"), now, msg[:2000]
        log_change(db, dev, "fix", f"{dep.label}: {msg} ({'ok' if ok else 'problem'})")
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
