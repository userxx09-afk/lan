"""Goverlan-style remote tools over WinRM: power, sessions, pop-up messages, remote command, WMI browser.

Same rules as pctools.py: every string typed in the browser reaches the PC base64-encoded and decoded into a variable
(never pasted into the script as code), names are validated, every change is written to the audit log and the PC's
History, and the UI confirms before anything changes.
"""
from __future__ import annotations

import re

from .db import Device
from .pctools import _b, _list, _record, _run

# ------------------------------------------------------------------ power
# Started from a one-off SYSTEM scheduled task so the WinRM call returns before the PC goes down (WinRM ends child
# processes with the session, and a hibernate from inside the session would cut our own reply off).
RUN_DETACHED = r'''
function Start-Detached([string]$exe, [string]$arguments) {
  $tn = 'NetInventory-Power'
  $a = New-ScheduledTaskAction -Execute $exe -Argument $arguments
  $p = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName $tn -Action $a -Principal $p -Settings $s -Force -ErrorAction Stop | Out-Null
  Start-ScheduledTask -TaskName $tn -ErrorAction Stop
}
# native tools (shutdown, logoff, msg) write to stderr; under 'Stop' Windows PowerShell 5.1 would throw on that
$ErrorActionPreference = 'Continue'
'''
POWER = {
    # op: (label for logs, script body). $msg and $min are set before the body.
    "shutdown": ("Shut down", r'''
if ($min -gt 0) { & shutdown.exe /s /f /t ($min * 60) /c $msg /d p:0:0 | Out-Null; $m = "shutting down in $min minute(s); the user sees a notice" }
else { Start-Detached 'shutdown.exe' '/s /f /t 5 /d p:0:0'; $m = 'shutting down now' }
if ($min -gt 0 -and $LASTEXITCODE) { $m = "Windows refused (code $LASTEXITCODE; is another shutdown already pending?)" }
@{ ok = -not ($min -gt 0 -and $LASTEXITCODE); message = $m } | ConvertTo-Json -Compress'''),
    "restart": ("Restart", r'''
if ($min -gt 0) { & shutdown.exe /r /f /t ($min * 60) /c $msg /d p:0:0 | Out-Null; $m = "restarting in $min minute(s); the user sees a notice" }
else { Start-Detached 'shutdown.exe' '/r /f /t 5 /d p:0:0'; $m = 'restarting now' }
if ($min -gt 0 -and $LASTEXITCODE) { $m = "Windows refused (code $LASTEXITCODE; is another shutdown already pending?)" }
@{ ok = -not ($min -gt 0 -and $LASTEXITCODE); message = $m } | ConvertTo-Json -Compress'''),
    "abort": ("Cancel a pending shutdown or restart on", r'''
$o = & shutdown.exe /a 2>&1 | Out-String
@{ ok = ($LASTEXITCODE -eq 0); message = $(if ($LASTEXITCODE -eq 0) { 'cancelled' } else { 'nothing was pending' }) } | ConvertTo-Json -Compress'''),
    "hibernate": ("Hibernate", r'''
$h = (& powercfg.exe /a 2>&1 | Out-String)
if ($h -match 'Hibernation has not been enabled|hibernation is not available') { & powercfg.exe /hibernate on 2>&1 | Out-Null }
Start-Detached 'shutdown.exe' '/h /f'
@{ ok = $true; message = 'hibernating (wake it with Wake on LAN or the power button)' } | ConvertTo-Json -Compress'''),
    "sleep": ("Sleep", r'''
Start-Detached 'rundll32.exe' 'powrprof.dll,SetSuspendState 0,1,0'
@{ ok = $true; message = 'going to sleep (if hibernation is on, Windows may hibernate instead)' } | ConvertTo-Json -Compress'''),
    "logoff_all": ("Log off everyone on", r'''
$ids = @(Get-UserSessions | Where-Object { $_.id -gt 0 } | ForEach-Object { $_.id })
foreach ($i in $ids) { & logoff.exe $i 2>&1 | Out-Null }
@{ ok = $true; message = "$($ids.Count) session(s) logged off" } | ConvertTo-Json -Compress'''),
    "lock": ("Lock the screen of", r'''
# LockWorkStation only works inside the user's own session: a task for the Users group runs in each signed-in session.
$tn = 'NetInventory-Lock'
$a = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'user32.dll,LockWorkStation'
$p = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545'
Register-ScheduledTask -TaskName $tn -Action $a -Principal $p -Force -ErrorAction Stop | Out-Null
Start-ScheduledTask -TaskName $tn -ErrorAction Stop
Start-Sleep 3
Unregister-ScheduledTask -TaskName $tn -Confirm:$false
@{ ok = $true; message = 'locked' } | ConvertTo-Json -Compress'''),
}

# quser is the only reliable list of sessions with idle time (Win32_LogonSession has no session ids for RDP).
SESSIONS_FN = r'''
function Get-UserSessions {
  $raw = @(cmd.exe /c 'quser 2>nul')
  foreach ($l in ($raw | Select-Object -Skip 1)) {
    $t = $l.Substring(1).TrimEnd()
    $f = $t -split '\s{2,}'
    if ($f.Count -lt 5) { continue }
    if ($f.Count -eq 5) { $f = @($f[0], '') + $f[1..4] }      # a disconnected session has no session name
    [pscustomobject]@{ user = $f[0]; session = $f[1]; id = [int]$f[2]; state = $f[3]; idle = $f[4]; logon = $f[5] }
  }
}
'''
SESSIONS = SESSIONS_FN + r'''
$s = @(Get-UserSessions)
$os = Get-CimInstance Win32_OperatingSystem
@{ sessions = $s; console = "$((Get-CimInstance Win32_ComputerSystem).UserName)"; boot = $os.LastBootUpTime.ToUniversalTime().ToString('s') } | ConvertTo-Json -Compress -Depth 3
'''
SESSION_OPS = {
    "logoff": ("Log off session", "& logoff.exe $id 2>&1 | Out-String"),
    "disconnect": ("Disconnect session", "& tsdiscon.exe $id 2>&1 | Out-String"),
}


def _go(db, dev: Device, who: str, action: str, detail: str, script: str) -> dict:
    try:
        r = _run(db, dev, script)
        ok, msg = bool(r.get("ok")), r.get("message") or "?"
    except Exception as exc:
        ok, msg = False, str(exc).split("\n")[0][:300]
    _record(db, dev, who, action, f"{detail}: {msg}", ok)
    return {"ok": ok, "output": msg}


NATIVE = "$ErrorActionPreference = 'Continue'\n"


def power(db, dev: Device, who: str, op: str, minutes: int = 0, message: str = "") -> dict:
    if op not in POWER:
        return {"ok": False, "output": "Unknown power action."}
    try:
        minutes = int(minutes or 0)
    except (TypeError, ValueError):
        minutes = -1
    if not 0 <= minutes <= 720:
        return {"ok": False, "output": "Give the delay in minutes, 0 to 720."}
    message = (message or "").strip()[:500] or "Your IT department is restarting this computer. Please save your work."
    label, body = POWER[op]
    head = RUN_DETACHED + SESSIONS_FN + f"$min = {minutes}\n$msg = D '{_b(message)}'\n"
    when = f" in {minutes} min" if minutes and op in ("shutdown", "restart") else ""
    return _go(db, dev, who, f"power.{op}", f"{label} {dev.hostname}{when}", head + body)


def sessions(db, dev: Device) -> dict:
    r = _run(db, dev, SESSIONS)
    return {"sessions": _list(r.get("sessions")), "console": r.get("console") or "", "boot": r.get("boot")}


def session_op(db, dev: Device, who: str, op: str, sid: int) -> dict:
    if op not in SESSION_OPS or not isinstance(sid, int) or not 0 < sid < 65536:
        return {"ok": False, "output": "Unknown session or action."}
    label, cmd = SESSION_OPS[op]
    return _go(db, dev, who, f"session.{op}", f"{label} {sid}",
               NATIVE + f"$id = {sid}\n$o = {cmd}\n@{{ ok = ($LASTEXITCODE -eq 0); message = $(if ($LASTEXITCODE -eq 0) {{ 'done' }} else {{ \"$o\".Trim() }}) }} | ConvertTo-Json -Compress")


# ------------------------------------------------------------------ one-way pop-up message
USER_RE = re.compile(r"^[\w.\-$ ]{1,104}$")
MESSAGE = SESSIONS_FN + r'''
$text = D '__TEXT__'
$title = D '__TITLE__'
$only = D '__USER__'
$sid = __SID__
$ErrorActionPreference = 'Continue'
$targets = @(Get-UserSessions | Where-Object { $_.id -gt 0 -and
  ((-not $only -and $sid -le 0) -or ($sid -gt 0 -and $_.id -eq $sid) -or ($only -and $_.user -ieq $only)) })
if (-not $targets) { @{ ok = $false; message = $(if ($only) { "$only isn't signed in" } else { 'nobody is signed in' }) } | ConvertTo-Json -Compress; return }
$body = if ($title) { "$title`n`n$text" } else { $text }
$sent = @()
foreach ($t in $targets) { & msg.exe $t.id /time:__SECS__ $body 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $sent += $t.user } }
if (-not $sent -and -not (Get-Command msg.exe -ErrorAction SilentlyContinue)) { throw 'msg.exe is missing on this PC (Windows Home editions have no msg.exe)' }
@{ ok = [bool]$sent; message = $(if ($sent) { 'shown to ' + ($sent -join ', ') } else { 'Windows refused to show it' }) } | ConvertTo-Json -Compress
'''


def message(db, dev: Device, who: str, text: str, title: str = "", user: str = "", session: int = 0, seconds: int = 300) -> dict:
    text = (text or "").strip()
    if not text or len(text) > 2000:
        return {"ok": False, "output": "Write a message (up to 2000 characters)."}
    if user and not USER_RE.match(user.split("\\")[-1]):
        return {"ok": False, "output": "Unknown user."}
    try:
        seconds, session = int(seconds), int(session or 0)
    except (TypeError, ValueError):
        return {"ok": False, "output": "Bad number."}
    seconds = max(10, min(seconds, 86400))
    script = (MESSAGE.replace("__TEXT__", _b(text)).replace("__TITLE__", _b((title or "")[:120]))
              .replace("__USER__", _b(user.split("\\")[-1] if user else "")).replace("__SID__", str(max(0, session)))
              .replace("__SECS__", str(seconds)))
    to = f"user {user}" if user else f"session {session}" if session > 0 else "everyone signed in"
    return _go(db, dev, who, "message", f"Pop-up message to {to}: {text[:200]}", script)


# ------------------------------------------------------------------ remote command (not interactive)
COMMAND = r'''
$cmd = D '__CMD__'
$shell = '__SHELL__'
$j = Start-Job -ScriptBlock {
  param($cmd, $shell)
  Set-Location $env:SystemDrive\
  if ($shell -eq 'cmd') { $o = & cmd.exe /d /c $cmd 2>&1 | Out-String -Width 250; $code = $LASTEXITCODE }
  else { $global:LASTEXITCODE = 0; $o = try { & ([scriptblock]::Create($cmd)) 2>&1 | Out-String -Width 250 } catch { "$_" }; $code = $LASTEXITCODE }
  [pscustomobject]@{ out = $o; code = $code }
} -ArgumentList $cmd, $shell
$done = Wait-Job $j -Timeout __TIMEOUT__
if (-not $done) { Stop-Job $j; $r = [pscustomobject]@{ out = (Receive-Job $j -ErrorAction SilentlyContinue | Out-String); code = $null }; $to = $true }
else { $r = Receive-Job $j -ErrorAction SilentlyContinue | Select-Object -Last 1; $to = $false }
Remove-Job $j -Force
$o = "$($r.out)"
if ($o.Length -gt 200000) { $o = $o.Substring(0, 200000) + "`n... (cut at 200,000 characters)" }
@{ ok = (-not $to -and ($r.code -eq 0 -or $r.code -eq $null)); timed_out = $to; exit_code = $r.code; output = $o; cwd = "$env:SystemDrive\"; user = "$env:USERDOMAIN\$env:USERNAME" } | ConvertTo-Json -Compress
'''


def command(db, dev: Device, who: str, cmd: str, shell: str = "powershell", timeout: int = 60) -> dict:
    cmd = (cmd or "").strip()
    if not cmd or len(cmd) > 20000:
        return {"ok": False, "output": "Type a command (up to 20,000 characters)."}
    if shell not in ("powershell", "cmd"):
        return {"ok": False, "output": "Pick PowerShell or cmd."}
    try:
        timeout = max(5, min(int(timeout), 100))
    except (TypeError, ValueError):
        timeout = 60
    script = COMMAND.replace("__CMD__", _b(cmd)).replace("__SHELL__", shell).replace("__TIMEOUT__", str(timeout))
    try:
        r = _run(db, dev, script)
    except Exception as exc:
        msg = str(exc).split("\n")[0][:300]
        _record(db, dev, who, "command", f"Command ({shell}) {cmd[:300]}: {msg}", False)
        raise
    ok = bool(r.get("ok"))
    end = "timed out" if r.get("timed_out") else f"exit code {r.get('exit_code')}" if r.get("exit_code") is not None else "done"
    _record(db, dev, who, "command", f"Command ({shell}) {cmd[:300]}: {end}", ok)
    return {"ok": ok, "timed_out": bool(r.get("timed_out")), "exit_code": r.get("exit_code"), "output": r.get("output") or "",
            "user": r.get("user"), "status": end}


# ------------------------------------------------------------------ WMI browser and ad-hoc WQL queries (read-only)
NS_RE = re.compile(r"^[A-Za-z0-9_]{1,64}(\\[A-Za-z0-9_]{1,64}){0,6}$")
CLASS_RE = re.compile(r"^[A-Za-z0-9_]{1,128}$")
FLATTEN = r'''
function Flat($o) {
  $skip = 'PSComputerName', 'CimClass', 'CimInstanceProperties', 'CimSystemProperties'
  $h = [ordered]@{}
  foreach ($p in $o.CimInstanceProperties) {
    if ($skip -contains $p.Name) { continue }
    $v = $p.Value
    $h[$p.Name] = if ($null -eq $v) { $null } elseif ($v -is [datetime]) { $v.ToUniversalTime().ToString('s') }
      elseif ($v -is [array]) { (@($v) | Select-Object -First 50 | ForEach-Object { "$_" }) -join ', ' }
      elseif ($v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [uint32] -or $v -is [uint64] -or $v -is [uint16] -or $v -is [byte]) { $v }
      else { $s = "$v"; $s.Substring(0, [Math]::Min(2000, $s.Length)) }
  }
  $h
}
'''
WMI_NAMESPACES = r'''
$ns = D '__NS__'
@{ namespaces = @(Get-CimInstance -Namespace $ns -ClassName __NAMESPACE -ErrorAction SilentlyContinue | ForEach-Object { "$ns\$($_.Name)" } | Sort-Object)
   classes = @(Get-CimClass -Namespace $ns -ErrorAction SilentlyContinue | Where-Object { $_.CimClassName -notlike '__*' } |
     ForEach-Object { [pscustomobject]@{ name = $_.CimClassName; dynamic = [bool]($_.CimClassQualifiers | Where-Object { $_.Name -eq 'dynamic' -or $_.Name -eq 'provider' }) } } | Sort-Object name) } | ConvertTo-Json -Compress -Depth 3
'''
WMI_CLASS = FLATTEN + r'''
$ns = D '__NS__'; $cn = D '__CLASS__'
$c = Get-CimClass -Namespace $ns -ClassName $cn
$props = @($c.CimClassProperties | ForEach-Object { [pscustomobject]@{ name = $_.Name; type = "$($_.CimType)"; key = [bool]($_.Qualifiers | Where-Object Name -eq 'key') } })
$methods = @($c.CimClassMethods | ForEach-Object { $_.Name })
$rows = @(Get-CimInstance -Namespace $ns -ClassName $cn -ErrorAction Stop | Select-Object -First __MAX__ | ForEach-Object { Flat $_ })
@{ properties = $props; methods = $methods; rows = $rows } | ConvertTo-Json -Compress -Depth 4
'''
WMI_QUERY = FLATTEN + r'''
$ns = D '__NS__'; $q = D '__QUERY__'
$rows = @(Get-CimInstance -Namespace $ns -Query $q -ErrorAction Stop | Select-Object -First __MAX__ | ForEach-Object { Flat $_ })
@{ rows = $rows } | ConvertTo-Json -Compress -Depth 4
'''
WQL_RE = re.compile(r"^\s*(select|associators\s+of|references\s+of)\s", re.I)


def _ns(ns: str) -> str:
    ns = (ns or "root\\cimv2").strip().replace("/", "\\").strip("\\")
    if not NS_RE.match(ns) or not ns.lower().startswith("root"):
        raise ValueError("A namespace looks like root\\cimv2.")
    return ns


def wmi_browse(db, dev: Device, ns: str) -> dict:
    ns = _ns(ns)
    r = _run(db, dev, WMI_NAMESPACES.replace("__NS__", _b(ns)))
    return {"namespace": ns, "namespaces": _list(r.get("namespaces")), "classes": _list(r.get("classes"))}


def wmi_class(db, dev: Device, ns: str, cls: str, limit: int = 500) -> dict:
    ns = _ns(ns)
    if not CLASS_RE.match(cls or ""):
        raise ValueError("Unknown class name.")
    r = _run(db, dev, WMI_CLASS.replace("__NS__", _b(ns)).replace("__CLASS__", _b(cls)).replace("__MAX__", str(max(1, min(int(limit), 2000)))))
    return {"namespace": ns, "class": cls, "properties": _list(r.get("properties")), "methods": _list(r.get("methods")),
            "rows": _list(r.get("rows"))}


def wmi_query(db, dev: Device, ns: str, query: str, limit: int = 1000) -> dict:
    """WQL is read-only by design (SELECT / ASSOCIATORS OF / REFERENCES OF); nothing here calls a WMI method."""
    ns = _ns(ns)
    query = (query or "").strip()
    if not WQL_RE.match(query) or len(query) > 4000:
        raise ValueError("A WQL query starts with SELECT (for example SELECT Name, State FROM Win32_Service WHERE StartMode='Auto').")
    r = _run(db, dev, WMI_QUERY.replace("__NS__", _b(ns)).replace("__QUERY__", _b(query)).replace("__MAX__", str(max(1, min(int(limit), 5000)))))
    return {"namespace": ns, "rows": _list(r.get("rows"))}
