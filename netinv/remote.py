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


# ------------------------------------------------------------------ more live tabs: read-only views
VIEWS = {
    "shares": r'''
$acc = @{}
try { Get-SmbShareAccess -Name * -ErrorAction SilentlyContinue | ForEach-Object { $acc[$_.Name] += @("$($_.AccountName): $($_.AccessRight)$(if ("$($_.AccessControlType)" -ne 'Allow') { ' (deny)' })") } } catch {}
ConvertTo-Json -Compress @(Get-CimInstance Win32_Share | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; path = $_.Path; description = $_.Description; special = ($_.Name -match '\$$')
    access = (@($acc[$_.Name]) | Where-Object { $_ }) -join '; ' } })''',
    "env": r'''
$out = @()
$m = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
foreach ($n in $m.GetValueNames()) { $out += [pscustomobject]@{ scope = 'System'; user = ''; sid = ''; name = $n; value = "$($m.GetValue($n, $null, 'DoNotExpandEnvironmentNames'))" } }
foreach ($u in Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }) {
  $who = try { (New-Object Security.Principal.SecurityIdentifier $u.PSChildName).Translate([Security.Principal.NTAccount]).Value } catch { $u.PSChildName }
  $k = Get-Item "Registry::HKEY_USERS\$($u.PSChildName)\Environment" -ErrorAction SilentlyContinue
  if ($k) { foreach ($n in $k.GetValueNames()) { $out += [pscustomobject]@{ scope = 'User'; user = $who; sid = $u.PSChildName; name = $n; value = "$($k.GetValue($n, $null, 'DoNotExpandEnvironmentNames'))" } } }
}
ConvertTo-Json -Compress @($out)''',
    "startup": r'''
$out = @()
$keys = @(@('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'All users'), @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'All users (once)'),
          @('HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'All users (32-bit)'))
foreach ($u in Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }) {
  $who = try { (New-Object Security.Principal.SecurityIdentifier $u.PSChildName).Translate([Security.Principal.NTAccount]).Value } catch { $u.PSChildName }
  $keys += ,@("HKU\$($u.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run", $who)
}
foreach ($k in $keys) {
  $key = Get-Item ('Registry::' + ($k[0] -replace '^HKLM', 'HKEY_LOCAL_MACHINE' -replace '^HKU', 'HKEY_USERS')) -ErrorAction SilentlyContinue
  if (-not $key) { continue }
  foreach ($n in $key.GetValueNames()) { if ($n) { $out += [pscustomobject]@{ name = $n; command = "$($key.GetValue($n))"; where = $k[1]; kind = 'registry'; location = $k[0] } } }
}
foreach ($f in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") + @(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })) {
  foreach ($i in Get-ChildItem $f -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }) {
    $out += [pscustomobject]@{ name = $i.Name; command = $i.FullName; where = $(if ($f -like "$env:ProgramData*") { 'All users' } else { ($f -split '\\')[2] }); kind = 'folder'; location = $f } }
}
ConvertTo-Json -Compress @($out)''',
    "tasks": r'''
ConvertTo-Json -Compress @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { __ALL__ -or $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $i = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
  [pscustomobject]@{ path = $_.TaskPath; name = $_.TaskName; state = "$($_.State)"; author = $_.Author
    runs_as = "$($_.Principal.UserId)$($_.Principal.GroupId)"
    action = (@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; ')
    triggers = (@($_.Triggers | ForEach-Object { ($_.CimClass.CimClassName -replace '^MSFT_Task|Trigger$', '') }) -join ', ')
    last_run = if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) { $i.LastRunTime.ToUniversalTime().ToString('s') } else { '' }
    last_result = if ($i) { '0x{0:X}' -f $i.LastTaskResult } else { '' }
    next_run = if ($i.NextRunTime) { $i.NextRunTime.ToUniversalTime().ToString('s') } else { '' } } })''',
    "events": r'''
$log = D '__LOG__'; $src = D '__SRC__'; $text = D '__TEXT__'
$f = @{ LogName = $log; StartTime = (Get-Date).AddHours(-__HOURS__) }
if (__LEVELS__) { $f.Level = @(__LEVELS__) }
if ($src) { $f.ProviderName = $src }
if (__ID__ -gt 0) { $f.Id = __ID__ }
$ev = try { @(Get-WinEvent -FilterHashtable $f -MaxEvents __MAX__ -ErrorAction Stop) } catch { if ("$_" -match 'No events were found') { @() } else { throw } }
ConvertTo-Json -Compress @($ev | Where-Object { -not $text -or $_.Message -like "*$text*" } | ForEach-Object {
  $msg = "$($_.Message)"
  [pscustomobject]@{ time = $_.TimeCreated.ToUniversalTime().ToString('s'); level = "$($_.LevelDisplayName)"; level_n = [int]$_.Level; source = $_.ProviderName; id = $_.Id
    user = "$($_.UserId)"; message = $msg.Substring(0, [Math]::Min(4000, $msg.Length)) } })''',
    "eventlogs": r'''
ConvertTo-Json -Compress @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 } | Sort-Object LogName | ForEach-Object {
  [pscustomobject]@{ name = $_.LogName; records = [int64]$_.RecordCount; size_mb = [math]::Round($_.FileSize / 1MB, 1) } })''',
    "devices": r'''
$drv = @{}
Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | ForEach-Object { if ($_.DeviceID) { $drv[$_.DeviceID] = $_ } }
ConvertTo-Json -Compress @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name } | ForEach-Object {
  $d = $drv[$_.PNPDeviceID]
  [pscustomobject]@{ name = $_.Name; class = $_.PNPClass; manufacturer = $_.Manufacturer; status = $_.Status; problem = [int]$_.ConfigManagerErrorCode
    present = [bool]$_.Present; driver = if ($d) { $d.DriverVersion } else { '' }
    driver_date = if ($d -and $d.DriverDate) { $d.DriverDate.ToString('yyyy-MM-dd') } else { '' }; provider = if ($d) { $d.DriverProviderName } else { '' }; id = $_.PNPDeviceID } })''',
    "network": r'''
$cfg = @{}
Get-CimInstance Win32_NetworkAdapterConfiguration | ForEach-Object { $cfg[[int]$_.InterfaceIndex] = $_ }
ConvertTo-Json -Compress -Depth 3 @(Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue | ForEach-Object {
  $c = $cfg[[int]$_.ifIndex]
  $ip = @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
  [pscustomobject]@{ name = $_.Name; description = $_.InterfaceDescription; status = "$($_.Status)"; speed = "$($_.LinkSpeed)"; mac = $_.MacAddress
    ip = $ip -join ', '; gateway = if ($c) { @($c.DefaultIPGateway) -join ', ' } else { '' }; dns = if ($c) { @($c.DNSServerSearchOrder) -join ', ' } else { '' }
    dhcp = if ($c) { [bool]$c.DHCPEnabled } else { $null }; dhcp_server = if ($c) { $c.DHCPServer } else { '' }
    suffix = if ($c) { $c.DNSDomain } else { '' }; vlan = "$($_.VlanID)"; media = "$($_.MediaType)" } })''',
    "connections": r'''
$p = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $p[$_.Id] = $_.ProcessName }
$t = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'TimeWait' } | ForEach-Object {
  [pscustomobject]@{ proto = 'TCP'; local = "$($_.LocalAddress):$($_.LocalPort)"; remote = "$($_.RemoteAddress):$($_.RemotePort)"; state = "$($_.State)"; pid = [int]$_.OwningProcess; process = $p[[int]$_.OwningProcess] } })
$u = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ proto = 'UDP'; local = "$($_.LocalAddress):$($_.LocalPort)"; remote = ''; state = 'Listen'; pid = [int]$_.OwningProcess; process = $p[[int]$_.OwningProcess] } })
ConvertTo-Json -Compress @($t + $u)''',
    "performance": r'''
$os = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [pscustomobject]@{ drive = $_.DeviceID; size_gb = [math]::Round($_.Size / 1GB, 1); free_gb = [math]::Round($_.FreeSpace / 1GB, 1) } })
$pd = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue
$net = @(Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ name = $_.Name; in_kbps = [math]::Round($_.BytesReceivedPersec * 8 / 1KB); out_kbps = [math]::Round($_.BytesSentPersec * 8 / 1KB) } })
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$top = @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin '_Total', 'Idle' } |
  Sort-Object PercentProcessorTime -Descending | Select-Object -First 8 | ForEach-Object { [pscustomobject]@{ name = $_.Name; pid = [int]$_.IDProcess; cpu_pct = [math]::Round($_.PercentProcessorTime / [math]::Max(1, $cores), 1); mem_mb = [math]::Round($_.WorkingSetPrivate / 1MB, 1) } })
@{ cpu_pct = [int]$cpu; mem_total_mb = [math]::Round($os.TotalVisibleMemorySize / 1KB); mem_free_mb = [math]::Round($os.FreePhysicalMemory / 1KB)
   disk_busy_pct = if ($pd) { [int]$pd.PercentDiskTime } else { $null }; disk_queue = if ($pd) { [int]$pd.CurrentDiskQueueLength } else { $null }
   disks = $disks; net = $net; top = $top; processes = @(Get-Process).Count; uptime_h = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1) } | ConvertTo-Json -Compress -Depth 3''',
}
EVENT_LEVELS = {"critical": 1, "error": 2, "warning": 3, "information": 4, "verbose": 5}
LOG_RE = re.compile(r"^[\w\-/ .%]{1,200}$")


def view(db, dev: Device, name: str, **p) -> list | dict:
    if name not in VIEWS:
        raise ValueError("Unknown view.")
    script = VIEWS[name]
    if name == "tasks":
        script = script.replace("__ALL__", "$true" if p.get("all") else "$false")
    if name == "events":
        log = (p.get("log") or "System").strip()
        if not LOG_RE.match(log):
            raise ValueError("Unknown event log.")
        levels = [EVENT_LEVELS[x] for x in (p.get("levels") or "").split(",") if x in EVENT_LEVELS]
        try:
            hours = max(1, min(int(p.get("hours") or 24), 24 * 90))
            eid = max(0, min(int(p.get("id") or 0), 1 << 30))
            mx = max(10, min(int(p.get("max") or 500), 5000))
        except (TypeError, ValueError):
            raise ValueError("Bad number.")
        script = (script.replace("__LOG__", _b(log)).replace("__SRC__", _b((p.get("source") or "")[:200]))
                  .replace("__TEXT__", _b((p.get("text") or "").replace("*", "")[:200])).replace("__HOURS__", str(hours))
                  .replace("__LEVELS__", ",".join(map(str, levels)) or "$null").replace("__ID__", str(eid)).replace("__MAX__", str(mx)))
    r = _run(db, dev, script)
    return r if isinstance(r, dict) and name == "performance" else _list(r)


# ------------------------------------------------------------------ more live tabs: changes
SHARE_RE = re.compile(r"^[^\\/:*?\"<>|\x00-\x1f\[\]=;,+]{1,80}$")
ACCOUNT_RE = re.compile(r"^([\w.\- ]{1,64}\\)?[\w.\-$@ ]{1,104}$")
PATH_RE = re.compile(r"^[A-Za-z]:\\[^\x00-\x1f*?\"<>|]{0,250}$")
ENV_RE = re.compile(r"^[A-Za-z_][\w.()\-]{0,99}$")
ENV_LOCKED = {"path", "pathext", "comspec", "windir", "systemroot", "os", "processor_architecture", "number_of_processors",
              "psmodulepath", "temp", "tmp", "driverdata", "username"}
TASK_RE = re.compile(r"^\\([^\x00-\x1f\\]{1,200}\\)*$")


def change(db, dev: Device, who: str, kind: str, op: str, a: dict) -> dict:
    """One change on a PC tab. a holds the strings for that change; each is checked here, then sent base64-encoded."""
    a = {k: ("" if v is None else str(v)) for k, v in (a or {}).items()}
    fail = lambda m: {"ok": False, "output": m}   # noqa: E731
    key = f"{kind}.{op}"
    if key == "share.add":
        if not SHARE_RE.match(a.get("name", "")) or a["name"].endswith("$") and a["name"].upper() in ("C$", "ADMIN$", "IPC$"):
            return fail("Pick a share name (no \\ / : * ? \" < > |).")
        if not PATH_RE.match(a.get("path", "")):
            return fail("Give a local folder like D:\\Shares\\Scans.")
        if a.get("access") not in ("Read", "Change", "Full"):
            return fail("Pick Read, Change or Full.")
        if not ACCOUNT_RE.match(a.get("account", "")):
            return fail("Give who gets access as DOMAIN\\name (or Everyone).")
        body = r'''
if (-not (Test-Path -LiteralPath $path -PathType Container)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
$p = @{ Name = $name; Path = $path; Description = $desc }
$p["$($access)Access"] = $account
New-SmbShare @p -ErrorAction Stop | Out-Null
@{ ok = $true; message = "shared as \\$env:COMPUTERNAME\$name ($account`: $access)" } | ConvertTo-Json -Compress'''
        detail = f"Share {a['path']} as {a['name']} ({a['account']}: {a['access']})"
    elif key == "share.remove":
        if not SHARE_RE.match(a.get("name", "")) or a["name"].upper() in ("C$", "ADMIN$", "IPC$", "D$", "E$", "PRINT$", "NETLOGON", "SYSVOL"):
            return fail("That share isn't removed from here (Windows or the domain needs it).")
        body = r'''
Remove-SmbShare -Name $name -Force -ErrorAction Stop
@{ ok = $true; message = 'share removed (the folder and its files are kept)' } | ConvertTo-Json -Compress'''
        detail = f"Remove share {a['name']}"
    elif key in ("env.set", "env.delete"):
        if not ENV_RE.match(a.get("name", "")):
            return fail("A variable name is letters, digits and _ (starting with a letter).")
        if len(a.get("value", "")) > 8000:
            return fail("Value too long.")
        sid = a.get("sid", "")
        if sid and not re.match(r"^S-1-5-21-[\d-]{5,80}$", sid):
            return fail("Unknown user.")
        if key == "env.delete" and not sid and a["name"].lower() in ENV_LOCKED:
            return fail(f"{a['name']} is needed by Windows; edit it instead of deleting it.")
        if key == "env.set" and not sid and a["name"].lower() == "path" and "system32" not in a.get("value", "").lower():
            return fail("That Path has no System32 in it; Windows wouldn't work. Check the value.")
        kpath = (f"Registry::HKEY_USERS\\{sid}\\Environment" if sid else
                 "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")
        body = (f"$k = '{kpath}'\n" + (r'''
$was = (Get-Item $k).GetValue($name, '(new)', 'DoNotExpandEnvironmentNames')
$type = if ($value -match '%\w+%') { 'ExpandString' } else { 'String' }
Set-ItemProperty -Path $k -Name $name -Value $value -Type $type -ErrorAction Stop
@{ ok = $true; message = "set (was: $was). Programs started from now on see it; signed-in users get it at their next sign-in." } | ConvertTo-Json -Compress'''
            if key == "env.set" else r'''
$was = (Get-Item $k).GetValue($name, $null, 'DoNotExpandEnvironmentNames')
if ($null -eq $was) { throw 'variable not found' }
Remove-ItemProperty -Path $k -Name $name -ErrorAction Stop
@{ ok = $true; message = "deleted (was: $was)" } | ConvertTo-Json -Compress'''))
        detail = (f"{'Set' if op == 'set' else 'Delete'} {'user' if sid else 'system'} variable {a['name']}"
                  + (f" = {a.get('value', '')[:200]}" if op == "set" else ""))
    elif key == "startup.remove":
        loc = a.get("location", "")
        if a.get("kind") == "registry":
            if not re.match(r"^(HKLM\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?|HKU\\S-1-5-21-[\d-]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)$", loc, re.I):
                return fail("Unknown startup location.")
            body = f"$k = 'Registry::{loc.replace('HKLM', 'HKEY_LOCAL_MACHINE', 1).replace('HKU', 'HKEY_USERS', 1)}'\n" + r'''
$was = (Get-Item $k).GetValue($name)
if ($null -eq $was) { throw 'entry not found' }
Remove-ItemProperty -Path $k -Name $name -ErrorAction Stop
@{ ok = $true; message = "removed from startup (was: $was)" } | ConvertTo-Json -Compress'''
        elif a.get("kind") == "folder":
            if not re.match(r"^[A-Za-z]:\\.*\\Start Menu\\Programs\\Startup$", loc, re.I) or not re.match(r"^[^\\/:*?\"<>|\x00-\x1f]{1,200}$", a.get("name", "")):
                return fail("Unknown startup location.")
            body = r'''
$f = Join-Path $location $name
if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw 'file not found' }
$bak = Join-Path $env:ProgramData 'NetInventory\startup-removed'
New-Item -ItemType Directory -Path $bak -Force | Out-Null
Move-Item -LiteralPath $f -Destination (Join-Path $bak ("{0:yyyyMMddHHmmss}-{1}" -f (Get-Date), $name)) -Force
@{ ok = $true; message = "moved out of the Startup folder (kept in $bak)" } | ConvertTo-Json -Compress'''
        else:
            return fail("Unknown startup entry.")
        detail = f"Remove startup entry {a.get('name')} ({loc})"
    elif kind == "task" and op in ("run", "end", "enable", "disable"):
        if not TASK_RE.match(a.get("path", "")) or not re.match(r"^[^\x00-\x1f\\]{1,200}$", a.get("name", "")):
            return fail("Unknown task.")
        if op in ("disable", "end") and a["path"].lower().startswith("\\microsoft\\") and not a.get("force"):
            return fail("Windows' own tasks aren't stopped or disabled from here.")
        cmd = {"run": "Start-ScheduledTask", "end": "Stop-ScheduledTask", "enable": "Enable-ScheduledTask", "disable": "Disable-ScheduledTask"}[op]
        body = f"{cmd} -TaskPath $path -TaskName $name -ErrorAction Stop | Out-Null\n" + r'''
Start-Sleep 1
$t = Get-ScheduledTask -TaskPath $path -TaskName $name
@{ ok = $true; message = "$($t.TaskName): $($t.State)" } | ConvertTo-Json -Compress'''
        detail = f"{op.capitalize()} scheduled task {a['path']}{a['name']}"
    elif kind == "net" and op in ("flushdns", "registerdns", "renew", "gpupdate"):
        body = {
            "flushdns": "Clear-DnsClientCache\n@{ ok = $true; message = 'DNS cache cleared' } | ConvertTo-Json -Compress",
            "registerdns": "$ErrorActionPreference = 'Continue'\n& ipconfig.exe /registerdns | Out-Null\n@{ ok = ($LASTEXITCODE -eq 0); message = 'DNS registration started (takes a few minutes)' } | ConvertTo-Json -Compress",
            # release cuts the network (and this WinRM call), so both run from a detached task
            "renew": RUN_DETACHED + "Start-Detached 'cmd.exe' '/c ipconfig /release & ipconfig /renew'\n@{ ok = $true; message = 'releasing and renewing the DHCP lease: the PC drops off the network for a few seconds' } | ConvertTo-Json -Compress",
            "gpupdate": "$ErrorActionPreference = 'Continue'\n$o = & gpupdate.exe /force /wait:90 2>&1 | Out-String\n@{ ok = ($LASTEXITCODE -eq 0); message = (($o -split \"`n\" | Where-Object { $_.Trim() }) -join ' ').Trim() } | ConvertTo-Json -Compress",
        }[op]
        detail = {"flushdns": "Flush DNS cache", "registerdns": "Register in DNS", "renew": "Release and renew DHCP lease", "gpupdate": "Group Policy update (gpupdate /force)"}[op]
    else:
        return fail("Unknown change.")
    head = "".join(f"${k} = D '{_b(a.get(k, ''))}'\n" for k in ("name", "path", "desc", "access", "account", "value", "location"))
    return _go(db, dev, who, key, detail, head + body)


# ------------------------------------------------------------------ remote files (browse, view, download, upload)
MAX_TRANSFER = 200 * 1024 * 1024      # per file, either way
MAX_PARALLEL = 4                       # transfers at once (they share the server's bandwidth)
FPATH_RE = re.compile(r"^[A-Za-z]:\\([^\x00-\x1f*?\"<>|:]{0,1000})$")
FNAME_RE = re.compile(r"^[^\\/:*?\"<>|\x00-\x1f]{1,255}$")
# never deleted, renamed or written from here (a typo here would break the PC)
FILE_LOCKED = re.compile(r"^[A-Za-z]:\\(windows|program files|program files \(x86\)|programdata|users|boot|recovery|system volume information)?\\?$|"
                         r"^[A-Za-z]:\\windows\\(system32|syswow64|winsxs)(\\|$)", re.I)

FILES = r'''
$p = D '__PATH__'
$drives = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2, 3 } | ForEach-Object { [pscustomobject]@{ name = $_.DeviceID + '\'; free_gb = [math]::Round($_.FreeSpace / 1GB, 1); size_gb = [math]::Round($_.Size / 1GB, 1) } })
if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw "That folder doesn't exist on this PC." }
$items = @(Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | Select-Object -First 5000 | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; dir = $_.PSIsContainer; size = if ($_.PSIsContainer) { $null } else { [int64]$_.Length }
    modified = $_.LastWriteTimeUtc.ToString('s'); hidden = [bool]($_.Attributes -band [IO.FileAttributes]::Hidden); ext = $_.Extension } })
@{ path = (Get-Item -LiteralPath $p -Force).FullName; items = $items; drives = $drives } | ConvertTo-Json -Compress -Depth 3
'''
FILE_INFO = r'''
$p = D '__PATH__'
$f = Get-Item -LiteralPath $p -Force -ErrorAction Stop
if ($f.PSIsContainer) { throw 'That is a folder.' }
@{ size = [int64]$f.Length; name = $f.Name } | ConvertTo-Json -Compress
'''
FILE_TEXT = r'''
$p = D '__PATH__'
$f = Get-Item -LiteralPath $p -Force -ErrorAction Stop
if ($f.PSIsContainer) { throw 'That is a folder.' }
$n = [Math]::Min([int64]$f.Length, __MAX__)
$fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite, Delete')       # also opens logs another program is writing
try { if (__TAIL__ -and $f.Length -gt $n) { [void]$fs.Seek(-$n, 'End') }; $buf = New-Object byte[] $n; $got = $fs.Read($buf, 0, $n) } finally { $fs.Close() }
$bin = ($buf[0..([Math]::Min($got, 4000) - 1)] | Where-Object { $_ -eq 0 }).Count -gt 0 -and -not ($got -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE)
$enc = if ($got -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { [Text.Encoding]::Unicode } else { [Text.Encoding]::UTF8 }
@{ size = [int64]$f.Length; shown = $got; binary = $bin; tail = [bool](__TAIL__ -and $f.Length -gt $n); text = $(if ($bin) { '' } else { $enc.GetString($buf, 0, $got) }) } | ConvertTo-Json -Compress
'''
FILE_OPS = {
    "mkdir": ("New folder", "New-Item -ItemType Directory -Path (Join-Path $p $name) -ErrorAction Stop | Out-Null\n$m = 'folder created'"),
    "rename": ("Rename", "Rename-Item -LiteralPath $p -NewName $name -ErrorAction Stop\n$m = \"renamed to $name\""),
    "delete": ("Delete", r'''$i = Get-Item -LiteralPath $p -Force -ErrorAction Stop
if ($i.PSIsContainer) { $c = @(Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue).Count; Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop; $m = "folder deleted with $c item(s)" }
else { $s = $i.Length; Remove-Item -LiteralPath $p -Force -ErrorAction Stop; $m = "deleted ($s bytes)" }'''),
}


def fpath(path: str) -> str:
    p = (path or "").strip().replace("/", "\\")
    if re.match(r"^[A-Za-z]:$", p):
        p += "\\"
    if not FPATH_RE.match(p) or "\\..\\" in p + "\\" or "\\\\" in p[2:]:
        raise ValueError("Give a local path like C:\\Users\\Public (no ..).")
    return p


def files(db, dev: Device, path: str) -> dict:
    p = fpath(path or "C:\\")
    r = _run(db, dev, FILES.replace("__PATH__", _b(p)))
    return {"path": r.get("path") or p, "items": _list(r.get("items")), "drives": _list(r.get("drives")), "max_mb": MAX_TRANSFER // 1048576}


def file_text(db, dev: Device, path: str, tail: bool = False) -> dict:
    p = fpath(path)
    return _run(db, dev, FILE_TEXT.replace("__PATH__", _b(p)).replace("__MAX__", str(512 * 1024)).replace("__TAIL__", "$true" if tail else "$false"))


def file_op(db, dev: Device, who: str, op: str, path: str, name: str = "") -> dict:
    p = fpath(path)
    if op not in FILE_OPS:
        return {"ok": False, "output": "Unknown action."}
    if op in ("mkdir", "rename") and not FNAME_RE.match(name or ""):
        return {"ok": False, "output": "A name can't contain \\ / : * ? \" < > |."}
    if op in ("rename", "delete") and (FILE_LOCKED.match(p) or p.count("\\") < 2 and len(p) <= 3):
        return {"ok": False, "output": f"{p} is part of Windows; it isn't renamed or deleted from here."}
    label, body = FILE_OPS[op]
    return _go(db, dev, who, f"file.{op}", f"{label} {p}" + (f" → {name}" if name and op != "delete" else ""),
               f"$p = D '{_b(p)}'\n$name = D '{_b(name)}'\n{body}\n@{{ ok = $true; message = $m }} | ConvertTo-Json -Compress")


import threading  # noqa: E402
_transfers = threading.BoundedSemaphore(MAX_PARALLEL)


def _client(db, dev: Device):
    """A pypsrp Client for this PC with the first credential the PC accepts (file transfer needs the Client itself)."""
    from .actions import _addr
    from .collectors import winrm
    from .pctools import _cfg
    cfg = _cfg(db)
    last = None
    for c in cfg.get("creds") or [{"user": cfg.get("user"), "password": cfg.get("password")}]:
        cl = winrm._client(_addr(dev), {**cfg, **c, "timeout": 900})
        try:
            cl.execute_ps("'ok'")
            return cl
        except Exception as exc:
            last = exc
            if winrm.classify_error(exc) != "access_denied":
                break
    raise last


def download(db, dev: Device, who: str, path: str, dest: str) -> dict:
    """Copy one file from the PC to dest (a temp file on this server). Raises on failure."""
    p = fpath(path)
    info = _run(db, dev, FILE_INFO.replace("__PATH__", _b(p)))
    size = int(info.get("size") or 0)
    if size > MAX_TRANSFER:
        raise PermissionError(f"{info.get('name')} is {size // 1048576} MB; files over {MAX_TRANSFER // 1048576} MB aren't copied from here.")
    if not _transfers.acquire(timeout=1):
        raise PermissionError(f"{MAX_PARALLEL} file transfers are already running; try again when one finishes.")
    try:
        _client(db, dev).fetch(p, dest)
    except Exception as exc:
        _record(db, dev, who, "file.download", f"Download {p}: {str(exc)[:200]}", False)
        raise
    finally:
        _transfers.release()
    _record(db, dev, who, "file.download", f"Download {p} ({size} bytes)", True)
    return {"name": info.get("name") or p.split("\\")[-1], "size": size}


def upload(db, dev: Device, who: str, folder: str, name: str, src: str, size: int) -> dict:
    p = fpath(folder)
    if not FNAME_RE.match(name or ""):
        return {"ok": False, "output": "Bad file name."}
    if size > MAX_TRANSFER:
        return {"ok": False, "output": f"Files over {MAX_TRANSFER // 1048576} MB aren't copied from here."}
    dest = p.rstrip("\\") + "\\" + name
    if FILE_LOCKED.match(p):
        return {"ok": False, "output": f"Files aren't copied into {p} from here."}
    if not _transfers.acquire(timeout=1):
        return {"ok": False, "output": f"{MAX_PARALLEL} file transfers are already running; try again when one finishes."}
    try:
        _client(db, dev).copy(src, dest)
        ok, msg = True, f"copied to {dest}"
    except Exception as exc:
        ok, msg = False, str(exc).split("\n")[0][:300]
    finally:
        _transfers.release()
    _record(db, dev, who, "file.upload", f"Upload {name} ({size} bytes) to {p}: {msg}", ok)
    return {"ok": ok, "output": msg}
