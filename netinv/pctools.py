"""Live tools on one PC over WinRM (the asset page's Processes and Services tabs).

Read-only views run on demand. Changes (end a process, start/stop/restart a service, change its start type) are
confirmed in the UI, written to the audit log and the PC's history. Process IDs and service names are validated
before they go into a script, so nothing typed in the browser reaches PowerShell unchecked.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager

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


_signed_in = threading.local()


@contextmanager
def signed_in_as(cfg: dict | None):
    """Within this block (one deployment in this thread), tools sign in with cfg instead of the scan credentials."""
    _signed_in.cfg = cfg
    try:
        yield
    finally:
        _signed_in.cfg = None


def _cfg(db):
    from .scanning import winrm_cfg
    cfg = getattr(_signed_in, "cfg", None) or winrm_cfg(db)
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


# ------------------------------------------------------------------ registry, printers, mapped drives, local accounts
# Text from the browser never goes into a script as code: every string is passed base64-encoded and decoded on the PC.
D = "function D([string]$s) { if (-not $s) { return '' }; [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }\n"


def _b(s: str) -> str:
    import base64
    return base64.b64encode((s or "").encode("utf-8")).decode()


def _run(db, dev: Device, script: str):
    from .collectors.winrm import run_ps
    return run_ps(_addr(dev), _cfg(db), "$ErrorActionPreference = 'Stop'\n" + D + script)


REG_ROOTS = {"HKLM": "LocalMachine", "HKU": "Users", "HKCR": "ClassesRoot"}
REG_TYPES = {"String", "ExpandString", "DWord", "QWord", "MultiString"}
# Never written from here: account databases and the security policy store
REG_LOCKED = ("HKLM\\SAM", "HKLM\\SECURITY", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa")


def reg_split(path: str) -> tuple[str, str]:
    p = (path or "").strip().strip("\\").replace("/", "\\")
    p = re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM:?)", "HKLM", p, flags=re.I)
    p = re.sub(r"^(HKEY_USERS|HKU:?)", "HKU", p, flags=re.I)
    p = re.sub(r"^(HKEY_CLASSES_ROOT|HKCR:?)", "HKCR", p, flags=re.I)
    root, _, sub = p.partition("\\")
    root = root.upper()
    if root not in REG_ROOTS:
        raise ValueError("Start the path with HKLM, HKU or HKCR (HKCU is the remote session's own hive; use HKU\\<SID>).")
    if len(sub) > 1000 or any(ord(ch) < 32 for ch in sub) or "\\\\" in sub:
        raise ValueError("That isn't a valid registry path.")
    return root, sub


REG_OPEN = r'''
$root = [Microsoft.Win32.Registry]::__ROOT__
$sub = D '__SUB__'
'''


def registry(db, dev: Device, path: str) -> dict:
    root, sub = reg_split(path)
    r = _run(db, dev, REG_OPEN.replace("__ROOT__", REG_ROOTS[root]).replace("__SUB__", _b(sub)) + r'''
$k = if ($sub) { $root.OpenSubKey($sub) } else { $root }
if (-not $k) { throw 'That key does not exist on this PC.' }
$vals = foreach ($n in $k.GetValueNames()) {
  $kind = "$($k.GetValueKind($n))"
  $v = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
  $d = switch ($kind) {
    'Binary' { (@($v) | Select-Object -First 512 | ForEach-Object { $_.ToString('x2') }) -join ' ' }
    'MultiString' { @($v) -join "`n" }
    'DWord' { '{0} (0x{0:x8})' -f [uint32]([int64]$v -band 0xffffffff) }
    default { "$v" } }
  [pscustomobject]@{ name = $n; type = $kind; data = $d.Substring(0, [Math]::Min(4000, $d.Length)) }
}
@{ subkeys = @($k.GetSubKeyNames() | Sort-Object); values = @($vals | Sort-Object name) } | ConvertTo-Json -Depth 3 -Compress''')
    return {"path": root + ("\\" + sub if sub else ""), "subkeys": _list(r.get("subkeys")), "values": _list(r.get("values"))}


def reg_change(db, dev: Device, who: str, op: str, path: str, name: str = "", kind: str = "String", data: str = "") -> dict:
    root, sub = reg_split(path)
    full = root + ("\\" + sub if sub else "")
    if any(full.lower() == x.lower() or full.lower().startswith(x.lower() + "\\") for x in REG_LOCKED):
        return {"ok": False, "output": f"{full} holds Windows accounts or security policy; it isn't changed from here."}
    if not sub:
        return {"ok": False, "output": "Pick a key below the root."}
    if op not in ("set", "delete_value", "new_key", "delete_key"):
        return {"ok": False, "output": "Unknown change."}
    if len(name) > 255 or len(data) > 32000:
        return {"ok": False, "output": "Name or data too long."}
    if op == "set":
        if kind not in REG_TYPES:
            return {"ok": False, "output": "Pick String, Expandable string, DWORD, QWORD or Multi-string."}
        if kind in ("DWord", "QWord"):
            try:
                n = int(data.strip(), 0)
            except ValueError:
                return {"ok": False, "output": "A DWORD or QWORD is a number (decimal, or hex like 0x1F)."}
            if n < 0 or n >= (1 << (32 if kind == "DWord" else 64)):
                return {"ok": False, "output": "Number out of range."}
            data = str(n)
    if op == "delete_key" and sub.count("\\") < 2:
        return {"ok": False, "output": "Keys this close to the root aren't deleted from here (at least three levels deep, e.g. HKLM\\SOFTWARE\\Vendor\\App)."}
    if op == "new_key" and not re.match(r"^[^\\\x00-\x1f]{1,255}$", name or ""):
        return {"ok": False, "output": "A key name can't be empty or contain a backslash."}
    body = {
        "set": r'''
$k = $root.CreateSubKey($sub)
$was = if ($k.GetValueNames() -contains $name) { "$($k.GetValueKind($name)) " + (@($k.GetValue($name, $null, 'DoNotExpandEnvironmentNames')) -join ' | ') } else { '(new)' }
$v = switch ('__KIND__') {
  'DWord' { [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$data), 0) }      # stored as the same 32 bits
  'QWord' { [BitConverter]::ToInt64([BitConverter]::GetBytes([uint64]$data), 0) }
  'MultiString' { [string[]]($data -split "`r?`n") }
  default { $data } }
$k.SetValue($name, $v, [Microsoft.Win32.RegistryValueKind]::__KIND__)
@{ ok = $true; message = "set (was: $was)" } | ConvertTo-Json -Compress''',
        "delete_value": r'''
$k = $root.OpenSubKey($sub, $true)
if (-not $k -or -not ($k.GetValueNames() -contains $name)) { throw 'value not found' }
$was = "$($k.GetValueKind($name)) " + (@($k.GetValue($name, $null, 'DoNotExpandEnvironmentNames')) -join ' | ')
$k.DeleteValue($name)
@{ ok = $true; message = "deleted (was: $was)" } | ConvertTo-Json -Compress''',
        "new_key": r'''
$k = $root.CreateSubKey($sub + '\' + $name)
@{ ok = $true; message = 'created' } | ConvertTo-Json -Compress''',
        "delete_key": r'''
$k = $root.OpenSubKey($sub)
if (-not $k) { throw 'key not found' }
$n = $k.SubKeyCount; $k.Close()
$root.DeleteSubKeyTree($sub)
@{ ok = $true; message = "deleted with $n subkey(s)" } | ConvertTo-Json -Compress''',
    }[op].replace("__KIND__", kind if kind in REG_TYPES else "String")
    try:
        r = _run(db, dev, REG_OPEN.replace("__ROOT__", REG_ROOTS[root]).replace("__SUB__", _b(sub))
                 + f"$name = D '{_b(name)}'\n$data = D '{_b(data)}'\n" + body)
        ok, msg = bool(r.get("ok")), r.get("message") or "?"
    except Exception as exc:
        ok, msg = False, str(exc).split("\n")[0][:300]
    what = {"set": f"Set {full}\\{name or '(Default)'} = {kind} {data[:200]}", "delete_value": f"Delete value {full}\\{name or '(Default)'}",
            "new_key": f"Create key {full}\\{name}", "delete_key": f"Delete key {full}"}[op]
    _record(db, dev, who, f"registry.{op}", f"{what}: {msg}", ok)
    return {"ok": ok, "output": msg}


PRINTERS = r'''
# printers added for every user (printui /ga) are listed here as ",,server,printer" with the server in a value
$conn = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Connections' -ErrorAction SilentlyContinue |
  ForEach-Object { '\\' + "$((Get-ItemProperty $_.PSPath).Server)".TrimStart('\') + '\' + ($_.PSChildName -split ',')[-1] })
$out = @(Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; driver = $_.DriverName; port = $_.PortName; shared = [bool]$_.Shared; share = $_.ShareName
    network = [bool]$_.Network; status = "$($_.PrinterStatus)"; jobs = 0; location = $_.Location; machine_wide = $false } })
foreach ($c in $conn) { if ($c -and -not ($out | Where-Object { $_.name -eq $c })) {
  $out += [pscustomobject]@{ name = $c; driver = ''; port = ''; shared = $false; share = ''; network = $true; status = 'for every user (applies at sign-in)'; jobs = 0; location = ''; machine_wide = $true } } }
foreach ($p in $out) { if ($conn -contains $p.name) { $p.machine_wide = $true } }
try { Get-CimInstance Win32_PrintJob | ForEach-Object { $n = ($_.Name -split ',')[0]; $p = $out | Where-Object { $_.name -eq $n }; if ($p) { $p.jobs++ } } } catch {}
ConvertTo-Json @($out) -Compress -Depth 2
'''
PRINTER_STATUS = {"1": "other", "2": "unknown", "3": "ready", "4": "printing", "5": "warming up", "6": "stopped", "7": "offline"}
UNC_RE = re.compile(r"^\\\\[A-Za-z0-9.\-]{1,253}\\[^\\/:*?\"<>|\x00-\x1f]{1,128}$")


def printers(db, dev: Device) -> list[dict]:
    rows = _list(_run(db, dev, PRINTERS))
    for r in rows:
        r["status"] = PRINTER_STATUS.get(r.get("status"), r.get("status"))
    return sorted(rows, key=lambda r: (r.get("name") or "").lower())


def printer_change(db, dev: Device, who: str, op: str, name: str) -> dict:
    if not name or len(name) > 260 or any(ord(ch) < 32 for ch in name):
        return {"ok": False, "output": "Unknown printer."}
    if op == "add" and not UNC_RE.match(name):
        return {"ok": False, "output": "Give the shared printer as \\\\server\\printer."}
    body = {
        "test": r'''$p = Get-CimInstance Win32_Printer | Where-Object { $_.Name -eq $n }
if (-not $p) { throw 'printer not found' }
$r = Invoke-CimMethod -InputObject $p -MethodName PrintTestPage
@{ ok = ($r.ReturnValue -eq 0); message = $(if ($r.ReturnValue -eq 0) { 'test page sent' } else { "Windows refused (code $($r.ReturnValue))" }) } | ConvertTo-Json -Compress''',
        "clear": r'''$jobs = @(Get-CimInstance Win32_PrintJob | Where-Object { ($_.Name -split ',')[0] -eq $n })
$jobs | ForEach-Object { Remove-CimInstance -InputObject $_ }
@{ ok = $true; message = "$($jobs.Count) job(s) removed from the queue" } | ConvertTo-Json -Compress''',
        "add": r'''& rundll32.exe printui.dll,PrintUIEntry /ga /n$n /q
Start-Sleep 2
Restart-Service Spooler -Force
@{ ok = $true; message = 'added for every user; it appears for each user at their next sign-in' } | ConvertTo-Json -Compress''',
        "remove": r'''$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Connections'
$mw = Get-ChildItem $key -ErrorAction SilentlyContinue | Where-Object { ('\\' + "$((Get-ItemProperty $_.PSPath).Server)".TrimStart('\') + '\' + ($_.PSChildName -split ',')[-1]) -eq $n }
if ($mw) { & rundll32.exe printui.dll,PrintUIEntry /gd /n$n /q; Start-Sleep 2; Restart-Service Spooler -Force; @{ ok = $true; message = 'removed for every user (gone at their next sign-in)' } | ConvertTo-Json -Compress; return }
$p = Get-CimInstance Win32_Printer | Where-Object { $_.Name -eq $n }
if (-not $p) { throw 'printer not found' }
if ($p.Network) { throw 'this is one user''s own connection; remove it in their session (or with a logon script)' }
Remove-Printer -Name $n
@{ ok = $true; message = 'removed' } | ConvertTo-Json -Compress''',
    }.get(op)
    if body is None:
        return {"ok": False, "output": "Unknown action."}
    try:
        r = _run(db, dev, f"$n = D '{_b(name)}'\n" + body)
        ok, msg = bool(r.get("ok")), r.get("message") or "?"
    except Exception as exc:
        ok, msg = False, str(exc).split("\n")[0][:300]
    label = {"test": "Print a test page on", "clear": "Clear the queue of", "add": "Add printer", "remove": "Remove printer"}[op]
    _record(db, dev, who, f"printer.{op}", f"{label} {name}: {msg}", ok)
    return {"ok": ok, "output": msg}


DRIVES = r'''
$names = @{}
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { $names[$_.PSChildName] = Split-Path ((Get-ItemProperty $_.PSPath).ProfileImagePath) -Leaf }
$out = foreach ($u in Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }) {
  $sid = $u.PSChildName
  $who = try { (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value } catch { $names[$sid] }
  foreach ($d in Get-ChildItem "Registry::HKEY_USERS\$sid\Network" -ErrorAction SilentlyContinue) {
    $p = Get-ItemProperty $d.PSPath
    [pscustomobject]@{ user = $who; sid = $sid; drive = $d.PSChildName.ToUpper() + ':'; path = $p.RemotePath; kind = 'mapped (persistent)' } }
  foreach ($m in Get-ChildItem "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '##*' }) {
    [pscustomobject]@{ user = $who; sid = $sid; drive = ''; path = ($m.PSChildName -replace '#', '\'); kind = 'used recently' } }
}
ConvertTo-Json @($out) -Compress -Depth 2
'''


def drives(db, dev: Device) -> list[dict]:
    return _list(_run(db, dev, DRIVES))


LOCAL = r'''
$sidAdm = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
$g = $sidAdm.Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$grp = [ADSI]"WinNT://./$g,group"
$members = @($grp.psbase.Invoke('Members') | ForEach-Object {
  $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
  $cls = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
  $sid = try { (New-Object Security.Principal.SecurityIdentifier($_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null), 0)).Value } catch { '' }
  $n = ($path -replace '^WinNT://', '') -replace '/', '\'
  $parts = $n.Split('\')
  if ($parts.Count -ge 3) { $n = $parts[-2] + '\' + $parts[-1] }     # WinNT://DOMAIN/PC/user -> PC\user
  [pscustomobject]@{ name = $n; type = $cls; sid = $sid; local = ($n -like "$env:COMPUTERNAME\*"); builtin = ($sid -match '-500$') } })
$users = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
  $u = $_
  $l = try { ([ADSI]"WinNT://./$($u.Name),user") } catch { $null }
  $last = try { $l.LastLogin.Value } catch { $null }
  [pscustomobject]@{ name = $u.Name; full_name = $u.FullName; enabled = -not $u.Disabled; locked = [bool]$u.Lockout; description = $u.Description
    sid = $u.SID; last_logon = if ($last) { ([datetime]$last).ToUniversalTime().ToString('s') } else { '' }
    admin = [bool]($members | Where-Object { $_.sid -eq $u.SID }) } })
@{ group = $g; members = $members; users = $users; computer = $env:COMPUTERNAME } | ConvertTo-Json -Depth 3 -Compress
'''
MEMBER_RE = re.compile(r"^[\w.\- ]{1,64}\\[\w.\-$@ ]{1,104}$")
LOCALUSER_RE = re.compile(r"^[\w.\-$ ]{1,20}$")


def local_accounts(db, dev: Device) -> dict:
    r = _run(db, dev, LOCAL)
    return {"group": r.get("group"), "computer": r.get("computer"), "members": _list(r.get("members")), "users": _list(r.get("users"))}


def _ours(db, member: str) -> bool:
    """The account NetInventory itself signs in with (removing it from Administrators would lock us out)."""
    cfg = _cfg(db)
    mine = {(c.get("user") or "").lower() for c in (cfg.get("creds") or [cfg])}
    short = lambda u: u.split("\\")[-1].split("@")[0]   # noqa: E731
    return short(member.lower()) in {short(u) for u in mine if u}


def local_change(db, dev: Device, who: str, op: str, name: str) -> dict:
    if op in ("add_admin", "remove_admin"):
        if not MEMBER_RE.match(name or ""):
            return {"ok": False, "output": "Give the account as DOMAIN\\name (a user or a group)."}
        if op == "remove_admin":
            low = name.lower()
            if low.endswith("\\domain admins") or low.endswith("\\administrator"):
                return {"ok": False, "output": f"{name} isn't removed from here (it's how the PC is managed and recovered)."}
            if _ours(db, name):
                return {"ok": False, "output": f"{name} is the account NetInventory signs in with; removing it would cut off this tool."}
    elif op in ("enable", "disable"):
        if not LOCALUSER_RE.match(name or ""):
            return {"ok": False, "output": "Unknown local account."}
    else:
        return {"ok": False, "output": "Unknown action."}
    body = {
        "add_admin": r'''$g = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$o = & net.exe localgroup $g $n /add 2>&1 | Out-String
@{ ok = ($LASTEXITCODE -eq 0); message = $(if ($LASTEXITCODE -eq 0) { "added to $g" } else { ($o -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' ' }) } | ConvertTo-Json -Compress''',
        "remove_admin": r'''$g = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$grp = [ADSI]"WinNT://./$g,group"
$count = @($grp.psbase.Invoke('Members')).Count
if ($count -le 1) { throw 'it is the only member left' }
$o = & net.exe localgroup $g $n /delete 2>&1 | Out-String
@{ ok = ($LASTEXITCODE -eq 0); message = $(if ($LASTEXITCODE -eq 0) { "removed from $g" } else { ($o -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' ' }) } | ConvertTo-Json -Compress''',
        "enable": r'''$u = [ADSI]"WinNT://./$n,user"; $u.InvokeSet('AccountDisabled', $false); $u.SetInfo()
@{ ok = $true; message = 'enabled' } | ConvertTo-Json -Compress''',
        "disable": r'''$u = [ADSI]"WinNT://./$n,user"
$u.InvokeSet('AccountDisabled', $true); $u.SetInfo()
@{ ok = $true; message = 'disabled' } | ConvertTo-Json -Compress''',
    }[op]
    if op == "disable" and _ours(db, name):
        return {"ok": False, "output": f"{name} is the account NetInventory signs in with."}
    try:
        r = _run(db, dev, f"$n = D '{_b(name)}'\n" + body)
        ok, msg = bool(r.get("ok")), r.get("message") or "?"
    except Exception as exc:
        ok, msg = False, str(exc).split("\n")[0][:300]
    label = {"add_admin": "Add to local Administrators:", "remove_admin": "Remove from local Administrators:",
             "enable": "Enable local account", "disable": "Disable local account"}[op]
    _record(db, dev, who, f"local.{op}", f"{label} {name}: {msg}", ok)
    return {"ok": ok, "output": msg}
