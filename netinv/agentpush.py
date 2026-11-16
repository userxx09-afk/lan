"""Install (push) or remove the NetInventory Agent on PCs from the dashboard, through the deployment queue (fixes.py).

What a push does, over WinRM with the scan credential, like every other deployment:
- sends the agent to the PC inside the script: the agent MSI that ships with this server (agent-msi folder, built
  by CI with the same version), or, when the server has no MSI (a development install), the three agent scripts;
- installs it as SYSTEM from a one-off scheduled task (Windows refuses MSI installs straight from a remote
  session), with this server's address, its certificate pin and a one-time enrollment ticket;
- runs the agent once and waits for it, so the push only counts as a success when the PC actually reached the
  server and enrolled. The agent's own error (certificate pin, firewall, name) is the failure message otherwise.

The ticket ("nip_..."): random, made at the moment of sending, good once, for that one hostname, for a day. Only
its SHA-256 hash is kept on the server. An agent that enrolls with it is approved at once (an admin chose to push
it), even when its earlier agent was revoked; a different machine already reporting under the same name still
waits for approval. The site enrollment token (Settings > Agent) isn't needed and is never sent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets as pysecrets
import socket
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from .db import get_setting, norm_host, set_setting, utcnow

RUN_AS = {"LOCALSERVICE": "Local Service", "SYSTEM": "SYSTEM"}
TICKET_HOURS = 24
AGENT_DIR = Path(__file__).resolve().parent / "agent"
URL_RE = re.compile(r"^https://[A-Za-z0-9.\-]+(:\d{1,5})?$")


# ------------------------------------------------------------------ server address, pin, bits
def msi_path() -> Path | None:
    """The agent MSI bundled with the server installer ({app}\\agent-msi), if there is one."""
    cands = []
    if os.environ.get("NETINV_AGENT_MSI"):
        cands.append(Path(os.environ["NETINV_AGENT_MSI"]))
    from .updater import install_dir
    root = install_dir()
    if root:
        cands.append(root / "agent-msi" / "NetInventory-Agent.msi")
    for p in cands:
        if p.is_file() and 10_000 < p.stat().st_size < 20_000_000:
            return p
    return None


def server_url(db, request_base: str | None = None) -> str:
    """Saved address the agents use, else the address the dashboard was opened with (never localhost)."""
    saved = get_setting(db, "agent:server_url", None)
    if saved:
        return saved
    u = urlparse(request_base or "")
    host = u.hostname or ""
    if not host or host in ("localhost", "127.0.0.1", "::1"):
        host = socket.getfqdn()
    port = f":{u.port}" if u.port else ""
    return f"https://{host}{port}"


def check_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not URL_RE.match(url):
        raise ValueError("The server address must look like https://netinv.corp.local:8080 (https, no path).")
    if urlparse(url).hostname in ("localhost", "127.0.0.1"):
        raise ValueError("Use this server's network name: the PCs can't reach it as localhost.")
    return url


def pin() -> str | None:
    from . import tlscert
    from .config import settings
    return tlscert.info(settings.tls_cert).get("sha256")


def status(db, request_base: str | None = None) -> dict:
    """What the push dialog shows."""
    from .scanning import winrm_cfg
    p = msi_path()
    return {"server": server_url(db, request_base), "saved": bool(get_setting(db, "agent:server_url", None)),
            "https": bool(pin()), "pin": pin(), "package": "msi" if p else "scripts",
            "credential": bool(winrm_cfg(db))}


# ------------------------------------------------------------------ one-time enrollment tickets
def _key(host: str) -> str:
    return f"agent:push:{norm_host(host)}"[:64]


def new_ticket(db, host: str) -> str:
    tok = "nip_" + pysecrets.token_urlsafe(24)
    set_setting(db, _key(host), json.dumps({"h": hashlib.sha256(tok.encode()).hexdigest(),
                                            "exp": (utcnow() + timedelta(hours=TICKET_HOURS)).isoformat()}))
    db.commit()
    return tok


def drop_ticket(db, host: str) -> None:
    if get_setting(db, _key(host), None):
        set_setting(db, _key(host), None)


def use_ticket(db, host: str, token: str) -> bool:
    """True (and the ticket is gone) when token is this hostname's valid push ticket."""
    raw = get_setting(db, _key(host), None) if host else None
    if not raw or not token.startswith("nip_"):
        return False
    try:
        t = json.loads(raw)
        from datetime import datetime
        if datetime.fromisoformat(t["exp"]) < utcnow():
            return False
        ok = hmac.compare_digest(hashlib.sha256(token.strip().encode()).hexdigest(), t["h"])
    except (ValueError, KeyError, TypeError):
        return False
    if ok:
        set_setting(db, _key(host), None)
    return ok


# ------------------------------------------------------------------ what runs on the PC (as SYSTEM)
# __KIND__ msi | scripts; __BITS__ base64 of the MSI, or of a JSON {file name: text} for the scripts.
INSTALL = r"""
$ErrorActionPreference = 'Stop'
$res = @{ ok = $false; stage = 'install' }
$dir = Join-Path $env:ProgramData 'NetInventory\fix'
$data = Join-Path $env:ProgramData 'NetInventory Agent'
$self = Join-Path $dir '__NAME__.ps1'
try {
  $t0 = (Get-Date).ToUniversalTime()
  $server = '__SERVER__'; $tok = '__TOKEN__'; $pin = '__PIN__'; $runas = '__RUNAS__'
  $bits = [Convert]::FromBase64String('__BITS__')
  if ('__KIND__' -eq 'msi') {
    $msi = Join-Path $dir 'NetInventory-Agent.msi'
    $mlog = Join-Path $dir 'agent-install.log'
    [IO.File]::WriteAllBytes($msi, $bits)
    $a = "/i `"$msi`" /qn /norestart /l*v `"$mlog`" SERVER=$server TOKEN=$tok PIN=$pin RUNAS=$runas"
    $p = Start-Process msiexec.exe -ArgumentList $a -Wait -PassThru
    $res.exit = $p.ExitCode
    Remove-Item $msi -ErrorAction SilentlyContinue
    if ($p.ExitCode -notin 0, 3010, 1641) {
      $why = switch ($p.ExitCode) { 1618 { 'another installation is running; it is tried again later' } 1603 { 'the installation failed (1603)' } 1638 { 'a newer agent is already installed' } default { "msiexec exit code $($p.ExitCode)" } }
      $tail = (Get-Content $mlog -ErrorAction SilentlyContinue | Select-String 'error|failed|return value 3' | Select-Object -Last 6 | ForEach-Object { "$_".Trim() }) -join "`n"
      throw ("MSI: $why" + $(if ($tail) { "`n$tail" } else { '' }))
    }
    Remove-Item $mlog -ErrorAction SilentlyContinue
    $res.package = 'MSI'
  } else {
    $files = [Text.Encoding]::UTF8.GetString($bits) | ConvertFrom-Json
    $prog = Join-Path $env:ProgramFiles 'NetInventory Agent'
    New-Item -ItemType Directory -Force $prog | Out-Null
    foreach ($f in $files.PSObject.Properties) { [IO.File]::WriteAllText((Join-Path $prog $f.Name), [string]$f.Value, (New-Object Text.UTF8Encoding $true)) }
    $ErrorActionPreference = 'Continue'     # native stderr must not abort (PowerShell 5.1)
    $out = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $prog 'Install-Agent.ps1') -Server $server -Token $tok -Pin $pin -RunAs $runas 2>&1 | Out-String
    $rc = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
    if ($rc) { throw "Install-Agent.ps1 failed: $($out.Trim())" }
    $res.package = 'scripts'
  }
  # Run the agent once now and wait for it: success means the PC reached this server and enrolled.
  $res.stage = 'first run'
  $code = $null
  $tn = 'NetInventory Agent'
  foreach ($try in 1, 2) {     # a revoked or unknown secret is dropped on one run and enrolled on the next
    $deadline = (Get-Date).AddMinutes(4)
    while ("$((Get-ScheduledTask -TaskName $tn).State)" -eq 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }   # the installer's own run
    $i = Get-ScheduledTaskInfo -TaskName $tn
    if ($try -eq 1 -and $i.LastTaskResult -eq 0 -and $i.LastRunTime.ToUniversalTime() -ge $t0) { $code = 0; break }
    $before = $i.LastRunTime
    Start-ScheduledTask -TaskName $tn
    do { Start-Sleep -Seconds 3; $t = Get-ScheduledTask -TaskName $tn; $i = Get-ScheduledTaskInfo -TaskName $tn }
    while (("$($t.State)" -eq 'Running' -or $i.LastRunTime -eq $before) -and (Get-Date) -lt $deadline)
    $code = $i.LastTaskResult
    if ($code -eq 0) { break }
  }
  $lines = @(Get-Content (Join-Path $data 'agent.log') -ErrorAction SilentlyContinue | Where-Object {
    $_ -match '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ) (.*)$' -and [datetime]::ParseExact($Matches[1], "yyyy-MM-dd HH:mm:ss'Z'", $null).AddSeconds(5) -ge $t0 } |
    ForEach-Object { ($_ -split ' ', 3)[2] })
  $res.log = ($lines | Select-Object -Last 6) -join "`n"
  $res.enrolled = [bool]($lines | Where-Object { $_ -like 'enrolled as *' })
  $res.exit = $code
  if ($code -eq 0) { $res.ok = $true; $res.message = "Installed ($($res.package), runs as $runas) and reporting" }
  else {
    $err = ($lines | Where-Object { $_ -like 'error: *' } | Select-Object -Last 1)
    $res.message = "Installed, but the agent couldn't reach the server: " + $(if ($err) { $err.Substring(7) } elseif ($code -eq 267009) { 'still running after 4 minutes' } else { "task result $code" })
  }
} catch { $res.message = "$_" }
Remove-Item $self -ErrorAction SilentlyContinue
$res
"""

REMOVE = r"""
$ErrorActionPreference = 'Stop'
$res = @{ ok = $false }
try {
  $k = $null
  foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
    $k = Get-ChildItem $root -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -eq 'NetInventory Agent' } | Select-Object -First 1
    if ($k) { break } }
  $prog = Join-Path $env:ProgramFiles 'NetInventory Agent'
  if ($k) {
    $p = Start-Process msiexec.exe -ArgumentList "/x $($k.PSChildName) /qn /norestart" -Wait -PassThru
    $res.exit = $p.ExitCode
    if ($p.ExitCode -notin 0, 3010, 1641, 1605) { throw "msiexec exit code $($p.ExitCode)" }
    $res.message = 'Agent uninstalled (MSI)'
  } elseif (Test-Path (Join-Path $prog 'Uninstall-Agent.ps1')) {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $prog 'Uninstall-Agent.ps1') | Out-Null
    Remove-Item -Recurse -Force $prog -ErrorAction SilentlyContinue
    $res.message = 'Agent removed'
  } elseif (Get-ScheduledTask -TaskName 'NetInventory Agent' -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName 'NetInventory Agent' -Confirm:$false
    Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'NetInventory Agent') -ErrorAction SilentlyContinue
    $res.message = 'Agent task removed'
  } else { $res.message = 'The agent was not installed' }
  $res.ok = $true
} catch { $res.message = "$_" }
$res
"""


def _bits() -> tuple[str, str]:
    p = msi_path()
    if p:
        return "msi", base64.b64encode(p.read_bytes()).decode()
    files = {f.name: f.read_text(encoding="utf-8-sig") for f in sorted(AGENT_DIR.glob("*.ps1"))}
    return "scripts", base64.b64encode(json.dumps(files).encode("utf-8")).decode()


def install_script(db, host: str, task: str, run_as: str) -> str:
    """The script for one PC, with a fresh ticket. Raises ValueError when the server isn't set up for agents."""
    url = check_url(server_url(db))
    if not get_setting(db, "agent:server_url", None):
        raise ValueError("Set the server address for agents first (Push agent dialog).")
    fp = pin()
    if not fp:
        raise ValueError("This server isn't on HTTPS: agents only talk HTTPS (Settings > HTTPS certificate).")
    kind, b64 = _bits()
    tok = new_ticket(db, host)
    return (INSTALL.replace("__NAME__", task).replace("__SERVER__", url).replace("__TOKEN__", tok).replace("__PIN__", fp)
            .replace("__RUNAS__", run_as if run_as in RUN_AS else "LOCALSERVICE").replace("__KIND__", kind)
            .replace("__BITS__", b64))


def agent_state(db, host: str) -> str | None:
    """'active', 'pending' (with why) or None, for the deployment's result line."""
    from sqlalchemy import select
    from .db import Agent
    a = db.scalars(select(Agent).where(Agent.hostname == norm_host(host), Agent.status != "revoked")
                   .order_by(Agent.enrolled.desc())).first()
    if not a:
        return None
    return "active" if a.status == "active" else f"waiting for approval in Settings > Agent ({a.note or 'pending'})"
