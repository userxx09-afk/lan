"""Agentless Windows collection over WinRM (PowerShell remoting).

* endpoints: runs ENDPOINT_SCRIPT on each PC and stores the result through the
  same EndpointPayload a future agent would POST.
* dc_logons: reads Kerberos TGT (4768) and logon (4624) events from each DC.

Needs WinRM enabled on targets (GPO: "Allow remote server management through WinRM")
and an account that is local admin on the PCs and in "Event Log Readers" on the DCs.
"""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from pypsrp.client import Client
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..db import Device, DomainController, LogonEvent, utcnow
from ..ingest import EndpointPayload, LogonIn, add_logons, apply_endpoint

log = logging.getLogger(__name__)

# Runs on the remote PC. Must stay PowerShell 5.1 compatible. Outputs one JSON object.
ENDPOINT_SCRIPT = r'''
$ErrorActionPreference = 'SilentlyContinue'
$CheckPending = __CHECK_PENDING__
$LogonDays = __LOGON_DAYS__
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$bio = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$gpu = (Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Remote|Mirror|Basic Display' } | ForEach-Object {
  if ($_.AdapterRAM -gt 0) { "$($_.Name) $([math]::Round($_.AdapterRAM/1GB,1)) GB" } else { $_.Name } }) -join '; '
$cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
  @{ mac = $_.MACAddress; ip = (@($_.IPAddress) | Where-Object { $_ -notmatch ':' } | Select-Object -First 1); description = $_.Description } })

$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  @{ drive = $_.DeviceID; size_gb = [math]::Round($_.Size/1GB,1); free_gb = [math]::Round($_.FreeSpace/1GB,1) } })

$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$software = @(Get-ItemProperty $keys | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } | ForEach-Object {
  @{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher; install_date = $_.InstallDate } })

$hotfixes = @(Get-HotFix | ForEach-Object {
  @{ kb = $_.HotFixID; title = $_.Description; installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString('o') } else { $null } } })

$pending = $null
if ($CheckPending) {
  try {
    $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $r = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $pending = @($r.Updates | ForEach-Object {
      @{ kb = (@($_.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ','; title = $_.Title; severity = $_.MsrcSeverity } })
  } catch { $pending = $null }
}

$av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
  $st = [int]$_.productState
  @{ name = $_.displayName; enabled = ((($st -shr 12) -band 0xF) -eq 1); up_to_date = (($st -band 0xFF) -eq 0) } })
if (-not $av) {  # Servers have no Security Center: ask Defender directly
  $mp = Get-MpComputerStatus
  if ($mp) { $av = @(@{ name = 'Microsoft Defender Antivirus'; enabled = ([bool]$mp.AntivirusEnabled -and [bool]$mp.RealTimeProtectionEnabled); up_to_date = ($mp.AntivirusSignatureAge -le 3) }) }
}
$fp = @{}
Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus | ForEach-Object { $fp[$_.InstanceName] = [bool]$_.PredictFailure }
$anyFail = [bool](@($fp.Values) -contains $true)
$pdisks = @(Get-PhysicalDisk | ForEach-Object {
  @{ model = $_.FriendlyName; serial = "$($_.SerialNumber)".Trim(); media = "$($_.MediaType)"; size_gb = [math]::Round($_.Size/1GB,1);
     health = "$($_.HealthStatus)"; predict_failure = $anyFail } })

$reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
          (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

$logons = @()
if ($LogonDays -gt 0) {
  $since = (Get-Date).AddDays(-$LogonDays)
  $logons = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$since} -MaxEvents 2000 | ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    $t = [int]$d.LogonType
    if ($t -in 2,10,11 -and $d.TargetDomainName -notin 'Window Manager','Font Driver Host','NT AUTHORITY') {
      @{ time = $_.TimeCreated.ToUniversalTime().ToString('o'); username = "$($d.TargetDomainName)\$($d.TargetUserName)"; logon_type = $t; ip = $d.IpAddress } }
  })
}

[pscustomobject]@{
  hostname = $env:COMPUTERNAME; fqdn = "$($cs.DNSHostName).$($cs.Domain)"; source = 'winrm'
  os_caption = $os.Caption; os_build = "$($os.BuildNumber).$($cv.UBR)"; os_display_version = $cv.DisplayVersion
  last_boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
  manufacturer = $cs.Manufacturer; model = $cs.Model; serial = $bio.SerialNumber; cpu = $cpu.Name; gpu = $gpu
  ram_gb = [math]::Round($cs.TotalPhysicalMemory/1GB,1); current_user = $cs.UserName
  nics = $nics; disks = $disks; software = $software; hotfixes = $hotfixes
  pending_updates = $pending; pending_reboot = $reboot; logons = $logons; antivirus = $av; physical_disks = $pdisks
} | ConvertTo-Json -Depth 5 -Compress
'''

DC_LOGON_SCRIPT = r'''
$ErrorActionPreference = 'SilentlyContinue'
$since = [datetime]::Parse('__SINCE__').ToLocalTime()
$xp = "*[System[(EventID=4768 or EventID=4624) and TimeCreated[@SystemTime>='" + $since.ToUniversalTime().ToString('o') + "']]]"
$out = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents __MAX__ | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  $ip = ($d.IpAddress -replace '^::ffff:','')
  if ($_.Id -eq 4768 -and $d.Status -eq '0x0') {
    @{ time = $_.TimeCreated.ToUniversalTime().ToString('o'); username = $d.TargetUserName; ip = $ip; logon_type = 0 }
  } elseif ($_.Id -eq 4624 -and $d.WorkstationName -and $d.WorkstationName -ne '-' -and [int]$d.LogonType -eq 3) {
    @{ time = $_.TimeCreated.ToUniversalTime().ToString('o'); username = $d.TargetUserName; hostname = $d.WorkstationName; ip = $ip; logon_type = 3 }
  }
})
ConvertTo-Json -InputObject $out -Depth 3 -Compress
'''


def _client(host: str, cfg: dict) -> Client:
    return Client(host, username=cfg["user"], password=cfg["password"],
                  ssl=cfg.get("use_ssl", False), cert_validation=cfg.get("verify_tls", True),
                  auth=cfg.get("auth", "negotiate"), operation_timeout=cfg.get("timeout", 120),
                  read_timeout=cfg.get("timeout", 120) + 10, connection_timeout=cfg.get("connect_timeout", 10))


def classify_error(exc: Exception) -> str:
    m = str(exc).lower()
    if any(k in m for k in ("401", "access is denied", "access denied", "unauthorized", "logon failure", "credentials")):
        return "access_denied"
    if any(k in m for k in ("timed out", "timeout", "refused", "unreachable", "no route", "name or service not known",
                            "getaddrinfo", "max retries", "connection")):
        return "unreachable"
    return "other"


def run_ps(host: str, cfg: dict, script: str):
    """Run a script, trying each credential in cfg["creds"] (or cfg user/password) until one is accepted."""
    creds = cfg.get("creds") or [{"user": cfg.get("user"), "password": cfg.get("password")}]
    last = None
    for c in creds:
        try:
            out, streams, had_errors = _client(host, {**cfg, **c}).execute_ps(script)
            if not out.strip():
                errs = "; ".join(str(e) for e in streams.error[:3])
                raise RuntimeError(errs or "no output")
            return json.loads(out)
        except Exception as exc:
            last = exc
            if classify_error(exc) != "access_denied":
                break   # only try the next credential when this one was refused
    raise last


def _targets(db: Session, cfg: dict) -> list[tuple[str | None, str]]:
    """(hostname or None, address). hosts = explicit names/IPs; otherwise enabled AD computers seen recently."""
    out = []
    for h in cfg.get("hosts") or []:
        is_ip = h.replace(".", "").isdigit()
        out.append((None if is_ip else h.split(".")[0].upper(), h))
    if cfg.get("hosts") and not cfg.get("include_ad", False):
        return out
    active = utcnow() - timedelta(days=cfg.get("active_days", 30))
    q = select(Device).where(Device.ad_enabled.is_(True), or_(Device.ad_last_logon >= active, Device.ad_last_logon.is_(None)))
    if not cfg.get("include_servers", True):
        q = q.where(or_(Device.ad_os.is_(None), ~Device.ad_os.ilike("%server%")))
    for path in cfg.get("computer_bases") or []:
        q = q.where(Device.ad_dn.ilike(f"%{path}"))
    names = {h for h, _ in out}
    out += [(d.hostname, d.fqdn or d.hostname) for d in db.scalars(q) if d.hostname not in names]
    return out


def _record_error(db: Session, host: str | None, exc: Exception) -> None:
    if not host:
        return
    dev = db.scalar(select(Device).where(Device.hostname == host))
    if dev:
        dev.scan_error, dev.scan_error_kind, dev.scan_error_time = str(exc)[:1000], classify_error(exc), utcnow()
        db.commit()


def collect_endpoints(db: Session, cfg: dict, check_pending: bool = False) -> str:
    targets = _targets(db, cfg)
    script = (ENDPOINT_SCRIPT.replace("__CHECK_PENDING__", "$true" if check_pending else "$false")
              .replace("__LOGON_DAYS__", str(int(cfg.get("local_logon_days", 14)))))
    ok, failed, denied = 0, [], 0
    with ThreadPoolExecutor(max_workers=cfg.get("parallel", 16)) as pool:
        futs = {pool.submit(run_ps, addr, cfg, script): (host, addr) for host, addr in targets}
        for fut in as_completed(futs):
            host, addr = futs[fut]
            try:
                payload = EndpointPayload.model_validate(fut.result())
                if host:
                    payload.hostname = host  # trust the AD name over $env:COMPUTERNAME
                dev = apply_endpoint(db, payload)
                dev.scan_error = dev.scan_error_kind = dev.scan_error_time = None
                db.commit()
                ok += 1
            except Exception as exc:
                db.rollback()
                failed.append(host or addr)
                denied += classify_error(exc) == "access_denied"
                _record_error(db, host, exc)
                log.warning("WinRM %s failed: %s", host or addr, exc)
    msg = f"{ok}/{len(targets)} computers collected"
    if failed:
        msg += f"; {len(failed)} failed ({denied} access denied): {', '.join(sorted(failed)[:15])}"
    return msg


def collect_dc_logons(db: Session, cfg: dict) -> str:
    dcs = list(db.scalars(select(DomainController)))
    total = 0
    for dc in dcs:
        last = db.scalar(select(func.max(LogonEvent.time)).where(LogonEvent.source == f"dc:{dc.hostname}"))
        since = last or (utcnow() - timedelta(days=cfg.get("dc_initial_days", 7)))
        script = (DC_LOGON_SCRIPT.replace("__SINCE__", since.isoformat() + "Z")
                  .replace("__MAX__", str(int(cfg.get("dc_max_events", 50000)))))
        try:
            rows = run_ps(dc.fqdn or dc.hostname, cfg, script) or []
        except Exception as exc:
            log.warning("DC %s logon pull failed: %s", dc.hostname, exc)
            continue
        if isinstance(rows, dict):
            rows = [rows]
        total += add_logons(db, [LogonIn(source=f"dc:{dc.hostname}", **r) for r in rows])
        db.commit()
    return f"{total} logon events from {len(dcs)} DCs"
