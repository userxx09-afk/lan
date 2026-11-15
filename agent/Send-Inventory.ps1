<#
  OPTIONAL push agent (not needed for agentless mode).
  Collects the same data the server pulls over WinRM and POSTs it to /api/ingest/endpoint.
  Use it for laptops that are rarely reachable over WinRM, e.g. as a GPO/Intune scheduled task
  running as SYSTEM at logon + daily:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Send-Inventory.ps1 -Server https://netinv.corp.local -Token <ingest_token>
  Generated from netinv/collectors/winrm.py ENDPOINT_SCRIPT so both paths stay identical.
#>
param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Token)
$ErrorActionPreference = 'SilentlyContinue'
$CheckPending = $true
$LogonDays = 14
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$bio = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
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
  hostname = $env:COMPUTERNAME; fqdn = "$($cs.DNSHostName).$($cs.Domain)"; source = 'agent'; agent_version = '0.1'
  os_caption = $os.Caption; os_build = "$($os.BuildNumber).$($cv.UBR)"; os_display_version = $cv.DisplayVersion
  last_boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
  manufacturer = $cs.Manufacturer; model = $cs.Model; serial = $bio.SerialNumber; cpu = $cpu.Name
  ram_gb = [math]::Round($cs.TotalPhysicalMemory/1GB,1); current_user = $cs.UserName
  nics = $nics; disks = $disks; software = $software; hotfixes = $hotfixes
  pending_updates = $pending; pending_reboot = $reboot; logons = $logons
} | ConvertTo-Json -Depth 5 -Compress | Set-Variable json

Invoke-RestMethod -Uri "$Server/api/ingest/endpoint" -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($json)) `
  -ContentType 'application/json; charset=utf-8' -Headers @{ 'X-Ingest-Token' = $Token } | Out-Null
