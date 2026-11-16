<#
  Sets up the NetInventory Agent on this PC (the MSI runs this as SYSTEM; it can also be run by hand as an admin).
  - writes %ProgramData%\NetInventory Agent\config.json (Server, EnrollToken, Pin) unless they come from GPO
    (HKLM\SOFTWARE\Policies\NetInventory\Agent), and locks that folder down to SYSTEM, Administrators and the
    task's account;
  - registers one scheduled task, "NetInventory Agent", every 5 minutes and at startup, as LOCAL SERVICE
    (-RunAs SYSTEM collects more: pending Windows updates, per-user apps, local logons, disk failure prediction).
  Nothing listens on the network. Remove with Uninstall-Agent.ps1 (or uninstall the MSI).
#>
param([string]$Server = '', [string]$Token = '', [string]$Pin = '', [ValidateSet('LOCALSERVICE', 'SYSTEM', '')][string]$RunAs = 'LOCALSERVICE')
$ErrorActionPreference = 'Stop'
if (-not $RunAs) { $RunAs = 'LOCALSERVICE' }
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Data = Join-Path $env:ProgramData 'NetInventory Agent'
New-Item -ItemType Directory -Force $Data | Out-Null

# Folder ACL: no inheritance; SYSTEM and Administrators full, the task account modify. Users can't read the secret.
$acct = if ($RunAs -eq 'SYSTEM') { '*S-1-5-18' } else { '*S-1-5-19' }      # LOCAL SERVICE = S-1-5-19
& icacls.exe $Data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${acct}:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE) { throw "icacls failed on $Data" }

$cfgFile = Join-Path $Data 'config.json'
$cfg = @{ Server = ''; EnrollToken = ''; Pin = '' }
if (Test-Path $cfgFile) { $old = Get-Content $cfgFile -Raw | ConvertFrom-Json; foreach ($k in 'Server', 'EnrollToken', 'Pin') { if ($old.$k) { $cfg[$k] = [string]$old.$k } } }
if ($Server) { $cfg.Server = $Server.Trim().TrimEnd('/') }
if ($Token) { $cfg.EnrollToken = $Token.Trim() }
if ($Pin) { $cfg.Pin = $Pin.Trim() }
[IO.File]::WriteAllText($cfgFile, ($cfg | ConvertTo-Json -Compress))

$script = Join-Path $Here 'NetInventoryAgent.ps1'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`""
$every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
$boot = New-ScheduledTaskTrigger -AtStartup
$boot.Delay = 'PT2M'
$principal = if ($RunAs -eq 'SYSTEM') { New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest }
             else { New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited }
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 7
Register-ScheduledTask -TaskName 'NetInventory Agent' -TaskPath '\' -Action $action -Trigger @($every, $boot) -Principal $principal `
    -Settings $settings -Description 'Sends a signed heartbeat and, when due, the inventory of this PC to NetInventory over HTTPS. Outbound only.' -Force | Out-Null
Start-ScheduledTask -TaskName 'NetInventory Agent' -ErrorAction SilentlyContinue
Write-Output "NetInventory Agent installed (runs as $RunAs, every 5 minutes)."
