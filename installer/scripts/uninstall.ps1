<#
  Called by the uninstaller. Removes the services, scheduled tasks, firewall rule and environment
  variable. The uninstaller then deletes the whole install folder, and asks whether to delete the data.
  The data folder chosen during setup (C:\ProgramData\NetInventory by default: config, logs, keys)
  and the bundled database folder are kept unless the person uninstalling chooses to delete them,
  so a reinstall picks up where it left off.
#>
param([Parameter(Mandatory)][string]$InstallDir)
$ErrorActionPreference = 'Continue'

$svcExe = Join-Path $InstallDir 'service\NetInventory.exe'
if (Get-Service NetInventory -ErrorAction SilentlyContinue) {
    & $svcExe stop 2>&1 | Out-Null
    & $svcExe uninstall 2>&1 | Out-Null
}
if (Get-Service NetInventory-PostgreSQL -ErrorAction SilentlyContinue) {
    Stop-Service NetInventory-PostgreSQL -Force -ErrorAction SilentlyContinue
    & (Join-Path $InstallDir 'pgsql\bin\pg_ctl.exe') unregister -N NetInventory-PostgreSQL 2>&1 | Out-Null
}
Get-NetFirewallRule -DisplayName 'NetInventory dashboard' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
# Scheduled tasks NetInventory creates on the server (the self-update task, "NetInventory update").
Get-ScheduledTask -TaskName 'NetInventory*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
# Anything still running from the install folder would keep its files locked and stop the folder being deleted.
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -like "$InstallDir\*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
[Environment]::SetEnvironmentVariable('NETINV_CONFIG', $null, 'Machine')
Get-ChildItem (Join-Path $InstallDir 'python') -Recurse -Include __pycache__ -Directory -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
exit 0
