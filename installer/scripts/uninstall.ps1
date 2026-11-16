<#
  Called by the uninstaller. Removes the services, firewall rule and environment variable.
  The data folder chosen during setup (C:\ProgramData\NetInventory by default: config, logs, keys)
  and the bundled database folder are kept, so a reinstall picks up where it left off. Delete them
  by hand to remove everything.
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
[Environment]::SetEnvironmentVariable('NETINV_CONFIG', $null, 'Machine')
Get-ChildItem (Join-Path $InstallDir 'python') -Recurse -Include __pycache__ -Directory -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
exit 0
