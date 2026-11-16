<# Removes the NetInventory Agent's scheduled task and its data (enrollment secret, config, log). The MSI runs this on uninstall. #>
$ErrorActionPreference = 'SilentlyContinue'
Unregister-ScheduledTask -TaskName 'NetInventory Agent' -Confirm:$false
Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'NetInventory Agent')
Write-Output 'NetInventory Agent removed. Revoke it in NetInventory (Settings > Agent) if the PC is being retired.'
