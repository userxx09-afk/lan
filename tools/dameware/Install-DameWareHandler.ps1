<#
  Registers the dameware:// link handler on this PC (run as administrator), so the
  "Remote control" buttons in NetInventory open DameWare Mini Remote Control.

    .\Install-DameWareHandler.ps1                       # install
    .\Install-DameWareHandler.ps1 -DWRCCPath "D:\Apps\DWRCC.exe" -AllowedSuffixes ".corp.example.com"
    .\Install-DameWareHandler.ps1 -Uninstall

  For many PCs, deploy by GPO instead: copy Open-DameWare.ps1 to C:\ProgramData\NetInventory\
  (Computer Configuration > Preferences > Windows Settings > Files) and import dameware-handler.reg
  (Preferences > Windows Settings > Registry, or a startup script running reg import).
#>
param([string]$DWRCCPath, [string]$AllowedSuffixes, [string]$ExtraArgs, [switch]$Uninstall)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) {
    throw 'Run this from an elevated PowerShell (Run as administrator).'
}
$dir = Join-Path $env:ProgramData 'NetInventory'
$script = Join-Path $dir 'Open-DameWare.ps1'
$cls = 'HKLM:\SOFTWARE\Classes\dameware'
if ($Uninstall) {
    Remove-Item -LiteralPath $cls -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue
    'dameware:// handler removed.'
    return
}
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Open-DameWare.ps1') -Destination $script -Force
New-Item -Path "$cls\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path $cls -Name '(default)' -Value 'URL:DameWare Remote Control (NetInventory)'
Set-ItemProperty -Path $cls -Name 'URL Protocol' -Value ''
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
Set-ItemProperty -Path "$cls\shell\open\command" -Name '(default)' `
    -Value "`"$ps`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`" `"%1`""
$cfg = 'HKLM:\SOFTWARE\NetInventory'
New-Item -Path $cfg -Force | Out-Null
if ($DWRCCPath) { Set-ItemProperty -Path $cfg -Name DameWarePath -Value $DWRCCPath }
if ($AllowedSuffixes) { Set-ItemProperty -Path $cfg -Name DameWareAllowedSuffixes -Value $AllowedSuffixes }
if ($ExtraArgs) { Set-ItemProperty -Path $cfg -Name DameWareExtraArgs -Value $ExtraArgs }
"dameware:// handler installed. Launcher: $script"
