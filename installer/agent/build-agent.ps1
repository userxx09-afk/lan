# Builds installer\output\NetInventory-Agent-<version>.msi with WiX v4 (installed as a .NET tool). Run from the repo root.
param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Resolve-Path (Join-Path $Here '..\..')
$out = Join-Path $Root 'installer\output'
New-Item -ItemType Directory -Force $out | Out-Null
$wixVer = '4.0.5'
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version $wixVer | Out-Host
    $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}
wix extension add -g "WixToolset.Util.wixext/$wixVer" | Out-Host
if ($LASTEXITCODE) { throw 'wix extension add failed' }
# MSI versions are major.minor.build with major/minor up to 255
$msi = Join-Path $out "NetInventory-Agent-$Version.msi"
wix build -arch x64 -ext WixToolset.Util.wixext -d "Version=$Version" -d "Src=$Root\netinv\agent" `
    -o $msi (Join-Path $Here 'NetInventoryAgent.wxs') | Out-Host
if ($LASTEXITCODE) { throw 'wix build failed' }
Copy-Item $msi (Join-Path $out 'NetInventory-Agent.msi') -Force
Write-Host "Built $msi"
