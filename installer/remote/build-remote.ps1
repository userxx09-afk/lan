# Builds the remote control agent: rcagent\ (Go) -> NetInventoryRemote.exe, signed, then
# installer\output\NetInventory-Remote-<version>.msi with WiX v4. Run from the repo root (needs Go and the .NET SDK).
param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Resolve-Path (Join-Path $Here '..\..')
$out = Join-Path $Root 'installer\output'
$bin = Join-Path $Root 'installer\build\remote'
New-Item -ItemType Directory -Force $out, $bin | Out-Null

# Reproducible, no cgo, no debug info; -mod=readonly so go.sum must match (no dependency changes in CI).
$env:CGO_ENABLED = '0'; $env:GOOS = 'windows'; $env:GOARCH = 'amd64'
Push-Location (Join-Path $Root 'rcagent')
try {
    go vet ./...
    if ($LASTEXITCODE) { throw 'go vet failed' }
    go build -mod=readonly -trimpath -ldflags "-s -w -H windowsgui -X main.version=$Version" -o (Join-Path $bin 'NetInventoryRemote.exe') .
    if ($LASTEXITCODE) { throw 'go build failed' }
} finally { Pop-Location }
& (Join-Path $Root 'installer\sign.ps1') (Join-Path $bin 'NetInventoryRemote.exe')

$wixVer = '4.0.5'
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version $wixVer | Out-Host
    $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}
wix extension add -g "WixToolset.Util.wixext/$wixVer" | Out-Host
if ($LASTEXITCODE) { throw 'wix extension add failed' }
$msi = Join-Path $out "NetInventory-Remote-$Version.msi"
wix build -arch x64 -ext WixToolset.Util.wixext -d "Version=$Version" -d "Src=$bin" -o $msi (Join-Path $Here 'NetInventoryRemote.wxs') | Out-Host
if ($LASTEXITCODE) { throw 'wix build failed' }
& (Join-Path $Root 'installer\sign.ps1') $msi
Copy-Item $msi (Join-Path $out 'NetInventory-Remote.msi') -Force
Write-Host "Built $msi"
