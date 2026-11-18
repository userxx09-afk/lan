<#
  Builds installer\output\NetInventory-Setup-<version>.exe on a Windows build machine.
  Needs internet access; no admin rights and no pre-installed Python required.

    powershell -ExecutionPolicy Bypass -File installer\build.ps1

  It downloads (into installer\build\, cached between runs):
    - Python embeddable package + the app's packages as offline wheels
    - PostgreSQL Windows binaries (EDB zip)
    - WinSW (runs the app as a Windows service)
    - Microsoft Visual C++ runtime installer
    - Inno Setup (portable, per-user) to compile the installer
#>
param(
    [string]$Version       = '',          # default: <VERSION file>.0, e.g. 0.3.0 (CI passes 0.3.<run number>)
    [string]$Notes         = '',          # release notes written into latest.json
    [string]$PythonVersion = '3.12.10',
    [string]$PgVersion     = '17.6-1',
    [string]$WinSWVersion  = '2.12.0',
    [string]$InnoVersion   = '6.5.4'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Build = Join-Path $Here 'build'
$Cache = Join-Path $Build 'downloads'
New-Item -ItemType Directory -Force -Path $Cache | Out-Null
if (-not $Version) { $Version = (Get-Content (Join-Path $Here '..\VERSION') -Raw).Trim() + '.0' }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version must look like 1.2.3 (got '$Version')" }
# The app reports this version and compares it with latest.json to offer updates.
Set-Content -LiteralPath (Join-Path $Here '..\netinv\_version.py') -Value "__version__ = `"$Version`"" -Encoding ASCII

function Get-File($url, $name) {
    $dest = Join-Path $Cache $name
    if (-not (Test-Path $dest)) {
        Write-Host "Downloading $url"
        try { Invoke-WebRequest -Uri $url -OutFile "$dest.part" -UseBasicParsing }
        catch { throw "Download failed: $url`n$($_.Exception.Message)`nCheck the version parameter at the top of build.ps1." }
        Move-Item "$dest.part" $dest
    }
    return $dest
}
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }

# ------------------------------------------------------------------ Python (embeddable) + packages
Step "Python $PythonVersion"
$py = Join-Path $Build 'python'
if (Test-Path $py) { Remove-Item $py -Recurse -Force }
Expand-Archive (Get-File "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip" "python-$PythonVersion.zip") $py
$pth = Get-ChildItem $py -Filter 'python*._pth' | Select-Object -First 1
$zipName = (Get-ChildItem $py -Filter 'python*.zip' | Select-Object -First 1).Name
# Enable site-packages and put the app folder on sys.path.
Set-Content -LiteralPath $pth.FullName -Encoding ASCII -Value @($zipName, '.', 'Lib\site-packages', '..\app', 'import site')

$getpip = Get-File 'https://bootstrap.pypa.io/get-pip.py' 'get-pip.py'
& "$py\python.exe" $getpip --no-warn-script-location --disable-pip-version-check | Out-Host
if ($LASTEXITCODE) { throw 'get-pip failed' }

$req = Join-Path $Here 'requirements-win.txt'
$wheels = Join-Path $py 'wheels'
Step 'Downloading wheels (bundled so setup can repair packages offline)'
& "$py\python.exe" -m pip download --only-binary=:all: --dest $wheels -r $req --disable-pip-version-check | Out-Host
if ($LASTEXITCODE) { throw 'pip download failed' }
Copy-Item $req (Join-Path $wheels 'requirements-win.txt')
Step 'Installing packages into the bundled Python'
& "$py\python.exe" -m pip install --no-index --find-links $wheels -r $req --no-warn-script-location --disable-pip-version-check | Out-Host
if ($LASTEXITCODE) { throw 'pip install failed' }

# Smoke test: the app must import and create its tables/views in SQLite with the bundled Python.
Step 'Smoke test'
$tmpdb = Join-Path $env:TEMP "netinv-build-$PID.db"
$env:DATABASE_URL = "sqlite:///$($tmpdb -replace '\\','/')"
$env:PYTHONPATH = ''
Push-Location (Join-Path $Here '..')
New-Item -ItemType Directory -Force -Path (Join-Path $Build 'app') | Out-Null
Copy-Item -Recurse -Force netinv (Join-Path $Build 'app')
Pop-Location
Push-Location (Join-Path $Build 'app')
& "$py\python.exe" -m netinv demo | Out-Host
$rc = $LASTEXITCODE
Pop-Location
Remove-Item $tmpdb -ErrorAction SilentlyContinue; Remove-Item Env:DATABASE_URL
Remove-Item (Join-Path $Build 'app') -Recurse -Force
if ($rc) { throw 'Smoke test failed: the app did not run with the bundled Python.' }
Get-ChildItem $py -Recurse -Include __pycache__ -Directory | Remove-Item -Recurse -Force

# ------------------------------------------------------------------ PostgreSQL binaries
Step "PostgreSQL $PgVersion"
$pg = Join-Path $Build 'pgsql'
if (-not (Test-Path "$pg\bin\pg_ctl.exe")) {
    $zip = Get-File "https://get.enterprisedb.com/postgresql/postgresql-$PgVersion-windows-x64-binaries.zip" "pgsql-$PgVersion.zip"
    $tmp = Join-Path $Build 'pg-extract'
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
    Expand-Archive $zip $tmp
    if (Test-Path $pg) { Remove-Item $pg -Recurse -Force }
    Move-Item (Join-Path $tmp 'pgsql') $pg
    Remove-Item $tmp -Recurse -Force
    # Drop the parts a server install doesn't need (pgAdmin, docs, StackBuilder, headers): ~70% smaller.
    'pgAdmin 4', 'doc', 'StackBuilder', 'include', 'symbols' | ForEach-Object {
        $d = Join-Path $pg $_; if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    }
}

# ------------------------------------------------------------------ WinSW + VC++ runtime
Step 'WinSW and Visual C++ runtime'
New-Item -ItemType Directory -Force -Path "$Build\winsw", "$Build\redist" | Out-Null
Copy-Item (Get-File "https://github.com/winsw/winsw/releases/download/v$WinSWVersion/WinSW-x64.exe" "WinSW-$WinSWVersion-x64.exe") "$Build\winsw\WinSW-x64.exe" -Force
Copy-Item (Get-File 'https://aka.ms/vs/17/release/vc_redist.x64.exe' 'vc_redist.x64.exe') "$Build\redist\vc_redist.x64.exe" -Force

# ------------------------------------------------------------------ Inno Setup (per-user, no admin)
Step 'Inno Setup'
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
          "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc -and (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host 'Installing Inno Setup with winget (per-user)'
    & winget install --id JRSoftware.InnoSetup -e --scope user --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Host
    $iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
              "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $iscc) {
    # Fallback: direct download. jrsoftware.org/download.php returns an HTML page to scripts, so use files.jrsoftware.org.
    $is = Get-File "https://files.jrsoftware.org/is/6/innosetup-$InnoVersion.exe" "innosetup-$InnoVersion.exe"
    $head = [IO.File]::ReadAllBytes($is)[0..1]
    if ($head[0] -ne 0x4D -or $head[1] -ne 0x5A) { Remove-Item $is; throw "Inno Setup download is not an .exe; install Inno Setup 6 manually and re-run." }
    Start-Process $is -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', '/SP-' -Wait
    $iscc = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    if (-not (Test-Path $iscc)) { throw 'Inno Setup install failed.' }
}

# ------------------------------------------------------------------ compile
Step 'Compiling installer'
& $iscc "/DAppVersion=$Version" (Join-Path $Here 'netinventory.iss') | Out-Host
if ($LASTEXITCODE) { throw 'ISCC failed' }
$out = Get-ChildItem (Join-Path $Here 'output') -Filter "NetInventory-Setup-$Version.exe" | Select-Object -First 1
# Signed before hashing: latest.json's sha256 must match the file servers download.
& (Join-Path $Here 'sign.ps1') $out.FullName
$out = Get-Item $out.FullName
# latest.json: what installed servers read to find and verify an update (published next to the exe).
$sha = (Get-FileHash -LiteralPath $out.FullName -Algorithm SHA256).Hash.ToLower()
[ordered]@{
    version   = $Version
    file      = $out.Name
    url       = "https://github.com/userxx09-afk/prod/releases/download/lan-latest/$($out.Name)"
    sha256    = $sha
    notes     = $Notes
    published = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
} | ConvertTo-Json | ForEach-Object {   # UTF-8 without BOM: Python's json module rejects a BOM
    [IO.File]::WriteAllText((Join-Path $Here 'output\latest.json'), $_, (New-Object Text.UTF8Encoding $false)) }
Write-Host "`nBuilt: $($out.FullName) ($([math]::Round($out.Length/1MB)) MB)  SHA-256 $sha" -ForegroundColor Green
