<#
  Runs at the end of setup (as admin). Checks and installs dependencies, sets up the
  database and registers the Windows services. Safe to re-run: it is also used for upgrades
  and repairs (scripts\postinstall.ps1 -ParamFile <file>).
#>
param([Parameter(Mandatory)][string]$ParamFile)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- params
$P = @{}
[IO.File]::ReadAllLines($ParamFile, [Text.UTF8Encoding]::new($false)) | ForEach-Object {
    $i = $_.IndexOf('=')
    if ($i -gt 0) { $P[$_.Substring(0, $i)] = $_.Substring($i + 1) }
}
Remove-Item -LiteralPath $ParamFile -Force -ErrorAction SilentlyContinue

$InstallDir = $P.InstallDir; $DataDir = $P.DataDir; $Port = [int]$P.Port
$Python   = Join-Path $InstallDir 'python\python.exe'
$PgBin    = Join-Path $InstallDir 'pgsql\bin'
# Both folders are chosen in the wizard (0.6+); older installers didn't pass PgData.
$PgData   = if ($P.PgData) { $P.PgData } else { Join-Path $DataDir 'pgdata' }
# Chosen in the wizard; 5442 by default (not 5432, so it never clashes with another PostgreSQL on this box).
# Older installers didn't pass it and always used 5442.
$PgPort   = if ($P.PgPort) { [int]$P.PgPort } else { 5442 }
$PgSvc    = 'NetInventory-PostgreSQL'
$Config   = Join-Path $DataDir 'config.toml'
$Secrets  = Join-Path $DataDir '.pg-password'
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'logs') | Out-Null
$Log = Join-Path $DataDir 'logs\install.log'

function Log($msg) { $line = "$(Get-Date -Format s)  $msg"; Add-Content -LiteralPath $Log -Value $line; Write-Host $line }
function Fail($msg) { Log "ERROR: $msg"; exit 1 }
# Runs a program and returns everything it printed, stderr included, as plain text.
# With $ErrorActionPreference = 'Stop', PowerShell 5.1 turns the first line a program writes to stderr into a
# terminating error, so a Python traceback would abort setup with only "Traceback (most recent call last):".
function Native($exe, [string[]]$argv) {
    $ErrorActionPreference = 'Continue'      # local to this function
    $lines = & $exe @argv 2>&1 | ForEach-Object { "$_" }
    return (($lines -join "`r`n").Trim())
}
function Run($exe, [string[]]$argv) {
    $out = Native $exe $argv
    if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($exe)) $($argv -join ' ') failed ($LASTEXITCODE): $out" }
    return $out
}
function NewSecret([int]$n = 24) {
    $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $bytes = New-Object byte[] $n
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}
function TomlStr([string]$s) { '"' + ($s -replace '\\', '\\' -replace '"', '\"') + '"' }
# config.toml is UTF-8 without a BOM: Python's TOML reader rejects a BOM, and PowerShell 5.1 would read and
# write the Windows code page otherwise. Reading accepts a BOM left by an older version.
function ReadUtf8([string]$path) { [IO.File]::ReadAllText($path, [Text.UTF8Encoding]::new($false)) }
function WriteUtf8([string]$path, [string]$text) { [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false)) }

function HashPw([string]$pw) {
    # Passed in the environment, not a pipe: PowerShell 5.1 pipes mangle accented characters
    $env:NETINV_HASHPW = $pw
    try { $h = Native $Python @('-m', 'netinv', 'hashpw') } finally { Remove-Item Env:NETINV_HASHPW -ErrorAction SilentlyContinue }
    if ($h -notlike 'pbkdf2_sha256$*') { throw "Hashing the dashboard password failed: $h" }
    return $h
}

try {
$Upgrade = $P.Upgrade -eq '1'
Log "=== NetInventory setup: mode=$($P.DbMode) port=$Port dir=$InstallDir data=$DataDir upgrade=$Upgrade"

# ---------------------------------------------------------------- 1. dependency checks
Log 'Checking prerequisites'
$os = [Environment]::OSVersion.Version
if ($os.Major -lt 10) { Fail "Windows 10 / Server 2019 or later is required (found $os)." }
if (-not [Environment]::Is64BitOperatingSystem) { Fail '64-bit Windows is required.' }
if ($PSVersionTable.PSVersion.Major -lt 5) { Fail 'PowerShell 5.1 or later is required.' }
if (-not (Test-Path $Python)) { Fail "Bundled Python not found at $Python" }

$vc = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue
if ($vc.Installed -ne 1) { Log 'WARNING: Visual C++ runtime not detected; PostgreSQL may fail to start.' }
else { Log "Visual C++ runtime $($vc.Version) present" }

# Python packages: verify imports; reinstall from the bundled offline wheels if anything is missing.
# No double quotes in Python code passed with -c: PowerShell 5.1 strips them on the way to the program,
# so print("ok") arrived as print(ok) and failed with a NameError even when every package was fine.
$check = "import fastapi, uvicorn, sqlalchemy, psycopg, pydantic, ldap3, pysnmp, pypsrp, openpyxl, cryptography; print('ok')"
$ok = Native $Python @('-c', $check)
if ($ok -ne 'ok') {
    Log "Python packages incomplete ($ok). Installing from bundled wheels..."
    $wheels = Join-Path $InstallDir 'python\wheels'
    Run $Python @('-m', 'pip', 'install', '--no-index', '--find-links', $wheels, '-r', (Join-Path $wheels 'requirements-win.txt')) | Out-Null
    $ok = Native $Python @('-c', $check)
    if ($ok -ne 'ok') { Fail "Python packages still failing to import: $ok" }
}
Log 'Python and packages OK'

# Backstop for the wizard's own check: never take over a port another program is listening on.
# NetInventory's own processes (from this install folder) are fine; they are restarted below.
function PortOwner([int]$port) {
    $l = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $l) { return $null }
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$($l.OwningProcess)"
    if ($proc.ExecutablePath -like "$InstallDir\*") { return $null }
    if ($proc.ExecutablePath) { return $proc.ExecutablePath }
    if ($l.OwningProcess -eq 4) { return 'Windows (System process, usually IIS or another HTTP.sys web service)' }
    return "$($proc.Name) (PID $($l.OwningProcess))"
}
$owner = PortOwner $Port
if ($owner) { Fail "Port $Port is already used by $owner. Re-run setup and choose another web port." }

# ---------------------------------------------------------------- 2. data folder ACL (config holds passwords)
Log 'Securing data folder'
& icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null   # SYSTEM, Administrators

# ---------------------------------------------------------------- 3. database
if ($P.DbMode -eq 'bundled') {
    if (-not (Test-Path (Join-Path $PgBin 'pg_ctl.exe'))) { Fail 'Bundled PostgreSQL binaries are missing.' }
    New-Item -ItemType Directory -Force -Path $PgData | Out-Null
    # The database folder may be outside the data folder (another drive), so lock it down the same way.
    # NETWORK SERVICE runs PostgreSQL.
    & icacls $PgData /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-20:(OI)(CI)F' | Out-Null

    if (Test-Path $Secrets) { $pgPass = (Get-Content -LiteralPath $Secrets -Raw).Trim() }
    if (-not (Test-Path (Join-Path $PgData 'PG_VERSION'))) {
        Log 'Initialising PostgreSQL cluster'
        $pgPass = NewSecret
        Set-Content -LiteralPath $Secrets -Value $pgPass -NoNewline
        $pw = Join-Path $env:TEMP "netinv-pw-$(NewSecret 8).txt"
        Set-Content -LiteralPath $pw -Value $pgPass -NoNewline
        # initdb refuses to run with admin rights: it restarts itself with the Administrators group
        # disabled, keeping only this user's own account. The database folder is locked down to SYSTEM,
        # Administrators and NETWORK SERVICE, so that restricted initdb couldn't even see it and failed with
        # 'could not create directory ...: File exists'. Let this account into the folder while initdb runs.
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls $PgData /grant "*${me}:(OI)(CI)F" | Out-Null
        try { Run (Join-Path $PgBin 'initdb.exe') @('-D', $PgData, '-U', 'netinv', "--pwfile=$pw", '-A', 'scram-sha-256', '-E', 'UTF8', '--locale=C') | Out-Null }
        finally {
            Remove-Item $pw -Force -ErrorAction SilentlyContinue
            & icacls $PgData /remove:g "*$me" /T /C /Q | Out-Null     # NETWORK SERVICE runs the database from here on
        }
        Add-Content -LiteralPath (Join-Path $PgData 'postgresql.conf') -Value "`nlisten_addresses = 'localhost'`nport = $PgPort`n"
    } else {
        # Existing cluster. Upgrades pass the port it already uses; a fresh install over a leftover
        # cluster may have picked another one, so set it (the last "port =" line wins).
        $conf = Join-Path $PgData 'postgresql.conf'
        $confPort = 5432
        foreach ($line in [IO.File]::ReadAllLines($conf)) { if ($line -match '^\s*port\s*=\s*(\d+)') { $confPort = [int]$Matches[1] } }
        if ($confPort -ne $PgPort) {
            Log "Moving the bundled PostgreSQL from port $confPort to $PgPort"
            Add-Content -LiteralPath $conf -Value "`nport = $PgPort`n"
            if ((Get-Service $PgSvc -ErrorAction SilentlyContinue).Status -eq 'Running') { Restart-Service $PgSvc -Force }
        }
    }
    if ((Get-Service $PgSvc -ErrorAction SilentlyContinue).Status -ne 'Running') {
        $owner = PortOwner $PgPort
        if ($owner) { Fail "Port $PgPort is already used by $owner. Re-run setup and choose another database port." }
    }
    if (-not (Get-Service $PgSvc -ErrorAction SilentlyContinue)) {
        Log "Registering service $PgSvc"
        Run (Join-Path $PgBin 'pg_ctl.exe') @('register', '-N', $PgSvc, '-U', 'NT AUTHORITY\NetworkService', '-D', $PgData, '-S', 'auto', '-w') | Out-Null
    }
    if ((Get-Service $PgSvc).Status -ne 'Running') { Start-Service $PgSvc }
    $env:PGPASSWORD = $pgPass
    for ($i = 0; $i -lt 30; $i++) {
        & (Join-Path $PgBin 'pg_isready.exe') -h localhost -p $PgPort -q
        if ($LASTEXITCODE -eq 0) { break }; Start-Sleep 1
    }
    $exists = Native (Join-Path $PgBin 'psql.exe') @('-h', 'localhost', '-p', "$PgPort", '-U', 'netinv', '-d', 'postgres', '-tAc', "SELECT 1 FROM pg_database WHERE datname='netinv'")
    if ($exists -ne '1') {
        Log 'Creating database netinv'
        Run (Join-Path $PgBin 'createdb.exe') @('-h', 'localhost', '-p', "$PgPort", '-U', 'netinv', 'netinv') | Out-Null
    }
    Remove-Item Env:PGPASSWORD
    $DbUrl = "postgresql+psycopg://netinv:$pgPass@localhost:$PgPort/netinv"
    Log "PostgreSQL ready on localhost:$PgPort"
} elseif ($Upgrade -and -not $P.DbUrl) {
    Log 'Upgrade: keeping the database settings in config.toml'
} else {
    $DbUrl = $P.DbUrl
    Log 'Testing connection to the existing PostgreSQL server'
    $env:NETINV_TEST_URL = $DbUrl
    $t = Native $Python @('-c', "import os,sqlalchemy as s; e=s.create_engine(os.environ['NETINV_TEST_URL']); e.connect().close(); print('ok')")
    Remove-Item Env:NETINV_TEST_URL
    if ($t -notmatch 'ok$') { Log "WARNING: could not connect to the database yet: $t" } else { Log 'Database connection OK' }
}

# ---------------------------------------------------------------- 4. config.toml
if (-not (Test-Path $Config)) {
    Log 'Writing config.toml'
    $c = ReadUtf8 (Join-Path $InstallDir 'config.example.toml')
    $c = $c -replace '(?m)^url = .*$', ('url = ' + (TomlStr $DbUrl))
    $c = $c -replace '(?m)^ui_password = .*$', ('ui_password = ' + (TomlStr (HashPw $P.UiPassword)))
    $c = $c -replace '(?m)^ingest_token = .*$', ('ingest_token = ' + (TomlStr (NewSecret 32)))
    # Collectors stay disabled until the admin fills in real servers and credentials.
    $c = $c -replace '(?m)^server = "dc01\.corp\.example\.com".*$', 'server = ""                       # e.g. "dc01.corp.example.com"'
    $c = $c -replace '(?m)^targets = \[.*$', 'targets = []                      # e.g. ["10.0.0.1", "10.0.0.0/27"]'
    $c = $c -replace '(?m)^user = "CORP\\\\svc-netinv"', 'user = ""          '
    $c = $c -replace '"env:([A-Z_]+)"', '""'
    $c = "# Edit, then restart the NetInventory service. Passwords can be written directly here;`r`n# this folder is readable by Administrators and SYSTEM only.`r`n`r`n" + $c
    WriteUtf8 $Config $c
} else {
    Log 'Keeping existing config.toml'
    $c = ReadUtf8 $Config
    if ($P.UiPassword) {
        $c = $c -replace '(?m)^ui_password = .*$', ('ui_password = ' + (TomlStr (HashPw $P.UiPassword)))
        if ($P.DbMode -eq 'existing') { $c = $c -replace '(?m)^url = .*$', ('url = ' + (TomlStr $DbUrl)) }
    }
    # On a new install over a reused data folder the bundled database may be in a different folder or on a
    # different port, so point config.toml at it. Upgrades keep the url in config.toml as it is.
    if ($P.DbMode -eq 'bundled' -and $DbUrl -and -not $Upgrade) { $c = $c -replace '(?m)^url = .*$', ('url = ' + (TomlStr $DbUrl)) }
    WriteUtf8 $Config $c
}
# Security settings, for new installs and upgrades alike:
#  - a dashboard password left in plain text by an older version is replaced with its hash
#  - HTTPS with a self-signed certificate unless one is configured already
$c = ReadUtf8 $Config
if ($c -match '(?m)^ui_password = "(?!pbkdf2_sha256\$)(?!env:)([^"]+)"') {
    $plainPw = $Matches[1] -replace '\\"', '"' -replace '\\\\', '\'
    $c = $c -replace '(?m)^ui_password = .*$', ('ui_password = ' + (TomlStr (HashPw $plainPw)))
    Log 'Dashboard password in config.toml replaced with its hash'
}
if ($c -notmatch '(?m)^tls_cert\s*=') {
    $env:NETINV_CONFIG = $Config
    Push-Location (Join-Path $InstallDir 'app')
    try { Log (Run $Python @('-m', 'netinv', 'cert', '--out', $DataDir)).Trim() } finally { Pop-Location }
    $crt = (Join-Path $DataDir 'tls.crt') -replace '\\', '/'; $key = (Join-Path $DataDir 'tls.key') -replace '\\', '/'
    $c = $c -replace '(?m)^\[server\]\s*$', "[server]`r`ntls_cert = $(TomlStr $crt)`r`ntls_key = $(TomlStr $key)"
    Log 'HTTPS turned on with a self-signed certificate'
}
WriteUtf8 $Config $c

[Environment]::SetEnvironmentVariable('NETINV_CONFIG', $Config, 'Machine')
$env:NETINV_CONFIG = $Config

# Create tables and views now so problems surface during setup, not on first start.
Push-Location (Join-Path $InstallDir 'app')
try { Run $Python @('-m', 'netinv', 'views') | Out-Null; Log 'Database schema and views created' } finally { Pop-Location }

# ---------------------------------------------------------------- 5. app service (WinSW)
$svcExe = Join-Path $InstallDir 'service\NetInventory.exe'
$depend = if ($P.DbMode -eq 'bundled') { "<depend>$PgSvc</depend>" } else { '' }
@"
<service>
  <id>NetInventory</id>
  <name>NetInventory</name>
  <description>Network and domain inventory: dashboard, reports and scheduled collectors.</description>
  <executable>$InstallDir\python\python.exe</executable>
  <arguments>-m netinv serve --host 0.0.0.0 --port $Port</arguments>
  <workingdirectory>$InstallDir\app</workingdirectory>
  <env name="NETINV_CONFIG" value="$Config"/>
  <env name="PYTHONUNBUFFERED" value="1"/>
  $depend
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="60 sec"/>
  <resetfailure>1 hour</resetfailure>
  <logpath>$DataDir\logs</logpath>
  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>5</keepFiles></log>
</service>
"@ | Set-Content -LiteralPath ([IO.Path]::ChangeExtension($svcExe, '.xml')) -Encoding UTF8

if (Get-Service NetInventory -ErrorAction SilentlyContinue) {
    Log 'Updating NetInventory service'
    Native $svcExe @('stop') | Out-Null
    Run $svcExe @('uninstall') | Out-Null
    Start-Sleep 2
}
Run $svcExe @('install') | Out-Null
Run $svcExe @('start') | Out-Null
Log 'NetInventory service installed and started'

# ---------------------------------------------------------------- 6. firewall
Get-NetFirewallRule -DisplayName 'NetInventory dashboard' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'NetInventory dashboard' -Direction Inbound -Protocol TCP -LocalPort $Port `
    -Action Allow -Profile Domain,Private | Out-Null
Log "Firewall opened for TCP $Port (Domain and Private profiles)"

# ---------------------------------------------------------------- 7. health check
$up = $false
$scheme = if ((ReadUtf8 $Config) -match '(?m)^tls_cert\s*=\s*"[^"]+"') { 'https' } else { 'http' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }   # localhost check of our own self-signed cert
for ($i = 0; $i -lt 40; $i++) {
    try { Invoke-WebRequest "${scheme}://localhost:$Port/login" -UseBasicParsing -TimeoutSec 3 | Out-Null; $up = $true; break }
    catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { $up = $true; break } }
    Start-Sleep 1
}
if (-not $up) { Fail "The service started but ${scheme}://localhost:$Port/ is not answering. See $DataDir\logs\NetInventory.err.log" }
# Downloaded update installers are no longer needed (the one running now can't be deleted; it goes next time).
Get-ChildItem -LiteralPath (Join-Path $DataDir 'updates') -Filter *.exe -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
Log "Done. Dashboard: ${scheme}://localhost:$Port/ (user admin)"
exit 0
}
catch { Fail $_.Exception.Message }
