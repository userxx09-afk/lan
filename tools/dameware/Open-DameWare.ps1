<#
  NetInventory -> DameWare Mini Remote Control launcher.
  Registered as the handler for dameware:// links, e.g.
      dameware://connect/?host=WS-031&mode=windows
  mode=windows : sign in with the technician's own Windows logon (default)
  mode=saved   : use the saved host entry (and its stored credentials) in DameWare's Remote Host list

  The link only carries a computer name and a mode. Nothing from the link is passed to DWRCC except
  a validated host name, so a web page can't inject switches or run anything else.

  Per-PC settings (HKLM\SOFTWARE\NetInventory, all optional, set by the installer or GPO):
    DameWarePath       full path to DWRCC.exe if it isn't found automatically
    DameWareExtraArgs  extra DWRCC switches added to every connection
    DameWareAllowedSuffixes  semicolon list of DNS suffixes allowed for full names, e.g. ".corp.example.com"
  Single-label names (WS-031) and private IPv4 addresses are always allowed.

  DWRCC switches used (check against your DameWare version: DWRCC.exe -? lists them):
    -c: connect at once   -m:<host> machine   -a:1 Windows NT challenge/response   -x use current logon
    -h: use the saved host entry for <host>
#>
param([Parameter(Position = 0)][string]$Url, [switch]$DryRun)
$ErrorActionPreference = 'Stop'

function Fail([string]$msg) {
    if ($DryRun) { Write-Output "FAIL: $msg"; exit 1 }
    Add-Type -AssemblyName System.Windows.Forms
    [void][System.Windows.Forms.MessageBox]::Show($msg, 'NetInventory - DameWare', 'OK', 'Warning')
    exit 1
}
function RegValue([string]$name) {
    foreach ($k in 'HKLM:\SOFTWARE\NetInventory', 'HKLM:\SOFTWARE\WOW6432Node\NetInventory') {
        $v = (Get-ItemProperty -Path $k -Name $name -ErrorAction SilentlyContinue).$name
        if ($v) { return [string]$v }
    }
    return $null
}

# ---- parse dameware://connect/?host=...&mode=...
if ($Url -notmatch '^dameware://connect/?\?(?<q>[^#]*)$') { Fail "Not a NetInventory DameWare link:`n$Url" }
$query = @{}
foreach ($pair in $Matches.q -split '&') {
    $kv = $pair -split '=', 2
    if ($kv.Count -eq 2) { $query[[uri]::UnescapeDataString($kv[0]).ToLower()] = [uri]::UnescapeDataString($kv[1]) }
}
$target = [string]$query['host']
$mode = if ($query['mode'] -eq 'saved') { 'saved' } else { 'windows' }

# ---- validate the host strictly
$isIp = [System.Net.IPAddress]::TryParse($target, [ref]$null) -and $target -match '^\d{1,3}(\.\d{1,3}){3}$'
if ($isIp) {
    $o = $target.Split('.') | ForEach-Object { [int]$_ }
    $private = $o[0] -eq 10 -or ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) -or ($o[0] -eq 192 -and $o[1] -eq 168)
    if (-not $private) { Fail "Refusing to connect to $target`: only private (internal) IP addresses are allowed." }
} elseif ($target -match '^[A-Za-z0-9][A-Za-z0-9-]{0,62}$') {
    # single-label computer name, resolved inside the domain
} elseif ($target -match '^[A-Za-z0-9][A-Za-z0-9-]{0,62}(\.[A-Za-z0-9][A-Za-z0-9-]{0,62})+$') {
    $suffixes = (RegValue 'DameWareAllowedSuffixes') -split ';' | Where-Object { $_ } | ForEach-Object { '.' + $_.Trim().TrimStart('.').ToLower() }
    if (-not ($suffixes | Where-Object { $target.ToLower().EndsWith($_) })) {
        Fail "Refusing to connect to $target`: full names must end in an allowed domain suffix (set DameWareAllowedSuffixes)."
    }
} else {
    Fail "Invalid computer name: $target"
}

# ---- find DWRCC.exe
$exe = RegValue 'DameWarePath'
if (-not ($exe -and (Test-Path -LiteralPath $exe))) {
    $exe = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\DWRCC.exe' -ErrorAction SilentlyContinue).'(default)'
}
if (-not ($exe -and (Test-Path -LiteralPath $exe))) {
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique
    $found = @(foreach ($r in $roots) {
        foreach ($d in 'SolarWinds', 'DameWare', 'DameWare Development') {
            $p = Join-Path $r $d
            if (Test-Path -LiteralPath $p) { Get-ChildItem -LiteralPath $p -Filter DWRCC.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName }
        }
    })
    $exe = $found | Select-Object -First 1
}
if (-not $exe) { Fail "DameWare Mini Remote Control (DWRCC.exe) was not found on this PC.`nInstall it, or set HKLM\SOFTWARE\NetInventory\DameWarePath to its full path." }

# ---- launch
$dwArgs = @('-c:', "-m:$target")
if ($mode -eq 'saved') { $dwArgs += '-h:' } else { $dwArgs += @('-a:1', '-x') }
$extra = RegValue 'DameWareExtraArgs'
if ($extra) { $dwArgs += ($extra -split '\s+' | Where-Object { $_ }) }
if ($DryRun) { "$exe $($dwArgs -join ' ')"; return }
Start-Process -FilePath $exe -ArgumentList $dwArgs
