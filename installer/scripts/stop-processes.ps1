<#
  Stops every NetInventory server process on this computer before setup replaces the program files.

  Stopping the service isn't always enough: a python.exe the service wrapper lost track of (a stop that timed
  out, a service removed while it was running, a copy started by hand or from an older install folder) keeps
  running the old code. On Windows it also keeps the dashboard port, so the new version's process can't
  listen, exits and is restarted over and over, while the old one keeps answering and running the scan
  schedule. Setup runs this before copying files and again before it starts the new service.

  Prints one line per process it stopped. Exit code 0 when none are left, 1 when one survived.
#>
param([string]$InstallDir = '')
$ErrorActionPreference = 'Continue'

foreach ($svc in 'NetInventory') {
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Stopped') {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        try { $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { }
    }
}

$bundled = if ($InstallDir) { (Join-Path $InstallDir 'python\').ToLowerInvariant() } else { $null }
function Find-NetInv {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $exe = "$($_.ExecutablePath)".ToLowerInvariant()
        $cmd = "$($_.CommandLine)"
        ($bundled -and $exe.StartsWith($bundled)) -or
        ($_.Name -match '^pythonw?(\d|\.)*\.exe$' -and $cmd -match '(^|\s)-m\s+netinv\s+(serve|collect)\b')
    }
}

for ($try = 0; $try -lt 5; $try++) {
    $procs = @(Find-NetInv)
    if (-not $procs) { exit 0 }
    foreach ($p in $procs) {
        Write-Output "Stopping leftover NetInventory process $($p.ProcessId): $($p.CommandLine)"
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep 2
}
$left = @(Find-NetInv)
foreach ($p in $left) { Write-Output "Could not stop process $($p.ProcessId): $($p.CommandLine)" }
exit ([int]($left.Count -gt 0))
