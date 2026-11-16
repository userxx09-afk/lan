<#
  Used by the setup wizard (extracted to a temp folder, never installed). Writes two lines to -Out:
    1. what is listening on -Port: the program's path, or its name and PID; empty when the port is free
    2. the next free port above -Port, skipping -Avoid (the other port the wizard is about to use)
#>
param([Parameter(Mandatory)][int]$Port, [int]$Avoid = 0, [Parameter(Mandatory)][string]$Out)

$owner = ''
$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
$hit = $listen | Where-Object { $_.LocalPort -eq $Port } | Select-Object -First 1
if ($hit) {
    $procId = $hit.OwningProcess
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
    if ($proc.ExecutablePath) { $owner = $proc.ExecutablePath }
    elseif ($procId -eq 4) { $owner = 'Windows (System process, usually IIS or another HTTP.sys web service)' }
    elseif ($proc.Name) { $owner = "$($proc.Name) (PID $procId)" }
    else { $owner = "process ID $procId" }
}

$used = @{}
foreach ($c in $listen) { $used[[int]$c.LocalPort] = $true }
$next = $Port + 1
while ($next -le 65535 -and ($used.ContainsKey($next) -or $next -eq $Avoid)) { $next++ }
if ($next -gt 65535) { $next = '' }

[IO.File]::WriteAllLines($Out, [string[]]@($owner, "$next"), [Text.UTF8Encoding]::new($true))
