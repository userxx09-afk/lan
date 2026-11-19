<#
  NetInventory Agent (optional). Runs every 5 minutes from one scheduled task, as LOCAL SERVICE by default.

  Each run sends a tiny signed heartbeat (boot time, signed-in user, IPv4 addresses) to the NetInventory server.
  When the server answers that an inventory is due (once a day by default, or when someone clicks Rescan), the same run
  collects the inventory (the same data the server pulls over WinRM) and sends it.

  Security:
  - Outbound HTTPS only. Nothing listens on the PC.
  - The server's certificate is pinned (SHA-256 of the certificate) when a pin is configured; otherwise it must be
    trusted by Windows. No proxy, no redirects.
  - Enrollment: the first run trades the site enrollment token for this PC's own secret, kept in
    %ProgramData%\NetInventory Agent (readable only by SYSTEM, Administrators and the task's account) and
    encrypted with DPAPI. Every later request is signed (HMAC-SHA256 over time, nonce, path and body).
  - The server can't make the agent run anything: it only answers "inventory due" or not.

  Config: HKLM\SOFTWARE\Policies\NetInventory\Agent (GPO) overrides %ProgramData%\NetInventory Agent\config.json
  (written by the MSI): Server, EnrollToken, Pin (one or more SHA-256 thumbprints, comma separated).
#>
param([ValidateSet('Run', 'Inventory', 'Test')][string]$Mode = 'Run')

$ErrorActionPreference = 'Stop'
$AgentVersion = '1.0'
$Data = Join-Path $env:ProgramData 'NetInventory Agent'
Add-Type -AssemblyName System.Security

function Write-Log([string]$Msg) {
    $f = Join-Path $Data 'agent.log'
    try {
        if ((Test-Path $f) -and (Get-Item $f).Length -gt 256KB) { Move-Item $f "$f.1" -Force }
        Add-Content -Path $f -Value ("{0:u} {1}" -f (Get-Date).ToUniversalTime(), $Msg) -Encoding UTF8
    } catch { }
}

function Get-Config {
    $c = @{ Server = ''; EnrollToken = ''; Pin = '' }
    $file = Join-Path $Data 'config.json'
    if (Test-Path $file) {
        $j = Get-Content $file -Raw | ConvertFrom-Json
        foreach ($k in 'Server', 'EnrollToken', 'Pin') { if ($j.$k) { $c[$k] = [string]$j.$k } }
    }
    $pol = 'HKLM:\SOFTWARE\Policies\NetInventory\Agent'
    if (Test-Path $pol) {
        $p = Get-ItemProperty $pol
        foreach ($k in 'Server', 'EnrollToken', 'Pin') { if ($p.$k) { $c[$k] = [string]$p.$k } }
    }
    if ($c.Server -notmatch '^https://[^/\s]+/?$') { throw "Server must look like https://netinv.corp.local:8080 (got '$($c.Server)')" }
    $c.Server = $c.Server.TrimEnd('/')
    $c.Pins = @($c.Pin -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { ($_ -replace '[:\s]', '').ToUpperInvariant() })
    $c
}

function Get-State {
    $f = Join-Path $Data 'state.json'
    if (-not (Test-Path $f)) { return $null }
    $j = Get-Content $f -Raw | ConvertFrom-Json
    $secret = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($j.secret), $null, 'LocalMachine')
    @{ AgentId = $j.agent_id; Secret = $secret }
}

function Save-State([string]$AgentId, [string]$SecretB64) {
    $raw = [Convert]::FromBase64String($SecretB64)
    $enc = [Security.Cryptography.ProtectedData]::Protect($raw, $null, 'LocalMachine')
    $json = @{ agent_id = $AgentId; secret = [Convert]::ToBase64String($enc) } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $Data 'state.json'), $json)
}

function Get-Hex([byte[]]$Bytes) { -join ($Bytes | ForEach-Object { $_.ToString('x2') }) }

# Minimal HTTPS POST over SslStream, so the pin check applies to this connection only (no process-wide callback).
function Invoke-Agent([hashtable]$Cfg, [string]$Path, [string]$Body, $State) {
    $uri = [Uri]($Cfg.Server + $Path)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $h = "POST $($uri.PathAndQuery) HTTP/1.1`r`nHost: $($uri.Authority)`r`nUser-Agent: NetInventoryAgent/$AgentVersion`r`n" +
         "Content-Type: application/json`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n"
    if ($State) {
        $ts = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $nonce = [Guid]::NewGuid().ToString('N')
        $sha = [Security.Cryptography.SHA256]::Create()
        $msg = "$ts`n$nonce`n$($uri.AbsolutePath)`n" + (Get-Hex $sha.ComputeHash($bytes))
        $hmac = New-Object Security.Cryptography.HMACSHA256 (, $State.Secret)
        $sig = Get-Hex $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg))
        $h += "X-Agent-Id: $($State.AgentId)`r`nX-Agent-Ts: $ts`r`nX-Agent-Nonce: $nonce`r`nX-Agent-Sig: $sig`r`n"
    }
    $h += "`r`n"
    $pins = $Cfg.Pins
    $check = [Net.Security.RemoteCertificateValidationCallback] {
        param($sender, $cert, $chain, $errors)
        if ($pins.Count) {
            $c2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, $cert)
            $thumb = Get-Hex ([Security.Cryptography.SHA256]::Create().ComputeHash($c2.RawData))
            return ($pins -contains $thumb.ToUpperInvariant())
        }
        return ($errors -eq [Net.Security.SslPolicyErrors]::None)
    }
    $tcp = New-Object Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($uri.Host, $uri.Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(10000)) { throw "can't reach $($uri.Authority)" }
        $tcp.EndConnect($iar)
        $tcp.SendTimeout = 60000; $tcp.ReceiveTimeout = 120000
        $ssl = New-Object Net.Security.SslStream ($tcp.GetStream(), $false, $check)
        try {
            $ssl.AuthenticateAsClient($uri.Host, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
        } catch { throw "TLS to $($uri.Authority) failed (wrong certificate pin, or the certificate isn't trusted): $($_.Exception.InnerException.Message)" }
        $hb = [Text.Encoding]::ASCII.GetBytes($h)
        $ssl.Write($hb, 0, $hb.Length); $ssl.Write($bytes, 0, $bytes.Length); $ssl.Flush()
        # Read until the body announced by Content-Length is in (or the server closes the connection).
        $ms = New-Object IO.MemoryStream
        $buf = New-Object byte[] 16384
        $need = -1
        while ($true) {
            $n = 0
            try { $n = $ssl.Read($buf, 0, $buf.Length) } catch [IO.IOException] { if ($ms.Length) { break } else { throw } }
            if ($n -le 0) { break }
            $ms.Write($buf, 0, $n)
            if ($need -lt 0) {
                $head = [Text.Encoding]::ASCII.GetString($ms.ToArray())
                $end = $head.IndexOf("`r`n`r`n")
                if ($end -ge 0) {
                    $cl = [regex]::Match($head.Substring(0, $end), '(?im)^content-length:\s*(\d+)')
                    if ($cl.Success) { $need = $end + 4 + [int]$cl.Groups[1].Value }
                }
            }
            if ($need -ge 0 -and $ms.Length -ge $need) { break }
        }
        $resp = [Text.Encoding]::UTF8.GetString($ms.ToArray())
    } finally { $tcp.Close() }
    $split = $resp.IndexOf("`r`n`r`n")
    if ($split -lt 0) { throw 'bad response from the server' }
    $status = [int]($resp.Substring(0, $split) -split ' ')[1]
    $text = $resp.Substring($split + 4)
    $obj = $null; try { $obj = $text | ConvertFrom-Json } catch { }
    if ($status -ge 300) { throw "server said $status $(if ($obj.detail) { $obj.detail } else { $text })" }
    $obj
}

function Get-MachineGuid { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid }

function Register-Agent([hashtable]$Cfg) {
    if (-not $Cfg.EnrollToken) { throw 'Not enrolled yet and no enrollment token is configured.' }
    $cs = Get-CimInstance Win32_ComputerSystem
    $body = @{ token = $Cfg.EnrollToken; hostname = $env:COMPUTERNAME; fqdn = "$($cs.DNSHostName).$($cs.Domain)"
               machine_guid = Get-MachineGuid; version = $AgentVersion; run_as = [Security.Principal.WindowsIdentity]::GetCurrent().Name } | ConvertTo-Json -Compress
    $r = Invoke-Agent $Cfg '/api/agent/enroll' $body $null
    Save-State $r.agent_id $r.secret
    Write-Log "enrolled as $($r.agent_id) ($($r.status))"
    Get-State
}

function Send-Heartbeat([hashtable]$Cfg, $State) {
    $os = Get-CimInstance Win32_OperatingSystem -Property LastBootUpTime
    $user = (Get-CimInstance Win32_ComputerSystem -Property UserName).UserName
    $ips = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq 'Up' } |
        ForEach-Object { $_.GetIPProperties().UnicastAddresses } | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and -not [Net.IPAddress]::IsLoopback($_.Address) } |
        ForEach-Object { $_.Address.ToString() })
    $body = @{ hostname = $env:COMPUTERNAME; last_boot = $os.LastBootUpTime.ToUniversalTime().ToString('o'); current_user = $user
               ips = $ips; version = $AgentVersion } | ConvertTo-Json -Compress
    Invoke-Agent $Cfg '/api/agent/heartbeat' $body $State
}

#region inventory (generated from netinv/collectors/winrm.py ENDPOINT_SCRIPT by tools/gen_agent.py: do not edit here)
function Get-Inventory([bool]$CheckPendingArg, [int]$LogonDaysArg) {
    $ErrorActionPreference = 'SilentlyContinue'
    $CheckPending = $CheckPendingArg
    $LogonDays = $LogonDaysArg
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $bio = Get-CimInstance Win32_BIOS
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $gpu = (Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Remote|Mirror|Basic Display' } | ForEach-Object {
      if ($_.AdapterRAM -gt 0) { "$($_.Name) $([math]::Round($_.AdapterRAM/1GB,1)) GB" } else { $_.Name } }) -join '; '
    $cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $nics = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
      @{ mac = $_.MACAddress; ip = (@($_.IPAddress) | Where-Object { $_ -notmatch ':' } | Select-Object -First 1); description = $_.Description } })

    # Wired or Wi-Fi: the adapter the default route goes out of. On Wi-Fi, the SSID and the AP's BSSID (needs the WLAN
    # service; on Windows 11 24H2+ the SSID/BSSID also need location services on, else only "wireless" is known).
    $connection = $null; $wifi = $null
    $route = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object { $_.RouteMetric + $_.InterfaceMetric }) | Select-Object -First 1
    if ($route) {
      $pa = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex
      if ($pa) { $connection = if ($pa.NdisPhysicalMedium -eq 9 -or "$($pa.PhysicalMediaType)" -match '802\.11') { 'wireless' } else { 'wired' } }
    }
    $wl = @{}
    foreach ($ln in @(netsh wlan show interfaces)) { if ("$ln" -match '^\s+(.+?)\s+:\s(.*)$') { $k = $Matches[1].Trim(); if (-not $wl.ContainsKey($k)) { $wl[$k] = $Matches[2].Trim() } } }
    if ($wl['State'] -eq 'connected') {
      $bssid = if ($wl['AP BSSID']) { $wl['AP BSSID'] } else { $wl['BSSID'] }
      $wifi = @{ ssid = $wl['SSID']; bssid = $bssid; signal = (($wl['Signal'] -replace '[^0-9]', '') -as [int]); radio = $wl['Radio type']
                 channel = $wl['Channel']; mac = $wl['Physical address']; adapter = $wl['Description'] }
    }

    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
      @{ drive = $_.DeviceID; size_gb = [math]::Round($_.Size/1GB,1); free_gb = [math]::Round($_.FreeSpace/1GB,1) } })

    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $sw = { param($scope) process { if ($_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName) {
      @{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher; install_date = $_.InstallDate;
         product_code = $_.PSChildName; scope = $scope } } } }
    # Per-user installs (Chrome, Zoom, Teams, VS Code...) from the profiles loaded right now
    $userKeys = @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
      ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" })
    $software = @(@(Get-ItemProperty $keys -ErrorAction SilentlyContinue | & $sw 'machine') +
                  @(if ($userKeys) { Get-ItemProperty $userKeys -ErrorAction SilentlyContinue | & $sw 'user' }))

    $hotfixes = @(Get-HotFix | ForEach-Object {
      @{ kb = $_.HotFixID; title = $_.Description; installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString('o') } else { $null } } })

    $pending = $null
    if ($CheckPending) {
      try {
        $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $r = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $pending = @($r.Updates | ForEach-Object {
          @{ kb = (@($_.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ','; title = $_.Title; severity = $_.MsrcSeverity } })
      } catch { $pending = $null }
    }

    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
      $st = [int]$_.productState
      @{ name = $_.displayName; enabled = ((($st -shr 12) -band 0xF) -eq 1); up_to_date = (($st -band 0xFF) -eq 0) } })
    if (-not $av) {  # Servers have no Security Center: ask Defender directly
      $mp = Get-MpComputerStatus
      if ($mp) { $av = @(@{ name = 'Microsoft Defender Antivirus'; enabled = ([bool]$mp.AntivirusEnabled -and [bool]$mp.RealTimeProtectionEnabled); up_to_date = ($mp.AntivirusSignatureAge -le 3) }) }
    }
    $fp = @{}
    Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus | ForEach-Object { $fp[$_.InstanceName] = [bool]$_.PredictFailure }
    $anyFail = [bool](@($fp.Values) -contains $true)
    $pdisks = @(Get-PhysicalDisk | ForEach-Object {
      @{ model = $_.FriendlyName; serial = "$($_.SerialNumber)".Trim(); media = "$($_.MediaType)"; size_gb = [math]::Round($_.Size/1GB,1);
         health = "$($_.HealthStatus)"; predict_failure = $anyFail } })

    $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
              (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

    $logons = @()
    if ($LogonDays -gt 0) {
      $since = (Get-Date).AddDays(-$LogonDays)
      $logons = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$since} -MaxEvents 2000 | ForEach-Object {
        $x = [xml]$_.ToXml(); $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        $t = [int]$d.LogonType
        if ($t -in 2,10,11 -and $d.TargetDomainName -notin 'Window Manager','Font Driver Host','NT AUTHORITY') {
          @{ time = $_.TimeCreated.ToUniversalTime().ToString('o'); username = "$($d.TargetDomainName)\$($d.TargetUserName)"; logon_type = $t; ip = $d.IpAddress } }
      })
    }

    [pscustomobject]@{
      hostname = $env:COMPUTERNAME; fqdn = "$($cs.DNSHostName).$($cs.Domain)"; source = 'agent'; agent_version = $AgentVersion
      os_caption = $os.Caption; os_build = "$($os.BuildNumber).$($cv.UBR)"; os_display_version = $cv.DisplayVersion
      last_boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
      manufacturer = $cs.Manufacturer; model = $cs.Model; serial = $bio.SerialNumber; cpu = $cpu.Name; gpu = $gpu
      ram_gb = [math]::Round($cs.TotalPhysicalMemory/1GB,1); current_user = $cs.UserName
      nics = $nics; disks = $disks; software = $software; hotfixes = $hotfixes
      pending_updates = $pending; pending_reboot = $reboot; logons = $logons; antivirus = $av; physical_disks = $pdisks
      connection = $connection; wifi = $wifi
    } | ConvertTo-Json -Depth 5 -Compress
}
#endregion

function Send-Inventory([hashtable]$Cfg, $State) {
    # Windows Update and the Security log need SYSTEM; as LOCAL SERVICE they're skipped quietly.
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
             [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
    $json = Get-Inventory $admin ($(if ($admin) { 14 } else { 0 }))
    Invoke-Agent $Cfg '/api/agent/inventory' $json $State | Out-Null
    Write-Log "inventory sent ($([math]::Round($json.Length / 1KB)) KB)"
}

try {
    $cfg = Get-Config
    $state = Get-State
    if (-not $state) { $state = Register-Agent $cfg }
    if ($Mode -eq 'Inventory') { Send-Inventory $cfg $state; exit 0 }
    $r = Send-Heartbeat $cfg $state
    if ($Mode -eq 'Test') { Write-Output "OK: $($cfg.Server) answered ($($r | ConvertTo-Json -Compress))"; exit 0 }
    if ($r.inventory) { Send-Inventory $cfg $state }
} catch {
    $m = $_.Exception.Message
    if ($m -match '\b401\b|unknown agent|revoked') {
        # The server doesn't know this secret (revoked, or the server was rebuilt): enroll again next run.
        Remove-Item (Join-Path $Data 'state.json') -Force -ErrorAction SilentlyContinue
    }
    Write-Log "error: $m"
    if ($Mode -eq 'Test') { Write-Output "FAILED: $m" }
    exit 1
}
