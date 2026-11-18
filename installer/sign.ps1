# Authenticode-signs files with the code-signing certificate in the CODESIGN_PFX_BASE64 / CODESIGN_PFX_PASSWORD
# environment variables (CI: repository secrets of the same names). Without them it does nothing and says so,
# so builds without the secrets (forks, a build by hand) still work, just unsigned.
#   .\installer\sign.ps1 netinv\agent\*.ps1 agent\*.ps1
# Works for .ps1, .msi and .exe. Timestamped (CODESIGN_TIMESTAMP_URL, default DigiCert's public server), so the
# signatures stay valid after the certificate expires.
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Path)
$ErrorActionPreference = 'Stop'
if (-not $env:CODESIGN_PFX_BASE64) {
    Write-Host "::warning::No CODESIGN_PFX_BASE64 secret: $($Path -join ', ') left unsigned."
    return
}
$ts = if ($env:CODESIGN_TIMESTAMP_URL) { $env:CODESIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
$pfx = Join-Path ([IO.Path]::GetTempPath()) "codesign-$PID.pfx"
try {
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String(($env:CODESIGN_PFX_BASE64 -replace '\s', '')))
    $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
    $all = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    $all.Import($pfx, $env:CODESIGN_PFX_PASSWORD, $flags)
    # The signing cert is the one with a private key and the Code Signing EKU; the rest of the .pfx is its chain.
    $eku = { param($c) @($c.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
                         ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value }) }
    $cert = $all | Where-Object { $_.HasPrivateKey -and ((& $eku $_) -contains '1.3.6.1.5.5.7.3.3') } | Select-Object -First 1
    if (-not $cert) { throw 'The .pfx has no certificate with a private key and the Code Signing purpose (EKU 1.3.6.1.5.5.7.3.3).' }
    Write-Host "Signing as $($cert.Subject) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')), thumbprint $($cert.Thumbprint))"
    $files = @($Path | ForEach-Object { Get-ChildItem $_ -File })
    foreach ($f in $files) {
        $ok = $false
        foreach ($try in 1..3) {      # timestamp servers fail now and then
            try {
                $r = Set-AuthenticodeSignature -LiteralPath $f.FullName -Certificate $cert -HashAlgorithm SHA256 `
                     -TimestampServer $ts -IncludeChain All -ErrorAction Stop
                # The build machine doesn't trust an internal CA, so the status is UnknownError there; the file is
                # still signed (domain PCs, which trust the CA, see it as Valid).
                if ($r.SignerCertificate -and $r.SignerCertificate.Thumbprint -eq $cert.Thumbprint) { $ok = $true; break }
                Write-Host "  $($f.Name): $($r.Status) $($r.StatusMessage)"
            } catch { Write-Host "  $($f.Name): try $try failed: $($_.Exception.Message)" }
            Start-Sleep -Seconds (5 * $try)
        }
        if (-not $ok) { throw "Signing $($f.FullName) failed." }
        Write-Host "  signed $($f.Name)"
    }
} finally {
    Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}
