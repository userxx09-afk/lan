"""Self-signed HTTPS certificate for the dashboard, made at install time.

Browsers warn about a self-signed certificate until it is trusted. For no warning, install a certificate from
your AD CS (or another CA) in Settings > HTTPS certificate: a .pfx, a certificate with its key (PEM or DER), a
certificate for a request made here, a PKCS#7 chain, or one from this server's Windows certificate store.
"""
from __future__ import annotations

import datetime
import ipaddress
import socket
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def make_self_signed(out: str, force: bool = False) -> str:
    folder = Path(out)
    crt, key = folder / "tls.crt", folder / "tls.key"
    if crt.exists() and key.exists() and not force:
        return f"kept existing {crt}"
    folder.mkdir(parents=True, exist_ok=True)
    host = socket.gethostname()
    fqdn = socket.getfqdn()
    names = {host, fqdn, "localhost"}
    ips = {"127.0.0.1"}
    try:
        ips |= {a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)}
    except OSError:
        pass
    sans = [x509.DNSName(n) for n in sorted(names) if n] + [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn or host),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetInventory")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(k, hashes.SHA256()))
    key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return f"wrote {crt} for {', '.join(sorted(names | ips))}"


# ------------------------------------------------------------------ certificate management (Settings > HTTPS certificate)
def _load_chain(pem: bytes) -> list:
    return x509.load_pem_x509_certificates(pem)


def info(crt_path: str) -> dict:
    """What the dashboard currently serves."""
    p = Path(crt_path) if crt_path else None
    if not p or not p.exists():
        return {"https": False}
    cert = _load_chain(p.read_bytes())[0]
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n.value) for n in sans]
    except x509.ExtensionNotFound:
        names = []
    pending = p.with_name("tls.pending.key").exists()
    return {"https": True, "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "self_signed": cert.issuer == cert.subject, "not_after": cert.not_valid_after_utc.isoformat(),
            "names": names, "pending_request": pending,
            "sha256": cert.fingerprint(hashes.SHA256()).hex().upper()}


def make_csr(folder: str) -> str:
    """New RSA key (kept on the server as tls.pending.key) and a CSR for this server's names, for AD CS."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    host, fqdn = socket.gethostname(), socket.getfqdn()
    names = sorted({host, fqdn, "localhost"} - {""})
    ips = {"127.0.0.1"}
    try:
        ips |= {a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)}
    except OSError:
        pass
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)   # AD CS Web Server templates expect RSA
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn or host)]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names] +
                                                      [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]), critical=False)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .sign(k, hashes.SHA256()))
    (Path(folder) / "tls.pending.key").write_bytes(
        k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _same_key(cert, key) -> bool:
    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert.public_key().public_bytes(*fmt) == key.public_key().public_bytes(*fmt)


# What Settings > HTTPS certificate offers. "auto" works out the format from the file itself.
FORMATS = {
    "auto": "Detect from the file",
    "pfx": "PFX / PKCS#12 (.pfx, .p12): certificate and private key in one file, usually with a password",
    "request": "Certificate for the request made here (.cer, .crt, .pem, .p7b): the key is already on this server",
    "pem_key": "Certificate and a separate private key (.crt/.cer/.pem + .key/.pem)",
    "pem_combined": "One PEM file with the certificate and its private key (.pem)",
    "store": "Windows certificate store of this server (Local Computer > Personal)",
}

_PEM_CERT = b"-----BEGIN CERTIFICATE-----"
_PEM_P7 = (b"-----BEGIN PKCS7-----", b"-----BEGIN CERTIFICATE CHAIN-----")


def _pw(password: str | None) -> bytes | None:
    return password.encode() if password else None


def _unwrap_base64(data: bytes) -> bytes:
    """A .cer/.key saved as bare base64 (no BEGIN/END lines) is DER underneath."""
    import base64
    import binascii
    t = data.strip()
    if not t or t.startswith(b"-----") or len(t) > 5_000_000:
        return data
    try:
        raw = base64.b64decode(b"".join(t.split()), validate=True)
    except (binascii.Error, ValueError):
        return data
    return raw if raw[:1] == b"\x30" else data


def _certs_from(data: bytes, what: str = "certificate file") -> tuple[list, str]:
    """Certificates in a PEM (one or a bundle), DER .cer/.crt or PKCS#7 .p7b/.p7c file, and the format found."""
    from cryptography.hazmat.primitives.serialization import pkcs7
    data = _unwrap_base64(data)
    if any(m in data for m in _PEM_P7):
        return list(pkcs7.load_pem_pkcs7_certificates(data.replace(b"CERTIFICATE CHAIN", b"PKCS7"))), "PKCS#7 (PEM)"
    if _PEM_CERT in data:
        return x509.load_pem_x509_certificates(data), "PEM"
    try:
        return [x509.load_der_x509_certificate(data)], "DER"
    except ValueError:
        pass
    try:
        return list(pkcs7.load_der_pkcs7_certificates(data)), "PKCS#7 (DER)"
    except ValueError:
        pass
    raise ValueError(f"the {what} isn't a certificate: use .cer/.crt/.pem (PEM or DER), .p7b, or a .pfx")


def _key_from(data: bytes, password: str | None) -> tuple[object, str]:
    """A private key in PEM (PKCS#8, PKCS#1 "RSA PRIVATE KEY", "EC PRIVATE KEY", encrypted or not) or DER."""
    data = _unwrap_base64(data)
    pem = b"PRIVATE KEY-----" in data
    load = serialization.load_pem_private_key if pem else serialization.load_der_private_key
    kind = "PEM" if pem else "DER"
    try:
        return load(data, _pw(password)), kind
    except TypeError:          # a password for a key that isn't encrypted, or none for one that is
        if password:
            return load(data, None), kind
        raise ValueError("the private key is encrypted: enter its password") from None
    except ValueError:
        if password and (pem or b"ENCRYPTED" in data):
            raise ValueError("wrong password for the private key") from None
        raise ValueError("the key file isn't a private key this server can read (PEM or DER, RSA or EC)") from None


def _pfx(data: bytes, password: str | None) -> tuple[object, list]:
    from cryptography.hazmat.primitives.serialization import pkcs12
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, _pw(password))
    except ValueError as exc:
        if password is None:
            try:     # some exports use an empty-string password rather than none
                key, cert, extra = pkcs12.load_key_and_certificates(data, b"")
            except ValueError:
                raise ValueError("this .pfx needs its password (or the password is wrong)") from None
        else:
            raise ValueError("wrong password for this .pfx file") from None
    if key is None:
        raise ValueError("this .pfx has no private key: export it again with \"Yes, export the private key\"")
    if cert is None:
        raise ValueError("this .pfx has no certificate in it")
    return key, [cert] + list(extra or [])


def _is_pfx(data: bytes) -> bool:
    """A binary file that isn't a DER certificate or PKCS#7 is taken as a .pfx (it may need a password to open)."""
    from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
    if data[:1] != b"\x30":
        return False
    try:
        pkcs12.load_key_and_certificates(data, None)
        return True
    except Exception:
        pass
    for load in (x509.load_der_x509_certificate, pkcs7.load_der_pkcs7_certificates):
        try:
            load(data)
            return False
        except Exception:
            pass
    return True


def _order_chain(certs: list, key) -> list:
    """Leaf (the one matching the key) first, then each issuer, then whatever is left; duplicates dropped."""
    seen, uniq = set(), []
    for c in certs:
        fp = c.fingerprint(hashes.SHA256())
        if fp not in seen:
            seen.add(fp)
            uniq.append(c)
    leaf = next((c for c in uniq if key is not None and _same_key(c, key)), None)
    if leaf is None:
        leaf = next((c for c in uniq if not _is_ca(c)), uniq[0])
    out, rest = [leaf], [c for c in uniq if c is not leaf]
    while rest:
        nxt = next((c for c in rest if c.subject == out[-1].issuer and out[-1].issuer != out[-1].subject), None)
        if nxt is None:
            break
        out.append(nxt)
        rest.remove(nxt)
    return out + rest


def _is_ca(c) -> bool:
    try:
        return c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return c.issuer == c.subject


def _names(c) -> list[str]:
    try:
        return [str(n.value) for n in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        return []


def _host_ok(names: list[str], host: str) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host or n.startswith("*.") and host.split(".", 1)[-1] == n[2:] and "." in host:
            return True
    return False


def parse(fmt: str, cert_data: bytes | None, password: str | None = None, key_data: bytes | None = None,
          key_password: str | None = None, chain_data: bytes | None = None, folder: str | None = None) -> dict:
    """Read an upload in any of FORMATS (except "store", which arrives here as a .pfx). Returns the key, the chain in
    order (leaf first) and what was found, without changing anything. Raises ValueError with a readable message."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown certificate format {fmt!r}")
    if not cert_data:
        raise ValueError("choose the certificate file")
    key, certs, found, key_src = None, [], "", ""
    if fmt == "store":
        fmt = "pfx"
    if fmt == "auto":
        if _is_pfx(cert_data):
            fmt = "pfx"
        elif b"PRIVATE KEY-----" in cert_data:
            fmt = "pem_combined"
        elif key_data:
            fmt = "pem_key"
        else:
            fmt = "request"
    if fmt == "pfx":
        key, certs = _pfx(cert_data, password)
        found, key_src = "PFX / PKCS#12", "in the .pfx"
    else:
        if fmt == "pem_combined" and b"PRIVATE KEY-----" not in cert_data:
            raise ValueError("this file has no private key in it: pick \"Certificate and a separate private key\" "
                             "and add the .key file, or \"Certificate for the request made here\"")
        certs, found = _certs_from(cert_data)
        if b"PRIVATE KEY-----" in cert_data:
            key, _ = _key_from(cert_data, key_password or password)
            found, key_src = "PEM with key", "in the same file"
        if fmt == "pem_key":
            if not key_data:
                raise ValueError("choose the private key file (.key)")
            key, kf = _key_from(key_data, key_password or password)
            key_src = f"separate key file ({kf})"
        if key is None and fmt in ("request", "auto"):
            pending = Path(folder) / "tls.pending.key" if folder else None
            if not pending or not pending.exists():
                raise ValueError("this certificate has no private key. Upload a .pfx, or the certificate with its "
                                 ".key file, or click \"Create request for AD CS\" first and install what the CA returns")
            key = serialization.load_pem_private_key(pending.read_bytes(), None)
            key_src = "the request made on this server"
    if not certs:
        raise ValueError("no certificate found in the file")
    extra_chain = 0
    if chain_data:
        more, _ = _certs_from(chain_data, "chain file")
        extra_chain = len(more)
        certs = certs + more
    chain = _order_chain(certs, key)
    leaf = chain[0]
    if not _same_key(leaf, key):
        where = {"the request made on this server": "the request made on this server (create a new request, or "
                 "upload a .pfx)"}.get(key_src, key_src or "the key")
        raise ValueError(f"the certificate doesn't match the private key from {where}")
    now = datetime.datetime.now(datetime.timezone.utc)
    if leaf.not_valid_after_utc < now:
        raise ValueError(f"this certificate expired on {leaf.not_valid_after_utc:%Y-%m-%d}")
    names = _names(leaf)
    warnings = []
    if leaf.not_valid_before_utc > now:
        warnings.append(f"not valid until {leaf.not_valid_before_utc:%Y-%m-%d %H:%M} UTC")
    if (leaf.not_valid_after_utc - now).days < 30:
        warnings.append(f"expires in {(leaf.not_valid_after_utc - now).days} days")
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            warnings.append("not made for web servers (no Server Authentication usage): browsers will refuse it")
    except x509.ExtensionNotFound:
        pass
    host, fqdn = socket.gethostname(), socket.getfqdn()
    if not names:
        warnings.append("no subject alternative names: browsers ignore the common name and will warn")
    elif not (_host_ok(names, fqdn) or _host_ok(names, host)):
        warnings.append(f"issued for {', '.join(names[:4])}, not for this server's name ({fqdn or host})")
    if leaf.issuer != leaf.subject and len(chain) == 1:
        warnings.append("no intermediate/CA certificates included. Fine when PCs already trust the issuing CA "
                        "(AD CS); otherwise add the chain file")
    return {"key": key, "chain": chain, "format": found, "key_source": key_src,
            "summary": {"format": found, "key_source": key_src, "subject": leaf.subject.rfc4514_string(),
                        "issuer": leaf.issuer.rfc4514_string(), "self_signed": leaf.issuer == leaf.subject,
                        "not_before": leaf.not_valid_before_utc.isoformat(),
                        "not_after": leaf.not_valid_after_utc.isoformat(), "names": names,
                        "chain": [c.subject.rfc4514_string() for c in chain[1:]], "chain_file_certs": extra_chain,
                        "key_type": _key_type(key), "key_match": True, "warnings": warnings,
                        "sha256": leaf.fingerprint(hashes.SHA256()).hex().upper()}}


def _key_type(key) -> str:
    from cryptography.hazmat.primitives.asymmetric import rsa
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"EC {key.curve.name}"
    return type(key).__name__


def install(folder: str, cert_data: bytes, password: str | None = None, fmt: str = "auto",
            key_data: bytes | None = None, key_password: str | None = None,
            chain_data: bytes | None = None) -> str:
    """Install a certificate for the dashboard from any of FORMATS. The current files are kept as tls.crt.bak /
    tls.key.bak. Returns the certificate's subject."""
    p = parse(fmt, cert_data, password, key_data, key_password, chain_data, folder)
    folder_p = Path(folder)
    crt, kf = folder_p / "tls.crt", folder_p / "tls.key"
    for f in (crt, kf):
        if f.exists():
            f.replace(f.with_name(f.name + ".bak"))
    kf.write_bytes(p["key"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    crt.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in p["chain"]))
    if p["key_source"] == "the request made on this server":
        (folder_p / "tls.pending.key").unlink(missing_ok=True)
    return p["summary"]["subject"]


# ------------------------------------------------------------------ Windows certificate store (Local Computer > Personal)
def _powershell(script: str, timeout: int = 60) -> str:
    import base64
    import os
    import subprocess
    exe = os.path.expandvars(r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe")
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
                       capture_output=True, text=True, timeout=timeout,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0:
        raise ValueError((r.stderr or r.stdout or "PowerShell failed").strip().splitlines()[-1][:300])
    return r.stdout


def store_available() -> bool:
    import os
    return os.name == "nt"


def store_list() -> list[dict]:
    """Certificates with a private key in Local Computer > Personal, newest first."""
    import json
    if not store_available():
        return []
    out = _powershell(r"""
$ErrorActionPreference = 'Stop'
$now = Get-Date
$r = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey } | ForEach-Object {
  [pscustomobject]@{ thumbprint = $_.Thumbprint; subject = $_.Subject; issuer = $_.Issuer
    not_after = $_.NotAfter.ToUniversalTime().ToString('o'); expired = ($_.NotAfter -lt $now)
    names = @($_.DnsNameList | ForEach-Object { $_.Unicode }); friendly = $_.FriendlyName
    server_auth = (@($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.1' }).Count -gt 0 -or @($_.EnhancedKeyUsageList).Count -eq 0) }
})
ConvertTo-Json -InputObject $r -Depth 4 -Compress
""")
    rows = json.loads(out.strip() or "[]")
    rows = rows if isinstance(rows, list) else [rows]
    rows.sort(key=lambda r: r.get("not_after") or "", reverse=True)
    return rows


def store_export(thumbprint: str) -> tuple[bytes, str]:
    """Export one certificate (with its key and chain) from Local Computer > Personal as a .pfx with a one-time password."""
    import re
    import secrets
    if not store_available():
        raise ValueError("the Windows certificate store is only available when NetInventory runs on Windows")
    tp = re.sub(r"[^0-9A-Fa-f]", "", thumbprint or "").upper()
    if len(tp) not in (40, 64):
        raise ValueError("pick a certificate from the list")
    pw = secrets.token_urlsafe(24)
    out = _powershell(rf"""
$ErrorActionPreference = 'Stop'
$c = Get-Item -LiteralPath 'Cert:\LocalMachine\My\{tp}'
if (-not $c.HasPrivateKey) {{ throw 'this certificate has no private key on this server' }}
$col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$null = $col.Add($c)
$ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$ch.ChainPolicy.RevocationMode = 'NoCheck'
$null = $ch.Build($c)
foreach ($e in $ch.ChainElements) {{ if ($e.Certificate.Thumbprint -ne $c.Thumbprint -and $e.Certificate.Subject -ne $e.Certificate.Issuer) {{ $null = $col.Add($e.Certificate) }} }}
try {{ $b = $col.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, '{pw}') }}
catch {{ throw 'Windows will not export this private key (it was imported as not exportable). Import it again with "Mark this key as exportable", or upload the .pfx instead' }}
[Convert]::ToBase64String($b)
""")
    import base64
    return base64.b64decode(out.strip()), pw
