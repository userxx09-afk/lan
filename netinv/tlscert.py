"""Self-signed HTTPS certificate for the dashboard, made at install time.

Browsers warn about a self-signed certificate until it is trusted. For no warning, put a certificate
from your AD CS (or another CA) in [server] tls_cert / tls_key in config.toml instead (PEM files).
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
