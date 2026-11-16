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
            "names": names, "pending_request": pending}


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


def install(folder: str, cert_data: bytes, password: str | None = None) -> str:
    """Install a certificate for the dashboard: a .pfx/.p12 (with its key), or a PEM/DER certificate issued for
    the request made by make_csr. The current files are kept as tls.crt.bak / tls.key.bak."""
    from cryptography.hazmat.primitives.serialization import pkcs12
    folder_p = Path(folder)
    key = None
    chain: list = []
    if cert_data.lstrip().startswith(b"-----BEGIN"):
        chain = _load_chain(cert_data)
        if b"PRIVATE KEY-----" in cert_data:
            key = serialization.load_pem_private_key(cert_data, password.encode() if password else None)
    else:
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(cert_data, password.encode() if password else None)
            chain = [cert] + list(extra or [])
        except ValueError as exc:
            if "password" in str(exc).lower() or "mac" in str(exc).lower():
                raise ValueError("wrong password for this .pfx file") from None
            try:
                chain = [x509.load_der_x509_certificate(cert_data)]
            except ValueError:
                raise ValueError("this isn't a certificate file: use a .pfx/.p12, or the .cer from your CA") from None
    if not chain:
        raise ValueError("no certificate found in the file")
    leaf = chain[0]
    if key is None:
        pending = folder_p / "tls.pending.key"
        if not pending.exists():
            raise ValueError("this certificate has no private key. Upload a .pfx, or create a certificate request first")
        key = serialization.load_pem_private_key(pending.read_bytes(), None)
    if not _same_key(leaf, key):
        raise ValueError("the certificate doesn't belong to the pending request's key (or the .pfx's key)")
    if leaf.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("this certificate has expired")
    crt, kf = folder_p / "tls.crt", folder_p / "tls.key"
    for f in (crt, kf):
        if f.exists():
            f.replace(f.with_name(f.name + ".bak"))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    crt.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain))
    (folder_p / "tls.pending.key").unlink(missing_ok=True)
    return leaf.subject.rfc4514_string()
