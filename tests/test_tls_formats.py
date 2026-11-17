"""HTTPS certificate import in every offered format: .pfx (with/without password), PEM + separate key (PKCS#8,
PKCS#1, EC, encrypted), DER .cer + DER key, combined PEM, PKCS#7 .p7b chains, a certificate for the request made here,
bare base64, and the Windows store (export faked). Also the readable errors and the /api/tls/check + import endpoints.
Run: python tests/test_tls_formats.py (DATABASE_URL set, demo loaded)."""
import base64, datetime, logging, socket, sys, tempfile
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from netinv import tlscert

E, F = serialization.Encoding, serialization.PrivateFormat
NOW = datetime.datetime.now(datetime.timezone.utc)
HOST = socket.getfqdn() or socket.gethostname()


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make(subject, key, issuer=None, issuer_key=None, ca=False, days=365, eku=True):
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer or subject))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - datetime.timedelta(days=max(1, 1 - days) + 1)).not_valid_after(NOW + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if eku else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


root_k = ec.generate_private_key(ec.SECP256R1()); root = make("Corp Root CA", root_k, ca=True)
int_k = ec.generate_private_key(ec.SECP256R1()); inter = make("Corp Issuing CA", int_k, "Corp Root CA", root_k, ca=True)
leaf_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
leaf = make(HOST, leaf_k, "Corp Issuing CA", int_k)
other_k = ec.generate_private_key(ec.SECP256R1())

pem = lambda *cs: b"".join(c.public_bytes(E.PEM) for c in cs)
k8 = leaf_k.private_bytes(E.PEM, F.PKCS8, serialization.NoEncryption())
k1 = leaf_k.private_bytes(E.PEM, F.TraditionalOpenSSL, serialization.NoEncryption())
kenc = leaf_k.private_bytes(E.PEM, F.PKCS8, serialization.BestAvailableEncryption(b"keypw"))
kder = leaf_k.private_bytes(E.DER, F.PKCS8, serialization.NoEncryption())
pfx_pw = pkcs12.serialize_key_and_certificates(b"nv", leaf_k, leaf, [inter], serialization.BestAvailableEncryption(b"pfxpw"))
pfx_nopw = pkcs12.serialize_key_and_certificates(b"nv", leaf_k, leaf, [inter], serialization.NoEncryption())
p7_pem = pkcs7.serialize_certificates([root, leaf, inter], E.PEM)
p7_der = pkcs7.serialize_certificates([inter, root], E.DER)


def ok(fmt, data, password=None, key=None, key_password=None, chain=None, folder=None, chain_len=None):
    s = tlscert.parse(fmt, data, password, key, key_password, chain, folder)["summary"]
    assert s["key_match"] and s["subject"] == f"CN={HOST}", (fmt, s)
    if chain_len is not None:
        assert len(s["chain"]) == chain_len, (fmt, s["chain"])
    return s


def bad(fmt, data, text, **kw):
    try:
        tlscert.parse(fmt, data, kw.pop("password", None), kw.pop("key", None), kw.pop("key_password", None),
                      kw.pop("chain", None), kw.pop("folder", None))
    except ValueError as exc:
        assert text in str(exc), (fmt, text, str(exc))
        return
    raise AssertionError(f"{fmt}: expected an error with {text!r}")


# .pfx
for fmt in ("pfx", "auto"):
    s = ok(fmt, pfx_pw, "pfxpw", chain_len=1)
    assert s["format"] == "PFX / PKCS#12" and s["chain"] == ["CN=Corp Issuing CA"]
    ok(fmt, pfx_nopw)
bad("pfx", pfx_pw, "wrong password", password="nope")
bad("pfx", pfx_pw, "needs its password")
bad("auto", pfx_pw, "needs its password")
bad("pfx", pkcs12.serialize_key_and_certificates(b"x", None, leaf, None, serialization.NoEncryption()), "no private key")

# certificate + separate key: PKCS#8, PKCS#1, encrypted, DER key, DER cert, with a chain file
for fmt in ("pem_key", "auto"):
    ok(fmt, pem(leaf), key=k8)
    ok(fmt, pem(leaf), key=k1)
    ok(fmt, pem(leaf), key=kenc, key_password="keypw")
    ok(fmt, leaf.public_bytes(E.DER), key=kder)
    s = ok(fmt, pem(leaf), key=k8, chain=pem(root, inter), chain_len=2)
    assert s["chain"] == ["CN=Corp Issuing CA", "CN=Corp Root CA"], s["chain"]      # ordered leaf -> root
    assert s["chain_file_certs"] == 2
    ok(fmt, pem(leaf), key=k8, chain=p7_der, chain_len=2)
ok("pem_key", pem(leaf), key=k8, key_password="ignored for an unencrypted key")
bad("pem_key", pem(leaf), "encrypted: enter its password", key=kenc)
bad("pem_key", pem(leaf), "wrong password", key=kenc, key_password="nope")
bad("pem_key", pem(leaf), "choose the private key")
bad("pem_key", pem(leaf), "doesn't match", key=other_k.private_bytes(E.PEM, F.PKCS8, serialization.NoEncryption()))
bad("pem_key", pem(leaf), "isn't a private key", key=b"hello")
bad("pem_key", b"not a cert", "isn't a certificate", key=k8)

# one PEM with everything, in any order (key first, CA before leaf)
for fmt in ("pem_combined", "auto"):
    s = ok(fmt, k1 + pem(root, inter, leaf), chain_len=2)
    assert s["format"] == "PEM with key"
    ok(fmt, pem(leaf) + kenc, key_password="keypw")
bad("pem_combined", pem(leaf), "no private key in it")

with tempfile.TemporaryDirectory() as d:
    # certificate for the request made here: PEM, DER, bare base64, .p7b (PEM and DER) from the CA
    bad("request", pem(leaf), "Create request for AD CS", folder=d)
    (Path(d) / "tls.pending.key").write_bytes(k8)
    b64 = base64.encodebytes(leaf.public_bytes(E.DER))
    for fmt in ("request", "auto"):
        ok(fmt, pem(leaf), folder=d)
        ok(fmt, leaf.public_bytes(E.DER), folder=d)
        ok(fmt, b64, folder=d)
        assert ok(fmt, p7_pem, folder=d, chain_len=2)["format"] == "PKCS#7 (PEM)"
        ok(fmt, pkcs7.serialize_certificates([leaf, inter], E.DER), folder=d, chain_len=1)
    (Path(d) / "tls.pending.key").write_bytes(other_k.private_bytes(E.PEM, F.PKCS8, serialization.NoEncryption()))
    bad("request", pem(leaf), "request made on this server", folder=d)

    # install writes PEM chain + PKCS#8 key, keeps backups, drops the pending key only when it was used
    (Path(d) / "tls.pending.key").write_bytes(k8)
    (Path(d) / "tls.crt").write_bytes(b"old"); (Path(d) / "tls.key").write_bytes(b"old")
    tlscert.install(d, pfx_pw, "pfxpw", "pfx")
    assert (Path(d) / "tls.crt.bak").read_bytes() == b"old"
    assert (Path(d) / "tls.pending.key").exists()
    tlscert.install(d, p7_pem, None, "request")
    assert not (Path(d) / "tls.pending.key").exists()
    chain = x509.load_pem_x509_certificates((Path(d) / "tls.crt").read_bytes())
    assert [c.subject.rfc4514_string() for c in chain] == [f"CN={HOST}", "CN=Corp Issuing CA", "CN=Corp Root CA"]
    key = serialization.load_pem_private_key((Path(d) / "tls.key").read_bytes(), None)
    assert tlscert._same_key(chain[0], key)
    assert tlscert.info(str(Path(d) / "tls.crt"))["subject"] == f"CN={HOST}"

# warnings and refusals
expired = make(HOST, leaf_k, days=-2)
bad("pem_key", pem(expired), "expired", key=k8)
w = ok("pem_key", pem(make(HOST, leaf_k, "Corp Issuing CA", int_k, days=10, eku=False)), key=k8)["warnings"]
assert any("expires in" in x for x in w) and any("Server Authentication" in x for x in w) and any("intermediate" in x for x in w), w
bad("bogus", pem(leaf), "unknown certificate format")
bad("auto", None, "choose the certificate file")

# API: formats, check (no change), import, store (export faked as on Windows)
import netinv.main as m
from fastapi.testclient import TestClient
with tempfile.TemporaryDirectory() as d, TestClient(m.app) as c:
    m.settings.tls_cert, m.settings.tls_key = str(Path(d) / "tls.crt"), str(Path(d) / "tls.key")
    tlscert.make_self_signed(d)
    before = (Path(d) / "tls.crt").read_bytes()
    ids = [f["id"] for f in c.get("/api/tls/formats").json()["formats"]]
    assert ids[:5] == ["auto", "pfx", "request", "pem_key", "pem_combined"], ids
    enc = lambda b: base64.b64encode(b).decode()
    r = c.post("/api/tls/check", json={"format": "pem_key", "data": enc(pem(leaf)), "key": enc(k1), "chain": enc(pem(inter))})
    assert r.status_code == 200 and r.json()["chain"] == ["CN=Corp Issuing CA"], r.text
    assert (Path(d) / "tls.crt").read_bytes() == before                     # check changes nothing
    r = c.post("/api/tls/check", json={"format": "pfx", "data": enc(pfx_pw), "password": "x"})
    assert r.status_code == 400 and "wrong password" in r.json()["detail"], r.text
    r = c.post("/api/tls/import", json={"format": "pem_combined", "data": enc(pem(leaf) + k8)})
    assert r.status_code == 200 and "Installed" in r.json()["output"], r.text
    assert (Path(d) / "tls.crt").read_bytes() != before
    assert c.get("/api/tls").json()["subject"] == f"CN={HOST}"

    tlscert.store_available = lambda: True
    tlscert.store_list = lambda: [{"thumbprint": "AB" * 20, "subject": f"CN={HOST}", "issuer": "CN=Corp Issuing CA",
                                   "not_after": leaf.not_valid_after_utc.isoformat(), "expired": False, "names": [HOST],
                                   "friendly": "", "server_auth": True}]
    tlscert.store_export = lambda tp: (pfx_pw, "pfxpw") if tp == "AB" * 20 else (_ for _ in ()).throw(ValueError("pick a certificate from the list"))
    assert "store" in [f["id"] for f in c.get("/api/tls/formats").json()["formats"]]
    assert c.get("/api/tls/store").json()["certs"][0]["names"] == [HOST]
    r = c.post("/api/tls/check", json={"format": "store", "thumbprint": "AB" * 20})
    assert r.status_code == 200 and r.json()["format"] == "PFX / PKCS#12", r.text
    assert c.post("/api/tls/check", json={"format": "store", "thumbprint": "zz"}).status_code == 400
    r = c.post("/api/tls/import", json={"format": "store", "thumbprint": "AB" * 20})
    assert r.status_code == 200, r.text
print("certificate formats OK")
