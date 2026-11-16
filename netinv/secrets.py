"""Encryption at rest for stored credentials (Fernet / AES-128-CBC + HMAC).

The key lives next to config.toml, in a folder the installer locks down to Administrators and SYSTEM.
On Windows it is also wrapped with DPAPI (machine scope) in secret.key.dpapi, so a copy of the file is
useless on any other computer; an older plain secret.key is converted on first use. Elsewhere (Docker,
Linux) it is a plain secret.key readable by its owner only. Losing the key (or moving to a new
server) means re-entering the credentials in Settings; no other data is affected.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_fernet: Fernet | None = None


def _key_path() -> Path:
    if os.environ.get("NETINV_KEY_FILE"):
        return Path(os.environ["NETINV_KEY_FILE"])
    cfg = Path(os.environ.get("NETINV_CONFIG", "config.toml")).resolve()
    return cfg.parent / "secret.key"


# ------------------------------------------------------------------ Windows DPAPI (machine scope)
def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in, blob_out = BLOB(len(data), buf), BLOB()
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    flags = 0x4 | 0x1                    # CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    args = (ctypes.byref(blob_in), None, None, None, None, flags, ctypes.byref(blob_out))
    if not fn(*args):
        raise OSError(f"DPAPI {'protect' if protect else 'unprotect'} failed: {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _load_key() -> bytes:
    plain = _key_path()
    wrapped = plain.with_name(plain.name + ".dpapi")
    if os.name == "nt":
        if wrapped.exists():
            return _dpapi(wrapped.read_bytes(), protect=False).strip()
        key = plain.read_bytes().strip() if plain.exists() else Fernet.generate_key()
        wrapped.parent.mkdir(parents=True, exist_ok=True)
        wrapped.write_bytes(_dpapi(key, protect=True))
        if _dpapi(wrapped.read_bytes(), protect=False).strip() != key:
            raise RuntimeError("DPAPI round trip failed; keeping the plain key")
        if plain.exists():
            plain.unlink()               # converted: only the DPAPI-wrapped copy remains
        return key
    if not plain.exists():
        plain.parent.mkdir(parents=True, exist_ok=True)
        plain.write_bytes(Fernet.generate_key())
        try:
            os.chmod(plain, 0o600)
        except OSError:
            pass
    return plain.read_bytes().strip()


def _f() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt(value: str | None) -> str | None:
    if not value:
        return None
    return _f().encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return _f().decrypt(value.encode()).decode()
    except InvalidToken:
        raise RuntimeError("Stored credential cannot be decrypted (secret.key changed). Re-enter it in Settings.")
