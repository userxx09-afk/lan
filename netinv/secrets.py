"""Encryption at rest for stored credentials (Fernet / AES-128-CBC + HMAC).

The key lives in a file next to config.toml (secret.key), which the installer
locks down to Administrators and SYSTEM. Losing the key means re-entering the
credentials; it does not affect any other data.
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


def _f() -> Fernet:
    global _fernet
    if _fernet is None:
        p = _key_path()
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(Fernet.generate_key())
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        _fernet = Fernet(p.read_bytes().strip())
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
