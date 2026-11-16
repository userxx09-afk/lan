"""Self-update from the prod repo.

The CI build of the `lan` repo publishes every installer to github.com/userxx09-afk/prod as the
rolling release `lan-latest`, next to a latest.json:

    {"version": "0.3.12", "file": "NetInventory-Setup-0.3.12.exe", "url": "https://github.com/...",
     "sha256": "...", "notes": "...", "published": "2026-11-16T10:00:00Z"}

The server checks that file (daily by default) and the Settings tab shows when a newer version is out.
Installing downloads the setup exe, checks its SHA-256, and runs it silently from a one-off
scheduled task as SYSTEM: setup stops the services, replaces the program files, keeps
config.toml, secret.key and the database, migrates the schema and starts the services again.

config.toml [update] (all optional):
    url          = "https://github.com/userxx09-afk/prod/releases/download/lan-latest/latest.json"
    check_hours  = 24      # 0 turns the check off
    auto_install = false   # true installs new versions as soon as they're found
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .config import settings
from .db import SessionLocal, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)
DEFAULT_URL = "https://github.com/userxx09-afk/prod/releases/download/lan-latest/latest.json"
ALLOWED_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
                 "raw.githubusercontent.com"}
_lock = threading.Lock()
STATE = {"installing": False, "message": None}


def _cfg(key, default):
    return settings.update.get(key, default)


def parse_version(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", (v or "").split("-")[0])[:4]) or (0,)


def install_dir() -> Path | None:
    """The install folder when running from the Windows installer's bundled Python, else None."""
    if os.name != "nt":
        return None
    root = Path(sys.executable).resolve().parent.parent       # <app>\python\python.exe -> <app>
    return root if (root / "service" / "NetInventory.exe").exists() else None


def _check_url(url: str) -> str:
    u = urlparse(url)
    if u.scheme != "https" or (u.hostname or "").lower() not in ALLOWED_HOSTS:
        raise ValueError(f"Refusing update URL {url}: only https GitHub addresses are allowed.")
    return url


def _get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(_check_url(url), headers={"User-Agent": f"NetInventory/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # follows redirects to the asset CDN
        _check_url(r.geturl())
        return r.read()


def check(db=None) -> dict:
    """Fetch latest.json and remember the result. Never raises: errors land in the result."""
    own = db is None
    db = db or SessionLocal()
    try:
        try:
            m = json.loads(_get(_cfg("url", DEFAULT_URL)).decode("utf-8-sig"))
            for k in ("version", "url", "sha256"):
                if not m.get(k):
                    raise ValueError(f"latest.json has no {k}")
            if not re.fullmatch(r"[0-9a-fA-F]{64}", m["sha256"]):
                raise ValueError("latest.json has an invalid sha256")
            _check_url(m["url"])
            set_setting(db, "update:latest", json.dumps(m))
            set_setting(db, "update:error", None)
        except Exception as exc:
            log.warning("update check failed: %s", exc)
            set_setting(db, "update:error", str(exc)[:500])
        set_setting(db, "update:checked", utcnow().isoformat(timespec="seconds"))
        db.commit()
        return status(db)
    finally:
        if own:
            db.close()


def status(db) -> dict:
    latest = json.loads(get_setting(db, "update:latest", None) or "null")
    available = bool(latest) and parse_version(latest["version"]) > parse_version(__version__)
    return {"current": __version__, "latest": latest and latest.get("version"), "available": available,
            "notes": latest and latest.get("notes"), "published": latest and latest.get("published"),
            "checked": get_setting(db, "update:checked", None), "error": get_setting(db, "update:error", None),
            "can_install": install_dir() is not None, "auto_install": bool(_cfg("auto_install", False)),
            "installing": STATE["installing"], "message": STATE["message"] or get_setting(db, "update:message", None)}


def install(db, force: bool = False) -> str:
    """Download, verify and launch the latest installer. Returns a message for the UI.
    force=True reinstalls the newest published version even when this one is already up to date (a repair)."""
    app = install_dir()
    if app is None:
        raise RuntimeError("Updates install only on a Windows server set up with the NetInventory installer. "
                           "For Docker, pull the new image instead.")
    st = check(db) if force else status(db)      # a repair always installs what is published right now
    if force and not st["latest"]:
        raise RuntimeError(f"Couldn't read the newest version: {st['error'] or 'no answer'}")
    if not force and not st["available"]:
        raise RuntimeError(f"Already on the newest version ({__version__}).")
    if not _lock.acquire(blocking=False):
        raise RuntimeError("An update is already being installed.")
    try:
        STATE["installing"] = True
        m = json.loads(get_setting(db, "update:latest"))
        data_dir = Path(os.environ.get("NETINV_CONFIG", str(app / "config.toml"))).resolve().parent
        folder = data_dir / "updates"
        folder.mkdir(parents=True, exist_ok=True)
        name = re.sub(r"[^A-Za-z0-9._-]", "", m.get("file") or f"NetInventory-Setup-{m['version']}.exe")
        exe = folder / name
        STATE["message"] = f"Downloading {m['version']}…"
        blob = _get(m["url"], timeout=600)
        digest = hashlib.sha256(blob).hexdigest()
        if digest.lower() != m["sha256"].lower():
            raise RuntimeError(f"Download check failed (SHA-256 {digest[:12]}… doesn't match latest.json). Nothing was installed.")
        if blob[:2] != b"MZ":
            raise RuntimeError("The download is not a Windows program. Nothing was installed.")
        exe.write_bytes(blob)
        logf = data_dir / "logs" / f"update-{m['version']}.log"
        cmd = f'"{exe}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG="{logf}"'
        task = "NetInventory update"
        start = (datetime.now() + timedelta(minutes=1)).strftime("%H:%M")
        # A one-off task as SYSTEM, so setup keeps running after it stops this service.
        subprocess.run(["schtasks", "/Create", "/TN", task, "/TR", cmd, "/SC", "ONCE", "/ST", start,
                        "/RU", "SYSTEM", "/RL", "HIGHEST", "/F", "/Z", "/V1"], check=True, capture_output=True)
        subprocess.run(["schtasks", "/Run", "/TN", task], check=True, capture_output=True)
        verb = "Reinstalling" if parse_version(m["version"]) <= parse_version(__version__) else "Installing"
        msg = (f"{verb} {m['version']}. NetInventory restarts in a minute or two; this page reconnects by itself. "
               f"Log: {logf}")
        STATE["message"] = msg
        set_setting(db, "update:message", msg)
        db.commit()
        return msg
    except subprocess.CalledProcessError as exc:
        STATE["installing"] = False
        raise RuntimeError(f"Could not start setup: {(exc.stderr or b'').decode(errors='replace').strip()}") from exc
    except Exception:
        STATE["installing"] = False
        STATE["message"] = None
        raise
    finally:
        _lock.release()


def loop(stop: threading.Event) -> None:
    """Check on start (after a minute) and then every check_hours; install if auto_install is on."""
    stop.wait(60)
    while not stop.is_set():
        hours = float(_cfg("check_hours", 24) or 0)
        if hours <= 0:
            stop.wait(3600)
            continue
        with SessionLocal() as db:
            last = get_setting(db, "update:checked", None)
            due = not last or datetime.fromisoformat(last) < utcnow() - timedelta(hours=hours)
            if due:
                st = check(db)
                if st["available"] and st["auto_install"] and st["can_install"]:
                    try:
                        install(db)
                    except Exception as exc:
                        log.warning("auto update failed: %s", exc)
                        set_setting(db, "update:error", str(exc)[:500])
                        db.commit()
        stop.wait(900)
