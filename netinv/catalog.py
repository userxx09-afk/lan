"""App catalog: match installed software to the public winget catalog and work out whether it is up to date.

Once a day the server downloads Microsoft's winget package index (``source2.msix``, about 4 MB, over HTTPS from
cdn.winget.microsoft.com) and keeps ``Public/index.db`` next to config.toml (``catalog/index.db``). Nothing is
installed on the PCs for this. Each installed program found by the PC scan is matched to a winget package:

1. a rule from Settings > App catalog (ignore it, map it to a package id, or set the version you want),
2. its uninstall key / MSI product code, which winget records for every package version (exact),
3. its name and publisher, normalized the way winget does it (version numbers, architecture, language and
   bracketed text removed from the name; legal suffixes like Inc. or GmbH removed from the publisher).

When several packages share a name (Python 3.11 and 3.12 are both "python"), the one whose version line matches
the installed version wins. Each software row then gets catalog_id, latest_version and sw_status:
``current``, ``outdated``, ``unknown`` (not in the catalog) or ``ignored``.
"""
from __future__ import annotations

import io
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.request
import zipfile
from collections import defaultdict
from contextlib import closing
from pathlib import Path

from sqlalchemy import select

from .config import settings
from .db import Software, SoftwareRule, SessionLocal, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)
DEFAULT_URL = "https://cdn.winget.microsoft.com/cache/source2.msix"
PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_\-]{0,127}$")
_lock = threading.Lock()


def _cfg() -> dict:
    return getattr(settings, "catalog", None) or {}


def catalog_file() -> Path:
    from .auth import data_dir
    return data_dir() / "catalog" / "index.db"


# ------------------------------------------------------------------ download
def refresh(db) -> str:
    """Download the winget index. Returns a short message; raises on failure."""
    url = _cfg().get("url") or DEFAULT_URL
    if not url.startswith("https://"):
        raise ValueError("catalog url must be https")
    req = urllib.request.Request(url, headers={"User-Agent": "NetInventory"})
    with urllib.request.urlopen(req, timeout=120) as r:
        blob = r.read(200 * 1024 * 1024)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        data = z.read("Public/index.db")
    out = catalog_file()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    tmp.write_bytes(data)
    with closing(sqlite3.connect(tmp)) as c:   # sanity check before replacing the old copy (closed, or Windows keeps it locked)
        n = c.execute("SELECT COUNT(*) FROM packages").fetchone()[0]
    if n < 1000:
        tmp.unlink(missing_ok=True)
        raise ValueError(f"catalog looks wrong ({n} packages)")
    os.replace(tmp, out)
    set_setting(db, "catalog:updated", utcnow().isoformat(timespec="seconds"))
    set_setting(db, "catalog:packages", str(n))
    set_setting(db, "catalog:error", None)
    db.commit()
    return f"{n} packages"


# ------------------------------------------------------------------ normalization
_ARCH = r"x64|x86|x86_64|amd64|arm64|arm|ia64|win64|win32|64[\s\-]?bit|32[\s\-]?bit"
_NAME_DROP = [
    re.compile(r"\([^)]*\)|\[[^\]]*\]"),                                # bracketed text
    re.compile(rf"(?<![a-z0-9])({_ARCH})(?![a-z0-9])"),                 # architecture
    re.compile(r"(?<![a-z])[a-z]{2}-[a-z]{2}(?![a-z])"),                # language (en-us)
    re.compile(r"(?<![a-z0-9])v?\d+(\.\d+)+[a-z0-9\-]*"),               # dotted versions
    re.compile(r"(?<![a-z0-9])(version|ver|build|release)\s*\d+"),
]
_LEGAL = {"inc", "incorporated", "corp", "corporation", "co", "company", "llc", "ltd", "limited", "gmbh", "ag",
          "sa", "sas", "sarl", "srl", "bv", "nv", "plc", "pty", "pvt", "oy", "ab", "as", "aps", "kg", "kk", "spa",
          "sro", "spzoo", "lp", "llp", "the"}


def norm_name(name: str | None) -> str:
    s = (name or "").lower().replace("(r)", "").replace("(tm)", "").replace("®", "").replace("™", "")
    for rx in _NAME_DROP:
        s = rx.sub(" ", s)
    return "".join(ch for ch in s if ch.isalnum())


def norm_publisher(pub: str | None) -> str:
    s = (pub or "").lower().replace("(r)", "").replace("®", "")
    s = re.sub(r"\([^)]*\)", " ", s)
    words = [w for w in re.split(r"[\s,]+", s) if w]
    while words and re.sub(r"[^a-z]", "", words[-1]) in _LEGAL:
        words.pop()
    return "".join(ch for ch in "".join(words) if ch.isalnum())


def vt(v: str | None) -> tuple:
    """Version tuple: first 4 numbers, padded, so 3.12.10 == 3.12.10.0."""
    nums = [int(x) for x in re.findall(r"\d+", v or "")[:4]]
    return tuple(nums + [0] * (4 - len(nums))) if nums else ()


# ------------------------------------------------------------------ matching
class Catalog:
    def __init__(self, path: Path):
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        self.pkg = {r[0]: {"id": r[1], "name": r[2], "latest": r[3], "arp_min": r[4], "arp_max": r[5]}
                    for r in c.execute("SELECT rowid, id, name, latest_version, arp_min_version, arp_max_version FROM packages")}
        self.by_id = {p["id"].lower(): k for k, p in self.pkg.items()}
        self.by_code = defaultdict(set)
        for code, p in c.execute("SELECT productcode, package FROM productcodes2"):
            self.by_code[code.lower()].add(p)
        self.by_name = defaultdict(set)
        for n, p in c.execute("SELECT norm_name, package FROM norm_names2"):
            self.by_name[re.sub(r"\([A-Z0-9]+\)$", "", n)].add(p)
        self.pubs = defaultdict(set)
        for n, p in c.execute("SELECT norm_publisher, package FROM norm_publishers2"):
            self.pubs[p].add(n)
        c.close()

    def _pick(self, cands: set, version: str | None) -> tuple[int | None, bool]:
        """(package, exact). exact is False when the choice is only "same product family, all newer"."""
        if len(cands) == 1:
            return next(iter(cands)), True
        v = vt(version)
        if not v:
            return None, False
        # ARP version range from the manifests first, then the same major.minor, then the same major
        inr = [k for k in cands if self.pkg[k]["arp_min"] and self.pkg[k]["arp_max"]
               and vt(self.pkg[k]["arp_min"]) <= v <= vt(self.pkg[k]["arp_max"])]
        if len(inr) == 1:
            return inr[0], True
        for depth in (2, 1):
            same = [k for k in cands if vt(self.pkg[k]["latest"])[:depth] == v[:depth]]
            if len(same) == 1:
                return same[0], True
            if same:
                cands = set(same)
        # Still several (e.g. the 32-bit and 64-bit Reader packages). If they are one family and all newer than
        # what is installed, the install is behind either way: report the newest, but don't offer a one-click update.
        ids = [self.pkg[k]["id"] for k in cands]
        fam = len({i.split(".")[0].lower() for i in ids}) == 1
        if fam and all(vt(self.pkg[k]["latest"]) > v for k in cands):
            return max(cands, key=lambda k: vt(self.pkg[k]["latest"])), False
        return None, False

    def match(self, name: str, version: str | None, publisher: str | None, code: str | None) -> tuple[int | None, str]:
        if code:
            hit = self.by_code.get(code.strip().lower())
            if hit:
                k, exact = self._pick(hit, version)
                if k is not None:
                    return k, "product code" if exact else "family"
        n = norm_name(name)
        if not n:
            return None, ""
        cands = self.by_name.get(n, set())
        if not cands:
            return None, ""
        pub = norm_publisher(publisher)
        if pub:
            same_pub = {k for k in cands if any(pub == p or pub.startswith(p) or p.startswith(pub) for p in self.pubs[k])}
            if not same_pub:
                return None, ""     # same name, other publisher: don't guess
            cands = same_pub
        elif len(cands) > 1:
            return None, ""
        k, exact = self._pick(cands, version)
        return (k, "name" if exact else "family") if k is not None else (None, "")

    def status(self, k: int, version: str | None) -> tuple[str, str]:
        p = self.pkg[k]
        want = p["arp_max"] if p["arp_max"] and vt(p["arp_max"]) else p["latest"]
        have = vt(version)
        if not have:
            return "unknown", p["latest"]
        return ("outdated" if have < vt(want) else "current"), p["latest"]


def _rules(db) -> list[tuple[re.Pattern, SoftwareRule]]:
    out = []
    for r in db.scalars(select(SoftwareRule).order_by(SoftwareRule.id)):
        try:
            out.append((re.compile(r.match, re.I), r))
        except re.error:
            continue
    return out


def reconcile(db, only_new: bool = False) -> str:
    """Set catalog_id / latest_version / sw_status on software rows. only_new: rows never reconciled."""
    path = catalog_file()
    if not path.exists():
        return "No catalog downloaded yet."
    with _lock:
        cat = Catalog(path)
        rules = _rules(db)
        q = select(Software)
        if only_new:
            q = q.where(Software.sw_status.is_(None))
        cache: dict[tuple, tuple] = {}
        counts: dict[str, int] = defaultdict(int)
        for s in db.scalars(q):
            key = (s.name, s.version, s.publisher, s.product_code)
            if key not in cache:
                cache[key] = _one(cat, rules, s)
            s.catalog_id, s.latest_version, s.sw_status, s.match_method = cache[key]
            counts[s.sw_status] += 1
        db.commit()
    set_setting(db, "catalog:reconciled", utcnow().isoformat(timespec="seconds"))
    db.commit()
    return ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "no software rows"


def _one(cat: Catalog, rules, s: Software) -> tuple:
    for rx, r in rules:
        if not rx.search(s.name or ""):
            continue
        if r.action == "ignore":
            return None, None, "ignored", "rule"
        if r.action == "package":
            k = cat.by_id.get((r.value or "").lower())
            if k is not None:
                st, latest = cat.status(k, s.version)
                return cat.pkg[k]["id"], latest, st, "rule"
        if r.action == "target":
            have, want = vt(s.version), vt(r.value)
            return None, r.value, ("unknown" if not have else "outdated" if have < want else "current"), "rule"
    k, how = cat.match(s.name, s.version, s.publisher, s.product_code)
    if k is None:
        return None, None, "unknown", None
    st, latest = cat.status(k, s.version)
    return cat.pkg[k]["id"], latest, st, how


def package_exists(pid: str) -> bool:
    if not PACKAGE_ID_RE.match(pid or ""):
        return False
    path = catalog_file()
    if not path.exists():
        return False
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as c:
        return c.execute("SELECT 1 FROM packages WHERE id = ? COLLATE NOCASE", (pid,)).fetchone() is not None


def search(q: str, limit: int = 20) -> list[dict]:
    path = catalog_file()
    if not path.exists() or not q.strip():
        return []
    like = f"%{q.strip()}%"
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as c:
        return [{"id": r[0], "name": r[1], "latest_version": r[2]} for r in c.execute(
            "SELECT id, name, latest_version FROM packages WHERE id LIKE ? OR name LIKE ? ORDER BY length(name) LIMIT ?",
            (like, like, limit))]


def status_info(db) -> dict:
    return {k: get_setting(db, f"catalog:{k}") for k in ("updated", "packages", "error", "reconciled")}


# ------------------------------------------------------------------ daily loop
def loop(stop: threading.Event) -> None:
    hours = float(_cfg().get("refresh_hours", 24))
    if hours <= 0:
        return
    stop.wait(60)
    while not stop.is_set():
        try:
            with SessionLocal() as db:
                last = get_setting(db, "catalog:updated")
                due = not last or not catalog_file().exists() or \
                    (utcnow() - __import__("datetime").datetime.fromisoformat(last)).total_seconds() > hours * 3600
                if due:
                    try:
                        log.info("App catalog: %s", refresh(db))
                        log.info("App catalog reconcile: %s", reconcile(db))
                    except Exception as exc:
                        log.warning("App catalog download failed: %s", exc)
                        set_setting(db, "catalog:error", f"{type(exc).__name__}: {exc}"[:300])
                        db.commit()
        except Exception:
            log.exception("catalog loop")
        stop.wait(3600)
