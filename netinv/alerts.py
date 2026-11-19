"""Alert rules for the dashboard, grouped High priority / Important / Informational.

Each rule returns the rows behind it, so a count on the dashboard always opens the
exact list of computers or users. Thresholds come from config [insights].
"""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import settings
from .db import utcnow
from .reports import DEFAULT_OUTDATED, OS_EOL_DEFAULT, _rows, _ver, outdated_installs
from .reports import os_eol as eol_date

HIGH, IMPORTANT, INFO = "high", "important", "info"
DEV_COLS = "hostname, os, os_display_version, role, last_user, ip, switch_name, switch_port, last_seen"


def _q(db: Session, sql: str, **params) -> list[dict]:
    return _rows(db.execute(text(sql), params))


def _active(where: str) -> str:
    return f"SELECT {DEV_COLS} FROM v_devices WHERE (ad_enabled IS NULL OR ad_enabled = TRUE) AND ({where}) ORDER BY hostname"


def _cfg(key, default):
    return settings.insights.get(key, default)


# ------------------------------------------------------------------ rule functions
def os_eol_rows(db):
    table = {**OS_EOL_DEFAULT, **_cfg("os_eol", {})}
    today = utcnow().date()
    out = []
    for d in _q(db, _active("os IS NOT NULL")):
        eol = eol_date(d["os"], d["os_display_version"], table)
        if eol and eol <= today:
            out.append({**d, "end_of_support": eol.isoformat()})
    return out


def not_latest_build(db, family: str):
    """Builds behind the newest build seen in the fleet for the same OS version (or a configured target)."""
    rows = _q(db, _active("os_build IS NOT NULL AND LOWER(os) LIKE :f").replace(DEV_COLS, DEV_COLS + ", os_build"),
              f=f"%{family.lower()}%")
    targets = _cfg("latest_builds", {})
    best: dict[str, tuple] = {}
    for r in rows:
        key = r["os_display_version"] or ""
        best[key] = max(best.get(key, ()), _ver(r["os_build"]))
    out = []
    for r in rows:
        key = r["os_display_version"] or ""
        want = _ver(targets.get(f"{family}|{key}")) or best[key]
        if _ver(r["os_build"]) < want:
            out.append({**r, "latest_build": ".".join(map(str, want))})
    return out


def outdated_software(db):
    rules = settings.outdated_software or DEFAULT_OUTDATED
    return [{**s, "required": rule.get("min_version") or "remove (end of life)"}
            for rule, s in outdated_installs(db, rules)]


def _days(n):
    return utcnow() - timedelta(days=n)


RULES: list[tuple[str, str, str, callable]] = [
    # ---- High priority
    ("os_eol", HIGH, "OS: End of life (no longer supported)", os_eol_rows),
    ("scan_denied", HIGH, "Scan issues: WinRM access denied",
     lambda db: _q(db, _active("scan_error_kind = 'access_denied'").replace(DEV_COLS, DEV_COLS + ", scan_error"))),
    ("disk_server_1gb", HIGH, "Disk: Servers with less than 1 GB free",
     lambda db: _q(db, _active("role = 'Server' AND min_disk_free_gb < 1"))),
    ("disk_ws_1gb", HIGH, "Disk: Workstations with less than 1 GB free",
     lambda db: _q(db, _active("role = 'Workstation' AND min_disk_free_gb < 1"))),
    ("no_av_server", HIGH, "Server: No antivirus detected",
     lambda db: _q(db, _active("role = 'Server' AND inventory_last_collected IS NOT NULL AND (av_name IS NULL OR av_name = '')"))),
    ("no_av_ws", HIGH, "Workstation: No antivirus detected",
     lambda db: _q(db, _active("role = 'Workstation' AND inventory_last_collected IS NOT NULL AND (av_name IS NULL OR av_name = '')"))),
    ("smart", HIGH, "Asset: Hard drive health not OK (SMART)",
     lambda db: _q(db, "SELECT hostname, model, serial, media, health, predict_failure FROM v_physical_disks "
                       "WHERE health NOT IN ('Healthy', 'OK', '0', '') OR predict_failure = TRUE ORDER BY hostname")),
    ("locked_users", HIGH, "Users: Locked out accounts",
     lambda db: _q(db, "SELECT username, display_name, department, last_logon, bad_pwd_count FROM v_users "
                       "WHERE locked = TRUE AND enabled = TRUE ORDER BY username")),
    # ---- Important
    ("scan_unreachable", IMPORTANT, "Scan issues: WinRM unreachable",
     lambda db: _q(db, _active("scan_error_kind IN ('unreachable', 'other')").replace(DEV_COLS, DEV_COLS + ", scan_error"))),
    ("not_seen_30", IMPORTANT, "Computer: Not seen in the last 30 days",
     lambda db: _q(db, _active("last_seen < :d"), d=_days(30))),
    ("low_disk", IMPORTANT, "Disk: Less than 10% free",
     lambda db: _q(db, "SELECT hostname, drive, size_gb, free_gb, pct_free FROM v_disks WHERE pct_free < :p ORDER BY pct_free",
                   p=_cfg("low_disk_pct", 10))),
    ("warranty_expired", IMPORTANT, "Asset: Out of warranty",
     lambda db: _q(db, _active("warranty_end < :n").replace(DEV_COLS, DEV_COLS + ", model, serial, warranty_end"), n=utcnow())),
    ("warranty_60", IMPORTANT, "Asset: Warranty ends in the next 60 days",
     lambda db: _q(db, _active("warranty_end >= :n AND warranty_end < :e").replace(DEV_COLS, DEV_COLS + ", model, serial, warranty_end"),
                   n=utcnow(), e=utcnow() + timedelta(days=60))),
    ("av_disabled", IMPORTANT, "Workstation: Antivirus disabled",
     lambda db: _q(db, _active("av_name IS NOT NULL AND av_enabled = FALSE").replace(DEV_COLS, DEV_COLS + ", av_name"))),
    ("av_outdated", IMPORTANT, "Workstation: Antivirus definitions out of date",
     lambda db: _q(db, _active("av_name IS NOT NULL AND av_up_to_date = FALSE").replace(DEV_COLS, DEV_COLS + ", av_name"))),
    ("patch_overdue", IMPORTANT, "Updates: Not patched in 35 days",
     lambda db: _q(db, _active("inventory_last_collected IS NOT NULL AND (last_patch_installed IS NULL OR last_patch_installed < :d)")
                   .replace(DEV_COLS, DEV_COLS + ", last_patch_installed"), d=_days(_cfg("patch_age_days", 35)))),
    ("pending_updates", IMPORTANT, "Updates: Pending Windows updates",
     lambda db: _q(db, _active("pending_updates > 0").replace(DEV_COLS, DEV_COLS + ", pending_updates"))),
    ("outdated_sw", IMPORTANT, "Software: Outdated or end-of-life installs", outdated_software),
    ("catalog_outdated", INFO, "Software: Apps behind the latest version (winget catalog)",
     lambda db: _q(db, "SELECT name, catalog_id, MAX(latest_version) AS latest_version, COUNT(DISTINCT hostname) AS computers "
                       "FROM v_software WHERE status = 'outdated' GROUP BY name, catalog_id ORDER BY computers DESC")),
    ("unknown_mac", IMPORTANT, "Network: Unknown devices on switch ports",
     lambda db: _q(db, "SELECT mac, ip, switch_name, port, vlan, last_seen FROM v_port_map WHERE hostname IS NULL ORDER BY switch_name, port")),
    # ---- Informational
    ("build_win11", INFO, "OS: Not latest build of Windows 11", lambda db: not_latest_build(db, "Windows 11")),
    ("build_win10", INFO, "OS: Not latest build of Windows 10", lambda db: not_latest_build(db, "Windows 10")),
    ("build_2016", INFO, "OS: Not latest build of Windows Server 2016", lambda db: not_latest_build(db, "Server 2016")),
    ("build_2019", INFO, "OS: Not latest build of Windows Server 2019", lambda db: not_latest_build(db, "Server 2019")),
    ("build_2022", INFO, "OS: Not latest build of Windows Server 2022", lambda db: not_latest_build(db, "Server 2022")),
    ("build_2025", INFO, "OS: Not latest build of Windows Server 2025", lambda db: not_latest_build(db, "Server 2025")),
    ("pending_reboot", INFO, "Computer: Reboot pending",
     lambda db: _q(db, _active("pending_reboot = TRUE").replace(DEV_COLS, DEV_COLS + ", last_boot"))),
    ("stale_ad", INFO, "Active Directory: Enabled computers not logged on in 90 days",
     lambda db: _q(db, "SELECT hostname, os, ad_last_logon, ou FROM v_devices WHERE ad_enabled = TRUE AND ad_last_logon < :d ORDER BY ad_last_logon",
                   d=_days(_cfg("stale_ad_days", 90)))),
    ("stale_users", INFO, "Active Directory: Enabled users not logged on in 90 days",
     lambda db: _q(db, "SELECT username, display_name, department, last_logon FROM v_users WHERE enabled = TRUE AND (last_logon IS NULL OR last_logon < :d) ORDER BY last_logon",
                   d=_days(_cfg("stale_ad_days", 90)))),
    ("pwd_never_expires", INFO, "Active Directory: Users whose password never expires",
     lambda db: _q(db, "SELECT username, display_name, department, password_last_set FROM v_users WHERE enabled = TRUE AND password_never_expires = TRUE ORDER BY username")),
]


def summary(db: Session) -> list[dict]:
    out = []
    for rid, sev, title, fn in RULES:
        try:
            n = len(fn(db))
            err = None
        except Exception as exc:  # one broken rule must not break the dashboard
            db.rollback()
            n, err = None, str(exc)
        out.append({"id": rid, "severity": sev, "title": title, "count": n, "error": err})
    return out


def rows(db: Session, rid: str) -> dict:
    for r, sev, title, fn in RULES:
        if r == rid:
            data = fn(db)
            return {"id": rid, "title": title, "severity": sev, "rows": data,
                    "columns": list(data[0].keys()) if data else []}
    raise KeyError(rid)
