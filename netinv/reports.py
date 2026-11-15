"""Prebuilt reports, insights and the ad-hoc report builder.

Everything reads the v_* views from correlate.py. The builder only accepts
dataset and column names that exist in those views, and binds every value as a
parameter, so it is safe to expose in the UI.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from .db import utcnow

DATASETS = {
    "v_devices": "Computers (one row per PC)",
    "v_port_map": "Switch port map (where each MAC is plugged in)",
    "v_user_devices": "Users and the devices they logged on to",
    "v_logons": "Raw logon events",
    "v_software": "Installed software",
    "v_updates": "Windows updates (installed and pending)",
    "v_disks": "Disks",
    "v_switch_ports": "Switch ports",
    "v_network_devices": "Network devices",
    "v_domain_controllers": "Domain controllers",
    "v_users": "AD users (one row per user)",
    "v_physical_disks": "Physical disks and health",
    "v_changes": "Change history",
    "v_audit": "Audit log (actions taken in NetInventory)",
}

OPS = {"eq": "=", "ne": "<>", "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
       "contains": "LIKE", "not_contains": "NOT LIKE", "empty": "IS NULL", "not_empty": "IS NOT NULL", "in": "IN"}


def columns(db: Session, dataset: str) -> list[str]:
    return list(column_types(db, dataset))


def column_types(db: Session, dataset: str) -> dict[str, str]:
    if dataset not in DATASETS:
        raise ValueError(f"unknown dataset {dataset}")
    return {c["name"]: str(c["type"]).upper() for c in inspect(db.get_bind()).get_columns(dataset)}


def _as_bool(v):
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _rows(result) -> list[dict]:
    return [{k: (v.isoformat(sep=" ", timespec="seconds") if isinstance(v, datetime) else
                 float(v) if v.__class__.__name__ == "Decimal" else v)
             for k, v in r._mapping.items()} for r in result]


def run_query(db: Session, dataset: str, fields: list[str] | None = None, filters: list[dict] | None = None,
              sort: str | None = None, desc: bool = False, limit: int = 1000, offset: int = 0,
              count: bool = False) -> dict:
    types = column_types(db, dataset)
    cols = list(types)
    fields = [f for f in (fields or cols) if f in cols] or cols
    where, params = [], {}
    for i, f in enumerate(filters or []):
        col, op = f.get("field"), f.get("op", "eq")
        if col not in cols or op not in OPS:
            raise ValueError(f"bad filter {f}")
        if op in ("empty", "not_empty"):
            where.append(f'"{col}" {OPS[op]}')
            continue
        val = f.get("value")
        if op == "in":
            vals = val if isinstance(val, list) else [v.strip() for v in str(val).split(",")]
            names = [f"p{i}_{j}" for j in range(len(vals))] or ["p_none"]
            where.append(f'"{col}" IN (' + ", ".join(":" + n for n in names) + ")")
            params.update(dict(zip(names, vals)) if vals else {"p_none": None})
            continue
        if op in ("contains", "not_contains"):
            where.append(f'LOWER(CAST("{col}" AS TEXT)) {OPS[op]} :p{i}')
            params[f"p{i}"] = f"%{str(val).lower()}%"
        else:
            where.append(f'"{col}" {OPS[op]} :p{i}')
            params[f"p{i}"] = _as_bool(val) if "BOOL" in types.get(col, "") else _coerce(val)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = "SELECT " + ", ".join(f'"{c}"' for c in fields) + f" FROM {dataset}" + where_sql
    if sort in cols:
        sql += f' ORDER BY "{sort}" {"DESC" if desc else "ASC"} NULLS LAST'
    sql += f" LIMIT {max(1, min(int(limit), 100000))} OFFSET {max(0, int(offset))}"
    out = {"columns": fields, "rows": _rows(db.execute(text(sql), params))}
    if count:
        out["total"] = db.execute(text(f"SELECT COUNT(*) FROM {dataset}" + where_sql), params).scalar()
    return out


def _coerce(v):
    if isinstance(v, str):
        if re.fullmatch(r"-?\d+", v):
            return int(v)
        if re.fullmatch(r"-?\d+\.\d+", v):
            return float(v)
        m = re.fullmatch(r"(-?\d+)d", v)  # "30d" = 30 days ago, handy for date filters
        if m:
            return utcnow() - timedelta(days=int(m.group(1)))
    return v


# ------------------------------------------------------------------ OS lifecycle
# Microsoft end-of-servicing dates. Check https://learn.microsoft.com/lifecycle and
# override in config [insights.os_eol] as new releases ship.
OS_EOL_DEFAULT = {
    "Windows 10|*": "2025-10-14",
    "Windows 11|21H2|pro": "2023-10-10", "Windows 11|21H2|enterprise": "2024-10-08",
    "Windows 11|22H2|pro": "2024-10-08", "Windows 11|22H2|enterprise": "2025-10-14",
    "Windows 11|23H2|pro": "2025-11-11", "Windows 11|23H2|enterprise": "2026-11-10",
    "Windows 11|24H2|pro": "2026-10-13", "Windows 11|24H2|enterprise": "2027-10-12",
    "Windows 11|25H2|pro": "2027-10-12", "Windows 11|25H2|enterprise": "2028-10-10",
    "Server 2012|*": "2023-10-10", "Server 2016|*": "2027-01-12",
    "Server 2019|*": "2029-01-09", "Server 2022|*": "2031-10-14",
}


def os_eol(os_name: str | None, display_version: str | None, table: dict) -> date | None:
    if not os_name:
        return None
    o = os_name.lower()
    edition = "enterprise" if ("enterprise" in o or "education" in o) else "pro"
    for key, d in table.items():
        parts = key.split("|")
        if parts[0].lower() not in o:
            continue
        if parts[1] == "*" or (display_version and parts[1].lower() == display_version.lower()
                               and (len(parts) < 3 or parts[2] == edition)):
            if "ltsc" in o or "ltsb" in o:
                return None  # LTSC has its own long lifecycle
            return date.fromisoformat(d)
    return None


def _ver(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4])


# ------------------------------------------------------------------ insights
# Used when config.toml has no [[outdated_software]] rules. Bump min versions as vendors release.
DEFAULT_OUTDATED = [
    {"match": r"^Google Chrome$", "min_version": "142.0"},
    {"match": r"^Mozilla Firefox", "min_version": "140.0"},
    {"match": r"^7-Zip (9|1\d|2[0-3])\.", "eol": True, "label": "7-Zip older than 24.x"},
    {"match": r"^Java (6|7|8) Update", "min_version": "8.0.4610", "label": "Java 8 below update 461"},
    {"match": r"Office .*(2010|2013|2016|2019)", "eol": True, "label": "Office 2019 or older (out of support)"},
    {"match": r"^Notepad\+\+", "min_version": "8.8"},
    {"match": r"^Zoom", "min_version": "6.0"},
    {"match": r"^Adobe Acrobat Reader", "min_version": "25.0"},
]


def insights(db: Session, cfg: dict, outdated_rules: list[dict]) -> dict:
    outdated_rules = outdated_rules or DEFAULT_OUTDATED
    now = utcnow()
    low_pct = cfg.get("low_disk_pct", 10)
    low_gb = cfg.get("low_disk_gb", 10)
    patch_days = cfg.get("patch_age_days", 35)
    stale_days = cfg.get("stale_ad_days", 90)
    uptime_days = cfg.get("uptime_days", 30)
    eol_table = {**OS_EOL_DEFAULT, **cfg.get("os_eol", {})}

    devs = _rows(db.execute(text("SELECT * FROM v_devices")))
    def dt(s):
        return datetime.fromisoformat(s) if isinstance(s, str) else s

    out: dict[str, list] = {k: [] for k in ("low_disk", "pending_updates", "patch_overdue", "os_unsupported",
                                             "pending_reboot", "long_uptime", "stale_ad", "not_inventoried",
                                             "outdated_software", "unknown_on_network")}
    for d in devs:
        h = d["hostname"]
        if d["ad_enabled"] is False:
            continue
        if d["ad_last_logon"] and dt(d["ad_last_logon"]) < now - timedelta(days=stale_days):
            out["stale_ad"].append({"hostname": h, "ad_last_logon": d["ad_last_logon"], "os": d["os"]})
            continue
        if not d["inventory_last_collected"] or dt(d["inventory_last_collected"]) < now - timedelta(days=7):
            out["not_inventoried"].append({"hostname": h, "last_collected": d["inventory_last_collected"],
                                           "ad_last_logon": d["ad_last_logon"]})
        if d["pending_updates"]:
            out["pending_updates"].append({"hostname": h, "pending": d["pending_updates"], "last_user": d["last_user"]})
        if d["inventory_last_collected"] and (not d["last_patch_installed"]
                                              or dt(d["last_patch_installed"]) < now - timedelta(days=patch_days)):
            out["patch_overdue"].append({"hostname": h, "last_patch": d["last_patch_installed"], "os": d["os"]})
        eol = os_eol(d["os"], d["os_display_version"], eol_table)
        if eol and eol <= now.date():
            out["os_unsupported"].append({"hostname": h, "os": d["os"], "version": d["os_display_version"],
                                          "end_of_support": eol.isoformat()})
        if d["pending_reboot"]:
            out["pending_reboot"].append({"hostname": h, "last_boot": d["last_boot"]})
        if d["last_boot"] and dt(d["last_boot"]) < now - timedelta(days=uptime_days):
            out["long_uptime"].append({"hostname": h, "last_boot": d["last_boot"]})

    for r in _rows(db.execute(text("SELECT * FROM v_disks"))):
        if r["pct_free"] is not None and (r["pct_free"] < low_pct or r["free_gb"] < low_gb):
            out["low_disk"].append(r)

    if outdated_rules:
        sw = _rows(db.execute(text("SELECT hostname, name, version FROM v_software")))
        for rule in outdated_rules:
            pat = re.compile(rule["match"], re.I)
            minv = _ver(rule.get("min_version"))
            for s in sw:
                if pat.search(s["name"]) and (rule.get("eol") or _ver(s["version"]) < minv):
                    out["outdated_software"].append({**s, "required": rule.get("min_version") or "remove (end of life)",
                                                     "rule": rule.get("label", rule["match"])})

    out["unknown_on_network"] = _rows(db.execute(text(
        "SELECT mac, ip, switch_name, port, vlan, last_seen FROM v_port_map WHERE hostname IS NULL "
        "ORDER BY last_seen DESC LIMIT 500")))
    return out


PREBUILT = {
    "pc_overview": ("All PCs: OS, last user, port, disk", "v_devices",
                    ["hostname", "os", "os_display_version", "model", "serial", "last_user", "last_user_logon",
                     "ip", "switch_name", "switch_port", "vlan", "c_free_gb", "pending_updates", "last_patch_installed"],
                    [], "hostname"),
    "last_logon_by_device": ("Last user per device", "v_devices",
                             ["hostname", "last_user", "last_user_logon", "current_user", "ad_last_logon"], [], "last_user_logon"),
    "devices_by_user": ("Devices per user (most recent first)", "v_user_devices",
                        ["username", "hostname", "last_logon", "logon_count"], [], "username"),
    "port_map": ("Which port each PC is plugged into", "v_port_map",
                 ["hostname", "ip", "mac", "switch_name", "port", "port_alias", "vlan", "last_seen"], [], "switch_name"),
    "software_catalog": ("Installed software (all PCs)", "v_software",
                         ["name", "version", "publisher", "hostname"], [], "name"),
    "pending_updates": ("Pending Windows updates", "v_updates", ["hostname", "kb", "title", "severity"],
                        [{"field": "status", "op": "eq", "value": "pending"}], "hostname"),
    "domain_controllers": ("Domain controllers", "v_domain_controllers",
                           ["hostname", "os", "site", "is_gc", "fsmo_roles", "last_seen"], [], "hostname"),
    "switches": ("Network devices", "v_network_devices",
                 ["sysname", "ip", "vendor", "location", "port_count", "last_polled", "poll_error"], [], "sysname"),
}
