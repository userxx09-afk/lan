"""Standard report library. Each entry is either a builder spec (opens in the report
builder for tweaking) or fixed read-only SQL over the v_* views."""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from .db import utcnow
from .reports import _rows, run_query


def S(dataset, fields, filters=None, sort=None, desc=False):
    return {"dataset": dataset, "fields": fields, "filters": filters or [], "sort": sort, "desc": desc}


def F(field, op, value=None):
    return {"field": field, "op": op, "value": value}


U = ["username", "display_name", "department", "title", "email", "ou", "last_logon"]
C = ["hostname", "os", "os_display_version", "model", "serial", "last_user", "ou", "last_seen"]

LIBRARY: list[tuple[str, str, str, dict]] = [
    # id, category, name, {"spec": ...} | {"sql": ...}
    ("ad_assets", "Active Directory", "Computers overview", {"spec": S("v_devices", ["hostname", "os", "ad_enabled", "ad_last_logon", "ad_created", "ou", "ad_description", "ad_location"], sort="hostname")}),
    ("ad_comp_nodesc", "Active Directory", "Computer has no description", {"spec": S("v_devices", ["hostname", "os", "ou", "ad_last_logon"], [F("ad_enabled", "eq", "1"), F("ad_description", "empty")], "hostname")}),
    ("ad_comp_noloc", "Active Directory", "Computer has no location", {"spec": S("v_devices", ["hostname", "os", "ou", "ad_last_logon"], [F("ad_enabled", "eq", "1"), F("ad_location", "empty")], "hostname")}),
    ("ad_comp_enabled", "Active Directory", "Enabled / disabled computers", {"sql": "SELECT CASE WHEN ad_enabled THEN 'Enabled' ELSE 'Disabled' END AS state, COUNT(*) AS computers FROM v_devices WHERE ad_enabled IS NOT NULL GROUP BY 1"}),
    ("ad_users_enabled", "Active Directory", "Enabled / disabled users", {"sql": "SELECT CASE WHEN enabled THEN 'Enabled' ELSE 'Disabled' END AS state, COUNT(*) AS users FROM v_users GROUP BY 1"}),
    ("ad_user_nodept", "Active Directory", "User has no department", {"spec": S("v_users", U, [F("enabled", "eq", "1"), F("department", "empty")], "username")}),
    ("ad_user_nodisplay", "Active Directory", "User has no display name", {"spec": S("v_users", U, [F("enabled", "eq", "1"), F("display_name", "empty")], "username")}),
    ("ad_user_noemail", "Active Directory", "User has no e-mail address", {"spec": S("v_users", U, [F("enabled", "eq", "1"), F("email", "empty")], "username")}),
    ("ad_user_nooffice", "Active Directory", "User has no office", {"spec": S("v_users", U, [F("enabled", "eq", "1"), F("office", "empty")], "username")}),
    ("ad_user_nophone", "Active Directory", "User has no telephone", {"spec": S("v_users", U, [F("enabled", "eq", "1"), F("phone", "empty")], "username")}),
    ("ad_user_notitle", "Active Directory", "User has no title", {"spec": S("v_users", U, [F("enabled", "eq", "1"), F("title", "empty")], "username")}),
    ("ad_user_locked", "Active Directory", "Locked out users", {"spec": S("v_users", U + ["bad_pwd_count"], [F("locked", "eq", "1")], "username")}),
    ("ad_user_pwdnever", "Active Directory", "Password never expires", {"spec": S("v_users", U + ["password_last_set"], [F("enabled", "eq", "1"), F("password_never_expires", "eq", "1")], "username")}),
    ("ad_user_stale", "Active Directory", "Users not logged on in 90 days", {"spec": S("v_users", U, [F("enabled", "eq", "1"), F("last_logon", "lt", "90d")], "last_logon")}),
    ("ad_user_pwdold", "Active Directory", "Password older than 1 year", {"spec": S("v_users", U + ["password_last_set"], [F("enabled", "eq", "1"), F("password_last_set", "lt", "365d")], "password_last_set")}),
    ("ad_dcs", "Active Directory", "Domain controllers and FSMO roles", {"spec": S("v_domain_controllers", ["hostname", "os", "site", "is_gc", "fsmo_roles", "last_seen"], sort="hostname")}),

    ("as_dup_serial", "Assets", "Duplicate serial numbers", {"sql": "SELECT serial, COUNT(*) AS computers, STRING_AGG_(hostname) AS hostnames FROM v_devices WHERE serial IS NOT NULL AND serial <> '' GROUP BY serial HAVING COUNT(*) > 1"}),
    ("as_smart", "Assets", "Hard drive health (SMART) status", {"spec": S("v_physical_disks", ["hostname", "model", "serial", "media", "size_gb", "health", "predict_failure"], sort="hostname")}),
    ("as_smart_bad", "Assets", "Hard drive health not OK", {"sql": "SELECT * FROM v_physical_disks WHERE health NOT IN ('Healthy','OK','0','') OR predict_failure = TRUE"}),
    ("as_disk_serial", "Assets", "Hard drive serial numbers", {"spec": S("v_physical_disks", ["hostname", "model", "serial", "size_gb"], sort="hostname")}),
    ("as_scan_times", "Assets", "Last scan times", {"spec": S("v_devices", ["hostname", "inventory_last_collected", "scan_error_kind", "scan_error", "ad_last_logon", "port_last_seen"], sort="inventory_last_collected")}),
    ("as_warranty", "Assets", "Warranty status", {"spec": S("v_devices", ["hostname", "manufacturer", "model", "serial", "purchase_date", "warranty_end"], sort="warranty_end")}),
    ("as_out_warranty", "Assets", "Out of warranty", {"spec": S("v_devices", ["hostname", "model", "serial", "warranty_end", "last_user"], [F("warranty_end", "lt", "0d")], "warranty_end")}),
    ("as_warranty60", "Assets", "Out of warranty in 60 days", {"spec": S("v_devices", ["hostname", "model", "serial", "warranty_end", "last_user"], [F("warranty_end", "ge", "0d"), F("warranty_end", "lt", "-60d")], "warranty_end")}),
    ("as_models", "Assets", "Computers by manufacturer and model", {"sql": "SELECT manufacturer, model, COUNT(*) AS computers FROM v_devices WHERE model IS NOT NULL GROUP BY manufacturer, model ORDER BY computers DESC"}),
    ("as_namelen", "Assets", "Computer name longer than 15 characters", {"sql": "SELECT hostname, os, ou FROM v_devices WHERE LENGTH(hostname) > 15"}),
    ("as_ram", "Assets", "Computers with 8 GB RAM or less", {"spec": S("v_devices", ["hostname", "model", "ram_gb", "cpu", "last_user"], [F("ram_gb", "le", "8")], "ram_gb")}),
    ("as_groups", "Assets", "Computers by group", {"sql": "SELECT g.name AS group_name, COUNT(*) AS computers FROM device_groups g GROUP BY g.name ORDER BY computers DESC"}),
    ("as_av", "Assets", "Antivirus status", {"spec": S("v_devices", ["hostname", "role", "av_name", "av_enabled", "av_up_to_date", "inventory_last_collected"], sort="av_name")}),

    ("os_versions", "Operating system", "Computers by OS and version", {"sql": "SELECT os, os_display_version AS version, COUNT(*) AS computers FROM v_devices GROUP BY os, os_display_version ORDER BY computers DESC"}),
    ("os_builds", "Operating system", "Computers by build", {"sql": "SELECT os, os_display_version AS version, os_build AS build, COUNT(*) AS computers FROM v_devices WHERE os_build IS NOT NULL GROUP BY 1,2,3 ORDER BY 1,2,3"}),
    ("os_pending", "Operating system", "Pending Windows updates", {"spec": S("v_updates", ["hostname", "kb", "title", "severity"], [F("status", "eq", "pending")], "hostname")}),
    ("os_uptime", "Operating system", "Uptime more than 30 days", {"spec": S("v_devices", ["hostname", "os", "last_boot", "last_user"], [F("last_boot", "lt", "30d")], "last_boot")}),

    ("sw_titles", "Software", "Software titles and install counts", {"sql": "SELECT name, publisher, COUNT(DISTINCT hostname) AS computers, COUNT(DISTINCT version) AS versions FROM v_software GROUP BY name, publisher ORDER BY computers DESC"}),
    ("sw_versions", "Software", "Software versions", {"sql": "SELECT name, version, COUNT(*) AS computers FROM v_software GROUP BY name, version ORDER BY name, version"}),
    ("sw_all", "Software", "Installed software by computer", {"spec": S("v_software", ["hostname", "name", "version", "publisher", "install_date"], sort="hostname")}),
    ("sw_outdated", "Software", "Outdated apps (winget catalog)", {"spec": S("v_software", ["hostname", "name", "version", "latest_version", "catalog_id", "scope"], [F("status", "eq", "outdated")], "name")}),
    ("sw_outdated_apps", "Software", "Outdated apps by program", {"sql": "SELECT name, catalog_id, MAX(latest_version) AS latest_version, COUNT(DISTINCT hostname) AS computers_behind FROM v_software WHERE status = 'outdated' GROUP BY name, catalog_id ORDER BY computers_behind DESC"}),
    ("sw_unknown", "Software", "Apps not found in the app catalog", {"sql": "SELECT name, publisher, COUNT(DISTINCT hostname) AS computers FROM v_software WHERE status = 'unknown' OR status IS NULL GROUP BY name, publisher ORDER BY computers DESC"}),
    ("sw_catalog_status", "Software", "Installs by app catalog status", {"sql": "SELECT COALESCE(status, 'not checked') AS status, COUNT(*) AS installs, COUNT(DISTINCT hostname) AS computers FROM v_software GROUP BY 1 ORDER BY installs DESC"}),
    ("sw_changes", "Software", "Software installed or removed in the last 30 days", {"spec": S("v_changes", ["time", "hostname", "kind", "detail"], [F("kind", "contains", "software"), F("time", "gt", "30d")], "time", True)}),

    ("net_portmap", "Network", "Which port each computer is plugged into", {"spec": S("v_port_map", ["hostname", "ip", "mac", "switch_name", "port", "port_alias", "vlan", "last_seen"], sort="switch_name")}),
    ("net_per_switch", "Network", "Devices per switch", {"sql": "SELECT switch_name, COUNT(*) AS macs, COUNT(hostname) AS known_computers FROM v_port_map GROUP BY switch_name ORDER BY switch_name"}),
    ("net_unknown", "Network", "Unknown MAC addresses on access ports", {"spec": S("v_port_map", ["mac", "ip", "switch_name", "port", "vlan", "last_seen"], [F("hostname", "empty")], "switch_name")}),
    ("net_moves", "Network", "Computers that moved switch port", {"spec": S("v_changes", ["time", "hostname", "detail"], [F("kind", "eq", "moved")], "time", True)}),
    ("net_devices", "Network", "Network devices", {"spec": S("v_network_devices", ["sysname", "ip", "vendor", "location", "port_count", "last_polled", "poll_error"], sort="sysname")}),
    ("net_ports_down", "Network", "Switch ports down", {"spec": S("v_switch_ports", ["switch_name", "port", "alias", "speed_mbps"], [F("oper_up", "eq", "0")], "switch_name")}),

    ("lg_last_user", "Logons", "Last user per computer", {"spec": S("v_devices", ["hostname", "last_user", "last_user_logon", "current_user"], sort="hostname")}),
    ("lg_user_devices", "Logons", "Computers per user", {"spec": S("v_user_devices", ["username", "hostname", "last_logon", "logon_count"], sort="username")}),
    ("lg_shared", "Logons", "Computers used by 3 or more users", {"sql": "SELECT hostname, COUNT(*) AS users, MAX(last_logon) AS last_logon FROM v_user_devices GROUP BY hostname HAVING COUNT(*) >= 3 ORDER BY users DESC"}),
    ("lg_audit", "Logons", "Actions taken in NetInventory (audit)", {"spec": S("v_audit", ["time", "actor", "action", "target", "result"], sort="time", desc=True)}),
]


def catalog() -> list[dict]:
    return [{"id": i, "category": c, "name": n, "kind": "spec" if "spec" in d else "sql", "spec": d.get("spec")}
            for i, c, n, d in LIBRARY]


def run(db: Session, rid: str) -> dict:
    for i, c, n, d in LIBRARY:
        if i == rid:
            if "spec" in d:
                res = run_query(db, **d["spec"], limit=20000)
            else:
                sql = d["sql"]
                dialect = db.get_bind().dialect.name
                sql = sql.replace("STRING_AGG_(hostname)", "GROUP_CONCAT(hostname, ', ')" if dialect == "sqlite" else "STRING_AGG(hostname, ', ')")
                if dialect == "sqlite":
                    sql = sql.replace("= TRUE", "= 1")
                r = db.execute(text(sql))
                res = {"columns": list(r.keys()), "rows": _rows(r)}
            return {"id": i, "category": c, "name": n, **res}
    raise KeyError(rid)
