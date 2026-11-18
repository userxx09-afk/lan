"""Correlation layer: SQL views that join AD, endpoint, logon and switch data.

The views are the reporting surface. The dashboard, the report builder and any BI
tool (Power BI, Excel, Metabase, Grafana) all read the same v_* views.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

VIEWS: dict[str, str] = {
    # Where each MAC physically is: latest sighting on an edge (non-uplink) port.
    "v_port_map": """
        SELECT mac, switch_name, switch_ip, port, port_alias, vlan, last_seen, first_seen, ip,
               hostname
        FROM (
          SELECT ms.mac, nd.sysname AS switch_name, nd.ip AS switch_ip, sp.name AS port,
                 sp.alias AS port_alias, ms.vlan, ms.last_seen, ms.first_seen,
                 (SELECT a.ip FROM arp_entries a WHERE a.mac = ms.mac ORDER BY a.last_seen DESC LIMIT 1) AS ip,
                 (SELECT d.hostname FROM device_nics n JOIN devices d ON d.id = n.device_id
                   WHERE n.mac = ms.mac LIMIT 1) AS hostname,
                 ROW_NUMBER() OVER (PARTITION BY ms.mac ORDER BY ms.last_seen DESC, sp.mac_count ASC) AS rn
          FROM mac_sightings ms
          JOIN switch_ports sp ON sp.id = ms.port_id
          JOIN network_devices nd ON nd.id = sp.switch_id
          WHERE sp.is_uplink = FALSE
        ) x WHERE rn = 1
    """,
    "v_user_devices": """
        SELECT username, hostname, MAX(time) AS last_logon, MIN(time) AS first_logon, COUNT(*) AS logon_count
        FROM logon_events WHERE hostname IS NOT NULL
        GROUP BY username, hostname
    """,
    "v_disks": """
        SELECT d.hostname, k.drive, k.size_gb, k.free_gb,
               ROUND(CAST(k.free_gb * 100.0 / NULLIF(k.size_gb, 0) AS NUMERIC), 1) AS pct_free
        FROM disks k JOIN devices d ON d.id = k.device_id
    """,
    "v_software": """
        SELECT d.hostname, s.name, s.version, s.publisher, s.install_date, s.scope, s.product_code,
               s.catalog_id, s.latest_version, s.sw_status AS status, s.match_method
        FROM software s JOIN devices d ON d.id = s.device_id
    """,
    "v_updates": """
        SELECT d.hostname, u.status, u.kb, u.title, u.severity, u.installed_on
        FROM updates u JOIN devices d ON d.id = u.device_id
    """,
    # hostname = the computer the user was on; dc = the domain controller that logged it (DC events only).
    "v_logons": """
        SELECT l.time, l.username, l.hostname, l.ip, l.logon_type, l.source, l.host_via AS matched_by,
               CASE WHEN l.source LIKE 'dc:%' THEN SUBSTR(l.source, 4) END AS dc,
               CASE WHEN EXISTS (SELECT 1 FROM devices d WHERE d.hostname = l.hostname) THEN 1 ELSE 0 END AS in_inventory
        FROM logon_events l
    """,
    "v_switch_ports": """
        SELECT nd.sysname AS switch_name, nd.ip AS switch_ip, nd.vendor, sp.name AS port, sp.alias,
               sp.oper_up, sp.speed_mbps, sp.is_uplink, sp.mac_count, sp.neighbor, sp.neighbor_port,
               (SELECT COUNT(*) FROM v_port_map pm WHERE pm.switch_ip = nd.ip AND pm.port = sp.name) AS devices_on_port
        FROM switch_ports sp JOIN network_devices nd ON nd.id = sp.switch_id
    """,
    "v_network_devices": """
        SELECT sysname, ip, vendor, location, sysdescr, uptime_s, last_polled, poll_error,
               (SELECT COUNT(*) FROM switch_ports p WHERE p.switch_id = nd.id) AS port_count
        FROM network_devices nd
    """,
    "v_domain_controllers": """
        SELECT hostname, fqdn, os, os_version, site, is_gc, fsmo_roles, last_seen FROM domain_controllers
    """,
    # One wide row per PC: the "pull this field and that" table.
    "v_devices": """
        SELECT d.hostname, d.fqdn,
               COALESCE(d.os_caption, d.ad_os) AS os, COALESCE(d.os_display_version, AD_DISPLAY_VERSION_) AS os_display_version,
               d.os_build,
               d.manufacturer, d.model, d.serial, d.cpu, d.ram_gb,
               d.ad_enabled, d.ad_last_logon, d.ad_created, d.ad_dn,
               d.current_user,
               (SELECT ud.username FROM v_user_devices ud WHERE ud.hostname = d.hostname
                 ORDER BY ud.last_logon DESC LIMIT 1) AS last_user,
               (SELECT MAX(ud.last_logon) FROM v_user_devices ud WHERE ud.hostname = d.hostname) AS last_user_logon,
               d.last_boot, d.pending_updates, d.pending_reboot, d.last_patch_installed,
               (SELECT MIN(k.pct_free) FROM v_disks k WHERE k.hostname = d.hostname) AS min_disk_pct_free,
               (SELECT k.free_gb FROM v_disks k WHERE k.hostname = d.hostname AND k.drive = 'C:') AS c_free_gb,
               (SELECT COUNT(*) FROM software s WHERE s.device_id = d.id) AS software_count,
               COALESCE((SELECT n.mac FROM device_nics n WHERE n.device_id = d.id LIMIT 1),
                        (SELECT s.mac FROM ip_sightings s WHERE s.hostname = d.hostname AND s.source LIKE 'dhcp:%'
                          AND s.mac IS NOT NULL ORDER BY s.last_seen DESC LIMIT 1)) AS mac,
               COALESCE((SELECT n.ip FROM device_nics n WHERE n.device_id = d.id AND n.ip IS NOT NULL LIMIT 1),
                        (SELECT s.ip FROM ip_sightings s WHERE s.hostname = d.hostname AND s.source LIKE 'dhcp:%'
                          ORDER BY s.last_seen DESC LIMIT 1),
                        (SELECT s.ip FROM ip_sightings s WHERE s.hostname = d.hostname AND s.source = 'dns'
                          ORDER BY CASE WHEN s.ip LIKE '%:%' THEN 1 ELSE 0 END, s.last_seen DESC LIMIT 1)) AS ip,
               CASE WHEN EXISTS (SELECT 1 FROM device_nics n WHERE n.device_id = d.id AND n.ip IS NOT NULL) THEN 'inventory'
                    WHEN EXISTS (SELECT 1 FROM ip_sightings s WHERE s.hostname = d.hostname AND s.source LIKE 'dhcp:%') THEN 'DHCP'
                    WHEN EXISTS (SELECT 1 FROM ip_sightings s WHERE s.hostname = d.hostname AND s.source = 'dns') THEN 'DNS'
                    END AS ip_source,
               (SELECT pm.switch_name FROM v_port_map pm WHERE pm.hostname = d.hostname
                 ORDER BY pm.last_seen DESC LIMIT 1) AS switch_name,
               (SELECT pm.port FROM v_port_map pm WHERE pm.hostname = d.hostname
                 ORDER BY pm.last_seen DESC LIMIT 1) AS switch_port,
               (SELECT pm.vlan FROM v_port_map pm WHERE pm.hostname = d.hostname
                 ORDER BY pm.last_seen DESC LIMIT 1) AS vlan,
               (SELECT pm.last_seen FROM v_port_map pm WHERE pm.hostname = d.hostname
                 ORDER BY pm.last_seen DESC LIMIT 1) AS port_last_seen,
               d.agent_last_report AS inventory_last_collected,
               d.gpu, d.state, d.asset_location, d.purchase_date, d.warranty_end, d.first_seen,
               GREATEST_(COALESCE(d.agent_last_report, '1900-01-01'), COALESCE(d.ad_last_logon, '1900-01-01'),
                   COALESCE((SELECT MAX(pm.last_seen) FROM v_port_map pm WHERE pm.hostname = d.hostname), '1900-01-01')) AS last_seen,
               (SELECT STRING_AGG_(g.name) FROM device_groups g WHERE g.device_id = d.id) AS groups,
               (SELECT COUNT(*) FROM v_logons l WHERE l.hostname = d.hostname) AS logon_events,
               CASE WHEN d.ad_dn IS NULL THEN NULL ELSE SUBSTR(d.ad_dn, STRPOS_(d.ad_dn, ',') + 1) END AS ou,
               DOMAIN_ AS domain,
               CASE WHEN LOWER(COALESCE(d.os_caption, d.ad_os, '')) LIKE '%server%' THEN 'Server' ELSE 'Workstation' END AS role,
               d.av_name, d.av_enabled, d.av_up_to_date, d.scan_error_kind, d.scan_error, d.scan_error_time,
               d.ad_description, d.ad_location,
               d.online, d.online_checked, d.online_changed, d.online_via, d.last_boot AS uptime,
               CASE WHEN EXISTS (SELECT 1 FROM agents a WHERE a.hostname = d.hostname AND a.status = 'active') THEN 'active'
                    WHEN EXISTS (SELECT 1 FROM agents a WHERE a.hostname = d.hostname AND a.status = 'pending') THEN 'pending'
                    WHEN EXISTS (SELECT 1 FROM deployments x WHERE x.hostname = d.hostname AND x.action = 'agent_install'
                                 AND x.status IN ('sending', 'running')) THEN 'installing'
                    WHEN EXISTS (SELECT 1 FROM deployments x WHERE x.hostname = d.hostname AND x.action = 'agent_install'
                                 AND x.status = 'queued') THEN 'waiting'
                    WHEN (SELECT x.status FROM deployments x WHERE x.hostname = d.hostname AND x.action = 'agent_install'
                          ORDER BY x.created DESC, x.id DESC LIMIT 1) IN ('failed', 'expired') THEN 'failed'
                    WHEN EXISTS (SELECT 1 FROM agents a WHERE a.hostname = d.hostname) THEN 'revoked'
                    ELSE NULL END AS agent_status,
               COALESCE((SELECT a.note FROM agents a WHERE a.hostname = d.hostname AND a.status = 'pending'
                         ORDER BY a.enrolled DESC LIMIT 1),
                        (SELECT x.message FROM deployments x WHERE x.hostname = d.hostname AND x.action = 'agent_install'
                         ORDER BY x.created DESC, x.id DESC LIMIT 1)) AS agent_note,
               (SELECT MAX(a.last_seen) FROM agents a WHERE a.hostname = d.hostname AND a.status <> 'revoked') AS agent_last_seen,
               (SELECT MAX(a.version) FROM agents a WHERE a.hostname = d.hostname AND a.status = 'active') AS agent_version,
               (SELECT MIN(k.free_gb) FROM disks k WHERE k.device_id = d.id) AS min_disk_free_gb,
               (SELECT COUNT(*) FROM physical_disks p WHERE p.device_id = d.id
                  AND (p.health NOT IN ('Healthy', 'OK', '0', '') OR p.predict_failure = TRUE)) AS disks_unhealthy
        FROM devices d
    """,
}

VIEWS["v_users"] = """
    SELECT u.username, u.domain, u.display_name, u.first_name, u.last_name, u.email, u.upn, u.title, u.department,
           u.company, u.office, u.phone, u.mobile, u.manager, u.description, u.enabled, u.locked,
           u.password_never_expires, u.password_last_set, u.last_logon, u.bad_pwd_count, u.created, u.changed,
           CASE WHEN u.dn IS NULL THEN NULL ELSE SUBSTR(u.dn, STRPOS_(u.dn, ',') + 1) END AS ou,
           u.logon_script, u.home_directory, u.sid,
           (SELECT ud.hostname FROM v_user_devices ud WHERE ud.username = u.username ORDER BY ud.last_logon DESC LIMIT 1) AS last_computer,
           (SELECT MAX(ud.last_logon) FROM v_user_devices ud WHERE ud.username = u.username) AS last_computer_logon,
           (SELECT COUNT(*) FROM v_user_devices ud WHERE ud.username = u.username) AS computer_count,
           (SELECT STRING_AGG_(g.name) FROM user_groups g WHERE g.user_id = u.id) AS groups
    FROM ad_users u
"""

VIEWS["v_physical_disks"] = """
    SELECT d.hostname, p.model, p.serial, p.media, p.size_gb, p.health, p.predict_failure
    FROM physical_disks p JOIN devices d ON d.id = p.device_id
"""

VIEWS["v_audit"] = """
    SELECT time, actor, action, target, result, ip FROM audit_log
"""

VIEWS["v_changes"] = """
    SELECT c.time, d.hostname, c.kind, c.detail FROM change_events c JOIN devices d ON d.id = c.device_id
"""

# PCs that were only read from AD (no WinRM/agent inventory yet) have no DisplayVersion, only AD's
# operatingSystemVersion, e.g. "10.0 (22631)". Map the build number to the release name so reports
# like "Computers by OS and version" aren't blank for them. Builds missing here show AD's string as is.
AD_BUILDS = {
    "10240": "1507", "10586": "1511", "14393": "1607", "15063": "1703", "16299": "1709", "17134": "1803",
    "17763": "1809", "18362": "1903", "18363": "1909", "19041": "2004", "19042": "20H2", "19043": "21H1",
    "19044": "21H2", "19045": "22H2", "20348": "21H2", "22000": "21H2", "22621": "22H2", "22631": "23H2",
    "25398": "23H2", "26100": "24H2", "26200": "25H2",
}
AD_DISPLAY_VERSION = ("CASE " + " ".join(f"WHEN d.ad_os_version LIKE '%({b})%' THEN '{v}'" for b, v in AD_BUILDS.items())
                      + " WHEN d.ad_os_version LIKE '%(%)%' THEN d.ad_os_version END")
# The PC's AD domain: the DC= parts of its distinguished name (CN=PC1,OU=PCs,DC=corp,DC=example,DC=com ->
# corp.example.com), else the DNS suffix of its FQDN (pc1.corp.example.com -> corp.example.com).
DOMAIN = ("CASE WHEN STRPOS_(UPPER(COALESCE(d.ad_dn, '')), 'DC=') > 0 THEN "
          "LOWER(REPLACE(REPLACE(SUBSTR(UPPER(d.ad_dn), STRPOS_(UPPER(d.ad_dn), 'DC=')), ',DC=', '.'), 'DC=', '')) "
          "WHEN STRPOS_(COALESCE(d.fqdn, ''), '.') > 0 THEN LOWER(SUBSTR(d.fqdn, STRPOS_(d.fqdn, '.') + 1)) END")
VIEWS["v_devices"] = VIEWS["v_devices"].replace("AD_DISPLAY_VERSION_", AD_DISPLAY_VERSION).replace("DOMAIN_", DOMAIN)

VIEW_ORDER = ["v_port_map", "v_user_devices", "v_disks", "v_software", "v_updates", "v_logons",
              "v_switch_ports", "v_network_devices", "v_domain_controllers", "v_devices", "v_changes",
              "v_users", "v_physical_disks", "v_audit"]


def create_views(db: Session) -> None:
    dialect = db.get_bind().dialect.name
    for name in reversed(VIEW_ORDER):
        db.execute(text(f"DROP VIEW IF EXISTS {name}" + (" CASCADE" if dialect == "postgresql" else "")))
    for name in VIEW_ORDER:
        sql = VIEWS[name]
        if dialect == "sqlite":
            sql = (sql.replace("= FALSE", "= 0").replace("AS NUMERIC", "AS REAL").replace("GREATEST_(", "MAX(")
                   .replace("STRING_AGG_(g.name)", "GROUP_CONCAT(g.name, ', ')").replace("STRPOS_(", "INSTR(")
                   .replace("= TRUE", "= 1"))
        else:
            sql = (sql.replace("GREATEST_(", "GREATEST(").replace("STRING_AGG_(g.name)", "STRING_AGG(g.name, ', ')")
                   .replace("STRPOS_(", "STRPOS(").replace("'1900-01-01'", "TIMESTAMP '1900-01-01'"))
        db.execute(text(f"CREATE VIEW {name} AS {sql}"))
    db.commit()


_LOCAL_SQL = "('', '-', '127.0.0.1', '::1')"
NAMED_WINDOW = timedelta(hours=8)     # another event from the same IP this close in time names the PC
LEASE_SLACK = timedelta(days=8)       # Windows DHCP's default lease: a binding holds this long after its last renewal


def _as_dt(v):
    """text() queries on SQLite give DATETIME columns back as strings."""
    return datetime.fromisoformat(v) if isinstance(v, str) else v


def _intervals(sightings: list[tuple]) -> list[tuple[datetime, datetime, str]]:
    """DHCP sightings of one IP -> non-overlapping (start, end, host): each binding holds from its first grant
    until the next PC got the address, or its lease ran out."""
    rows = sorted(sightings, key=lambda r: r[1])
    out = []
    for i, (host, first, last, expires) in enumerate(rows):
        end = max(expires, last) if expires else last + LEASE_SLACK
        nxt = next((r[1] for r in rows[i + 1:] if r[0] != host), None)
        if nxt is not None:
            end = min(end, nxt)
        start = first - (LEASE_SLACK if i == 0 else timedelta(0))   # renewals in the log can start mid-lease
        out.append((start, end, host))
    return out


def _match_in_python(db: Session, open_: str) -> int:
    """DHCP binding at the time of the event, then another event from that IP close in time that named the PC
    (NTLM 4624/4776 carry WorkstationName; Kerberos 4768 only an IP)."""
    rows = db.execute(text(f"SELECT id, ip, time FROM logon_events WHERE {open_}")).all()
    if not rows:
        return 0
    ips = sorted({r[1] for r in rows})
    by_mac = dict(db.execute(text("SELECT n.mac, d.hostname FROM device_nics n JOIN devices d ON d.id = n.device_id")).all())
    dhcp: dict[str, list] = {}
    named: dict[str, list] = {}
    for k in range(0, len(ips), 500):
        chunk = ips[k:k + 500]
        params = {f"i{n}": ip for n, ip in enumerate(chunk)}
        inl = ", ".join(f":i{n}" for n in range(len(chunk)))
        for ip, host, mac, first, last, exp in db.execute(text(
                f"SELECT ip, hostname, mac, first_seen, last_seen, expires FROM ip_sightings "
                f"WHERE source LIKE 'dhcp:%' AND ip IN ({inl})"), params):
            host = by_mac.get(mac) or host        # the PC that owns that MAC beats the name the client sent
            if host:
                dhcp.setdefault(ip, []).append((host, _as_dt(first), _as_dt(last), _as_dt(exp)))
        for ip, host, t in db.execute(text(
                f"SELECT ip, hostname, time FROM logon_events WHERE host_via = 'event' AND hostname IS NOT NULL "
                f"AND source LIKE 'dc:%' AND ip IN ({inl})"), params):
            if host:
                named.setdefault(ip, []).append((_as_dt(t), host))
    dcs = {r[0] for r in db.execute(text("SELECT hostname FROM domain_controllers"))}
    win = {ip: _intervals(v) for ip, v in dhcp.items()}
    upd = []
    for rid, ip, t in rows:
        t = _as_dt(t)
        host = via = None
        for a, b, h in win.get(ip, ()):
            if a <= t <= b:
                host, via = h, "dhcp"
        if host is None and ip in named:
            near = [(abs(nt - t), h) for nt, h in named[ip] if h not in dcs]
            near = [x for x in near if x[0] <= NAMED_WINDOW]
            if near:
                host, via = min(near)[1], "named"
        if host:
            upd.append({"id": rid, "h": host[:64], "v": via})
    if upd:
        db.execute(text("UPDATE logon_events SET hostname = :h, host_via = :v WHERE id = :id"), upd)
    return len(upd)


def resolve_logon_hosts(db: Session, dns: bool = True, dns_budget_s: float = 30.0) -> int:
    """Fill in the computer for DC logon events, which mostly carry only the client IP.

    Tries, in order: the PC that held that IP in DHCP at the time of the event; a PC that another event from the
    same IP named within 8 hours (NTLM logons carry WorkstationName); a PC whose NIC has that IP today; a PC whose
    MAC the routers' ARP tables give for that IP; a PC whose DNS A/AAAA record is that IP; reverse DNS (PTR).
    The NIC/ARP/DNS steps use today's addresses, so they can be wrong for old events after a DHCP move."""
    from .db import get_setting, set_setting, utcnow
    n = 0
    if not get_setting(db, "migr:logon_client_v1"):
        # Before 0.22, network logons kept the DC's own name from WorkstationName as the computer.
        db.execute(text(f"""
            UPDATE logon_events SET hostname = NULL
            WHERE source LIKE 'dc:%' AND hostname IS NOT NULL AND ip IS NOT NULL AND ip NOT IN {_LOCAL_SQL}
              AND (UPPER(source) = 'DC:' || UPPER(hostname) OR UPPER(source) LIKE 'DC:' || UPPER(hostname) || '.%')
        """))
        set_setting(db, "migr:logon_client_v1", "1")
        db.commit()
    if not get_setting(db, "migr:logon_client_v2"):
        # Before 0.28 the computer of a Kerberos (4768) logon was guessed from today's IPs only, and nothing recorded
        # how. Guess again now that DHCP history and named events can say who had the address at the time.
        db.execute(text("UPDATE logon_events SET hostname = NULL WHERE source LIKE 'dc:%' AND logon_type = 0 "
                        "AND host_via IS NULL"))
        db.execute(text("UPDATE logon_events SET host_via = 'event' WHERE host_via IS NULL AND hostname IS NOT NULL"))
        set_setting(db, "migr:logon_client_v2", "1")
        db.commit()
    open_ = f"hostname IS NULL AND ip IS NOT NULL AND ip NOT IN {_LOCAL_SQL}"
    n += _match_in_python(db, open_)
    n += db.execute(text(f"""
        UPDATE logon_events SET host_via = 'nic', hostname = (
          SELECT d.hostname FROM device_nics n JOIN devices d ON d.id = n.device_id
          WHERE n.ip = logon_events.ip LIMIT 1)
        WHERE {open_} AND EXISTS (SELECT 1 FROM device_nics n WHERE n.ip = logon_events.ip)
    """)).rowcount or 0
    arp = """FROM arp_entries a JOIN device_nics n ON n.mac = a.mac JOIN devices d ON d.id = n.device_id
             WHERE a.ip = logon_events.ip"""
    n += db.execute(text(f"""
        UPDATE logon_events SET host_via = 'arp', hostname = (SELECT d.hostname {arp} ORDER BY a.last_seen DESC LIMIT 1)
        WHERE {open_} AND EXISTS (SELECT 1 {arp})
    """)).rowcount or 0
    fwd = "FROM ip_sightings s WHERE s.source = 'dns' AND s.ip = logon_events.ip AND s.hostname IS NOT NULL"
    n += db.execute(text(f"""
        UPDATE logon_events SET host_via = 'dns', hostname = (SELECT s.hostname {fwd} ORDER BY s.last_seen DESC LIMIT 1)
        WHERE {open_} AND EXISTS (SELECT 1 {fwd})
    """)).rowcount or 0
    db.commit()
    if dns:
        since = utcnow() - timedelta(days=30)
        ips = [r[0] for r in db.execute(text(f"SELECT DISTINCT ip FROM logon_events WHERE {open_} AND time >= :s"),
                                        {"s": since}).all()][:1000]
        for ip, name in reverse_dns(ips, dns_budget_s).items():
            n += db.execute(text(f"UPDATE logon_events SET hostname = :h, host_via = 'ptr' WHERE {open_} AND ip = :ip"),
                            {"h": name, "ip": ip}).rowcount or 0
        db.commit()
    return n


_GENERIC_PTR = re.compile(r"^(ip|host|dhcp|client|pool|dyn|static)?[-_]?\d{1,3}([-_.]\d{1,3}){3}\b", re.I)


def reverse_dns(ips: list[str], budget_s: float = 20.0) -> dict[str, str]:
    """PTR lookups in parallel, giving up on whatever hasn't answered within budget_s."""
    import socket
    from concurrent.futures import ThreadPoolExecutor, wait
    from .db import norm_host
    if not ips:
        return {}
    ex = ThreadPoolExecutor(max_workers=32)
    futs = {ex.submit(socket.gethostbyaddr, ip): ip for ip in ips}
    done, _ = wait(futs, timeout=budget_s)
    ex.shutdown(wait=False, cancel_futures=True)
    out = {}
    for f in done:
        try:
            full = f.result()[0]
        except Exception:
            continue
        name = norm_host(full)
        # skip "10-1-2-3"/"ip-10-1-2-3"-style generic PTRs, but keep real names that start with a digit (2FL-PC01)
        if name and not _GENERIC_PTR.match(full):
            out[futs[f]] = name[:64]
    return out


def track_port_moves(db: Session) -> int:
    """Record a history entry when a PC shows up on a different switch port than last time."""
    from .db import ChangeEvent, Device
    rows = db.execute(text("""
        SELECT d.id, d.last_switch_port, pm.switch_name || ' ' || pm.port AS now_port
        FROM devices d JOIN v_port_map pm ON pm.hostname = d.hostname
    """)).all()
    moved = 0
    for dev_id, old, new in rows:
        if old != new:
            if old:
                db.add(ChangeEvent(device_id=dev_id, kind="moved", detail=f"Switch port: {old} -> {new}"))
                moved += 1
            db.get(Device, dev_id).last_switch_port = new
    db.commit()
    return moved
