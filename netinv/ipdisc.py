"""Where a computer's IP address comes from when its own inventory doesn't say (WinRM never reached it, no agent):

* DHCP: the active leases on each Windows DHCP server, plus the DHCP audit log (DhcpSrvLog-*.log, 7 days), which
  says which PC had which address *when*, so a DC logon from 10.1.2.3 last Tuesday goes to the PC that held
  10.1.2.3 last Tuesday, not to whoever has it today. Read over WinRM; the account needs to be in the server's
  "DHCP Users" group (or an admin) and allowed to use WinRM there.
* DNS: forward (A and AAAA) lookups of the AD computers' names through this server's own resolver.

Both are stored in ip_sightings. v_devices shows the address when the PC has no inventoried one, and
correlate.resolve_logon_hosts uses them to put a name on logons that carry only an IP.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import Device, DeviceNic, DomainController, IpSighting, get_setting, norm_host, norm_mac, set_setting, utcnow

log = logging.getLogger(__name__)

LOG_DAYS = 7                 # Windows keeps one audit log per weekday, so a week is all there is
DNS_MAX_HOSTS = 5000
KEEP_DAYS = 120              # sightings older than this are dropped

# Run on a DC: the DHCP servers authorized in AD (CN=NetServices in the configuration partition).
DISCOVER_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$out = @(); $err = $null
try {
  $root = [ADSI]'LDAP://RootDSE'
  $base = [ADSI]("LDAP://CN=NetServices,CN=Services," + $root.configurationNamingContext)
  $s = New-Object DirectoryServices.DirectorySearcher($base, '(objectClass=dHCPClass)')
  [void]$s.PropertiesToLoad.Add('cn'); [void]$s.PropertiesToLoad.Add('dhcpServers')
  $out = @($s.FindAll() | ForEach-Object { "$($_.Properties['cn'][0])" } | Where-Object { $_ -and $_ -ne 'DhcpRoot' })
} catch { $err = "$($_.Exception.Message)".Trim() }
ConvertTo-Json -InputObject @{ servers = $out; error = $err } -Compress
'''

# Run on a DHCP server: active IPv4 leases and the audit log since __SINCE__ (Assign 10 / Renew 11 lines).
DHCP_SCRIPT = r'''
$ErrorActionPreference = 'SilentlyContinue'
$since = [datetime]::Parse('__SINCE__').ToLocalTime()
$err = $null; $logerr = $null; $leases = @(); $log = @()
try {
  Import-Module DhcpServer -ErrorAction Stop
  $scopes = @(Get-DhcpServerv4Scope -ErrorAction Stop)
  $leases = @($scopes | ForEach-Object { Get-DhcpServerv4Lease -ScopeId $_.ScopeId } |
    Where-Object { "$($_.AddressState)" -like 'Active*' } | ForEach-Object {
      @{ ip = "$($_.IPAddress)"; mac = "$($_.ClientId)"; host = "$($_.HostName)"
         expires = $(if ($_.LeaseExpiryTime) { $_.LeaseExpiryTime.ToUniversalTime().ToString('o') } else { $null }) } })
} catch { $err = "$($_.Exception.Message)".Trim() }
if (-not $err) {
  try {
    $dir = (Get-DhcpServerAuditLog -ErrorAction Stop).Path
    if (-not $dir) { $dir = Join-Path $env:SystemRoot 'System32\dhcp' }
    $agg = @{}
    $inv = [Globalization.CultureInfo]::InvariantCulture
    foreach ($f in @(Get-ChildItem -Path $dir -Filter 'DhcpSrvLog-*.log' -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $since })) {
      foreach ($line in @(Get-Content -LiteralPath $f.FullName -ErrorAction Stop)) {
        if ($line -notmatch '^1[01],') { continue }
        $c = $line.Split(',')
        if ($c.Count -lt 7 -or -not $c[4]) { continue }
        $t = [datetime]::MinValue
        if (-not [datetime]::TryParseExact("$($c[1]) $($c[2])", 'MM/dd/yy HH:mm:ss', $inv, 'None', [ref]$t)) { continue }
        if ($t -lt $since) { continue }
        $k = "$($c[4])|$($c[5])|$($c[6])"
        $u = $t.ToUniversalTime()
        if ($agg.ContainsKey($k)) {
          if ($u -lt $agg[$k].f) { $agg[$k].f = $u }; if ($u -gt $agg[$k].l) { $agg[$k].l = $u }
        } else { $agg[$k] = @{ ip = $c[4]; host = $c[5]; mac = $c[6]; f = $u; l = $u } }
      }
    }
    $log = @($agg.Values | ForEach-Object { @{ ip = $_.ip; host = $_.host; mac = $_.mac; first = $_.f.ToString('o'); last = $_.l.ToString('o') } })
  } catch { $logerr = "$($_.Exception.Message)".Trim() }
}
$who = $(try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "$env:USERDOMAIN\$env:USERNAME" })
ConvertTo-Json -InputObject @{ leases = $leases; log = $log; error = $err; log_error = $logerr; who = $who } -Depth 4 -Compress
'''


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is not None:
        from datetime import timezone
        d = d.astimezone(timezone.utc).replace(tzinfo=None)
    return d


def clean_ip(ip: str | None) -> str | None:
    """A usable unicast address as text (IPv4-mapped IPv6 turned into IPv4), else None."""
    s = (ip or "").strip()
    if s.lower().startswith("::ffff:"):
        s = s[7:]
    s = s.split("%")[0]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast:
        return None
    return str(a)


def upsert(db: Session, ip: str, hostname: str | None, mac: str | None, source: str,
           first: datetime, last: datetime, expires: datetime | None = None) -> None:
    row = db.scalar(select(IpSighting).where(IpSighting.ip == ip, IpSighting.source == source,
                                             IpSighting.hostname.is_(None) if hostname is None
                                             else IpSighting.hostname == hostname))
    if row is None:
        db.add(IpSighting(ip=ip, hostname=hostname, mac=mac, source=source, first_seen=first, last_seen=last,
                          expires=expires))
        db.flush()
        return
    row.first_seen = min(row.first_seen, first)
    row.last_seen = max(row.last_seen, last)
    row.mac = mac or row.mac
    if expires:
        row.expires = expires


# ------------------------------------------------------------------ DHCP
def dhcp_servers(db: Session, cfg: dict) -> tuple[list[str], str]:
    """Settings > Scanning "DHCP servers" if filled in, else the ones authorized in AD (looked up on a DC once a
    day), else the DCs themselves (small sites often run DHCP on the DC). Returns (servers, where from)."""
    manual = [s.strip() for s in (get_setting(db, "dhcp:servers") or "").replace(";", ",").split(",") if s.strip()]
    if manual:
        return manual, "Settings"
    cached = json.loads(get_setting(db, "dhcp:discovered", "null") or "null")
    if cached and _dt(cached.get("at")) and _dt(cached["at"]) > utcnow() - timedelta(days=1):
        if cached.get("servers"):
            return cached["servers"], "AD"
    else:
        from .collectors.winrm import run_ps
        found = None
        for dc in db.scalars(select(DomainController)):
            try:
                res = run_ps(dc.fqdn or dc.hostname, cfg, DISCOVER_SCRIPT) or {}
            except Exception as exc:
                log.info("DHCP server lookup on %s failed: %s", dc.hostname, exc)
                continue
            found = [s for s in res.get("servers") or [] if s]
            break
        if found is not None:
            set_setting(db, "dhcp:discovered", json.dumps({"at": utcnow().isoformat(), "servers": found}))
            db.commit()
            if found:
                return found, "AD"
    dcs = [dc.fqdn or dc.hostname for dc in db.scalars(select(DomainController))]
    return dcs, "DCs"


def store_dhcp(db: Session, server: str, res: dict, now: datetime | None = None) -> tuple[int, int]:
    """Save one server's answer. Returns (leases, audit-log bindings) stored."""
    now = now or utcnow()
    src = f"dhcp:{norm_host(server) or server}"[:64]
    nl = nh = 0
    for r in res.get("leases") or []:
        ip = clean_ip(r.get("ip"))
        if not ip:
            continue
        exp = _dt(r.get("expires"))
        host = norm_host(r.get("host"))
        upsert(db, ip, host and host[:64], norm_mac(r.get("mac")), src, now, now, exp)
        nl += 1
    for r in res.get("log") or []:
        ip, first, last = clean_ip(r.get("ip")), _dt(r.get("first")), _dt(r.get("last"))
        if not ip or not first or not last:
            continue
        host = norm_host(r.get("host"))
        upsert(db, ip, host and host[:64], norm_mac(r.get("mac")), src, first, last)
        nh += 1
    return nl, nh


def collect_dhcp(db: Session, cfg: dict) -> str:
    """Pull leases and the audit log from every DHCP server. Never raises: returns a one-line summary."""
    from .collectors.winrm import classify_error, run_ps
    from .scanning import short_error
    servers, where = dhcp_servers(db, cfg)
    if not servers:
        return "DHCP: no DHCP servers found (add them in Settings, Scanning)"
    ok, leases, hist, errs, notes = 0, 0, 0, [], []
    for srv in servers:
        key = f"dhcp:log_since:{norm_host(srv)}"
        since = _dt(get_setting(db, key)) or (utcnow() - timedelta(days=LOG_DAYS))
        started = utcnow()
        script = DHCP_SCRIPT.replace("__SINCE__", (since - timedelta(minutes=5)).isoformat() + "Z")
        try:
            res = run_ps(srv, cfg, script) or {}
        except Exception as exc:
            if where == "DCs":
                continue          # just guessing that a DC runs DHCP
            hint = {"access_denied": " (the account needs to be in DHCP Users on that server and allowed to use WinRM)",
                    "unreachable": " (WinRM, TCP 5985, didn't answer)"}.get(classify_error(exc), "")
            errs.append(f"{srv}: {short_error(exc)}{hint}")
            continue
        if res.get("error"):
            if where != "DCs":
                errs.append(f"{srv}: connected as {res.get('who') or '?'}, but reading DHCP failed: {res['error']}"
                            " (it needs the DHCP Server role and an account in DHCP Users)")
            continue
        try:
            nl, nh = store_dhcp(db, srv, res)
            if not res.get("log_error"):
                set_setting(db, key, started.isoformat())
            else:
                notes.append(f"{srv} audit log: {res['log_error']}")
            db.commit()
        except Exception as exc:
            db.rollback()
            errs.append(f"{srv}: {short_error(exc)}")
            continue
        ok, leases, hist = ok + 1, leases + nl, hist + nh
    prune(db)
    if where == "DCs" and not ok:
        return "DHCP: no DHCP servers authorized in AD, and no DC runs DHCP (add them in Settings, Scanning)"
    msg = f"DHCP: {leases} leases and {hist} address histories from {ok} of {len(servers)} servers"
    if errs:
        msg += "; failed: " + "; ".join(errs[:5])
    if notes:
        msg += "; " + "; ".join(notes[:3])
    return msg


def prune(db: Session) -> None:
    db.execute(delete(IpSighting).where(IpSighting.last_seen < utcnow() - timedelta(days=KEEP_DAYS)))
    db.commit()


# ------------------------------------------------------------------ DNS
def _lookup(name: str) -> list[str]:
    out = []
    for fam, *_rest, addr in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP):
        ip = clean_ip(addr[0])
        if ip and ip not in out:
            out.append(ip)
    return out


def forward_dns(db: Session, budget_s: float = 30.0, lookup=_lookup) -> str:
    """A/AAAA lookups of the enabled AD computers (and any PC without an inventoried IP), in parallel."""
    now = utcnow()
    devs = db.execute(select(Device.hostname, Device.fqdn).where(Device.ad_enabled.isnot(False))
                      .order_by(Device.ad_last_logon.desc())).all()[:DNS_MAX_HOSTS]
    if not devs:
        return "DNS: no computers to look up"
    ex = ThreadPoolExecutor(max_workers=32)
    futs = {ex.submit(lookup, fqdn or host): host for host, fqdn in devs}
    done, _ = wait(futs, timeout=budget_s)
    ex.shutdown(wait=False, cancel_futures=True)
    found = 0
    for f in done:
        host = futs[f]
        try:
            ips = f.result()
        except Exception:
            continue
        for ip in ips:
            upsert(db, ip, host, None, "dns", now, now)
        found += bool(ips)
    db.commit()
    timed_out = len(devs) - len(done)
    return f"DNS: {found} of {len(devs)} computers resolved" + (f" ({timed_out} didn't answer in time)" if timed_out else "")


def refresh(db: Session, cfg: dict | None) -> str:
    """DHCP (when there's a Windows credential) then DNS. Used by the DC logons step before matching logons."""
    parts = []
    if cfg is not None:
        try:
            parts.append(collect_dhcp(db, cfg))
        except Exception as exc:
            db.rollback()
            log.exception("DHCP import")
            parts.append(f"DHCP: failed ({exc})")
    try:
        parts.append(forward_dns(db))
    except Exception as exc:
        db.rollback()
        log.exception("DNS lookups")
        parts.append(f"DNS: failed ({exc})")
    return "; ".join(parts)
