"""Wireless: which access point a Wi-Fi client is on.

Two sources, both optional:
* the PC itself (WinRM scan or agent): its default-route adapter (wired or Wi-Fi) and, on Wi-Fi, the SSID and the
  BSSID (the AP radio's MAC) it is associated with;
* a wireless controller, set up in Settings > Wireless controller: UniFi Network (local account), Cisco Meraki
  (Dashboard API key) or a Cisco WLC (AireOS / Catalyst 9800, read over SNMP with the saved SNMP credentials). It gives
  every client's MAC, IP, SSID and AP, so phones, printers and PCs we can't scan are placed too, and it names the APs.

A BSSID is turned into an AP name from the controller's AP list (exact BSSID, or a MAC within 64 of the AP's radio or
Ethernet MAC, since vendors number BSSIDs up from the radio MAC), else from a switch port whose LLDP/CDP neighbour is
an access point with a nearby MAC. Each client keeps a history (wifi_sightings): which AP, first and last seen there.
"""
from __future__ import annotations

import http.cookiejar
import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from sqlalchemy import select, text

from .db import Device, NetworkDevice, SwitchPort, WifiSighting, WirelessAp, get_setting, norm_host, norm_mac, set_setting, utcnow
from .secrets import decrypt, encrypt

log = logging.getLogger(__name__)
KINDS = {"unifi": "UniFi Network", "meraki": "Cisco Meraki", "cisco": "Cisco WLC (SNMP)"}
TIMEOUT = 20
NEAR = 0x40           # a BSSID within this many of an AP's MAC belongs to that AP


class WlcError(Exception):
    pass


# ------------------------------------------------------------------ settings
def config(db) -> dict:
    """What the Settings page shows. The password / API key never leaves the server."""
    return {"kind": get_setting(db, "wlc:kind"), "url": get_setting(db, "wlc:url"), "user": get_setting(db, "wlc:user"),
            "site": get_setting(db, "wlc:site"), "org": get_setting(db, "wlc:org"),
            "verify_tls": get_setting(db, "wlc:verify_tls", "0") == "1",
            "every_min": int(get_setting(db, "wlc:every_min", "15") or 15),
            "secret_set": bool(get_setting(db, "wlc:secret")),
            "last_poll": get_setting(db, "wlc:last_poll"), "last_result": get_setting(db, "wlc:last_result"),
            "aps": db.scalar(text("SELECT COUNT(*) FROM wireless_aps")) or 0}


def save(db, body: dict) -> None:
    kind = (body.get("kind") or "").strip() or None
    if kind and kind not in KINDS:
        raise ValueError("Pick UniFi, Meraki or Cisco WLC")
    url = (body.get("url") or "").strip().rstrip("/") or None
    if kind == "unifi" and url:
        if not url.startswith("http"):
            url = "https://" + url
        u = urllib.parse.urlparse(url)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError("The UniFi address must look like https://unifi.corp.local or https://10.0.0.5:8443")
        url = f"{u.scheme}://{u.netloc}"
    if kind == "cisco" and url and not all(c.isalnum() or c in ".-:" for c in url):
        raise ValueError("The WLC address must be a host name or IP address")
    try:
        every = max(5, min(1440, int(body.get("every_min") or 15)))
    except (TypeError, ValueError):
        raise ValueError("Poll interval must be a number of minutes") from None
    set_setting(db, "wlc:kind", kind)
    set_setting(db, "wlc:url", url)
    set_setting(db, "wlc:user", (body.get("user") or "").strip() or None)
    set_setting(db, "wlc:site", (body.get("site") or "").strip() or None)
    set_setting(db, "wlc:org", (body.get("org") or "").strip() or None)
    set_setting(db, "wlc:verify_tls", "1" if body.get("verify_tls") else "0")
    set_setting(db, "wlc:every_min", str(every))
    if body.get("clear_secret") or not kind:
        set_setting(db, "wlc:secret", None)
    elif body.get("secret"):
        set_setting(db, "wlc:secret", encrypt(body["secret"].strip()))


def is_set_up(db) -> bool:
    kind = get_setting(db, "wlc:kind")
    if kind == "cisco":
        return bool(get_setting(db, "wlc:url"))
    if kind == "meraki":
        return bool(get_setting(db, "wlc:secret"))
    if kind == "unifi":
        return bool(get_setting(db, "wlc:url") and get_setting(db, "wlc:user") and get_setting(db, "wlc:secret"))
    return False


def due(db, now=None) -> bool:
    if not is_set_up(db):
        return False
    last = get_setting(db, "wlc:last_poll")
    if not last:
        return True
    try:
        age = ((now or utcnow()) - datetime.fromisoformat(last)).total_seconds()
    except ValueError:
        return True
    return age >= int(get_setting(db, "wlc:every_min", "15") or 15) * 60


# ------------------------------------------------------------------ MAC helpers
def mac_int(mac: str | None) -> int | None:
    m = norm_mac(mac) if mac else None
    return int(m.replace(":", ""), 16) if m else None


def near(a: str | None, b: str | None, within: int = NEAR) -> bool:
    x, y = mac_int(a), mac_int(b)
    return x is not None and y is not None and abs(x - y) <= within


class ApIndex:
    """Turns a BSSID or AP MAC into the AP's name, and finds the switch port the AP is plugged into."""

    def __init__(self, db):
        self.aps = list(db.scalars(select(WirelessAp)))
        self.ports = [(p, nd) for p, nd in db.execute(
            select(SwitchPort, NetworkDevice).join(NetworkDevice, NetworkDevice.id == SwitchPort.switch_id)
            .where(SwitchPort.neighbor.is_not(None)))]

    def ap_for(self, bssid: str | None) -> dict | None:
        b = norm_mac(bssid) if bssid else None
        if not b:
            return None
        for ap in self.aps:
            if b in (ap.bssids or "").split(",") or b in (ap.mac, ap.radio_mac):
                return self._out(ap.name, ap.mac, ap.ip)
        best = None
        for ap in self.aps:
            for m in (ap.radio_mac, ap.mac):
                x, y = mac_int(m), mac_int(b)
                if x is not None and abs(x - y) <= NEAR and (best is None or abs(x - y) < best[0]):
                    best = (abs(x - y), ap)
        if best:
            return self._out(best[1].name, best[1].mac, best[1].ip)
        for p, nd in self.ports:          # no controller: an AP that is a switch port's LLDP/CDP neighbour
            if p.neighbor_kind == "ap" and near(p.neighbor_mac, b):
                return {"name": p.neighbor, "ip": p.neighbor_ip, "switch_name": nd.sysname, "switch_ip": nd.ip, "port": p.name}
        return None

    def _out(self, name, mac, ip) -> dict:
        out = {"name": name, "ip": ip, "switch_name": None, "switch_ip": None, "port": None}
        lname = (name or "").lower()
        for p, nd in self.ports:
            n = (p.neighbor or "").lower()
            if (lname and (n == lname or n.startswith(lname + "."))) or (mac and near(p.neighbor_mac, mac, 2)) or \
                    (ip and p.neighbor_ip == ip):
                out.update(switch_name=nd.sysname, switch_ip=nd.ip, port=p.name)
                break
        return out


# ------------------------------------------------------------------ recording sightings
def record(db, mac: str, ap_key: str, source: str, now=None, **kw) -> WifiSighting:
    now = now or utcnow()
    ws = db.scalar(select(WifiSighting).where(WifiSighting.mac == mac, WifiSighting.ap_key == ap_key[:128]))
    if ws is None:
        ws = WifiSighting(mac=mac, ap_key=ap_key[:128], source=source, first_seen=now, last_seen=now)
        db.add(ws)
    ws.source, ws.last_seen = source, max(now, ws.last_seen or now)
    for k, v in kw.items():
        if v:
            setattr(ws, k, str(v)[:128] if isinstance(v, str) else v)
    return ws


def from_pc(db, dev: Device, connection: str | None, wifi: dict | None) -> None:
    """A PC reported its own connection (WinRM scan or agent)."""
    now = utcnow()
    if connection in ("wired", "wireless"):
        dev.connection = connection
    if not wifi:
        return
    mac, bssid = norm_mac(wifi.get("mac")), norm_mac(wifi.get("bssid"))
    ap = ApIndex(db).ap_for(bssid) if bssid else None
    dev.wifi_ssid = (wifi.get("ssid") or "")[:64] or None
    dev.wifi_bssid, dev.wifi_signal = bssid, wifi.get("signal")
    dev.wifi_ap, dev.wifi_seen = (ap or {}).get("name"), now
    if mac and (bssid or dev.wifi_ap):
        record(db, mac, dev.wifi_ap or bssid, "pc", now, hostname=dev.hostname, ssid=dev.wifi_ssid, bssid=bssid,
               ap_name=dev.wifi_ap)


def store_poll(db, source: str, aps: list[dict], clients: list[dict]) -> str:
    """Save what a controller returned: its APs, then each Wi-Fi client on its AP, tied to our computers by MAC."""
    now = utcnow()
    have = {(a.source, a.key): a for a in db.scalars(select(WirelessAp).where(WirelessAp.source == source))}
    for a in aps:
        key = (a.get("key") or a.get("mac") or "")[:64]
        if not key:
            continue
        row = have.get((source, key)) or WirelessAp(source=source, key=key)
        db.add(row)
        have[(source, key)] = row
        row.name, row.mac, row.radio_mac = a.get("name") or row.name, norm_mac(a.get("mac")), norm_mac(a.get("radio_mac"))
        row.bssids = ",".join(sorted({m for b in a.get("bssids") or [] if (m := norm_mac(b))})) or row.bssids
        row.ip, row.model, row.last_seen = a.get("ip") or row.ip, (a.get("model") or "")[:64] or row.model, now
    db.flush()
    idx = ApIndex(db)
    owners = {m: h for m, h in db.execute(text("SELECT mac, hostname FROM v_mac_owner"))}
    by_ap = {a.get("key"): a.get("name") for a in aps}
    placed = matched = 0
    for c in clients:
        mac = norm_mac(c.get("mac"))
        if not mac:
            continue
        ap_name = c.get("ap_name") or by_ap.get(c.get("ap_key"))
        if not ap_name and c.get("ap_mac"):
            ap_name = (idx.ap_for(c["ap_mac"]) or {}).get("name")
        key = ap_name or norm_mac(c.get("ap_mac")) or norm_mac(c.get("bssid"))
        if not key:
            continue
        seen = c.get("last_seen") or now
        host = owners.get(mac)
        record(db, mac, key, source, seen, client_name=c.get("name"), ip=c.get("ip"), ssid=c.get("ssid"),
               bssid=norm_mac(c.get("bssid")), ap_name=ap_name, hostname=host)
        placed += 1
        if host:
            dev = db.scalar(select(Device).where(Device.hostname == host))
            if dev and (dev.wifi_seen is None or seen >= dev.wifi_seen):
                dev.wifi_ap, dev.wifi_seen, dev.wifi_ssid = ap_name or dev.wifi_ap, seen, c.get("ssid") or dev.wifi_ssid
                dev.connection = "wireless" if dev.connection is None else dev.connection
                matched += 1
    return f"{len(aps)} access points, {placed} Wi-Fi clients ({matched} of them our computers)"


def history(db, hostname: str, macs: list[str], limit: int = 50) -> list[dict]:
    q = select(WifiSighting).where((WifiSighting.hostname == norm_host(hostname)) | WifiSighting.mac.in_(macs or ["-"]))
    rows = db.scalars(q.order_by(WifiSighting.last_seen.desc()).limit(limit)).all()
    idx = ApIndex(db) if rows else None
    out = []
    for r in rows:
        ap = (idx.ap_for(r.bssid) if r.bssid and not r.ap_name else None) or {}
        port = idx._out(r.ap_name, None, None) if r.ap_name else ap
        out.append({"ap": r.ap_name or ap.get("name") or r.bssid, "ssid": r.ssid, "bssid": r.bssid, "mac": r.mac, "ip": r.ip,
                    "source": r.source, "first_seen": r.first_seen, "last_seen": r.last_seen,
                    "switch_name": port.get("switch_name"), "switch_ip": port.get("switch_ip"), "port": port.get("port")})
    return out


# ------------------------------------------------------------------ controllers
def _ctx(db):
    if get_setting(db, "wlc:verify_tls", "0") == "1":
        return ssl.create_default_context()
    c = ssl.create_default_context()
    c.check_hostname, c.verify_mode = False, ssl.CERT_NONE      # controllers usually have a self-signed certificate
    return c


def _http(opener, method, url, body=None, headers=None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Accept": "application/json", "Content-Type": "application/json", **(headers or {})})
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}, r.headers
    except urllib.error.HTTPError as e:
        hint = {401: "the controller refused the account or key", 403: "the account or key has no access to that",
                404: "not found (wrong address, site or organization?)", 429: "rate limited, try again in a minute"}
        raise WlcError(f"HTTP {e.code}: {hint.get(e.code, e.reason)}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise WlcError(f"Can't reach {urllib.parse.urlparse(url).netloc}: {getattr(e, 'reason', e)}") from None


def _epoch(v):
    try:
        return datetime.fromtimestamp(int(v), timezone.utc).replace(tzinfo=None) if v else None
    except (TypeError, ValueError, OSError):
        return None


def _iso(v):
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None) if v else None
    except ValueError:
        return None


def poll_unifi(db) -> tuple[list, list]:
    url, user, pw = get_setting(db, "wlc:url"), get_setting(db, "wlc:user"), decrypt(get_setting(db, "wlc:secret"))
    site = get_setting(db, "wlc:site") or "default"
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ctx(db)), urllib.request.HTTPCookieProcessor(jar))
    headers, prefix = {}, ""
    try:            # UniFi OS (Cloud Key Gen2, UDM, UCG, self-hosted UniFi OS Server)
        _, h = _http(opener, "POST", f"{url}/api/auth/login", {"username": user, "password": pw, "remember": False})
        prefix = "/proxy/network"
        if h.get("X-CSRF-Token"):
            headers["X-CSRF-Token"] = h["X-CSRF-Token"]
    except WlcError as first:
        try:        # classic UniFi Network application (port 8443)
            _http(opener, "POST", f"{url}/api/login", {"username": user, "password": pw})
        except WlcError:
            raise WlcError(f"UniFi sign-in failed ({first}). Use a local UniFi account, not a UI.com cloud account.") from None
    devs, _ = _http(opener, "GET", f"{url}{prefix}/api/s/{urllib.parse.quote(site)}/stat/device", headers=headers)
    sta, _ = _http(opener, "GET", f"{url}{prefix}/api/s/{urllib.parse.quote(site)}/stat/sta", headers=headers)
    aps = [{"key": d.get("mac"), "name": d.get("name") or d.get("mac"), "mac": d.get("mac"), "ip": d.get("ip"),
            "model": d.get("model"), "bssids": [v.get("bssid") for v in d.get("vap_table") or []]}
           for d in devs.get("data") or [] if d.get("type") == "uap"]
    names = {norm_mac(a["mac"]): a["name"] for a in aps}
    clients = [{"mac": c.get("mac"), "ip": c.get("ip"), "name": c.get("hostname") or c.get("name"), "ssid": c.get("essid"),
                "bssid": c.get("bssid"), "ap_mac": c.get("ap_mac"), "ap_name": names.get(norm_mac(c.get("ap_mac"))),
                "last_seen": _epoch(c.get("last_seen"))}
               for c in sta.get("data") or [] if not c.get("is_wired")]
    return aps, clients


def poll_meraki(db) -> tuple[list, list]:
    key, org = decrypt(get_setting(db, "wlc:secret")), get_setting(db, "wlc:org")
    base = "https://api.meraki.com/api/v1"
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    h = {"Authorization": f"Bearer {key}"}
    if not org:
        orgs, _ = _http(opener, "GET", f"{base}/organizations", headers=h)
        if not orgs:
            raise WlcError("That API key has no Meraki organizations")
        org = orgs[0]["id"]
    devs, _ = _http(opener, "GET", f"{base}/organizations/{urllib.parse.quote(str(org))}/devices?perPage=1000&productTypes[]=wireless", headers=h)
    nets, _ = _http(opener, "GET", f"{base}/organizations/{urllib.parse.quote(str(org))}/networks?perPage=1000", headers=h)
    aps = [{"key": d.get("serial"), "name": d.get("name") or d.get("serial"), "mac": d.get("mac"), "ip": d.get("lanIp"),
            "model": d.get("model")} for d in devs]
    names = {d.get("serial"): d.get("name") or d.get("serial") for d in devs}
    clients = []
    for n in nets:
        if "wireless" not in (n.get("productTypes") or []):
            continue
        rows, _ = _http(opener, "GET", f"{base}/networks/{urllib.parse.quote(n['id'])}/clients?timespan=86400&perPage=1000", headers=h)
        for c in rows:
            if c.get("recentDeviceConnection") not in (None, "Wireless") or not c.get("ssid"):
                continue
            clients.append({"mac": c.get("mac"), "ip": c.get("ip"), "name": c.get("description") or c.get("dhcpHostname"),
                            "ssid": c.get("ssid"), "ap_key": c.get("recentDeviceSerial"),
                            "ap_name": c.get("recentDeviceName") or names.get(c.get("recentDeviceSerial")),
                            "ap_mac": c.get("recentDeviceMac"), "last_seen": _iso(c.get("lastSeen"))})
    return aps, clients


# AIRESPACE-WIRELESS-MIB, served by AireOS controllers and the Catalyst 9800
BSN_STA_IP, BSN_STA_AP, BSN_STA_SSID = "1.3.6.1.4.1.14179.2.1.4.1.2", "1.3.6.1.4.1.14179.2.1.4.1.4", "1.3.6.1.4.1.14179.2.1.4.1.7"
BSN_AP_NAME, BSN_AP_IP, BSN_AP_ETH = "1.3.6.1.4.1.14179.2.2.1.1.3", "1.3.6.1.4.1.14179.2.2.1.1.19", "1.3.6.1.4.1.14179.2.2.1.1.33"


def poll_cisco(db) -> tuple[list, list]:
    import asyncio
    from .collectors.snmp import Snmp, _octets, _str
    from .db import Credential
    from .scanning import cred_cfg
    host = get_setting(db, "wlc:url")
    creds = [cred_cfg(c) for c in db.scalars(select(Credential).where(Credential.kind.in_(("snmp2", "snmp3"))))]
    if not creds:
        raise WlcError("Add an SNMP credential (Settings > Credentials) that can read the WLC")

    def mac_of(idx):
        return norm_mac(bytes(idx[:6]).hex()) if len(idx) >= 6 else None

    async def run(cfg):
        s = Snmp(host, cfg)
        names = {mac_of(i): _str(v) for i, v in await s.walk(BSN_AP_NAME)}
        if not names:
            raise WlcError("no access points in AIRESPACE-WIRELESS-MIB (not a Cisco WLC, or SNMP refused)")
        ips = {mac_of(i): _str(v) for i, v in await s.walk(BSN_AP_IP)}
        eth = {mac_of(i): norm_mac(_octets(v).hex()) for i, v in await s.walk(BSN_AP_ETH)}
        sta_ap = {mac_of(i): norm_mac(_octets(v).hex()) for i, v in await s.walk(BSN_STA_AP)}
        sta_ip = {mac_of(i): _str(v) for i, v in await s.walk(BSN_STA_IP)}
        sta_ssid = {mac_of(i): _str(v) for i, v in await s.walk(BSN_STA_SSID)}
        aps = [{"key": m, "name": n, "radio_mac": m, "mac": eth.get(m), "ip": ips.get(m)} for m, n in names.items() if m]
        clients = [{"mac": m, "ap_mac": a, "ap_name": names.get(a), "ip": sta_ip.get(m), "ssid": sta_ssid.get(m)}
                   for m, a in sta_ap.items() if m]
        return aps, clients

    err = None
    for cfg in creds:
        try:
            return asyncio.run(run({**cfg, "timeout": 5, "retries": 1}))
        except Exception as exc:
            err = exc
    raise WlcError(f"SNMP to {host} failed: {err}")


POLLERS = {"unifi": poll_unifi, "meraki": poll_meraki, "cisco": poll_cisco}


def poll(db) -> str:
    kind = get_setting(db, "wlc:kind")
    if not is_set_up(db):
        raise WlcError("The wireless controller isn't set up (Settings > Wireless controller)")
    try:
        aps, clients = POLLERS[kind](db)
        msg = f"{KINDS[kind]}: " + store_poll(db, kind, aps, clients)
    except WlcError as exc:
        db.rollback()
        msg = f"{KINDS.get(kind, kind)}: failed, {exc}"
        set_setting(db, "wlc:last_poll", utcnow().isoformat())
        set_setting(db, "wlc:last_result", msg)
        db.commit()
        raise
    set_setting(db, "wlc:last_poll", utcnow().isoformat())
    set_setting(db, "wlc:last_result", msg)
    db.commit()
    return msg


def test(db) -> str:
    kind = get_setting(db, "wlc:kind")
    if not is_set_up(db):
        raise WlcError("Save the controller type, address and account first")
    aps, clients = POLLERS[kind](db)
    return f"Connected to {KINDS[kind]}: {len(aps)} access points, {len(clients)} Wi-Fi clients right now."
