"""Agentless switch/router collector over SNMP v2c or v3 (read-only).

Per device it reads: system info, interfaces, the MAC forwarding table
(Q-BRIDGE-MIB, BRIDGE-MIB, or Cisco per-VLAN BRIDGE-MIB), LLDP and CDP neighbours,
and the ARP table (on routers / L3 switches). Ports with a switch neighbour, or with more
MACs than `uplink_mac_threshold`, are flagged as uplinks so PCs are only mapped
to real edge ports. Neighbours are classified from their LLDP/CDP capabilities: a switch,
router or access point makes the port an uplink; an IP phone (with a PC behind it) or a PC
that sends LLDP itself does not.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging

from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget,
    UsmUserData, bulk_walk_cmd, get_cmd, usmAesCfb128Protocol, usmHMACSHAAuthProtocol,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import ArpEntry, Device, MacSighting, NetworkDevice, SwitchPort, norm_host, norm_mac, utcnow

log = logging.getLogger(__name__)

SYS = {"descr": "1.3.6.1.2.1.1.1.0", "uptime": "1.3.6.1.2.1.1.3.0",
       "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0"}
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
IF_HIGHSPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_OPER = "1.3.6.1.2.1.2.2.1.8"
BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1D_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
DOT1Q_VLAN_FDBID = "1.3.6.1.2.1.17.7.1.4.2.1.3"     # (timemark, vlan) -> FDB id, to turn Q-BRIDGE FDB ids into VLANs
DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"           # bridge port -> untagged VLAN
CISCO_VM_VLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"      # ifIndex -> access VLAN (Cisco)
LLDP_LOC_PORTID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_LOC_PORTDESC = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORTID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYSDESC = "1.0.8802.1.1.2.1.4.1.1.10"
LLDP_REM_CAP_ENABLED = "1.0.8802.1.1.2.1.4.1.1.12"
LLDP_REM_MAN_ADDR_IF = "1.0.8802.1.1.2.1.4.2.1.3"
CDP_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
CDP_CAPABILITIES = "1.3.6.1.4.1.9.9.23.1.2.1.1.9"
# A neighbour of these kinds means the port leads to more network: its MACs are not plugged in there.
INFRA_KINDS = {"switch", "router", "ap", "other", "unknown"}
ARP_TABLE = "1.3.6.1.2.1.4.22.1.2"
CISCO_VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"


class Snmp:
    def __init__(self, ip: str, cfg: dict):
        self.ip, self.cfg = ip, cfg
        self.engine = SnmpEngine()
        self.target = None

    def auth(self, vlan: int | None = None):
        if str(self.cfg.get("version", "2c")) == "3":
            return UsmUserData(self.cfg["v3_user"], self.cfg.get("v3_auth_key"), self.cfg.get("v3_priv_key"),
                               authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol)
        community = self.cfg.get("community", "public")
        return CommunityData(f"{community}@{vlan}" if vlan else community, mpModel=1)

    def context(self, vlan: int | None = None):
        if vlan and str(self.cfg.get("version", "2c")) == "3":
            return ContextData(contextName=f"vlan-{vlan}")
        return ContextData()

    async def _tgt(self):
        if self.target is None:
            self.target = await UdpTransportTarget.create((self.ip, 161), timeout=self.cfg.get("timeout", 3),
                                                          retries=self.cfg.get("retries", 1))
        return self.target

    async def get(self, oids: dict) -> dict:
        err, status, _, binds = await get_cmd(self.engine, self.auth(), await self._tgt(), self.context(),
                                              *[ObjectType(ObjectIdentity(o)) for o in oids.values()])
        if err or status:
            raise RuntimeError(str(err or status.prettyPrint()))
        return {k: binds[i][1] for i, k in enumerate(oids)}

    async def walk(self, oid: str, vlan: int | None = None) -> list[tuple[tuple[int, ...], object]]:
        """Return [(index suffix, value)] for every row under `oid`."""
        base = tuple(int(x) for x in oid.split("."))
        out = []
        async for err, status, _, binds in bulk_walk_cmd(
                self.engine, self.auth(vlan), await self._tgt(), self.context(vlan), 0, 25,
                ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
            if err or status:
                break
            for name, val in binds:
                t = tuple(name)
                if t[:len(base)] != base or isinstance(val, (EndOfMibView, NoSuchInstance, NoSuchObject)):
                    return out
                if out and t <= tuple(base) + out[-1][0]:
                    return out  # agent returned a non-increasing OID: stop instead of looping
                out.append((t[len(base):], val))
        return out


def _str(v) -> str:
    try:
        return v.prettyPrint() if hasattr(v, "prettyPrint") else str(v)
    except Exception:
        return str(v)


def _octets_text(v) -> str:
    b = bytes(v) if hasattr(v, "asOctets") else None
    if b is not None:
        try:
            s = b.decode()
            if s.isprintable():
                return s
        except UnicodeDecodeError:
            pass
        return norm_mac(b.hex()) or b.hex()
    return _str(v)


def _vendor(descr: str) -> str:
    d = descr.lower()
    for key, name in (("cisco", "Cisco"), ("aruba", "Aruba"), ("procurve", "HPE"), ("hewlett", "HPE"),
                      ("juniper", "Juniper"), ("dell", "Dell"), ("netgear", "Netgear"), ("ubiquiti", "Ubiquiti"),
                      ("unifi", "Ubiquiti"), ("mikrotik", "MikroTik"), ("fortinet", "Fortinet"), ("meraki", "Meraki")):
        if key in d:
            return name
    return "Other"


def _octets(v) -> bytes:
    try:
        return bytes(v) if hasattr(v, "asOctets") else b""
    except Exception:
        return b""


def lldp_kind(caps: bytes, descr: str = "") -> str:
    """lldpRemSysCapEnabled is a BITS value: other(0) repeater(1) bridge(2) wlanAccessPoint(3) router(4)
    telephone(5) docsis(6) station(7), bit 0 being the top bit of the first octet. Phones and APs usually
    also set the bridge bit, so they are checked first."""
    b = caps[0] if caps else 0
    if b & 0x04 or "phone" in descr.lower():
        return "phone"
    if b & 0x10:
        return "ap"
    if b & 0x08 and not b & 0x20:
        return "router"
    if b & 0x60:
        return "switch"
    if b & 0x01:
        return "computer"
    if b & 0x80 or b & 0x02:
        return "other"
    return "unknown"


def cdp_kind(caps: bytes, platform: str = "") -> str:
    """cdpCacheCapabilities: router(0x01) trans-bridge(0x02) source-route-bridge(0x04) switch(0x08) host(0x10)
    igmp(0x20) repeater(0x40) phone(0x80), sent as a 4-octet big-endian number."""
    c = int.from_bytes(caps[-4:], "big") if caps else 0
    p = platform.lower()
    if c & 0x80 or "phone" in p:
        return "phone"
    if p.startswith("cisco air") or p.startswith("air-") or " ap" in f" {p}":
        return "ap"
    if c & 0x08 or c & 0x04 or c & 0x40:
        return "switch"
    if c & 0x01:
        return "router"
    if c & 0x02:
        return "ap"        # a transparent bridge without switching is almost always an access point
    if c & 0x10:
        return "computer"
    return "unknown"


def _ip_from_octets(b: bytes) -> str | None:
    return ".".join(str(x) for x in b) if len(b) == 4 else None


async def poll_device(ip: str, cfg: dict) -> dict:
    s = Snmp(ip, cfg)
    sysinfo = {k: _str(v) for k, v in (await s.get(SYS)).items()}
    names = {i[0]: _str(v) for i, v in await s.walk(IF_NAME)}
    aliases = {i[0]: _str(v) for i, v in await s.walk(IF_ALIAS)}
    speeds = {i[0]: int(v) for i, v in await s.walk(IF_HIGHSPEED)}
    oper = {i[0]: int(v) == 1 for i, v in await s.walk(IF_OPER)}
    baseport = {i[0]: int(v) for i, v in await s.walk(BASEPORT_IFINDEX)}

    fdb: list[tuple[str, int, int | None]] = []  # (mac, ifindex, vlan)
    fdb_vlan: dict[int, set[int]] = {}
    for idx, v in await s.walk(DOT1Q_VLAN_FDBID):
        fdb_vlan.setdefault(int(v), set()).add(idx[-1])
    for idx, port in await s.walk(DOT1Q_FDB_PORT):
        fid, mac = idx[0], norm_mac(bytes(idx[1:7]).hex())
        vl = fdb_vlan.get(fid)
        vlan = next(iter(vl)) if vl and len(vl) == 1 else fid   # shared FDBs (IVL off) can't name one VLAN
        if mac and int(port) in baseport:
            fdb.append((mac, baseport[int(port)], vlan))
    if not fdb:
        status = {i: int(v) for i, v in await s.walk(DOT1D_FDB_STATUS)}
        for idx, port in await s.walk(DOT1D_FDB_PORT):
            if status.get(idx, 3) == 3 and int(port) in baseport:
                fdb.append((norm_mac(bytes(idx[:6]).hex()), baseport[int(port)], None))
    if not fdb and _vendor(sysinfo["descr"]) == "Cisco":
        # Cisco IOS only exposes BRIDGE-MIB per VLAN (community@vlan / context vlan-N).
        vlans = [i[1] for i, v in await s.walk(CISCO_VTP_VLAN_STATE) if int(v) == 1 and i[1] not in range(1002, 1006)]
        for vlan in vlans:
            bp = {i[0]: int(v) for i, v in await s.walk(BASEPORT_IFINDEX, vlan)}
            for idx, port in await s.walk(DOT1D_FDB_PORT, vlan):
                if int(port) in bp:
                    fdb.append((norm_mac(bytes(idx[:6]).hex()), bp[int(port)], vlan))

    port_vlan: dict[int, int] = {}
    for i, v in await s.walk(DOT1Q_PVID):
        if i[0] in baseport and int(v):
            port_vlan[baseport[i[0]]] = int(v)
    for i, v in await s.walk(CISCO_VM_VLAN):
        port_vlan.setdefault(i[0], int(v))

    # LLDP numbers ports by lldpLocPortNum, which is the ifIndex on some switches and the bridge port on others.
    # The local port ID/description usually is the interface name, so match on that first.
    descrs = {i[0]: _str(v) for i, v in await s.walk(IF_DESCR)}
    by_label: dict[str, int] = {}
    for table in (aliases, descrs, names):              # later tables win: ifName is the most specific
        for ifi, label in table.items():
            if label:
                by_label[label.strip().lower()] = ifi
    loc = {}
    for oid in (LLDP_LOC_PORTDESC, LLDP_LOC_PORTID):
        for i, v in await s.walk(oid):
            t = _octets_text(v).strip().lower()
            if t in by_label:
                loc[i[0]] = by_label[t]

    def lldp_ifindex(num: int) -> int:
        if num in loc:
            return loc[num]
        if num in baseport:
            return baseport[num]
        return num

    # ifindex -> neighbour dict(name, port, kind, mac, ip, descr)
    neighbors: dict[int, dict] = {}
    rem = lambda rows: {(i[1], i[2]): v for i, v in rows}  # noqa: E731  index (timemark, port, n) -> (port, n)
    lldp_ports = {k: _octets_text(v) for k, v in rem(await s.walk(LLDP_REM_PORTID)).items()}
    lldp_desc = {k: _octets_text(v) for k, v in rem(await s.walk(LLDP_REM_SYSDESC)).items()}
    lldp_caps = {k: _octets(v) for k, v in rem(await s.walk(LLDP_REM_CAP_ENABLED)).items()}
    lldp_csub = {k: int(v) for k, v in rem(await s.walk(LLDP_REM_CHASSIS_SUBTYPE)).items()}
    lldp_chassis = {k: _octets(v) for k, v in rem(await s.walk(LLDP_REM_CHASSIS_ID)).items()}
    lldp_ip: dict[tuple, str] = {}
    for i, _ in await s.walk(LLDP_REM_MAN_ADDR_IF):
        # index: timemark, localPort, remIndex, addrSubtype, addrLen, addr...
        if len(i) >= 9 and i[3] == 1 and i[4] == 4:
            lldp_ip.setdefault((i[1], i[2]), ".".join(str(x) for x in i[5:9]))
    lldp_names = {k: _octets_text(v) for k, v in rem(await s.walk(LLDP_REM_SYSNAME)).items()}
    for key in set(lldp_names) | set(lldp_chassis):
        ifindex = lldp_ifindex(key[0])
        chassis = lldp_chassis.get(key, b"")
        mac = norm_mac(chassis.hex()) if lldp_csub.get(key) == 4 and len(chassis) == 6 else None
        name = (lldp_names.get(key) or "").strip() or mac or (_octets_text(chassis) if chassis else "")
        descr = lldp_desc.get(key, "")
        nb = dict(name=name, port=lldp_ports.get(key, ""), kind=lldp_kind(lldp_caps.get(key, b""), descr),
                  mac=mac, ip=lldp_ip.get(key), descr=descr)
        prev = neighbors.get(ifindex)
        # a PC behind a phone can send LLDP too: the infrastructure neighbour describes the port best
        if prev is None or (prev["kind"] not in INFRA_KINDS and nb["kind"] in INFRA_KINDS) or \
                (prev["kind"] == "computer" and nb["kind"] == "phone"):
            neighbors[ifindex] = nb
    cdp_ports = {(i[0], i[1]): _octets_text(v) for i, v in await s.walk(CDP_DEVICE_PORT)}
    cdp_plat = {(i[0], i[1]): _octets_text(v) for i, v in await s.walk(CDP_PLATFORM)}
    cdp_caps = {(i[0], i[1]): _octets(v) for i, v in await s.walk(CDP_CAPABILITIES)}
    cdp_addr = {(i[0], i[1]): _ip_from_octets(_octets(v)) for i, v in await s.walk(CDP_ADDRESS)}
    for i, v in await s.walk(CDP_DEVICE_ID):
        key = (i[0], i[1])
        plat = cdp_plat.get(key, "")
        neighbors.setdefault(i[0], dict(name=_octets_text(v), port=cdp_ports.get(key, ""), kind=cdp_kind(cdp_caps.get(key, b""), plat),
                                        mac=None, ip=cdp_addr.get(key), descr=plat))

    arp = []
    for idx, v in await s.walk(ARP_TABLE):
        ipaddr = ".".join(str(x) for x in idx[1:5])
        mac = norm_mac(bytes(v).hex()) if hasattr(v, "asOctets") else None
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            arp.append((ipaddr, mac))

    return dict(sys=sysinfo, names=names, aliases=aliases, speeds=speeds, oper=oper,
                fdb=fdb, neighbors=neighbors, arp=arp, port_vlan=port_vlan)


def expand_targets(targets: list[str]) -> list[str]:
    """Accepts single IPs, CIDRs (10.0.0.0/24) and ranges (10.0.0.10-10.0.0.50 or 10.0.0.10-50)."""
    out = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if "/" in t:
            out += [str(h) for h in ipaddress.ip_network(t, strict=False).hosts()]
        elif "-" in t:
            a, b = (x.strip() for x in t.split("-", 1))
            if "." not in b:
                b = a.rsplit(".", 1)[0] + "." + b
            start, end = int(ipaddress.ip_address(a)), int(ipaddress.ip_address(b))
            if end - start > 65535:
                raise ValueError(f"range too large: {t}")
            out += [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
        else:
            out.append(t)
    return out


def is_uplink(neighbor_kind: str | None, mac_count: int, threshold: int) -> bool:
    """A port leads to more network (and its MACs are not plugged in there) when a switch, router or AP is the
    LLDP/CDP neighbour, or when more MACs than the threshold are learned on it. A phone (with the PC behind it)
    or a PC that speaks LLDP itself is an access port."""
    return neighbor_kind in INFRA_KINDS or mac_count > threshold


def store(db: Session, ip: str, data: dict, threshold: int) -> str:
    now = utcnow()
    nd = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == ip)) or NetworkDevice(ip=ip)
    db.add(nd)
    sysd = data["sys"]
    nd.sysname, nd.sysdescr, nd.location = sysd["name"], sysd["descr"], sysd["location"]
    nd.vendor = _vendor(sysd["descr"])
    nd.uptime_s = int(sysd["uptime"]) // 100 if sysd["uptime"].isdigit() else None
    nd.last_polled, nd.poll_error = now, None
    db.flush()

    ports = {p.ifindex: p for p in nd.ports}
    pcs = set(db.scalars(select(Device.hostname))) if any(
        not isinstance(n, dict) or n.get("kind") in (None, "unknown") for n in data["neighbors"].values()) else set()
    mac_count: dict[int, int] = {}
    for _, ifi, _ in data["fdb"]:
        mac_count[ifi] = mac_count.get(ifi, 0) + 1
    for ifi in set(data["names"]) | set(mac_count):
        p = ports.get(ifi)
        if p is None:
            p = SwitchPort(switch_id=nd.id, ifindex=ifi)
            db.add(p)
        ports[ifi] = p
        p.name = data["names"].get(ifi, str(ifi))
        p.alias = data["aliases"].get(ifi)
        p.speed_mbps = data["speeds"].get(ifi)
        p.oper_up = data["oper"].get(ifi)
        nb = data["neighbors"].get(ifi)
        if isinstance(nb, (tuple, list)):     # (name, port) from older callers
            nb = dict(name=nb[0], port=nb[1], kind="unknown")
        nb = nb or {}
        kind = nb.get("kind") or ("unknown" if nb else None)
        if kind == "unknown" and norm_host(nb.get("name")) in pcs:
            kind = "computer"                 # no capabilities sent, but the name is one of our PCs
        p.neighbor, p.neighbor_port, p.neighbor_kind = nb.get("name") or None, nb.get("port") or None, kind
        p.neighbor_mac, p.neighbor_ip = nb.get("mac"), nb.get("ip")
        p.neighbor_descr = (nb.get("descr") or "")[:2000] or None
        p.vlan = data.get("port_vlan", {}).get(ifi)
        p.mac_count = mac_count.get(ifi, 0)
        p.is_uplink = is_uplink(kind, p.mac_count, threshold)
    db.flush()

    for mac, ifi, vlan in data["fdb"]:
        port = ports[ifi]
        ms = db.scalar(select(MacSighting).where(MacSighting.mac == mac, MacSighting.port_id == port.id))
        if ms is None:
            db.add(MacSighting(mac=mac, port_id=port.id, vlan=vlan, first_seen=now, last_seen=now))
        else:
            ms.last_seen, ms.vlan = now, vlan
    for ipaddr, mac in data["arp"]:
        a = db.scalar(select(ArpEntry).where(ArpEntry.ip == ipaddr, ArpEntry.mac == mac))
        if a is None:
            db.add(ArpEntry(ip=ipaddr, mac=mac, source=nd.sysname or ip, last_seen=now))
        else:
            a.last_seen = now
    return f"{nd.sysname or ip}: {len(ports)} ports, {len(data['fdb'])} MACs, {len(data['arp'])} ARP"


async def _poll_all(ips: list[str], cfg: dict):
    sem = asyncio.Semaphore(cfg.get("parallel", 20))

    async def one(ip):
        async with sem:
            err = None
            for cred in cfg.get("creds") or [{}]:   # try each SNMP credential until one answers
                try:
                    return ip, await poll_device(ip, {**cfg, **cred}), None
                except Exception as exc:
                    err = str(exc)
            return ip, None, err
    return await asyncio.gather(*(one(ip) for ip in ips))


def collect(db: Session, cfg: dict) -> str:
    from ..exclusions import Exclusions
    excl = Exclusions.load(db)
    ips = [ip for ip in expand_targets(cfg.get("targets", [])) if not excl.ip(ip)]
    results = asyncio.run(_poll_all(ips, cfg))
    msgs, errors = [], 0
    for ip, data, err in results:
        if err:
            errors += 1
            nd = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == ip))
            if nd:  # only record errors for devices we already know (avoid noise from CIDR sweeps)
                nd.poll_error = err
            continue
        msgs.append(store(db, ip, data, cfg.get("uplink_mac_threshold", 6)))
        db.commit()
    db.commit()
    return f"{len(msgs)} devices polled, {errors} no response. " + "; ".join(msgs[:10])
