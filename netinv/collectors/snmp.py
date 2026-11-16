"""Agentless switch/router collector over SNMP v2c or v3 (read-only).

Per device it reads: system info, interfaces, the MAC forwarding table
(Q-BRIDGE-MIB, BRIDGE-MIB, or Cisco per-VLAN BRIDGE-MIB), LLDP and CDP neighbours,
and the ARP table (on routers / L3 switches). Ports with a neighbour, or with more
MACs than `uplink_mac_threshold`, are flagged as uplinks so PCs are only mapped
to real edge ports.
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

from ..db import ArpEntry, MacSighting, NetworkDevice, SwitchPort, norm_mac, utcnow

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
LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_PORTID = "1.0.8802.1.1.2.1.4.1.1.7"
CDP_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
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


async def poll_device(ip: str, cfg: dict) -> dict:
    s = Snmp(ip, cfg)
    sysinfo = {k: _str(v) for k, v in (await s.get(SYS)).items()}
    names = {i[0]: _str(v) for i, v in await s.walk(IF_NAME)}
    aliases = {i[0]: _str(v) for i, v in await s.walk(IF_ALIAS)}
    speeds = {i[0]: int(v) for i, v in await s.walk(IF_HIGHSPEED)}
    oper = {i[0]: int(v) == 1 for i, v in await s.walk(IF_OPER)}
    baseport = {i[0]: int(v) for i, v in await s.walk(BASEPORT_IFINDEX)}

    fdb: list[tuple[str, int, int | None]] = []  # (mac, ifindex, vlan)
    for idx, port in await s.walk(DOT1Q_FDB_PORT):
        vlan, mac = idx[0], norm_mac(bytes(idx[1:7]).hex())
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

    neighbors: dict[int, tuple[str, str]] = {}
    lldp_ports = {(i[1], i[2]): _octets_text(v) for i, v in await s.walk(LLDP_REM_PORTID)}
    for i, v in await s.walk(LLDP_REM_SYSNAME):
        local = i[1]
        ifindex = baseport.get(local, local)  # localPortNum is usually the bridge port
        neighbors[ifindex] = (_octets_text(v), lldp_ports.get((i[1], i[2]), ""))
    cdp_ports = {(i[0], i[1]): _octets_text(v) for i, v in await s.walk(CDP_DEVICE_PORT)}
    for i, v in await s.walk(CDP_DEVICE_ID):
        neighbors.setdefault(i[0], (_octets_text(v), cdp_ports.get((i[0], i[1]), "")))

    arp = []
    for idx, v in await s.walk(ARP_TABLE):
        ipaddr = ".".join(str(x) for x in idx[1:5])
        mac = norm_mac(bytes(v).hex()) if hasattr(v, "asOctets") else None
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            arp.append((ipaddr, mac))

    return dict(sys=sysinfo, names=names, aliases=aliases, speeds=speeds, oper=oper,
                fdb=fdb, neighbors=neighbors, arp=arp)


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
        p.neighbor, p.neighbor_port = (nb if nb else (None, None))
        p.mac_count = mac_count.get(ifi, 0)
        p.is_uplink = bool(nb) or p.mac_count > threshold
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
