"""Switch ports <-> computers: MAC table entries matched to PCs, LLDP/CDP neighbours classified, uplinks left out.
Run: python tests/test_switch_links.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv.collectors import snmp
from netinv.db import Device, DeviceNic, IpSighting, NetworkDevice, SessionLocal, SwitchPort, utcnow

# LLDP capability BITS: first octet, bit 0 (other) is 0x80 ... station is 0x01
assert snmp.lldp_kind(bytes([0x20])) == "switch"
assert snmp.lldp_kind(bytes([0x28])) == "switch"           # bridge + router = L3 switch
assert snmp.lldp_kind(bytes([0x08])) == "router"
assert snmp.lldp_kind(bytes([0x24])) == "phone"            # phones also set the bridge bit
assert snmp.lldp_kind(bytes([0x30])) == "ap"
assert snmp.lldp_kind(bytes([0x01])) == "computer"
assert snmp.lldp_kind(b"") == "unknown"
assert snmp.lldp_kind(b"", "Polycom VVX 450 phone") == "phone"
assert snmp.cdp_kind((0x28).to_bytes(4, "big")) == "switch"
assert snmp.cdp_kind((0x90).to_bytes(4, "big"), "Cisco IP Phone 8845") == "phone"
assert snmp.cdp_kind((0x02).to_bytes(4, "big"), "cisco AIR-AP2802I-E-K9") == "ap"
assert snmp.cdp_kind((0x01).to_bytes(4, "big")) == "router"
assert snmp.cdp_kind((0x10).to_bytes(4, "big")) == "computer"
assert snmp.is_uplink("phone", 2, 6) is False and snmp.is_uplink("computer", 1, 6) is False
assert snmp.is_uplink("switch", 1, 6) and snmp.is_uplink("unknown", 1, 6) and snmp.is_uplink(None, 7, 6)
assert snmp.is_uplink(None, 1, 6) is False

PC_NIC, PC_DHCP, PHONE = "02:aa:00:00:00:01", "02:aa:00:00:00:02", "00:1b:4f:aa:bb:01"
with TestClient(m.app) as c:
    with SessionLocal() as db:
        now = utcnow()
        a = db.scalar(select(Device).where(Device.hostname == "LINK-NIC")) or Device(hostname="LINK-NIC")
        b = db.scalar(select(Device).where(Device.hostname == "LINK-DHCP")) or Device(hostname="LINK-DHCP")
        lldp = db.scalar(select(Device).where(Device.hostname == "LINK-LLDP")) or Device(hostname="LINK-LLDP")
        db.add_all([a, b, lldp])
        db.flush()
        if not a.nics:
            db.add(DeviceNic(device_id=a.id, mac=PC_NIC, ip="10.77.0.1"))
        if not db.scalar(select(IpSighting).where(IpSighting.mac == PC_DHCP)):
            db.add(IpSighting(ip="10.77.0.2", hostname="LINK-DHCP", mac=PC_DHCP, source="dhcp:DC1", first_seen=now, last_seen=now))
        db.commit()
        trunk = [(f"02:bb:00:00:00:{k:02x}", 4, 10) for k in range(10)]
        data = dict(sys={"name": "link-sw", "descr": "Aruba 6300", "location": "", "uptime": "100"},
                    names={1: "1/1/1", 2: "1/1/2", 3: "1/1/3", 4: "1/1/4", 5: "1/1/5"}, aliases={}, speeds={},
                    oper={1: True, 2: True, 3: True, 4: True, 5: True}, arp=[], port_vlan={1: 20, 2: 20},
                    fdb=[(PC_NIC, 1, 20), (PHONE, 1, 120),        # PC behind an IP phone
                         (PC_DHCP, 2, 20),                         # PC with no inventory, MAC only from its DHCP lease
                         (PC_NIC, 3, 20), (PC_DHCP, 3, 20)]        # the same MACs again via the uplink to core
                    + trunk + [("02:cc:00:00:00:01", 5, 20)],      # 10 MACs on a port with no neighbour; one on port 5
                    neighbors={1: dict(name="SEP001B4FAABB01", port="Port 1", kind="phone", mac=PHONE, ip=None, descr="IP phone"),
                               3: dict(name="core-sw01", port="Te1/1/9", kind="switch", mac=None, ip="10.0.0.1", descr=""),
                               5: ("link-lldp.corp.example.com", "eth0")})   # old (name, port) shape, no capabilities
        msg = snmp.store(db, "10.77.0.250", data, 6)
        db.commit()
        assert "5 ports" in msg, msg
        sw = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == "10.77.0.250"))
        ports = {p.name: p for p in db.scalars(select(SwitchPort).where(SwitchPort.switch_id == sw.id))}
        assert not ports["1/1/1"].is_uplink and ports["1/1/1"].neighbor_kind == "phone" and ports["1/1/1"].vlan == 20
        assert ports["1/1/3"].is_uplink and ports["1/1/4"].is_uplink           # switch neighbour; too many MACs
        assert ports["1/1/5"].neighbor_kind == "computer" and not ports["1/1/5"].is_uplink   # named like one of our PCs

    def dev(h):
        return c.post("/api/query", json={"dataset": "v_devices", "fields": ["switch_name", "switch_port", "vlan"],
                                           "filters": [{"field": "hostname", "op": "eq", "value": h}]}).json()["rows"][0]
    assert dev("LINK-NIC") == {"switch_name": "link-sw", "switch_port": "1/1/1", "vlan": 20}, dev("LINK-NIC")
    assert dev("LINK-DHCP") == {"switch_name": "link-sw", "switch_port": "1/1/2", "vlan": 20}, dev("LINK-DHCP")

    d = c.get("/api/devices/LINK-DHCP").json()
    assert [(x["port"], x["matched_by"]) for x in d["location"]] == [("1/1/2", "DHCP")], d["location"]
    d = c.get("/api/devices/LINK-NIC").json()
    assert [(x["port"], x["phone"]) for x in d["location"]] == [("1/1/1", "SEP001B4FAABB01")], d["location"]

    sp = {r["port"]: r for r in c.post("/api/query", json={"dataset": "v_switch_ports", "limit": 100000,
          "filters": [{"field": "switch_ip", "op": "eq", "value": "10.77.0.250"}]}).json()["rows"]}
    assert sp["1/1/1"]["port_type"] == "phone" and sp["1/1/1"]["computers"] == "LINK-NIC" and sp["1/1/1"]["unknown_devices"] == 0
    assert sp["1/1/2"]["port_type"] == "access" and sp["1/1/2"]["computers"] == "LINK-DHCP"
    assert sp["1/1/3"]["port_type"] == "uplink" and not sp["1/1/3"]["computers"]
    assert sp["1/1/3"]["neighbor_switch_ip"] == "10.0.0.1", sp["1/1/3"]          # demo's core-sw01
    assert sp["1/1/4"]["port_type"] == "uplink"
    assert sp["1/1/5"]["neighbor_computer"] == "LINK-LLDP" and sp["1/1/5"]["unknown_devices"] == 1

    r = c.get("/api/switch-port", params={"switch_ip": "10.77.0.250", "port": "1/1/1"}).json()
    kinds = {x["mac"]: (x["hostname"], x["device_kind"]) for x in r["macs"]}
    assert kinds == {PC_NIC: ("LINK-NIC", None), PHONE: (None, "phone")}, kinds
    r = c.get("/api/switch-port", params={"switch_ip": "10.77.0.250", "port": "1/1/3"}).json()
    assert {x["now_on"] for x in r["macs"]} == {"link-sw 1/1/1", "link-sw 1/1/2"}, r["macs"]
    assert c.get("/api/switch-port", params={"switch_ip": "10.77.0.250", "port": "nope"}).status_code == 404
    pm = c.post("/api/query", json={"dataset": "v_port_map", "fields": ["hostname", "matched_by", "device_kind"],
                                     "filters": [{"field": "switch_ip", "op": "eq", "value": "10.77.0.250"}]}).json()["rows"]
    assert {(x["hostname"], x["matched_by"], x["device_kind"]) for x in pm} >= {
        ("LINK-NIC", "inventory", "computer"), ("LINK-DHCP", "DHCP", "computer"), (None, None, "phone")}, pm
    print("switch ports link to computers: phones, DHCP-only PCs and uplinks OK")

# poll_device against a fake SNMP agent: an Aruba-style switch where lldpLocPortNum is not the ifIndex.
import asyncio
from pysnmp.proto.rfc1902 import Integer, OctetString, TimeTicks

mac_idx = lambda mac: tuple(int(x, 16) for x in mac.split(":"))  # noqa: E731
WALK = {
    snmp.IF_NAME: [((10,), OctetString("1/1/1")), ((11,), OctetString("1/1/2")), ((49,), OctetString("1/1/49"))],
    snmp.IF_DESCR: [((10,), OctetString("1/1/1")), ((11,), OctetString("1/1/2")), ((49,), OctetString("1/1/49"))],
    snmp.IF_OPER: [((10,), Integer(1)), ((11,), Integer(1)), ((49,), Integer(1))],
    snmp.BASEPORT_IFINDEX: [((1,), Integer(10)), ((2,), Integer(11)), ((49,), Integer(49))],
    snmp.DOT1Q_VLAN_FDBID: [((0, 20), Integer(1)), ((0, 120), Integer(2))],
    snmp.DOT1Q_FDB_PORT: [((1,) + mac_idx(PC_NIC), Integer(1)), ((2,) + mac_idx(PHONE), Integer(1)),
                          ((1,) + mac_idx(PC_DHCP), Integer(2)), ((1,) + mac_idx("02:dd:00:00:00:01"), Integer(49))],
    snmp.DOT1Q_PVID: [((1,), Integer(20)), ((2,), Integer(20)), ((49,), Integer(1))],
    # lldpLocPortNum 101/149 -> port IDs "1/1/1" / "1/1/49": matched to ifIndex 10 / 49 by name
    snmp.LLDP_LOC_PORTID: [((101,), OctetString("1/1/1")), ((149,), OctetString("1/1/49"))],
    snmp.LLDP_REM_SYSNAME: [((0, 101, 1), OctetString("SEP001B4FAABB01")), ((0, 149, 2), OctetString("core-sw01.corp.example.com"))],
    snmp.LLDP_REM_PORTID: [((0, 101, 1), OctetString("Port 1")), ((0, 149, 2), OctetString("Te1/1/9"))],
    snmp.LLDP_REM_CAP_ENABLED: [((0, 101, 1), OctetString(bytes([0x24]))), ((0, 149, 2), OctetString(bytes([0x28])))],
    snmp.LLDP_REM_CHASSIS_SUBTYPE: [((0, 101, 1), Integer(4)), ((0, 149, 2), Integer(4))],
    snmp.LLDP_REM_CHASSIS_ID: [((0, 101, 1), OctetString(bytes(mac_idx(PHONE)))), ((0, 149, 2), OctetString(bytes(6)))],
    snmp.LLDP_REM_MAN_ADDR_IF: [((0, 149, 2, 1, 4, 10, 0, 0, 1), Integer(2))],
}


async def fake_get(self, oids):
    return {"descr": OctetString("Aruba JL659A 6300M"), "uptime": TimeTicks(100), "name": OctetString("fake-sw"),
            "location": OctetString("")}


async def fake_walk(self, oid, vlan=None):
    return WALK.get(oid, [])

snmp.Snmp.get, snmp.Snmp.walk = fake_get, fake_walk
data = asyncio.run(snmp.poll_device("10.77.0.251", {}))
assert sorted(data["fdb"]) == sorted([(PC_NIC, 10, 20), (PHONE, 10, 120), (PC_DHCP, 11, 20), ("02:dd:00:00:00:01", 49, 20)]), data["fdb"]
nb = data["neighbors"]
assert set(nb) == {10, 49}, nb
assert nb[10]["kind"] == "phone" and nb[10]["mac"] == PHONE and nb[10]["name"] == "SEP001B4FAABB01"
assert nb[49]["kind"] == "switch" and nb[49]["ip"] == "10.0.0.1" and nb[49]["port"] == "Te1/1/9"
assert data["port_vlan"] == {10: 20, 11: 20, 49: 1}, data["port_vlan"]
with SessionLocal() as db:
    snmp.store(db, "10.77.0.251", data, 6)
    db.commit()
    sw = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == "10.77.0.251"))
    up = {p.name: p.is_uplink for p in sw.ports}
    assert up == {"1/1/1": False, "1/1/2": False, "1/1/49": True}, up
print("SNMP poll: LLDP port mapping, neighbour kinds, Q-BRIDGE VLANs OK")
