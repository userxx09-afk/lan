"""Reading switch MAC tables: Cisco per-VLAN BRIDGE-MIB even when VLAN 1 answers, switches without
dot1dBasePortIfIndex, and the per-switch note that says how many MACs came back and why not.
Run: python tests/test_mac_tables.py (DATABASE_URL set, demo loaded)."""
import asyncio, logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pysnmp.proto.rfc1902 import Integer, OctetString, TimeTicks
from netinv.collectors import snmp

mac_idx = lambda mac: tuple(int(x, 16) for x in mac.split(":"))  # noqa: E731
A, B, C, SELF = "02:c1:00:00:00:01", "02:c1:00:00:00:02", "02:c1:00:00:00:03", "00:c1:00:00:00:ff"
IFN = [((10101,), OctetString("Gi1/0/1")), ((10102,), OctetString("Gi1/0/2")), ((10103,), OctetString("Gi1/0/3"))]
CISCO = {
    (snmp.IF_NAME, None): IFN,
    (snmp.BASEPORT_IFINDEX, None): [((1,), Integer(10101))],
    # the plain community answers for VLAN 1 only: just the switch's own MAC
    (snmp.DOT1D_FDB_PORT, None): [(mac_idx(SELF), Integer(1))],
    (snmp.CISCO_VTP_VLAN_STATE, None): [((1, 1), Integer(1)), ((1, 20), Integer(1)), ((1, 30), Integer(1)), ((1, 1002), Integer(1))],
    (snmp.BASEPORT_IFINDEX, 20): [((1,), Integer(10101)), ((2,), Integer(10102))],
    (snmp.DOT1D_FDB_PORT, 20): [(mac_idx(A), Integer(1)), (mac_idx(B), Integer(2))],
    (snmp.DOT1D_FDB_STATUS, 20): [(mac_idx(A), Integer(3)), (mac_idx(B), Integer(3))],
    (snmp.BASEPORT_IFINDEX, 30): [((3,), Integer(10103))],
    (snmp.DOT1D_FDB_PORT, 30): [(mac_idx(C), Integer(3)), (mac_idx(SELF), Integer(3))],
    (snmp.DOT1D_FDB_STATUS, 30): [(mac_idx(C), Integer(3)), (mac_idx(SELF), Integer(4))],     # 4 = the switch itself
}
DESCR = {"cisco": "Cisco IOS Software, C2960X Software", "other": "Generic L2 switch", "silent": "Generic L2 switch"}
WALK, KIND = {}, ["cisco"]


async def fake_get(self, oids):
    return {"descr": OctetString(DESCR[KIND[0]]), "uptime": TimeTicks(100), "name": OctetString("sw"), "location": OctetString("")}


async def fake_walk(self, oid, vlan=None):
    if KIND[0] == "silent" and oid == snmp.DOT1D_FDB_PORT:
        self.errors.append(f"{oid}: No SNMP response received before timeout")
        return []
    return WALK.get((oid, vlan), [])

snmp.Snmp.get, snmp.Snmp.walk = fake_get, fake_walk

WALK.update(CISCO)
d = asyncio.run(snmp.poll_device("10.88.0.1", {}))
assert sorted(d["fdb"]) == sorted([(A, 10101, 20), (B, 10102, 20), (C, 10103, 30)]), d["fdb"]
assert d["fdb_method"] == "Cisco per-VLAN BRIDGE-MIB (3 VLANs)", d["fdb_method"]
assert snmp.mac_table_note(d) == "3 MACs via Cisco per-VLAN BRIDGE-MIB (3 VLANs)"

# a switch with BRIDGE-MIB but no dot1dBasePortIfIndex: bridge port numbers are the ifIndexes
WALK.clear()
KIND[0] = "other"
WALK.update({(snmp.IF_NAME, None): [((1,), OctetString("1")), ((2,), OctetString("2"))],
             (snmp.DOT1D_FDB_PORT, None): [(mac_idx(A), Integer(1)), (mac_idx(B), Integer(2))],
             (snmp.DOT1D_FDB_STATUS, None): [(mac_idx(A), Integer(3)), (mac_idx(B), Integer(3))]})
d = asyncio.run(snmp.poll_device("10.88.0.2", {}))
assert sorted(d["fdb"]) == [(A, 1, None), (B, 2, None)] and d["fdb_method"] == "BRIDGE-MIB", d

# nothing back: the note says why
KIND[0] = "silent"
d = asyncio.run(snmp.poll_device("10.88.0.3", {}))
note = snmp.mac_table_note(d)
assert not d["fdb"] and note.startswith("no MAC table returned") and "timeout" in note, note
print("MAC tables: Cisco per-VLAN, no base-port map, and the why-not note OK")
