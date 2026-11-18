"""DHCP leases / audit log and DNS lookups give PCs an IP and DC logons a computer.
Run: python tests/test_ip_discovery.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from datetime import timedelta
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text
import netinv.main as m
from netinv import correlate, ipdisc
from netinv.db import Device, DeviceNic, IpSighting, LogonEvent, SessionLocal, utcnow
from netinv.ingest import LOGON_NTLM, LogonIn, add_logons

assert ipdisc.clean_ip("::ffff:10.1.2.3") == "10.1.2.3"
assert ipdisc.clean_ip("fe80::1%12") is None and ipdisc.clean_ip("127.0.0.1") is None and ipdisc.clean_ip("x") is None
assert ipdisc.clean_ip("2001:db8::5") == "2001:db8::5"
assert correlate._GENERIC_PTR.match("10-1-2-3.corp.local") and correlate._GENERIC_PTR.match("ip-10-1-2-3")
assert not correlate._GENERIC_PTR.match("2FL-PC01.corp.local")

with TestClient(m.app) as c:
    with SessionLocal() as db:
        now = utcnow()
        pc_a, pc_b, pc_c = "IPD-PC-A", "IPD-PC-B", "IPD-PC-C"
        for h in (pc_a, pc_b, pc_c):
            if not db.scalar(select(Device).where(Device.hostname == h)):
                db.add(Device(hostname=h, ad_enabled=True, fqdn=f"{h.lower()}.corp.local"))
        db.execute(delete(IpSighting))
        db.execute(delete(LogonEvent).where(LogonEvent.username.in_(["ipduser", "ipdntlm"])))
        db.commit()

        # 10.77.0.5 was PC-A's until two days ago, then PC-B's (audit log); PC-C only has a current lease.
        res = {"leases": [{"ip": "10.77.0.5", "mac": "aa-bb-cc-77-00-0b", "host": "ipd-pc-b.corp.local",
                           "expires": (now + timedelta(days=6)).isoformat() + "Z"},
                          {"ip": "10.77.0.9", "mac": "aa-bb-cc-77-00-0c", "host": "IPD-PC-C", "expires": None}],
               "log": [{"ip": "10.77.0.5", "host": "ipd-pc-a.corp.local", "mac": "aabbcc77000a",
                        "first": (now - timedelta(days=6)).isoformat() + "Z", "last": (now - timedelta(days=3)).isoformat() + "Z"},
                       {"ip": "10.77.0.5", "host": "ipd-pc-b.corp.local", "mac": "aabbcc77000b",
                        "first": (now - timedelta(days=2)).isoformat() + "Z", "last": (now - timedelta(hours=1)).isoformat() + "Z"}]}
        assert ipdisc.store_dhcp(db, "dhcp01.corp.local", res) == (2, 2)
        assert ipdisc.store_dhcp(db, "dhcp01.corp.local", res) == (2, 2)      # upserts, no duplicates
        db.commit()
        assert db.scalar(text("SELECT COUNT(*) FROM ip_sightings")) == 3

        # DNS: PC-A only resolves; one lookup fails
        fake = {f"{pc_a.lower()}.corp.local": ["10.77.1.1", "2001:db8::a"], f"{pc_b.lower()}.corp.local": []}
        def lookup(name):
            if name in fake:
                return fake[name]
            raise OSError("not found")
        msg = ipdisc.forward_dns(db, budget_s=10, lookup=lookup)
        assert "resolved" in msg, msg

        add_logons(db, [
            LogonIn(time=now - timedelta(days=4), username="ipduser", ip="10.77.0.5", logon_type=0, source="dc:IPD-DC"),
            LogonIn(time=now - timedelta(hours=5), username="ipduser", ip="10.77.0.5", logon_type=0, source="dc:IPD-DC"),
            LogonIn(time=now - timedelta(hours=3), username="ipduser", ip="10.77.0.9", logon_type=0, source="dc:IPD-DC"),
            LogonIn(time=now - timedelta(hours=2), username="ipduser", ip="2001:db8::a", logon_type=0, source="dc:IPD-DC"),
            # named: NTLM network logon from 10.77.3.3 says PC-C; a Kerberos logon 1 h later from the same IP has no name
            LogonIn(time=now - timedelta(hours=9), username="ipduser", hostname="IPD-PC-C", ip="10.77.3.3", logon_type=3, source="dc:IPD-DC"),
            LogonIn(time=now - timedelta(hours=8), username="ipduser", ip="10.77.3.3", logon_type=0, source="dc:IPD-DC"),
            LogonIn(time=now - timedelta(days=3), username="ipduser", ip="10.77.3.3", logon_type=0, source="dc:IPD-DC"),
        ])
        ntlm = LogonIn(time=now - timedelta(minutes=30), username="ipdntlm", hostname="\\\\ipd-pc-b", logon_type=LOGON_NTLM, source="dc:IPD-DC")
        assert add_logons(db, [ntlm]) == 1
        db.commit()
        assert add_logons(db, [ntlm]) == 0             # 4776 read again at the edge of the next pull: not stored twice
        db.commit()
        correlate.resolve_logon_hosts(db, dns=False)

        got = {(r.ip, r.time.replace(microsecond=0)): (r.hostname, r.host_via) for r in
               db.scalars(select(LogonEvent).where(LogonEvent.username == "ipduser"))}
        def at(ip, delta):
            return got[(ip, (now - delta).replace(microsecond=0))]
        assert at("10.77.0.5", timedelta(days=4)) == (pc_a, "dhcp"), got
        assert at("10.77.0.5", timedelta(hours=5)) == (pc_b, "dhcp"), got
        assert at("10.77.0.9", timedelta(hours=3)) == (pc_c, "dhcp"), got
        assert at("2001:db8::a", timedelta(hours=2)) == (pc_a, "dns"), got
        assert at("10.77.3.3", timedelta(hours=8)) == (pc_c, "named"), got
        assert at("10.77.3.3", timedelta(days=3)) == (None, None), got        # too far from the named event
        n = db.scalar(select(LogonEvent).where(LogonEvent.username == "ipdntlm"))
        assert (n.hostname, n.host_via, n.ip) == (pc_b, "event", None)

    rows = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname", "ip", "mac", "ip_source"],
                                      "filters": [{"field": "hostname", "op": "contains", "value": "IPD-PC-"}],
                                      "limit": 10}).json()["rows"]
    by = {r["hostname"]: r for r in rows}
    assert by[pc_b]["ip"] == "10.77.0.5" and by[pc_b]["ip_source"] == "DHCP" and by[pc_b]["mac"] == "aa:bb:cc:77:00:0b", by
    assert by[pc_c]["ip"] == "10.77.0.9", by
    assert by[pc_a]["ip"] in ("10.77.0.5", "10.77.1.1"), by      # its old DHCP lease or its DNS record
    logons = c.get("/api/users/ipduser").json()["logons"]
    assert any(l.get("matched_by") == "dhcp" for l in logons), logons[:2]
    s = c.put("/api/settings", json={"dhcp:servers": " dhcp01 ; dhcp02 ,"}).json()
    assert s["dhcp:servers"] == "dhcp01, dhcp02", s
    with SessionLocal() as db:
        assert ipdisc.dhcp_servers(db, {}) == (["dhcp01", "dhcp02"], "Settings")
    c.put("/api/settings", json={"dhcp:servers": ""})
    print("IP discovery (DHCP, DNS, named logons) OK")
