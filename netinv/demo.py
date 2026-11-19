"""Fake but realistic sample data, so the dashboard can be tried before any collector is configured."""
from __future__ import annotations

import random
from datetime import timedelta

from sqlalchemy import select
from .db import (AdGroup, AdUser, ArpEntry, IpSighting, ChangeEvent, CollectorRun, Comment, DeviceGroup, DomainController, MacSighting, NetworkDevice, SwitchPort, utcnow)
from .ingest import AvIn, PhysDiskIn, DiskIn, EndpointPayload, HotfixIn, LogonIn, Nic, PendingIn, SoftwareIn, add_logons, apply_endpoint

USERS = ["jsmith", "mgarcia", "alee", "pnguyen", "kpatel", "rjohnson", "lchen", "dwilliams", "sbrown", "tmiller",
         "ewilson", "hmoore", "ctaylor", "banderson", "jthomas"]
MODELS = [("Dell Inc.", "OptiPlex 7010"), ("Dell Inc.", "Latitude 5440"), ("HP", "EliteDesk 800 G6"),
          ("Lenovo", "ThinkPad T14 Gen 3"), ("HP", "ProBook 450 G9")]
OSES = [("Microsoft Windows 11 Pro", "24H2", "26100.4652"), ("Microsoft Windows 11 Pro", "25H2", "26200.7171"),
        ("Microsoft Windows 11 Enterprise", "23H2", "22631.5909"), ("Microsoft Windows 10 Pro", "22H2", "19045.6036"),
        ("Microsoft Windows 11 Pro", "25H2", "26200.7171"), ("Microsoft Windows 11 Pro", "24H2", "26100.6899"),
        ("Microsoft Windows 10 Pro", "22H2", "19045.6456")]
SOFTWARE = [("Google Chrome", ["142.0.7444.60", "138.0.7204.101", "131.0.6778.86"], "Google LLC"),
            ("Mozilla Firefox (x64 en-US)", ["145.0", "128.0.3"], "Mozilla"),
            ("Microsoft 365 Apps for enterprise - en-us", ["16.0.19328.20000"], "Microsoft Corporation"),
            ("Adobe Acrobat Reader", ["25.001.20844", "23.008.20470"], "Adobe"),
            ("7-Zip 24.08 (x64)", ["24.08"], "Igor Pavlov"), ("7-Zip 19.00 (x64)", ["19.00"], "Igor Pavlov"),
            ("Zoom Workplace (64-bit)", ["6.6.0", "5.17.11"], "Zoom"),
            ("Java 8 Update 202", ["8.0.2020.8"], "Oracle Corporation"),
            ("Microsoft Office Professional Plus 2016", ["16.0.4266.1001"], "Microsoft Corporation"),
            ("Notepad++ (64-bit x64)", ["8.8.7", "7.9.5"], "Notepad++ Team"),
            ("VLC media player", ["3.0.21"], "VideoLAN")]


def _mac(i: int) -> str:
    return f"00:1a:2b:{(i >> 8) & 255:02x}:{i & 255:02x}:{random.randint(16, 250):02x}"


def _gjson(v) -> str:
    import json
    return json.dumps(v)


def seed(db) -> str:
    random.seed(7)
    now = utcnow()
    for name, site, roles, gc in (("DC01", "HQ", "PDC, RID, Infrastructure, Schema, DomainNaming", True),
                                  ("DC02", "HQ", None, True), ("DC03", "Branch-East", None, False)):
        db.add(DomainController(hostname=name, fqdn=f"{name.lower()}.corp.example.com",
                                os="Windows Server 2022 Standard", os_version="10.0 (20348)", site=site,
                                is_gc=gc, fsmo_roles=roles, last_seen=now))

    core = NetworkDevice(ip="10.0.0.1", sysname="core-sw01", vendor="Cisco", location="HQ server room",
                         sysdescr="Cisco IOS Software, C9300 Software, Version 17.12.4", uptime_s=8_400_000, last_polled=now)
    access = [NetworkDevice(ip=f"10.0.0.{10 + i}", sysname=f"access-sw0{i + 1}", vendor=v, location=loc,
                            sysdescr=d, uptime_s=random.randint(10**5, 10**7), last_polled=now)
              for i, (v, loc, d) in enumerate([("Cisco", "HQ floor 1 IDF", "Cisco IOS Software, C9200L, Version 17.9.5"),
                                               ("Aruba", "HQ floor 2 IDF", "Aruba JL659A 6300M Switch FL.10.13"),
                                               ("HPE", "Branch-East", "HP J9773A 2530-24G-PoEP Switch")])]
    db.add_all([core] + access)
    db.flush()
    uplinks = {}
    for i, sw in enumerate(access):
        up = SwitchPort(switch=sw, ifindex=52, name="Gi1/0/52" if sw.vendor == "Cisco" else "1/1/52", oper_up=True,
                        speed_mbps=10000, neighbor="core-sw01", neighbor_port=f"Te1/1/{i + 1}", neighbor_kind="switch", is_uplink=True)
        db.add(up)
        cp = SwitchPort(switch=core, ifindex=100 + i, name=f"Te1/1/{i + 1}", oper_up=True, speed_mbps=10000,
                        neighbor=sw.sysname, neighbor_port=up.name, neighbor_kind="switch", is_uplink=True)
        db.add(cp)
        uplinks[sw.id] = (up, cp)
    db.flush()

    pcs = 42
    for i in range(1, pcs + 1):
        host = f"WS-{i:03d}"
        mac, ip = _mac(i), f"10.10.{i // 200}.{(i % 200) + 20}"
        os_caption, dv, build = random.choice(OSES)
        man, model = random.choice(MODELS)
        size = random.choice([237.9, 476.3, 953.2])
        free = round(size * random.choice([0.02, 0.05, 0.12, 0.3, 0.45, 0.6, 0.7]), 1)
        sw_list = []
        for name, vers, pub in random.sample(SOFTWARE, k=random.randint(5, 9)):
            sw_list.append(SoftwareIn(name=name, version=random.choice(vers), publisher=pub))
        last_patch = now - timedelta(days=random.choice([3, 9, 12, 20, 45, 80]))
        users = random.sample(USERS, k=random.choice([1, 1, 1, 2, 3]))
        logons = [LogonIn(time=now - timedelta(hours=random.randint(1, 24 * 20)), username=f"CORP\\{u}",
                          logon_type=random.choice([2, 2, 2, 10, 11])) for u in users for _ in range(random.randint(1, 6))]
        reachable = i % 11 != 0
        if reachable:
            apply_endpoint(db, EndpointPayload(
                hostname=host, fqdn=f"{host.lower()}.corp.example.com", os_caption=os_caption, os_display_version=dv,
                os_build=build, manufacturer=man, model=model, serial=f"{random.randint(10**6, 10**7 - 1):X}",
                cpu="Intel(R) Core(TM) i5-1345U", gpu="Intel(R) Iris(R) Xe Graphics 1 GB", ram_gb=random.choice([8, 16, 16, 32]),
                last_boot=now - timedelta(days=random.choice([0, 1, 2, 5, 12, 40])), current_user=f"CORP\\{users[0]}",
                nics=[Nic(mac=mac, ip=ip, description="Intel(R) Ethernet Connection")],
                disks=[DiskIn(drive="C:", size_gb=size, free_gb=free)], software=sw_list,
                hotfixes=[HotfixIn(kb="KB5066835", title="Security Update", installed_on=last_patch),
                          HotfixIn(kb="KB5065789", title="Update", installed_on=last_patch - timedelta(days=30))],
                pending_updates=[PendingIn(kb="KB5068861", title="2026-11 Cumulative Update", severity="Critical")]
                if last_patch < now - timedelta(days=30) else [],
                pending_reboot=random.random() < 0.15, logons=logons,
                antivirus=[AvIn(name="Microsoft Defender Antivirus", enabled=i % 13 != 0, up_to_date=i % 7 != 0)] if i % 19 else [],
                physical_disks=[PhysDiskIn(model="SAMSUNG MZVL2512HCJQ" if size < 500 else "WDC PC SN740 1TB",
                                           serial=f"S{random.randint(10**9, 10**10)}", media="SSD", size_gb=size,
                                           health="Warning" if i in (8, 29) else "Healthy", predict_failure=i == 8)]))
        from .ingest import get_or_create_device
        dev = get_or_create_device(db, host)
        dev.ad_enabled, dev.ad_os, dev.ad_os_version = True, os_caption.replace("Microsoft ", ""), "10.0"
        dev.ad_last_logon = now - timedelta(days=random.choice([1, 2, 5, 9]) if i % 17 else 120)
        dev.ad_created = now - timedelta(days=random.randint(100, 1500))
        if i % 23:      # live status: most up, a few down, some never checked
            dev.online, dev.online_via = i % 6 != 0, random.choice(["ping", "tcp", "winrm"])
            dev.online_checked, dev.online_changed = now - timedelta(minutes=2), now - timedelta(hours=random.randint(1, 72))
        dev.ad_dn = f"CN={host},OU=Workstations,DC=corp,DC=example,DC=com"
        dev.ad_groups = _gjson(["cn=bitlocker pcs,ou=groups,dc=corp,dc=example,dc=com"] if i % 3 == 0 else [])
        dev.fqdn = f"{host.lower()}.corp.example.com"
        dev.first_seen = dev.ad_created
        dev.purchase_date = dev.ad_created - timedelta(days=7)
        dev.warranty_end = dev.purchase_date + timedelta(days=365 * random.choice([1, 3, 3, 5]))
        dev.state = "Active"
        dev.ad_description = f"{random.choice(['Finance', 'Sales', 'Engineering'])} desktop" if i % 4 else None
        dev.ad_location = dev.asset_location if i % 3 else None
        dev.asset_location = random.choice(["HQ floor 1", "HQ floor 2", "Branch-East"])
        db.add(DeviceGroup(device_id=dev.id, name=random.choice(["Finance", "Sales", "Engineering", "Front desk", "HR"])))
        if i % 5 == 0:
            db.add(DeviceGroup(device_id=dev.id, name="Replace 2027"))
        if reachable:
            db.add(ChangeEvent(device_id=dev.id, time=now - timedelta(days=12), kind="software_updated",
                               detail="Google Chrome: 138.0.7204.101 -> 142.0.7444.60"))
            db.add(ChangeEvent(device_id=dev.id, time=now - timedelta(days=30), kind="os",
                               detail="OS build: 26100.4349 -> 26100.4652"))
        if i % 9 == 0:
            db.add(Comment(device_id=dev.id, author="admin", text="Battery swelling reported, replacement ordered.",
                           created=now - timedelta(days=3)))

        sw = access[i % 3]
        vlan = 20 if sw.location.startswith("HQ") else 30
        port = SwitchPort(switch=sw, ifindex=i, name=(f"Gi1/0/{i}" if sw.vendor == "Cisco" else f"1/1/{i}"),
                          alias=f"Desk {i:03d}", oper_up=True, speed_mbps=1000, mac_count=1, vlan=vlan)
        phone_mac = None
        if i % 4 == 0:      # the PC is plugged into the desk phone: the phone is the LLDP neighbour, not an uplink
            phone_mac = f"00:1b:4f:00:{i // 256:02x}:{i % 256:02x}"
            port.neighbor, port.neighbor_port, port.neighbor_kind = f"SEP001B4F00{i // 256:02X}{i % 256:02X}", "Port 1", "phone"
            port.neighbor_mac, port.neighbor_descr, port.mac_count = phone_mac, "Cisco IP Phone 8845", 2
        elif i == 5:        # a PC whose NIC sends LLDP itself
            port.neighbor, port.neighbor_port, port.neighbor_kind, port.neighbor_mac = f"{host}.corp.example.com", mac, "computer", mac
        db.add(port)
        db.flush()
        db.add(MacSighting(mac=mac, port_id=port.id, vlan=vlan, first_seen=now - timedelta(days=60),
                           last_seen=now - timedelta(minutes=random.randint(1, 600))))
        if phone_mac:
            db.add(MacSighting(mac=phone_mac, port_id=port.id, vlan=vlan + 100, last_seen=now))
        if not reachable:   # never inventoried, so no NIC: its MAC comes from the DHCP lease
            db.add(IpSighting(ip=ip, hostname=host, mac=mac, source="dhcp:DC01", first_seen=now - timedelta(days=3),
                              last_seen=now, expires=now + timedelta(days=5)))
        for p in uplinks[sw.id]:
            db.add(MacSighting(mac=mac, port_id=p.id, vlan=vlan, last_seen=now))
        db.add(ArpEntry(ip=ip, mac=mac, source="core-sw01", last_seen=now))
        if not reachable:
            dev.scan_error_kind = "access_denied" if i % 2 else "unreachable"
            dev.scan_error = ("Access is denied (401 Unauthorized)" if i % 2 else "Connection to port 5985 timed out")
            dev.scan_error_time = now
        if not reachable:  # still visible on the network even though WinRM failed
            dev.nics = []
    # AD users
    import json as _json
    depts = {"Finance": "Accountant", "Sales": "Account Manager", "Engineering": "Engineer", "HR": "HR Partner",
             "Front desk": "Receptionist", "IT": "Systems Administrator"}
    first = {"jsmith": "John Smith", "mgarcia": "Maria Garcia", "alee": "Andrew Lee", "pnguyen": "Phuong Nguyen",
             "kpatel": "Kiran Patel", "rjohnson": "Rachel Johnson", "lchen": "Li Chen", "dwilliams": "David Williams",
             "sbrown": "Sarah Brown", "tmiller": "Tom Miller", "ewilson": "Emma Wilson", "hmoore": "Hannah Moore",
             "ctaylor": "Chris Taylor", "banderson": "Ben Anderson", "jthomas": "Julia Thomas"}
    for k, (u, full) in enumerate(first.items()):
        dept = list(depts)[k % len(depts)]
        fn, ln = full.split(" ", 1)
        db.add(AdUser(username=u, domain="CORP", display_name=full if k != 4 else None, first_name=fn, last_name=ln,
                      initials=ln[0], upn=f"{u}@corp.example.com", email=f"{u}@example.com" if k % 6 else None,
                      title=depts[dept] if k % 5 else None, department=dept if k != 9 else None,
                      company="Example Corp", office=["HQ floor 1", "HQ floor 2", "Branch-East"][k % 3],
                      phone=f"+1 555 01{k:02d}" if k % 4 else None, manager="Rachel Johnson" if u != "rjohnson" else None,
                      description=f"{dept} - {depts[dept]}", dn=f"CN={full},OU={dept},OU=Staff,DC=corp,DC=example,DC=com",
                      sid=f"S-1-5-21-1004336348-1177238915-682003330-{1100 + k}", logon_script="logon.bat",
                      home_directory=f"\\\\fs01\\home$\\{u}", enabled=k != 13, locked=k in (2, 11),
                      password_never_expires=k in (5, 12), bad_pwd_count=5 if k in (2, 11) else 0,
                      password_last_set=now - timedelta(days=random.randint(5, 500)),
                      last_logon=now - timedelta(days=random.choice([0, 1, 2, 3, 120])),
                      created=now - timedelta(days=random.randint(200, 2500)), changed=now - timedelta(days=random.randint(1, 60)),
                      groups=_json.dumps([{"name": "Domain Users", "type": "Security - global"},
                                          {"name": f"{dept} Staff", "type": "Security - global"},
                                          {"name": f"ALL-{dept.upper().replace(' ', '')}", "type": "Distribution - universal"}]
                                         + ([{"name": "VPN Users", "type": "Security - universal"}] if k % 3 == 0 else [])),
                      group_dns=_json.dumps([f"cn={dept.lower()} staff,ou=groups,dc=corp,dc=example,dc=com",
                                             f"cn=all-{dept.lower().replace(' ', '')},ou=groups,dc=corp,dc=example,dc=com"]
                                            + (["cn=vpn users,ou=groups,dc=corp,dc=example,dc=com"] if k % 3 == 0 else [])),
                      last_scanned=now))
    # AD groups: "<dept> Staff" sit inside "All Staff", so a condition on All Staff finds everyone by nesting
    gdn = lambda n: f"cn={n.lower()},ou=groups,dc=corp,dc=example,dc=com"
    for n, t, parents in ([("All Staff", "Security - global", []), ("VPN Users", "Security - universal", []),
                           ("BitLocker PCs", "Security - global", [])]
                          + [(f"{d} Staff", "Security - global", [gdn("All Staff")]) for d in depts]
                          + [(f"ALL-{d.upper().replace(' ', '')}", "Distribution - universal", []) for d in depts]):
        db.add(AdGroup(dn=gdn(n), name=n, sam=n, type=t, member_of=_json.dumps(parents), seen=now))
    # A couple of devices nobody knows about (printers, a rogue AP...)
    for j, (vendor_mac, ip) in enumerate((("3c:2a:f4:11:22:33", "10.10.0.240"), ("b4:fb:e4:aa:bb:cc", "10.10.0.241"))):
        port = SwitchPort(switch=access[j], ifindex=200 + j, name=f"Gi1/0/{40 + j}", alias="", oper_up=True,
                          speed_mbps=100, mac_count=1)
        db.add(port)
        db.flush()
        db.add(MacSighting(mac=vendor_mac, port_id=port.id, vlan=20, last_seen=now))
        db.add(ArpEntry(ip=ip, mac=vendor_mac, source="core-sw01", last_seen=now))
        if j == 0:          # the printer asked DHCP for a name
            db.add(IpSighting(ip=ip, hostname="BRN3C2AF4112233", mac=vendor_mac, source="dhcp:DC01", first_seen=now, last_seen=now))
    # something with no IP or name at all: only its MAC is known
    odd = SwitchPort(switch=access[2], ifindex=210, name="1/1/44", alias="Lab bench", oper_up=True, speed_mbps=100, mac_count=1)
    db.add(odd)
    db.flush()
    db.add(MacSighting(mac="b8:27:eb:12:34:56", port_id=odd.id, vlan=30, last_seen=now))
    # A ceiling access point: its wireless clients are learned on its port, which is an uplink
    ap = SwitchPort(switch=access[1], ifindex=300, name="1/1/45", alias="AP lobby", oper_up=True, speed_mbps=2500, mac_count=9,
                    neighbor="ap-lobby-01", neighbor_port="eth0", neighbor_kind="ap", neighbor_ip="10.0.5.21",
                    neighbor_descr="ArubaOS AP-535", is_uplink=True)
    db.add(ap)
    db.flush()
    for k in range(9):
        db.add(MacSighting(mac=f"de:ad:be:ef:00:{k:02x}", port_id=ap.id, vlan=40, last_seen=now))
    db.flush()
    for p in db.scalars(select(SwitchPort).where(SwitchPort.oper_up.is_(True))):
        p.last_up = now                       # a scan just saw these up
    # Wi-Fi: the lobby AP (a switch port's LLDP neighbour) and a second AP the controller knows; three laptops on Wi-Fi
    from .db import Device, WifiSighting, WirelessAp
    ap.neighbor_mac = "20:4c:03:aa:00:10"
    db.add(WirelessAp(source="unifi", key="20:4c:03:aa:00:10", name="ap-lobby-01", mac="20:4c:03:aa:00:10", ip="10.0.5.21",
                      bssids="20:4c:03:aa:00:11,20:4c:03:aa:00:12", model="AP-535", last_seen=now))
    db.add(WirelessAp(source="unifi", key="20:4c:03:aa:00:20", name="ap-floor2-east", mac="20:4c:03:aa:00:20", ip="10.0.5.22",
                      bssids="20:4c:03:aa:00:21,20:4c:03:aa:00:22", model="AP-535", last_seen=now))
    for k, host in enumerate(("WS-007", "WS-014", "WS-021")):
        dev = db.scalar(select(Device).where(Device.hostname == host))
        if not dev:
            continue
        wmac = f"a4:c3:f0:00:00:{k + 1:02x}"
        dev.connection, dev.wifi_ssid, dev.wifi_signal, dev.wifi_seen = "wireless", "CORP", 70 + k * 8, now - timedelta(minutes=10 * k)
        dev.wifi_bssid = "20:4c:03:aa:00:12" if k != 1 else "20:4c:03:aa:00:21"
        dev.wifi_ap = "ap-lobby-01" if k != 1 else "ap-floor2-east"
        db.add(WifiSighting(mac=wmac, hostname=host, ssid="CORP", bssid=dev.wifi_bssid, ap_key=dev.wifi_ap, ap_name=dev.wifi_ap,
                            source="pc", first_seen=now - timedelta(days=2), last_seen=dev.wifi_seen))
        db.add(WifiSighting(mac=wmac, hostname=host, ssid="CORP", bssid="20:4c:03:aa:00:22", ap_key="ap-floor2-east" if k != 1 else "ap-lobby-01",
                            ap_name="ap-floor2-east" if k != 1 else "ap-lobby-01", source="unifi",
                            first_seen=now - timedelta(days=9), last_seen=now - timedelta(days=3)))
    # Empty desks: ports that went down an hour ago, last week, two months ago, never since boot, and one shut down
    for j, sw in enumerate(access):
        boot = now - timedelta(seconds=sw.uptime_s)
        for k, (ago, admin) in enumerate(((timedelta(hours=1), True), (timedelta(days=6), True), (timedelta(days=62), True),
                                          (None, True), (timedelta(days=20), False))):
            ifi = 400 + k
            went = max(now - ago, boot + timedelta(minutes=5)) if ago else None
            db.add(SwitchPort(switch=sw, ifindex=ifi, name=(f"Gi1/0/{46 + k}" if sw.vendor == "Cisco" else f"1/1/{46 + k}"),
                              alias=["Desk spare", "Meeting room", "Old printer", "", "Disabled - reception"][k], oper_up=False,
                              admin_up=admin, speed_mbps=None, mac_count=0, vlan=20 if sw.location.startswith("HQ") else 30,
                              last_change=went or boot, changed_since_boot=went is not None, last_up=went))
    for sw in [core] + access:
        db.flush()
    # DC kerberos events (IP only) to show IP -> PC resolution
    add_logons(db, [LogonIn(time=now - timedelta(minutes=k * 7), username=random.choice(USERS),
                            ip=f"10.10.0.{random.randint(21, 60)}", logon_type=0, source="dc:DC01") for k in range(60)])
    for name, msg in (("ad", "42 computers, 3 domain controllers"), ("snmp", "4 devices polled"),
                      ("pcs", "39/42 PCs collected"), ("dc_logons", "60 logon events from 3 DCs")):
        db.add(CollectorRun(collector=name, started=now, finished=now, ok=True, message=msg + " (demo data)"))
    db.commit()
    from .correlate import resolve_logon_hosts
    resolve_logon_hosts(db)
    return f"Demo data loaded: {pcs} PCs, 3 DCs, 4 switches."
