"""User groups (AD users by OU, AD security group, department...), AD group conditions for computers, user groups as
computer targets and as the sign-in allow list. Run: python tests/test_user_groups.py (DATABASE_URL set, demo loaded)."""
import json, logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv import auth, fixes, groups
from netinv.collectors import ad as adc
from netinv.db import AdUser, Device, LogonEvent, SessionLocal, set_setting, utcnow

queued = []
auth.auth_required = lambda: False      # the test sets a sign-in group but stays signed out
fixes.run_many = lambda hosts, action, user, value=None, adhoc=None, **kw: queued.append(sorted(set(hosts))) or len(set(hosts))

with TestClient(m.app) as c:
    with SessionLocal() as db:
        users = {u.username: u for u in db.scalars(select(AdUser))}
        finance = sorted(u for u, x in users.items() if ",ou=engineering," in x.dn.lower())
        vpn = sorted(u for u, x in users.items() if "vpn users" in x.group_dns)
        locked = sorted(u for u, x in users.items() if x.locked)
        bitlocker = sorted(d.hostname for d in db.scalars(select(Device)) if "bitlocker" in (d.ad_groups or ""))
    assert finance and vpn and locked and bitlocker

    G = lambda **kw: {"name": "x", "kind": "users", **kw}
    bad = lambda **kw: c.post("/api/groups", json=G(**kw)).status_code
    assert bad(conditions=[{"field": "hostname", "value": "PC*"}]) == 400, "computer field on a user group"
    assert bad(conditions=[{"field": "adgroup", "value": "No Such Group"}]) == 400, "unknown AD group"
    assert bad(conditions=[{"field": "status", "value": "Sleepy"}]) == 400
    assert bad(usernames=["nobody"]) == 400
    assert c.post("/api/groups", json={"name": "x", "kind": "printers", "usernames": ["alee"]}).status_code == 400

    # OU (ADUC path), includes sub-OUs
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "ou", "value": "corp.example.com/Staff/Engineering"}])).json()
    assert p["names"] == finance, p
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "ou", "value": "OU=Staff,DC=corp,DC=example,DC=com"}])).json()
    assert p["count"] == len(users)
    # AD security group: direct, nested (All Staff holds the department groups), by DN, wildcard
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "adgroup", "value": "VPN Users"}])).json()
    assert p["names"] == vpn, p
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "adgroup", "value": "All Staff"}])).json()
    assert p["count"] == len(users), "nested membership"
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "adgroup", "value": "CN=Finance Staff, OU=Groups,DC=corp,DC=example,DC=com"}])).json()
    assert p["names"] == sorted(u for u, x in users.items() if "finance staff" in x.group_dns), p
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "adgroup", "value": "fin*"}])).json()
    assert p["count"] >= 1
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "adgroup", "value": "Domain Users"}])).json()
    assert p["count"] == len(users), "primary group"
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "status", "value": "Locked"}])).json()
    assert p["names"] == locked
    p = c.post("/api/groups/preview", json=G(conditions=[{"field": "other", "column": "office", "op": "is", "value": "HQ floor 1"}])).json()
    assert p["names"] == sorted(u for u, x in users.items() if x.office == "HQ floor 1"), p

    # save: OU and AD group together, plus a user added by hand
    extra = next(u for u in users if u not in vpn and u not in finance)
    body = G(name="Finance VPN", match="any", conditions=[{"field": "ou", "value": "corp.example.com/Staff/Engineering"},
                                                          {"field": "adgroup", "value": "VPN Users"}], usernames=[f"CORP\\{extra}"])
    r = c.post("/api/groups", json=body)
    want = sorted(set(finance) | set(vpn) | {extra})
    assert r.status_code == 200 and r.json()["members"] == len(want), r.text
    lst = {g["name"]: g for g in c.get("/api/groups").json()["groups"]}
    assert lst["Finance VPN"]["of"] == "users" and lst["Finance VPN"]["members"] == len(want)
    assert "OU is" in lst["Finance VPN"]["rule"] and "AD group is VPN Users" in lst["Finance VPN"]["rule"]
    mem = c.get("/api/groups/Finance%20VPN/members").json()
    assert mem["of"] == "users" and sorted(x["username"] for x in mem["members"]) == want
    assert {x["username"]: x["how"] for x in mem["members"]}[extra] == "added by hand"
    assert "Finance VPN" in c.get(f"/api/users/{finance[0]}").json()["ni_groups"]
    row = c.post("/api/query", json={"dataset": "v_users", "fields": ["username", "groups"],
                                     "filters": [{"field": "username", "op": "eq", "value": finance[0]}]}).json()["rows"][0]
    assert "Finance VPN" in row["groups"], row
    # a user group can't become a computer group, and computer names are refused
    assert c.post("/api/groups?old=Finance%20VPN", json={**body, "kind": "computers"}).status_code == 400

    # membership follows AD: moving a user out of the Finance OU drops them (unless VPN / by hand)
    mover = next(u for u in finance if u not in vpn and u != extra)
    with SessionLocal() as db:
        u = db.scalar(select(AdUser).where(AdUser.username == mover))
        old_dn, u.dn = u.dn, u.dn.replace("OU=Engineering", "OU=Sales")
        db.commit()
        groups.refresh(db)
        assert mover not in groups.users(db, "Finance VPN")
        db.scalar(select(AdUser).where(AdUser.username == mover)).dn = old_dn
        db.commit()
        assert mover in groups.users(db, "Finance VPN")

    # as a computer target: the PCs its users signed in to lately
    with SessionLocal() as db:
        pc = db.scalar(select(Device).order_by(Device.hostname)).hostname
        db.add(LogonEvent(username=finance[0], hostname=pc, time=utcnow(), source="test", logon_type=2))
        db.commit()
        hosts = groups.hosts(db, "Finance VPN")
    assert pc in hosts
    assert "Finance VPN" in c.get("/api/scripts").json()["groups"]
    queued.clear()
    r = c.post("/api/fix/bulk", json={"action": "reboot", "group": "Finance VPN"})
    assert r.status_code == 200 and queued and pc in queued[-1], (r.text, queued)

    # computers by AD group
    r = c.post("/api/groups", json={"name": "BitLocker", "conditions": [{"field": "adgroup", "value": "BitLocker PCs"}]})
    assert r.status_code == 200 and r.json()["members"] == len(bitlocker), r.text
    p = c.post("/api/groups/preview", json={"name": "x", "conditions": [{"field": "adgroup", "value": "Domain Computers"}]}).json()
    assert p["count"] >= len(bitlocker)

    # bulk account actions on the group's users (AD write mocked)
    calls = []
    adc.user_action = lambda cfg, dn, action, *a, **k: calls.append((dn, action)) or "done"
    import netinv.scanning as sc
    sc.ad_action_cfg = lambda db, dn: {}
    r = c.post("/api/groups/Finance%20VPN/users/unlock").json()
    assert r["ok"] and len(calls) == len([u for u in want if u in locked]), (r, calls)
    assert c.post("/api/groups/BitLocker/users/unlock").status_code == 400

    # sign-in: allow a user group; checked against the user's live AD entry (here: built by hand)
    r = c.put("/api/auth", json={"ad_domain": "corp.example.com", "ad_group": "", "access_group": "No such"})
    assert r.status_code == 400
    r = c.put("/api/auth", json={"ad_domain": "corp.example.com", "ad_group": "", "access_group": "Finance VPN"})
    assert r.status_code == 200 and r.json()["access_group"] == "Finance VPN"
    with SessionLocal() as db:
        tree = groups._GroupTree(db)
        live = lambda name, dn, gs, **kw: groups.user_entity(name, dn, gs, tree=tree, nested=True, **kw)
        assert groups.user_in_group(db, "Finance VPN", live("newhire", "CN=New Hire,OU=Engineering,OU=Staff,DC=corp,DC=example,DC=com", []))
        assert groups.user_in_group(db, "Finance VPN", live("x1", "CN=X,OU=Sales,OU=Staff,DC=corp,DC=example,DC=com",
                                                            ["CN=VPN Users,OU=Groups,DC=corp,DC=example,DC=com"]))
        assert not groups.user_in_group(db, "Finance VPN", live("x2", "CN=X,OU=Sales,OU=Staff,DC=corp,DC=example,DC=com", []))
        assert groups.user_in_group(db, "Finance VPN", live(extra, "CN=X,OU=Sales,DC=corp,DC=example,DC=com", [])), "added by hand"
        assert not groups.user_in_group(db, "BitLocker", live("newhire", "CN=New Hire,OU=Engineering,OU=Staff,DC=corp,DC=example,DC=com", []))
    assert c.delete("/api/groups/Finance%20VPN").status_code == 400, "used by sign-in"
    r = c.post("/api/groups?old=Finance%20VPN", json={**body, "name": "Finance and VPN"})
    assert r.status_code == 200 and c.get("/api/auth").json()["access_group"] == "Finance and VPN", "rename follows"
    with SessionLocal() as db:
        set_setting(db, "auth:access_group", None)
        set_setting(db, "auth:ad_domain", None)
        db.commit()
    assert c.delete("/api/groups/Finance%20and%20VPN").status_code == 200
    assert c.delete("/api/groups/BitLocker").status_code == 200
    assert c.get("/api/users/alee").status_code == 200

print("user groups: ok")
