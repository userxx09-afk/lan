"""Admins (only they see and change Settings), no lock-out on upgrade or when saving, and per-user state: saved
reports belong to whoever saved them. Run: python tests/test_admins.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import delete, select
import netinv.main as m
from netinv import auth
from netinv.config import settings
from netinv.db import SavedReport, SessionLocal, get_setting, set_setting

settings.ui_user, settings.ui_password = "admin", auth.hash_password("correct horse battery")
assert not auth.local_disabled_file().exists(), "remove local-login.disabled before running this test"

# Fake AD: alice and bob may sign in (password "pw"). Membership of the admin AD group comes from AD_ADMINS.
AD_ADMINS = set()


def fake_ad_login_admin(db, username, password):
    sam = username.lower()
    if sam not in ("alice", "bob", "carol") or password != "pw":
        return None
    cfg = auth.admin_config(db)
    adm = not auth.admin_configured(cfg) or sam in cfg["users"] or bool(cfg["ad_group"] and sam in AD_ADMINS)
    return sam, adm


def fake_admin_live(db, sam, cfg=None):
    cfg = cfg or auth.admin_config(db)
    if not auth.admin_configured(cfg) or sam.lower() in cfg["users"]:
        return True
    if cfg["ad_group"] == "Unreachable":
        raise RuntimeError("no DC answered")
    return bool(cfg["ad_group"] and sam in AD_ADMINS)


auth.ad_login_admin = fake_ad_login_admin
auth.admin_live = fake_admin_live

def setup():
    with SessionLocal() as db:
        for k in ("auth:admin_users", "auth:admin_group", "auth:admin_user_group"):
            set_setting(db, k, None)
        set_setting(db, "auth:ad_domain", "corp.example.com")
        set_setting(db, "auth:ad_group", "NetInventory Users")
        db.execute(delete(SavedReport))
        db.add(SavedReport(name="Old shared report", spec='{"dataset": "v_devices", "fields": ["hostname"], "filters": []}'))
        db.commit()


def client(user, pw="pw"):
    c = TestClient(m.app)
    r = c.post("/api/login", json={"username": user, "password": pw})
    assert r.status_code == 200, (user, r.text)
    return c


SPEC = {"dataset": "v_devices", "fields": ["hostname"], "filters": [{"field": "hostname", "op": "contains", "value": "PC0"}]}
try:
    with TestClient(m.app) as boot:      # starts the app once
        setup()
        local = client("admin", "correct horse battery")
        auth.local_disabled_file().unlink(missing_ok=True)
        alice, bob = client("alice"), client("bob")
        auth.local_disabled_file().unlink(missing_ok=True)   # the AD sign-ins turned the local admin off; turn it back on

        # Upgrade: no admins set up yet, so everyone keeps Settings (nobody is locked out).
        assert alice.get("/api/me").json()["admin"] and bob.get("/api/me").json()["admin"]
        assert bob.get("/api/auth").status_code == 200 and not bob.get("/api/auth").json()["admins_set"]

        # Saving an admin list that leaves out the person saving it is refused.
        r = alice.put("/api/auth", json={"ad_domain": "corp.example.com", "ad_group": "NetInventory Users", "admin_users": "bob"})
        assert r.status_code == 400 and "wouldn't be an admin" in r.json()["detail"], r.text
        with SessionLocal() as db:
            assert not auth.admin_configured(auth.admin_config(db)), "a refused save must not change anything"
        # ...as is one AD can't confirm.
        r = alice.put("/api/auth", json={"ad_domain": "corp.example.com", "ad_group": "NetInventory Users", "admin_group": "Unreachable"})
        assert r.status_code == 400 and "Admin usernames" in r.json()["detail"], r.text
        r = alice.put("/api/auth", json={"ad_domain": "corp.example.com", "ad_group": "NetInventory Users",
                                         "admin_users": "CORP\\Alice"})
        assert r.status_code == 200, r.text
        assert r.json()["admin_users"] == "alice" and r.json()["admins_set"]

        # Bob's session (signed in before the change) is checked again: no longer an admin.
        me = bob.get("/api/me").json()
        assert me["user"] == "bob" and me["admin"] is False, me
        assert alice.get("/api/me").json()["admin"] and local.get("/api/me").json()["admin"], "local admin is always an admin"
        for call in (lambda c: c.get("/api/auth"), lambda c: c.put("/api/auth", json={"admin_users": "bob"}),
                     lambda c: c.put("/api/settings", json={"fix:reboot_hour": "3"}),
                     lambda c: c.post("/api/credentials", json={"name": "x", "kind": "winrm", "username": "a", "password": "b"}),
                     lambda c: c.post("/api/targets", json={"kind": "subnet", "value": "10.9.9.0/24"}),
                     lambda c: c.put("/api/retention", json={"days": {}}), lambda c: c.post("/api/agents/token", json={}),
                     lambda c: c.put("/api/jira/settings", json={"mode": "off"}), lambda c: c.post("/api/update/install", json={}),
                     lambda c: c.post("/api/exclusions", json={"kind": "ip", "value": "10.0.0.9"}),
                     lambda c: c.put("/api/deployments/settings", json={"queue_days": 3, "parallel": 4})):
            r = call(bob)
            assert r.status_code == 403, (r.request.method, r.request.url, r.status_code, r.text[:200])
        # Bob's own settings and the rest of the app still work.
        assert bob.put("/api/settings", json={"dameware_mode": "saved"}).status_code == 200
        assert bob.get("/api/settings").json()["dameware_mode"] == "saved"
        assert alice.get("/api/settings").json()["dameware_mode"] != "saved", "Bob's own choice must not reach Alice"
        for u in ("/api/summary", "/api/alerts", "/api/reports", "/api/logs/audit"):
            assert bob.get(u).status_code == 200, u
        assert alice.put("/api/settings", json={"fix:reboot_hour": "3"}).status_code == 200

        # An admin AD group: carol, who is in it, signs in as an admin; bob isn't.
        AD_ADMINS.add("carol")
        assert alice.put("/api/auth", json={"ad_domain": "corp.example.com", "ad_group": "NetInventory Users",
                                            "admin_users": "alice", "admin_group": "NetInventory Admins"}).status_code == 200
        carol = client("carol")
        auth.local_disabled_file().unlink(missing_ok=True)
        assert carol.get("/api/me").json()["admin"] and carol.get("/api/auth").status_code == 200
        assert not bob.get("/api/me").json()["admin"]

        # The user group that decides who is an admin can't be edited from the Groups tab by a non-admin.
        assert alice.post("/api/groups", json={"name": "NI admins", "kind": "users", "usernames": ["alee"]}).status_code == 200
        assert alice.put("/api/auth", json={"ad_domain": "corp.example.com", "ad_group": "NetInventory Users",
                                            "admin_users": "alice", "admin_group": "NetInventory Admins",
                                            "admin_user_group": "NI admins"}).status_code == 200
        r = bob.post("/api/groups", params={"old": "NI admins"}, json={"name": "NI admins", "kind": "users", "usernames": ["alee", "bob"]})
        assert r.status_code == 403, r.text
        assert bob.delete("/api/groups/NI admins").status_code in (400, 403)

        # Saved reports belong to whoever saved them.
        assert alice.post("/api/reports", json={"name": "Alice PCs", "spec": SPEC}).status_code == 200
        names = lambda c: {r["name"]: r for r in c.get("/api/reports").json() if not r["builtin"]}
        assert "Alice PCs" in names(alice) and "Alice PCs" not in names(bob), "a private report leaked to another user"
        assert names(alice)["Alice PCs"]["editable"] and names(alice)["Alice PCs"]["mine"]
        assert bob.post("/api/reports", json={"name": "Alice PCs", "spec": SPEC}).status_code == 409, "overwrote another user's report"
        rid = names(alice)["Alice PCs"]["id"]
        assert bob.delete(f"/api/reports/{rid}").status_code == 403
        assert alice.post("/api/reports", json={"name": "Alice PCs", "spec": SPEC, "shared": True}).status_code == 200
        b = names(bob)
        assert b["Alice PCs"]["shared"] and not b["Alice PCs"]["editable"]
        assert bob.post("/api/reports", json={"name": "Bob's", "spec": SPEC}).status_code == 200
        assert "Bob's" not in names(alice) and names(bob)["Bob's"]["editable"]
        # Reports from before 0.44 stay shared; only an admin can change them.
        assert names(bob)["Old shared report"]["shared"] and not names(bob)["Old shared report"]["editable"]
        assert bob.post("/api/reports", json={"name": "Old shared report", "spec": SPEC}).status_code == 409
        assert alice.post("/api/reports", json={"name": "Old shared report", "spec": SPEC}).status_code == 200
        assert alice.delete(f"/api/reports/{names(alice)['Old shared report']['id']}").status_code == 200

        # A browser that is now signed in as someone else gets that person's identity (the page then starts over).
        assert bob.get("/api/me").json()["user"] == "bob"
        bob.cookies = alice.cookies
        assert bob.get("/api/me").json()["user"] == "alice"

        # Removing every admin designation gives Settings back to everyone (and needs no AD check).
        assert alice.put("/api/auth", json={"ad_domain": "corp.example.com", "ad_group": "NetInventory Users",
                                            "admin_users": "", "admin_group": "", "admin_user_group": ""}).status_code == 200
        assert carol.get("/api/me").json()["admin"]
        print("admins and per-user reports OK")
finally:
    auth.local_disabled_file().unlink(missing_ok=True)
    with SessionLocal() as db:
        for k in ("auth:admin_users", "auth:admin_group", "auth:admin_user_group", "auth:ad_domain", "auth:ad_group"):
            set_setting(db, k, None)
        db.execute(delete(SavedReport).where(SavedReport.name.in_(("Alice PCs", "Bob's"))))
        from netinv.db import GroupDef, UserGroup
        db.execute(delete(UserGroup).where(UserGroup.name == "NI admins"))
        db.execute(delete(GroupDef).where(GroupDef.name == "NI admins"))
        db.commit()
