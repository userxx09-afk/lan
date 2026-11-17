"""Computers list: Domain column/filter and per-user saved columns.
Run: python tests/test_computers_view.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv.db import Device, SessionLocal

with TestClient(m.app) as c:
    with SessionLocal() as db:
        devs = sorted(db.scalars(select(Device)), key=lambda d: d.hostname)
        a, b, x = devs[0], devs[1], devs[2]
        a.ad_dn, a.fqdn = f"CN={a.hostname},OU=PCs,DC=Branch,DC=Example,DC=org", None        # domain from the DN
        b.ad_dn, b.fqdn = None, f"{b.hostname.lower()}.lab.example.net"                      # only DNS knows it
        x.ad_dn, x.fqdn = None, x.hostname                                                    # no domain at all
        names = a.hostname, b.hostname, x.hostname
        db.commit()

    def dom(h):
        r = c.post("/api/query", json={"dataset": "v_devices", "fields": ["domain"],
                                        "filters": [{"field": "hostname", "op": "eq", "value": h}]})
        assert r.status_code == 200, r.text
        return r.json()["rows"][0]["domain"]
    assert dom(names[0]) == "branch.example.org", dom(names[0])
    assert dom(names[1]) == "lab.example.net", dom(names[1])
    assert dom(names[2]) is None, dom(names[2])

    ds = {d["domain"]: d["computers"] for d in c.get("/api/domains").json()}
    assert ds.get("branch.example.org") == 1 and ds.get("lab.example.net") == 1, ds
    assert ds.get("corp.example.com", 0) > 0, ds
    r = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "count": True,
                                    "filters": [{"field": "domain", "op": "eq", "value": "branch.example.org"}]}).json()
    assert [row["hostname"] for row in r["rows"]] == [names[0]], r

    # per-user columns
    assert c.get("/api/prefs/computers").json() == {}
    cols = ["hostname", "domain", "serial", "ram_gb"]
    assert c.put("/api/prefs/computers", json={"columns": cols}).status_code == 200
    assert c.get("/api/prefs/computers").json() == {"columns": cols}
    assert c.put("/api/prefs/computers", json={"columns": ["hostname", "nope; DROP"]}).status_code == 400
    assert c.get("/api/prefs/nope").status_code == 404
    assert c.put("/api/prefs/computers", json={}).status_code == 200
    assert c.get("/api/prefs/computers").json() == {}
    print("Computers list domain filter and saved columns OK")
