"""Groups page: rule-based groups (IP range, model, host name, OU...), hand-added members, and groups as targets.
Run: python tests/test_groups.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv import fixes, groups, scanning
from netinv.db import Device, DeviceNic, ScanJob, SessionLocal

queued = []
fixes.run_many = lambda hosts, action, user, value=None, adhoc=None: queued.append(sorted(set(hosts))) or len(set(hosts))

with TestClient(m.app) as c:
    with SessionLocal() as db:
        devs = {d.hostname: d for d in db.scalars(select(Device))}
        ips = {n.device_id: n.ip for n in db.scalars(select(DeviceNic)) if n.ip}
        optiplex = sorted(h for h, d in devs.items() if (d.model or "").startswith("OptiPlex"))
        in_10_10_0 = sorted(h for h, d in devs.items() if (ips.get(d.id) or "").startswith("10.10.0.")
                            and 20 <= int(ips[d.id].rsplit(".", 1)[1]) <= 30)
    assert optiplex and in_10_10_0

    # validation
    bad = lambda **kw: c.post("/api/groups", json={"name": "x", **kw}).status_code
    assert bad() == 400, "no conditions and no computers"
    assert bad(conditions=[{"field": "ip", "value": "10.1.2.300"}]) == 400
    assert bad(conditions=[{"field": "ou", "value": "Workstations"}]) == 400
    assert bad(conditions=[{"field": "nope", "value": "x"}]) == 400
    assert bad(hostnames=["NOT-A-PC"]) == 400
    assert c.post("/api/groups", json={"name": "a,b", "hostnames": [optiplex[0]]}).status_code == 400

    # preview, then save: model wildcard
    p = c.post("/api/groups/preview", json={"name": "x", "conditions": [{"field": "model", "value": "optiplex*"}]}).json()
    assert p["hostnames"] == optiplex, p
    r = c.post("/api/groups", json={"name": "OptiPlex", "conditions": [{"field": "model", "value": "OptiPlex*"}]})
    assert r.status_code == 200 and r.json()["members"] == len(optiplex), r.text
    # IP range, short form, AND an OU given as an ADUC path, AND a negated hostname
    conds = [{"field": "ip", "value": "10.10.0.20-30"}, {"field": "ou", "value": "corp.example.com/Workstations"},
             {"field": "hostname", "value": in_10_10_0[0], "not": True}]
    r = c.post("/api/groups", json={"name": "Office range", "match": "all", "conditions": conds})
    assert r.json()["members"] == len(in_10_10_0) - 1, r.text
    # any-of: CIDR or hostname wildcard
    r = c.post("/api/groups", json={"name": "Any", "match": "any",
                                    "conditions": [{"field": "ip", "value": "10.10.0.21/32"}, {"field": "hostname", "value": "WS-00?"}]})
    assert r.json()["members"] >= 1

    lst = {g["name"]: g for g in c.get("/api/groups").json()["groups"]}
    assert lst["OptiPlex"]["kind"] == "rules" and lst["OptiPlex"]["members"] == len(optiplex)
    assert "model is OptiPlex*" in lst["OptiPlex"]["rule"]

    # the grid's Groups column and the PC page see rule-based membership
    row = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname", "groups"],
                                     "filters": [{"field": "hostname", "op": "eq", "value": optiplex[0]}]}).json()["rows"][0]
    assert "OptiPlex" in row["groups"], row
    d = c.get(f"/api/devices/{optiplex[0]}").json()
    assert "OptiPlex" in d["rule_groups"]
    # a rule-based member can't be removed by hand (it would come back), a hand-added one can
    assert c.delete(f"/api/devices/{optiplex[0]}/groups/OptiPlex").status_code == 400
    other = next(h for h in devs if h not in optiplex)
    assert c.post(f"/api/devices/{other}/groups", json={"name": "OptiPlex"}).status_code == 200
    mem = {x["hostname"]: x["how"] for x in c.get("/api/groups/OptiPlex/members").json()["members"]}
    assert mem[other] == "added by hand" and mem[optiplex[0]] == "rules"
    assert c.delete(f"/api/devices/{other}/groups/OptiPlex").status_code == 200
    bulk = c.post("/api/bulk", json={"hostnames": [optiplex[0]], "action": "remove_group", "value": "OptiPlex"}).json()
    assert bulk["count"] == 0 and "rules" in bulk["note"]

    # membership follows the inventory
    with SessionLocal() as db:
        dev = db.scalar(select(Device).where(Device.hostname == other))
        old_model, dev.model = dev.model, "OptiPlex 9020"
        db.commit()
        groups.refresh(db)
    assert other in {x["hostname"] for x in c.get("/api/groups/OptiPlex/members").json()["members"]}
    with SessionLocal() as db:
        db.scalar(select(Device).where(Device.hostname == other)).model = old_model
        db.commit()
    assert other not in {x["hostname"] for x in c.get("/api/groups/OptiPlex/members").json()["members"]}, "hosts() refreshes"

    # "always include" on a rule group, then rename: members and scan jobs follow
    r = c.post("/api/groups?old=OptiPlex", json={"name": "Dell OptiPlex", "conditions": [{"field": "model", "value": "OptiPlex*"}],
                                                  "hostnames": [other]})
    assert r.json()["members"] == len(optiplex) + 1, r.text
    assert "OptiPlex" not in {g["name"] for g in c.get("/api/groups").json()["groups"]}

    # scripts run on a rule-based group
    assert "Dell OptiPlex" in c.get("/api/scripts").json()["groups"]
    r = c.post("/api/fix/bulk", json={"action": "script", "group": "Dell OptiPlex", "adhoc": {"language": "cmd", "body": "dir"}})
    assert r.status_code == 200 and queued[-1] == sorted(optiplex + [other]), (r.text, queued)

    # a group made from the Groups page by listing computers only
    r = c.post("/api/groups", json={"name": "Pilot", "hostnames": optiplex[:2]})
    assert r.json()["members"] == 2
    assert {g["name"]: g for g in c.get("/api/groups").json()["groups"]}["Pilot"]["kind"] == "manual"

    # "Other field": any v_devices column, with is / is not / less / more / empty
    with SessionLocal() as db:
        big = sorted(h for h, d in devs.items() if d.ram_gb is not None and d.ram_gb > 8)
        nomodel = sorted(h for h, d in devs.items() if not d.model)
    pv = lambda *conds, match="all": c.post("/api/groups/preview", json={"name": "x", "match": match, "conditions": list(conds)})
    r = pv({"field": "other", "column": "ram_gb", "op": "gt", "value": "8"})
    assert r.status_code == 200 and r.json()["hostnames"] == big, (r.text, big)
    assert pv({"field": "other", "column": "nope", "op": "is", "value": "x"}).status_code == 400
    assert pv({"field": "other", "column": "groups", "op": "is", "value": "x"}).status_code == 400, "no self-reference"
    assert pv({"field": "other", "column": "model", "op": "empty"}).json()["hostnames"] == nomodel
    assert pv({"field": "other", "column": "model", "op": "is", "value": "optiplex*"}).json()["hostnames"] == optiplex
    assert pv({"field": "other", "column": "model", "op": "not", "value": "OptiPlex"}).json()["count"] == len(devs) - len(optiplex)
    r = c.post("/api/groups", json={"name": "Big RAM", "conditions": [{"field": "other", "column": "ram_gb", "op": "gt", "value": "8"}]})
    assert r.json()["members"] == len(big)
    g = {g["name"]: g for g in c.get("/api/groups").json()["groups"]}["Big RAM"]
    assert g["rule"] == "ram_gb is more than 8" and g["conditions"][0]["column"] == "ram_gb", g
    mem = c.get("/api/groups/Big%20RAM/members").json()["members"]
    assert mem and all(k in mem[0] for k in ("os", "ip", "model", "ou")), mem[0]
    assert c.delete("/api/groups/Big%20RAM").status_code == 200

    # scan jobs: a group limits PC scans to its members
    job = {"name": "OptiPlex nightly", "collectors": ["pcs"], "at_time": "02:00", "group_name": "Dell OptiPlex"}
    assert c.post("/api/jobs", json={**job, "group_name": "nope"}).status_code == 400
    assert c.post("/api/jobs", json={**job, "collectors": ["ad"]}).status_code == 400
    assert c.post("/api/jobs", json=job).status_code == 200
    j = next(x for x in c.get("/api/jobs").json()["jobs"] if x["name"] == "OptiPlex nightly")
    assert j["group_name"] == "Dell OptiPlex" and "Dell OptiPlex" in j["scope"]
    assert c.delete("/api/groups/Dell%20OptiPlex").status_code == 400, "in use by a scan job"
    r = c.post("/api/groups?old=Dell%20OptiPlex", json={"name": "OptiPlex PCs", "conditions": [{"field": "model", "value": "OptiPlex*"}]})
    assert r.status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(ScanJob).where(ScanJob.name == "OptiPlex nightly")).group_name == "OptiPlex PCs"
        m.settings.winrm["user"] = "corp\\scan"      # so winrm_cfg doesn't need a stored credential
        with scanning.scoped(None, None, None, "OptiPlex PCs"):
            cfg = scanning.winrm_cfg(db)
        assert cfg["include_ad"] is False and sorted(h.split(".")[0].upper() for h in cfg["hosts"]) == optiplex, cfg
        with scanning.scoped(None, None, None, "Pilot"):
            pass
    jid = j["id"]
    assert c.delete(f"/api/jobs/{jid}").status_code == 200
    assert c.delete("/api/groups/OptiPlex%20PCs").status_code == 200
    assert "OptiPlex PCs" not in {g["name"] for g in c.get("/api/groups").json()["groups"]}
    for n in ("Office range", "Any", "Pilot"):
        assert c.delete(f"/api/groups/{n}").status_code == 200

print("groups: ok")
