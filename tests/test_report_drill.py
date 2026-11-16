"""Reports -> Computers list: every row of a summary report opens exactly the computers it counts.
Run: python tests/test_report_drill.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv import groups, library
from netinv.db import Device, SessionLocal

with TestClient(m.app) as c:
    with SessionLocal() as db:
        devs = sorted(db.scalars(select(Device)), key=lambda d: d.hostname)
        # PCs only known from AD: no WinRM DisplayVersion, the version comes from AD's build number
        devs[0].os_caption, devs[0].os_display_version, devs[0].ad_os, devs[0].ad_os_version = None, None, "Windows 11 Enterprise", "10.0 (22631)"
        devs[1].os_caption, devs[1].os_display_version, devs[1].ad_os = None, None, None     # no OS at all
        devs[2].os_display_version = "1809"                                                 # numeric-looking text
        db.commit()
        if not groups.names(db):
            c.post("/api/groups", json={"name": "Drill", "hostnames": [devs[3].hostname, devs[4].hostname]})

    row = c.post("/api/query", json={"dataset": "v_devices", "fields": ["os", "os_display_version"],
                                      "filters": [{"field": "hostname", "op": "eq", "value": devs[0].hostname}]}).json()["rows"][0]
    assert row == {"os": "Windows 11 Enterprise", "os_display_version": "23H2"}, row
    r = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"],
                                    "filters": [{"field": "os_display_version", "op": "eq", "value": "1809"}]})
    assert r.status_code == 200 and devs[2].hostname in [x["hostname"] for x in r.json()["rows"]], r.text

    lib = {x["id"]: x for x in c.get("/api/library").json()}
    assert set(library.DRILL) <= set(lib), set(library.DRILL) - set(lib)
    checked = 0
    for rid, d in library.DRILL.items():
        assert lib[rid]["drill"] == {"count": d["count"]}
        res = c.get(f"/api/library/{rid}").json()
        assert d["count"] in res["columns"], (rid, res["columns"])
        for row in res["rows"]:
            dr = c.post(f"/api/library/{rid}/drill", json={"row": row})
            assert dr.status_code == 200, (rid, dr.text)
            filters = dr.json()["filters"]
            got = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "filters": filters,
                                              "limit": 100000, "count": True}).json()["total"] if filters else 0
            assert got == row[d["count"]], (rid, row, got, filters)
            checked += 1
    if "os_versions" in library.DRILL:
        rows = c.get("/api/library/os_versions").json()["rows"]
        assert any(r["os"] == library.NOT_REPORTED for r in rows), rows
    assert c.post("/api/library/nope/drill", json={"row": {}}).status_code == 404
    print(checked, "report rows drill down to the right computers")
