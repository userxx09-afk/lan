"""App catalog + fixes API test against the demo data. Run: python tests/test_catalog.py (DATABASE_URL set, demo loaded)."""
import logging, os, sqlite3, sys, tempfile
from pathlib import Path
logging.disable(logging.CRITICAL)
tmp = Path(tempfile.mkdtemp())
os.environ["NETINV_CONFIG"] = str(tmp / "config.toml")      # catalog lives next to it
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netinv import catalog
assert catalog.norm_name("Mozilla Firefox (x64 en-US)") == "mozillafirefox"
assert catalog.norm_name("7-Zip 24.08 (x64)") == "7zip"
assert catalog.norm_name("Python 3.12.1 (64-bit)") == "python"
assert catalog.norm_name("Microsoft 365 Apps for enterprise - en-us") == "microsoft365appsforenterprise"
assert catalog.norm_name("Notepad++ (64-bit x64)") == "notepad"
assert catalog.norm_publisher("Google LLC") == "google"
assert catalog.norm_publisher("Cisco Systems, Inc.") == "ciscosystems"
assert catalog.norm_publisher("Microsoft Corporation") == "microsoft"
assert catalog.vt("3.12.10") == catalog.vt("3.12.10.0") and catalog.vt("6.0.11 (39959)") > catalog.vt("6.0.11")

# Small catalog with the real source2 index.db schema
db = catalog.catalog_file(); db.parent.mkdir(parents=True)
c = sqlite3.connect(db)
c.executescript("""
CREATE TABLE packages(rowid INTEGER PRIMARY KEY, id TEXT NOT NULL, name TEXT NOT NULL, moniker TEXT, latest_version TEXT NOT NULL, arp_min_version TEXT, arp_max_version TEXT, hash BLOB);
CREATE TABLE productcodes2(productcode TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(productcode, package)) WITHOUT ROWID;
CREATE TABLE norm_names2(norm_name TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(norm_name, package)) WITHOUT ROWID;
CREATE TABLE norm_publishers2(norm_publisher TEXT NOT NULL, package INT64 NOT NULL, PRIMARY KEY(norm_publisher, package)) WITHOUT ROWID;
""")
P = [(1, "Google.Chrome", "Google Chrome", "142.0.7444.60", ["googlechrome"], ["google"]),
     (2, "Mozilla.Firefox", "Mozilla Firefox (en-US)", "145.0", ["mozillafirefox", "mozillafirefox(X64)"], ["mozilla"]),
     (3, "7zip.7zip", "7-Zip", "25.01", ["7zip", "7zip(X64)"], ["igorpavlov"]),
     (4, "Zoom.Zoom", "Zoom Workplace", "6.6.0", ["zoomworkplace", "zoom(X64)"], ["zoom"]),
     (5, "Adobe.Acrobat.Reader.64-bit", "Adobe Acrobat Reader (64-bit)", "26.003.22075", ["adobeacrobatreader"], ["adobe"]),
     (6, "Adobe.Acrobat.Reader.32-bit", "Adobe Acrobat Reader (32-bit)", "26.002.22031", ["adobeacrobatreader"], ["adobe"]),
     (7, "Notepad++.Notepad++", "Notepad++", "8.8.7", ["notepad"], ["notepadteam"]),
     (8, "VideoLAN.VLC", "VLC media player", "3.0.21", ["vlcmediaplayer"], ["videolan"]),
     (9, "Evil.VLC", "VLC media player", "9.9", ["vlcmediaplayer"], ["someoneelse"])]
for k, pid, name, latest, norms, pubs in P:
    c.execute("INSERT INTO packages(rowid, id, name, latest_version) VALUES (?,?,?,?)", (k, pid, name, latest))
    c.executemany("INSERT INTO norm_names2 VALUES (?,?)", [(n, k) for n in norms])
    c.executemany("INSERT INTO norm_publishers2 VALUES (?,?)", [(p, k) for p in pubs])
c.executemany("INSERT INTO packages(rowid, id, name, latest_version) VALUES (?,?,?,?)",
              [(100 + i, f"Filler.App{i}", f"Filler {i}", "1.0") for i in range(1000)])
c.commit(); c.close()

from fastapi.testclient import TestClient
import netinv.main as m
from netinv.db import SessionLocal, Software
with TestClient(m.app) as cl:
    with SessionLocal() as s:
        print("reconcile:", catalog.reconcile(s))
        st = {}
        for r in s.query(Software):
            st.setdefault(r.name, set()).add((r.version, r.sw_status, r.catalog_id, r.match_method))
    for k, v in sorted(st.items()):
        print(" ", k, sorted(v, key=str))
    chrome = st["Google Chrome"]
    assert ("142.0.7444.60", "current", "Google.Chrome", "name") in chrome
    assert any(x[1] == "outdated" for x in chrome if x[0] != "142.0.7444.60")
    assert all(x[2] == "VideoLAN.VLC" for x in st["VLC media player"]), "publisher must pick VideoLAN, not the look-alike"
    assert all(x[3] == "family" and x[1] == "outdated" for x in st["Adobe Acrobat Reader"])
    assert all(x[1] == "outdated" for x in st["7-Zip 19.00 (x64)"])
    assert all(x[1] == "unknown" for x in st["Java 8 Update 202"])

    a = cl.get("/api/apps").json()
    assert a["apps"][0]["outdated"] > 0 and a["catalog"] is not None
    assert cl.get("/api/apps/computers", params={"name": "Google Chrome", "status": "outdated"}).json()
    assert cl.get("/api/catalog/search", params={"q": "chrome"}).json()[0]["id"] == "Google.Chrome"
    # rules: ignore, map, target; bad input refused
    assert cl.post("/api/catalog/rules", json={"match": "^Java 8", "action": "target", "value": "8.0.4510"}).status_code == 200
    assert cl.post("/api/catalog/rules", json={"match": "Acrobat", "action": "package", "value": "Nope.Nope"}).status_code == 400
    assert cl.post("/api/catalog/rules", json={"match": "(", "action": "ignore"}).status_code == 400
    with SessionLocal() as s:
        catalog.reconcile(s)
        assert {r.sw_status for r in s.query(Software).filter(Software.name.like("Java 8%"))} == {"outdated"}
    rules = cl.get("/api/catalog").json()["rules"]
    assert cl.delete(f"/api/catalog/rules/{rules[0]['id']}").status_code == 200
    # fixes: validation (no credential is configured in the demo, so nothing reaches a PC)
    host = cl.get("/api/apps/computers", params={"name": "Google Chrome"}).json()[0]["hostname"]
    r = cl.post(f"/api/devices/{host}/fix", json={"action": "app_update", "value": "Google.Chrome"}).json()
    assert r["ok"] is False and "credential" in r["output"], r
    assert cl.post(f"/api/devices/{host}/fix", json={"action": "format_c"}).json()["ok"] is False
    assert cl.post("/api/fix/bulk", json={"action": "format_c", "hostnames": [host]}).status_code == 400
    for lid in ("sw_outdated", "sw_outdated_apps", "sw_unknown", "sw_catalog_status"):
        assert cl.get(f"/api/library/{lid}").status_code == 200, lid
    d = cl.get(f"/api/devices/{host}").json()
    assert "status" in d["software"][0] and "fixes_running" in d
print("app catalog OK")
