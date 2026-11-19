"""Settings > DameWare: the launcher files and the zip download.
Run: python tests/test_dameware_kit.py (DATABASE_URL set, demo loaded)."""
import io, logging, sys, zipfile
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import dwkit
from netinv.db import SessionLocal, set_setting

with TestClient(m.app) as c:
    with SessionLocal() as db:
        set_setting(db, "auth:ad_domain", "Corp.Example.com")
        db.commit()
        assert "corp.example.com" in dwkit.suffixes(db)
        set_setting(db, "auth:ad_domain", 'bad"; calc & x.com')        # never ends up in Install.cmd
        db.commit()
        assert not any('"' in s or "&" in s for s in dwkit.suffixes(db))
        set_setting(db, "auth:ad_domain", "corp.example.com")
        db.commit()

    k = c.get("/api/dameware/kit").json()
    assert k["files"] == list(dwkit.FILES) and "corp.example.com" in k["suffixes"], k

    for n in dwkit.FILES:
        r = c.get(f"/api/dameware/files/{n}")
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"], (n, r.status_code)
    assert c.get("/api/dameware/files/..%2Fmain.py").status_code == 404
    assert c.get("/api/dameware/files/config.toml").status_code == 404
    reg = c.get("/api/dameware/files/dameware-handler.reg").text
    assert '\n"DameWareAllowedSuffixes"=".corp.example.com' in reg, reg       # filled in, uncommented

    r = c.get("/api/dameware/kit.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    want = {f"{dwkit.FOLDER}/{n}" for n in (*dwkit.FILES, "Install.cmd", "Uninstall.cmd", "README.txt")}
    assert names == want, names
    inst = z.read(f"{dwkit.FOLDER}/Install.cmd").decode()
    assert "\r\n" in inst and "Install-DameWareHandler.ps1" in inst and "-AllowedSuffixes" in inst and "RunAs" in inst
    assert "-Uninstall" in z.read(f"{dwkit.FOLDER}/Uninstall.cmd").decode()
    readme = z.read(f"{dwkit.FOLDER}/README.txt").decode()
    assert "Startup" in readme and "NETLOGON" in readme and ".corp.example.com" in readme
    assert z.read(f"{dwkit.FOLDER}/Open-DameWare.ps1") == (dwkit.DIR / "Open-DameWare.ps1").read_bytes()
# all three need a signed-in user (same dependency as the rest of the UI API)
for r in m.app.routes:
    if getattr(r, "path", "").startswith("/api/dameware/"):
        assert any(d.call is m.ui_auth for d in r.dependant.dependencies), r.path
print("ok")
