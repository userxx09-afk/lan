"""Computer page / Computers list: the last user's first and last name from AD next to the user ID.
Run: python tests/test_last_user_name.py (DATABASE_URL set, demo loaded)."""
import logging, sys
from datetime import datetime
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import select
import netinv.main as m
from netinv.db import AdUser, Device, LogonEvent, SessionLocal

with TestClient(m.app) as c:
    with SessionLocal() as db:
        devs = sorted(db.scalars(select(Device)), key=lambda d: d.hostname)[:3]
        hosts = [d.hostname for d in devs]
        t = datetime(2099, 1, 1, 8, 0)
        db.add_all([AdUser(username="lun_full", first_name="Jane", last_name="Doe", display_name="Doe, Jane"),
                    AdUser(username="lun_disp", display_name="Help Desk")])
        for i, (h, u) in enumerate(zip(hosts, ["lun_full", "lun_disp", "lun_none"])):
            db.add(LogonEvent(time=t, username=u, hostname=h, source="test", ip=f"10.99.0.{i}", logon_type=2))
        db.commit()

    def row(h):
        r = c.post("/api/query", json={"dataset": "v_devices", "fields": ["last_user", "last_user_name"],
                                        "filters": [{"field": "hostname", "op": "eq", "value": h}]})
        assert r.status_code == 200, r.text
        return r.json()["rows"][0]
    assert row(hosts[0]) == {"last_user": "lun_full", "last_user_name": "Jane Doe"}, row(hosts[0])   # given name + surname
    assert row(hosts[1])["last_user_name"] == "Help Desk", row(hosts[1])                              # display name fallback
    assert row(hosts[2]) == {"last_user": "lun_none", "last_user_name": None}, row(hosts[2])         # not in AD
print("last user name OK")
