"""Remote control (rcontrol.py) with the PC faked: enrollment, signed control connection, asking the user, the
direct-connect group, one-time tokens, the input filter, view only, ending, history, audit and the push.
Run: python tests/test_rcontrol.py (DATABASE_URL set, demo loaded)."""
import base64, hashlib, hmac, json, logging, os, re, sys, tempfile, time, uuid
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

msi = Path(tempfile.mkdtemp()) / "NetInventory-Remote.msi"
msi.write_bytes(b"MSI" * 50_000)
os.environ["NETINV_RC_MSI"] = str(msi)

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import agentpush, auth, fixes, rcontrol, scanning
from netinv.collectors import winrm

ORIGIN = {"origin": "http://testserver"}


def sig_headers(agent_id, secret, path="/api/rc/agent/control", body=b""):
    ts, nonce = str(int(time.time())), uuid.uuid4().hex
    msg = f"{ts}\n{nonce}\n{path}\n{hashlib.sha256(body).hexdigest()}".encode()
    return {"x-agent-id": agent_id, "x-agent-ts": ts, "x-agent-nonce": nonce,
            "x-agent-sig": hmac.new(secret, msg, hashlib.sha256).hexdigest(), "x-agent-version": "test"}


def denied(c, url, headers=None):
    try:
        with c.websocket_connect(url, headers=headers or {}) as ws:
            ws.receive_text()
        return False
    except Exception:
        return True


def audit(c, action):
    return c.get("/api/logs/audit", params={"action": action, "limit": 50}).json()["rows"]


who = {"user": "admin", "source": "local"}
rcontrol._session_of = lambda conn: auth.Session(user=who["user"], source=who["source"], created=time.time(), seen=time.time())
member = {}
rcontrol._member = lambda db, sam, group: member.get((sam, group), False)

with TestClient(m.app) as c:
    from netinv.db import RcAgent, RcSession, SessionLocal
    with SessionLocal() as db:     # rerunnable
        db.query(RcAgent).delete(); db.query(RcSession).delete(); db.commit()
    hosts = [r["hostname"] for r in c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "limit": 3}).json()["rows"]]
    host = hosts[0]

    # ---- enrollment: no token, wrong token, site token
    assert c.post("/api/rc/agent/enroll", json={"token": "nra_x", "hostname": host}).status_code == 403
    tok = c.post("/api/rc/token").json()["token"]
    assert tok.startswith("nra_")
    assert c.put("/api/rc/settings", json={"approve": "all"}).status_code == 200
    e = c.post("/api/rc/agent/enroll", json={"token": tok, "hostname": host, "machine_guid": "g1", "version": "1"}).json()
    assert e["status"] == "active", e
    aid, secret = e["agent_id"], base64.b64decode(e["secret"])
    # another machine claiming the same name waits for approval
    e2 = c.post("/api/rc/agent/enroll", json={"token": tok, "hostname": host, "machine_guid": "g2"}).json()
    assert e2["status"] == "pending", e2
    assert denied(c, "/api/rc/agent/control", sig_headers(e2["agent_id"], base64.b64decode(e2["secret"])))
    # bad signature, replayed nonce
    assert denied(c, "/api/rc/agent/control", sig_headers(aid, b"x" * 32))
    h = sig_headers(aid, secret)

    with c.websocket_connect("/api/rc/agent/control", headers=h) as ctl:
        assert denied(c, "/api/rc/agent/control", h), "a replayed signature must be refused"
        ctl.send_text(json.dumps({"t": "hello", "user": "CORP\\bob", "version": "test"}))
        time.sleep(0.2)
        st = c.get(f"/api/devices/{host}/rc").json()
        assert st["online"] and st["user"] == "CORP\\bob", st

        # ---- offline PC
        assert c.post("/api/rc/sessions", json={"hostname": hosts[1]}).status_code == 409

        # ---- asked, accepted, connected, input filtered, ended by the technician
        r = c.post("/api/rc/sessions", json={"hostname": host, "reason": "printer issue"}).json()
        sid, vt = r["sid"], r["token"]
        assert r["direct"] is False
        req = json.loads(ctl.receive_text())
        assert req["t"] == "session" and req["sid"] == sid and req["ask"] is True and req["reason"] == "printer issue", req
        assert c.post("/api/rc/sessions", json={"hostname": host}).status_code == 409, "one session per PC"
        assert denied(c, f"/api/rc/view/{sid}?t={vt}", {"origin": "https://evil.example"}), "cross-site WebSocket"
        assert denied(c, f"/api/rc/view/{sid}?t=wrong", ORIGIN)
        who["user"] = "mallory"
        assert denied(c, f"/api/rc/view/{sid}?t={vt}", ORIGIN), "another user can't open someone else's session"
        who["user"] = "admin"
        with c.websocket_connect(f"/api/rc/view/{sid}?t={vt}", headers=ORIGIN) as v:
            assert json.loads(v.receive_text())["s"] == "asking"
            assert denied(c, f"/api/rc/view/{sid}?t={vt}", ORIGIN), "viewer token is one use"
            assert denied(c, "/api/rc/agent/stream", {"x-rc-session": sid, "x-rc-token": req["token"]}), "no stream before the answer"
            ctl.send_text(json.dumps({"t": "consent", "sid": sid, "result": "accepted", "user": "CORP\\bob"}))
            assert json.loads(v.receive_text())["s"] == "connecting"
            with c.websocket_connect("/api/rc/agent/stream", headers={"x-rc-session": sid, "x-rc-token": req["token"]}) as pc:
                assert json.loads(v.receive_text())["s"] == "connected"
                assert denied(c, "/api/rc/agent/stream", {"x-rc-session": sid, "x-rc-token": req["token"]}), "stream token is one use"
                pc.send_text(json.dumps({"t": "info", "mon": 0, "mons": [{"x": 0, "y": 0, "w": 1920, "h": 1080, "primary": True}], "desk": "Default"}))
                info = json.loads(v.receive_text())
                assert info["t"] == "info" and info["mons"][0]["w"] == 1920, info
                frame = b"F" + bytes(6) + b"jpeg..."
                pc.send_bytes(frame)
                assert v.receive_bytes() == frame
                for bad in ({"t": "exec", "cmd": "calc"}, {"t": "kd", "c": "Key A; rm"}, {"t": "mm", "x": -1, "y": 5},
                            {"t": "md", "x": 1, "y": 1, "b": 7}, {"t": "mm", "x": "1", "y": 2}, [1, 2]):
                    v.send_text(json.dumps(bad))
                v.send_text("not json")
                v.send_text(json.dumps({"t": "mm", "x": 10, "y": 20, "extra": "dropped"}))
                assert json.loads(pc.receive_text()) == {"t": "mm", "x": 10, "y": 20}, "only checked input reaches the PC"
                v.send_text(json.dumps({"t": "cad"}))
                assert json.loads(ctl.receive_text()) == {"t": "cad", "sid": sid}
                v.send_text(json.dumps({"t": "kd", "c": "KeyA"}))
                assert json.loads(pc.receive_text()) == {"t": "kd", "c": "KeyA"}
                v.send_text(json.dumps({"t": "end"}))
                assert json.loads(pc.receive_text()) == {"t": "end"}
            assert json.loads(ctl.receive_text()) == {"t": "end", "sid": sid}
        time.sleep(0.3)
        hist = c.get("/api/rc/history", params={"host": host}).json()["rows"]
        assert hist[0]["status"] == "ended" and hist[0]["consent"] == "accepted" and hist[0]["pc_user"] == "CORP\\bob", hist[0]
        assert hist[0]["reason"] == "printer issue" and hist[0]["kb"] == 0 and not hist[0]["live"], hist[0]
        for a in ("rc.request", "rc.consent", "rc.start", "rc.cad", "rc.end"):
            assert audit(c, a), f"no {a} in the audit log"

        # ---- refused by the user
        r = c.post("/api/rc/sessions", json={"hostname": host}).json()
        req = json.loads(ctl.receive_text())
        with c.websocket_connect(f"/api/rc/view/{r['sid']}?t={r['token']}", headers=ORIGIN) as v:
            v.receive_text()
            ctl.send_text(json.dumps({"t": "consent", "sid": r["sid"], "result": "denied", "user": "CORP\\bob"}))
            s = json.loads(v.receive_text())
            assert s["s"] == "denied" and "Refused by CORP\\bob" in s["msg"], s
        assert denied(c, "/api/rc/agent/stream", {"x-rc-session": r["sid"], "x-rc-token": req["token"]})
        assert c.get("/api/rc/history").json()["rows"][0]["status"] == "denied"
        assert audit(c, "rc.denied")

        # ---- view only: no input passes
        r = c.post("/api/rc/sessions", json={"hostname": host, "view_only": True}).json()
        req = json.loads(ctl.receive_text())
        with c.websocket_connect(f"/api/rc/view/{r['sid']}?t={r['token']}", headers=ORIGIN) as v:
            v.receive_text()
            ctl.send_text(json.dumps({"t": "consent", "sid": r["sid"], "result": "accepted", "user": "CORP\\bob"}))
            v.receive_text()
            with c.websocket_connect("/api/rc/agent/stream", headers={"x-rc-session": r["sid"], "x-rc-token": req["token"]}) as pc:
                v.receive_text()
                v.send_text(json.dumps({"t": "kd", "c": "KeyA"}))
                v.send_text(json.dumps({"t": "full"}))
                assert json.loads(pc.receive_text()) == {"t": "full"}, "view only: keys dropped, display requests pass"
                # the user ends it at the PC
                pc.send_text(json.dumps({"t": "bye", "why": "ended by the user at the PC"}))
            s = json.loads(v.receive_text())
            assert s["s"] == "ended" and "user at the PC" in s["msg"], s
        assert json.loads(ctl.receive_text())["t"] == "end"    # the end notice to the service

        # ---- direct-connect group (AD) and the PC's own AlwaysAsk policy
        c.put("/api/rc/settings", json={"approve": "all", "direct_group": "RC Direct"})
        who.update(user="alice", source="ad")
        member[("alice", "RC Direct")] = True
        assert c.post("/api/rc/check").json()["direct"] is True
        r = c.post("/api/rc/sessions", json={"hostname": host}).json()
        assert r["direct"] is True
        assert json.loads(ctl.receive_text())["ask"] is False
        assert c.post(f"/api/rc/sessions/{r['sid'][:8]}/end").status_code == 200
        assert json.loads(ctl.receive_text())["t"] == "end"
        ctl.send_text(json.dumps({"t": "hello", "user": "CORP\\bob", "always_ask": True}))
        time.sleep(0.2)
        r = c.post("/api/rc/sessions", json={"hostname": host}).json()
        assert r["direct"] is False and json.loads(ctl.receive_text())["ask"] is True, "the PC's AlwaysAsk policy wins"
        c.post(f"/api/rc/sessions/{r['sid']}/end"); assert json.loads(ctl.receive_text())["t"] == "end"
        ctl.send_text(json.dumps({"t": "hello", "user": "CORP\\bob"}))
        # local admin is never direct
        who.update(user="admin", source="local")
        r = c.post("/api/rc/sessions", json={"hostname": host}).json()
        assert r["direct"] is False and json.loads(ctl.receive_text())["ask"] is True
        c.post(f"/api/rc/sessions/{r['sid']}/end"); assert json.loads(ctl.receive_text())["t"] == "end"

        # ---- allowed group: non-members, local accounts and AD failures are refused
        c.put("/api/rc/settings", json={"approve": "all", "allowed_group": "RC Users", "direct_group": "RC Direct"})
        assert c.post("/api/rc/sessions", json={"hostname": host}).status_code == 403
        who.update(user="bob", source="ad")
        assert c.post("/api/rc/sessions", json={"hostname": host}).status_code == 403
        member[("bob", "RC Users")] = True
        r = c.post("/api/rc/sessions", json={"hostname": host})
        assert r.status_code == 200 and r.json()["direct"] is False and json.loads(ctl.receive_text())["t"] == "session"
        c.post(f"/api/rc/sessions/{r.json()['sid']}/end"); assert json.loads(ctl.receive_text())["t"] == "end"

        def boom(db, sam, group):
            raise RuntimeError("DC unreachable")
        rcontrol._member = boom
        assert c.post("/api/rc/sessions", json={"hostname": host}).status_code == 403, "fail closed when AD can't be asked"
        rcontrol._member = lambda db, sam, group: member.get((sam, group), False)
        assert audit(c, "rc.refused")
        c.put("/api/rc/settings", json={"approve": "all", "require_reason": True})
        assert c.post("/api/rc/sessions", json={"hostname": host}).status_code == 400
        c.put("/api/rc/settings", json={"approve": "all", "enabled": False})
        assert c.post("/api/rc/sessions", json={"hostname": host, "reason": "x"}).status_code == 403
        c.put("/api/rc/settings", json={"approve": "ad"})
        who.update(user="admin", source="local")

        # ---- revoking drops the connection
        ag = [a for a in c.get("/api/rc").json()["agents"] if a["hostname"] == host and a["status"] == "active"][0]
        assert ag["online"]
        assert c.post(f"/api/rc/agents/{ag['id']}/revoke").status_code == 200
        try:
            ctl.receive_text()
            raise AssertionError("still connected after revoke")
        except AssertionError:
            raise
        except Exception:
            pass
    assert denied(c, "/api/rc/agent/control", sig_headers(aid, secret))

    # ---- input filter
    ci = rcontrol.clean_input
    assert ci({"t": "wh", "dy": 120}) == {"t": "wh", "dx": 0, "dy": 120}
    assert ci({"t": "wh", "dy": 99999}) is None and ci({"t": "q", "v": 5}) is None and ci({"t": "mon", "i": 2}) == {"t": "mon", "i": 2}
    assert ci({"t": "md", "x": True, "y": 1, "b": 0}) is None

    # ---- push from the dashboard: one-time nrp_ ticket, enrolls approved at once
    sent = []

    def fake_run_ps(addr, cfg, script):
        if "NetInventory fix" in script and "FromBase64String('" in script:
            sent.append(base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)", script).group(1)).decode())
            return {"ok": True}
        if "done = $true" in script:
            return {"done": True, "state": "Ready", "result": {"ok": True, "message": "Installed and connected", "signature": "Valid"}}
        return {}
    winrm.run_ps = fake_run_ps
    scanning.winrm_cfg = lambda db: {"username": "x", "password": "y"}
    fixes._cfg = lambda db, dep=None: {"username": "x", "password": "y"}
    agentpush.pin = lambda: "AB" * 32
    r = c.post("/api/rc/push", json={"hostnames": [hosts[2]], "server_url": "https://netinv.corp.local:8080"}).json()
    assert r["count"] == 1, r
    fixes.poll_once(); time.sleep(1.5)
    assert sent, "nothing sent"
    inner = sent[0]
    ticket = re.search(r"TOKEN=(nrp_[A-Za-z0-9_\-]+)", inner).group(1)
    assert "SERVER=https://netinv.corp.local:8080" in inner and "PIN=" + "AB" * 32 in inner
    assert c.post("/api/rc/agent/enroll", json={"token": ticket.replace("nrp_", "nip_"), "hostname": hosts[2]}).status_code == 403
    e = c.post("/api/rc/agent/enroll", json={"token": ticket, "hostname": hosts[2]}).json()
    assert e["status"] == "active", e     # pushed: approved even though approve mode is "ad"
    assert c.post("/api/rc/agent/enroll", json={"token": ticket, "hostname": hosts[2]}).status_code == 403, "ticket is one use"
    assert c.post("/api/rc/push", json={"hostnames": [hosts[2]], "remove": True}).json()["count"] == 1
    fixes.poll_once(); time.sleep(1.5)       # send it now, so nothing is left in the queue for the other tests
    assert "NetInventory Remote" in sent[-1]
    from netinv.db import set_setting
    with SessionLocal() as db:      # leave the push address unset for the other tests
        set_setting(db, "agent:server_url", None); db.commit()
print("remote control OK")
