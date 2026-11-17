"""Jira integration with Jira faked at the HTTP layer: settings, drafts, create, related issues.
Run: python tests/test_jira.py (DATABASE_URL set, demo loaded)."""
import base64, io, json, logging, sys, urllib.error
from pathlib import Path
logging.disable(logging.CRITICAL)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import netinv.main as m
from netinv import jira
from netinv.db import SessionLocal, get_setting

calls = []
TOKEN = "ATATT-secret-token-123"


class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): pass


def fake_urlopen(req, timeout=None):
    body = json.loads(req.data) if req.data else None
    calls.append((req.get_method(), req.full_url, body, req.headers.get("Authorization")))
    url = req.full_url
    if url.endswith("/rest/api/3/myself"):
        return Resp(json.dumps({"displayName": "NetInventory Service"}).encode())
    if "/rest/api/3/project/NOPE" in url:
        raise urllib.error.HTTPError(url, 404, "nf", {}, io.BytesIO(b'{"errorMessages":["No project could be found with key NOPE."]}'))
    if "/rest/api/3/project/search" in url:
        return Resp(json.dumps({"values": [{"key": "IT", "name": "IT Help"}]}).encode())
    if "/rest/api/3/project/IT" in url:
        return Resp(json.dumps({"key": "IT", "name": "IT Help"}).encode())
    if "/issuetypes" in url:
        return Resp(json.dumps({"issueTypes": [{"name": "Task"}, {"name": "Incident"}, {"name": "Sub-task", "subtask": True}]}).encode())
    if url.endswith("/rest/api/3/issue"):
        return Resp(json.dumps({"id": "1", "key": "IT-42"}).encode())
    if url.endswith("/remotelink"):
        return Resp(b'{"id": 1}')
    if "/user/search" in url:
        return Resp(json.dumps([{"accountId": "acc-1", "accountType": "customer", "emailAddress": "alee@corp.example.com"}]).encode())
    if url.endswith("/search/jql"):
        return Resp(json.dumps({"issues": [{"key": "IT-7", "fields": {
            "summary": "Printer jam", "status": {"name": "In Progress", "statusCategory": {"key": "indeterminate"}},
            "assignee": {"displayName": "Tech One"}, "updated": "2026-11-17T10:00:00.000+0000", "issuetype": {"name": "Task"}}}]}).encode())
    raise AssertionError(f"unexpected Jira call {url}")


jira.urllib.request.urlopen = fake_urlopen

# pure helpers
assert jira.label("pc", "PC-01") == "netinv-pc-01" and jira.label("user", "A.Lee") == "netinv-user-a.lee"
doc = jira.adf("line one\nline two\n\nsecond para", "https://ni/#asset/X", "X")
assert [c["type"] for c in doc["content"]] == ["paragraph"] * 3 and doc["content"][0]["content"][1]["type"] == "hardBreak"
assert doc["content"][2]["content"][1]["marks"][0]["attrs"]["href"] == "https://ni/#asset/X"
for bad in ('x" OR project = SECRET', "a b", "", "x\\y"):
    try:
        jira.related_jql(None, "pc", bad)
        raise SystemExit(f"JQL accepted {bad!r}")
    except jira.JiraError:
        pass
assert jira.clean_site("acme.atlassian.net/jira/your-work") == "https://acme.atlassian.net"

with TestClient(m.app) as c:
    host = c.post("/api/query", json={"dataset": "v_devices", "fields": ["hostname"], "limit": 1}).json()["rows"][0]["hostname"]

    # not set up: the tab says so, no Jira calls, create refused
    assert c.get(f"/api/jira/related?kind=pc&ref={host}").json() == {"enabled": False, "issues": []}
    assert not c.get(f"/api/jira/draft?kind=pc&ref={host}").json()["enabled"]
    assert not calls

    # settings: validation, token encrypted and never returned
    assert c.put("/api/jira/settings", json={"site": "http://evil/x?y"}).status_code == 400
    assert c.put("/api/jira/settings", json={"site": "acme.atlassian.net", "project": "it-help"}).status_code == 400
    r = c.put("/api/jira/settings", json={"site": "https://acme.atlassian.net/", "email": "svc@corp.example.com",
                                          "token": TOKEN, "project": "it", "issue_type": "Incident"})
    assert r.status_code == 200, r.text
    cfg = r.json()
    assert cfg["site"] == "https://acme.atlassian.net" and cfg["project"] == "IT" and cfg["token_set"]
    assert TOKEN not in r.text and TOKEN not in c.get("/api/jira/settings").text
    with SessionLocal() as db:
        assert get_setting(db, "jira:token") and TOKEN not in get_setting(db, "jira:token")
    # blank token on save keeps the saved one
    c.put("/api/jira/settings", json={**{k: cfg[k] for k in ("site", "email", "project", "issue_type")}, "token": ""})
    assert c.get("/api/jira/settings").json()["token_set"]

    t = c.post("/api/jira/test").json()
    assert t["ok"] and "NetInventory Service" in t["output"] and "IT" in t["output"], t
    assert calls[0][3] == "Basic " + base64.b64encode(f"svc@corp.example.com:{TOKEN}".encode()).decode()
    assert c.get("/api/jira/issuetypes?project=IT").json() == ["Task", "Incident"]
    assert c.get("/api/jira/projects?q=it").json() == [{"key": "IT", "name": "IT Help"}]

    # drafts
    d = c.get(f"/api/jira/draft?kind=pc&ref={host}").json()
    assert d["enabled"] and d["project"] == "IT" and host in d["summary"] and f"Computer: {host}" in d["description"]
    assert jira.label("pc", host) in d["labels"]
    u = c.get("/api/jira/draft?kind=user&ref=CORP%5Calee").json()
    assert "netinv-user-alee" in u["labels"] and "alee" in u["description"], u
    al = next(a for a in c.get("/api/alerts").json() if a["count"])
    da = c.get(f"/api/jira/draft?kind=alert&ref={al['id']}").json()
    assert al["title"] in da["summary"] and da["labels"][0].startswith("netinv-alert-")
    assert c.get("/api/jira/draft?kind=alert&ref=nope").status_code == 404
    assert c.get("/api/jira/draft?kind=pc&ref=NO-SUCH-PC").status_code == 404

    # create: labels and link come from the server; the browser can't add its own
    calls.clear()
    r = c.post("/api/jira/issue", json={"kind": "pc", "ref": host, "summary": f"{host}: no sound", "description": "Hi\n\nThere",
                                        "labels": ["evil"]}).json()
    assert r["key"] == "IT-42" and r["url"] == "https://acme.atlassian.net/browse/IT-42", r
    f = calls[0][2]["fields"]
    assert f["project"] == {"key": "IT"} and f["issuetype"] == {"name": "Incident"} and "evil" not in f["labels"]
    assert "netinv" in f["labels"] and jira.label("pc", host) in f["labels"]
    assert any("#asset/" in json.dumps(p) for p in f["description"]["content"])
    assert calls[1][1].endswith("/rest/api/3/issue/IT-42/remotelink")
    assert c.post("/api/jira/issue", json={"kind": "pc", "ref": host, "summary": "  "}).status_code == 400

    # a Jira error comes back readable
    c.put("/api/jira/settings", json={**{k: cfg[k] for k in ("site", "email", "issue_type")}, "project": "NOPE"})
    t = c.post("/api/jira/test").json()
    assert not t["ok"] and "No project could be found" in t["output"], t
    c.put("/api/jira/settings", json={**{k: cfg[k] for k in ("site", "email", "issue_type")}, "project": "IT"})

    # related issues: label, mention, and for users what they reported
    calls.clear()
    r = c.get(f"/api/jira/related?kind=pc&ref={host}").json()
    assert r["issues"][0]["key"] == "IT-7" and r["issues"][0]["status_cat"] == "indeterminate"
    jql = calls[-1][2]["jql"]
    assert f'labels = "{jira.label("pc", host)}"' in jql and f'text ~ "\\"{host}\\""' in jql, jql
    calls.clear()
    r = c.get("/api/jira/related?kind=user&ref=alee").json()
    assert 'reporter = "acc-1"' in r["jql"] and 'labels = "netinv-user-alee"' in r["jql"], r["jql"]
    c.put("/api/jira/settings", json={**{k: cfg[k] for k in ("site", "email", "project", "issue_type")}, "match_text": False})
    assert "text ~" not in c.get(f"/api/jira/related?kind=pc&ref={host}").json()["jql"]

    # clearing the token turns it off again
    c.put("/api/jira/settings", json={**{k: cfg[k] for k in ("site", "email", "project")}, "clear_token": True})
    assert not c.get("/api/jira/settings").json()["token_set"]
    assert not c.get(f"/api/jira/related?kind=pc&ref={host}").json()["enabled"]

print("Jira integration OK")
