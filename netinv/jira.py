"""Jira Cloud integration: create an issue from a computer, a user or an alert, and list the issues related to one.

Signs in with a Jira account's e-mail and an API token (id.atlassian.com > Security > API tokens), stored encrypted
like the scan credentials and never sent to the browser. Every issue NetInventory creates gets the label `netinv`
plus `netinv-<hostname>` / `netinv-user-<username>`, and a link back to the NetInventory page, so the related-issues
panel finds it again. That panel can also match issues that just mention the name, and (for users) issues the user
reported, for example through the service desk portal.

Nothing is sent to Jira unless someone clicks Create; the description is shown to them first and they can edit it.
Only inventory facts go in (hostname, OS, IP, model, last user...), never passwords, keys or BitLocker recovery keys.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from .db import get_setting, set_setting
from .secrets import decrypt, encrypt

SITE_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?$")
PROJECT_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,49}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")          # hostnames and sAMAccountNames we put in JQL
FIELDS = ["summary", "status", "assignee", "reporter", "updated", "created", "priority", "issuetype"]
TIMEOUT = 20


class JiraError(Exception):
    pass


# ------------------------------------------------------------------ settings
def config(db) -> dict:
    """What the Settings page shows. The token itself never leaves the server."""
    return {"site": get_setting(db, "jira:site"), "email": get_setting(db, "jira:email"),
            "token_set": bool(get_setting(db, "jira:token")), "project": get_setting(db, "jira:project"),
            "issue_type": get_setting(db, "jira:issue_type"),
            "match_text": get_setting(db, "jira:match_text", "1") == "1"}


def enabled(db) -> bool:
    return bool(get_setting(db, "jira:site") and get_setting(db, "jira:email") and get_setting(db, "jira:token"))


def clean_site(site: str | None) -> str | None:
    site = (site or "").strip().rstrip("/")
    if not site:
        return None
    if not site.startswith("http"):
        site = "https://" + site
    u = urllib.parse.urlparse(site)
    site = f"https://{u.netloc}" if u.scheme == "https" and u.netloc else site
    if not SITE_RE.match(site):
        raise ValueError("The Jira site must look like https://yourcompany.atlassian.net")
    return site


def save(db, body: dict) -> None:
    site = clean_site(body.get("site"))
    email = (body.get("email") or "").strip() or None
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("The Jira account must be an e-mail address")
    project = (body.get("project") or "").strip().upper() or None
    if project and not PROJECT_RE.match(project):
        raise ValueError("The default project must be a Jira project key, like IT or HELP")
    itype = (body.get("issue_type") or "").strip() or None
    if itype and len(itype) > 100:
        raise ValueError("Issue type name is too long")
    set_setting(db, "jira:site", site)
    set_setting(db, "jira:email", email)
    set_setting(db, "jira:project", project)
    set_setting(db, "jira:issue_type", itype)
    set_setting(db, "jira:match_text", "1" if body.get("match_text", True) else "0")
    token = body.get("token")
    if body.get("clear_token"):
        set_setting(db, "jira:token", None)
    elif token:
        set_setting(db, "jira:token", encrypt(token.strip()))


# ------------------------------------------------------------------ HTTP
def _call(db, method: str, path: str, body: dict | None = None, query: dict | None = None):
    site, email, tok = get_setting(db, "jira:site"), get_setting(db, "jira:email"), get_setting(db, "jira:token")
    if not (site and email and tok):
        raise JiraError("Jira isn't set up yet. Add the site, account and API token in Settings > Jira.")
    url = site + path + (("?" + urllib.parse.urlencode(query)) if query else "")
    auth = base64.b64encode(f"{email}:{decrypt(tok)}".encode()).decode()
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Basic {auth}", "Accept": "application/json",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise JiraError(_http_error(e)) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise JiraError(f"Can't reach {site}: {getattr(e, 'reason', e)}. The server needs outbound HTTPS to Atlassian.") from None


def _http_error(e: urllib.error.HTTPError) -> str:
    try:
        d = json.loads(e.read() or b"{}")
        msgs = list(d.get("errorMessages") or []) + [f"{k}: {v}" for k, v in (d.get("errors") or {}).items()]
    except Exception:
        msgs = []
    hint = {401: "Jira refused the e-mail and API token. Check both, and that the token hasn't expired.",
            403: "The Jira account isn't allowed to do this (check its project permissions).",
            404: "Not found in Jira (check the project key, or the account can't see it)."}.get(e.code, f"Jira answered {e.code}.")
    return f"{hint} {' '.join(msgs)}".strip()[:600]


# ------------------------------------------------------------------ calls
def test(db) -> str:
    me = _call(db, "GET", "/rest/api/3/myself")
    out = f"Signed in to Jira as {me.get('displayName') or me.get('emailAddress') or 'the account'}."
    project = get_setting(db, "jira:project")
    if project:
        p = _call(db, "GET", f"/rest/api/3/project/{project}")
        out += f" Default project {p.get('key')} ({p.get('name')}) found."
    return out


def projects(db, query: str = "") -> list[dict]:
    r = _call(db, "GET", "/rest/api/3/project/search", query={"query": query[:100], "maxResults": 50, "action": "create"})
    return [{"key": p["key"], "name": p.get("name")} for p in r.get("values", [])]


def issue_types(db, project: str) -> list[str]:
    project = (project or "").strip().upper()
    if not PROJECT_RE.match(project):
        raise JiraError("Pick a project first")
    r = _call(db, "GET", f"/rest/api/3/issue/createmeta/{project}/issuetypes", query={"maxResults": 100})
    items = r.get("issueTypes") or r.get("values") or []
    return [t["name"] for t in items if not t.get("subtask")]


def label(kind: str, name: str) -> str:
    """Jira labels can't contain spaces; keep them lower case so PC01 and pc01 match."""
    slug = re.sub(r"[^a-z0-9._-]", "_", (name or "").lower())[:200]
    return f"netinv-{slug}" if kind == "pc" else f"netinv-user-{slug}"


def adf(text: str, link: str | None = None, link_title: str = "") -> dict:
    """Plain text to Atlassian Document Format: blank lines split paragraphs, single newlines become line breaks."""
    content = []
    for para in re.split(r"\n\s*\n", (text or "").strip()):
        if not para.strip():
            continue
        parts = []
        for i, line in enumerate(para.split("\n")):
            if i:
                parts.append({"type": "hardBreak"})
            if line:
                parts.append({"type": "text", "text": line})
        content.append({"type": "paragraph", "content": parts})
    if link:
        content.append({"type": "paragraph", "content": [
            {"type": "text", "text": "Open in NetInventory: "},
            {"type": "text", "text": link_title or link, "marks": [{"type": "link", "attrs": {"href": link}}]}]})
    return {"type": "doc", "version": 1, "content": content}


def create(db, project: str, issue_type: str, summary: str, description: str, labels: list[str],
           link: str | None, link_title: str) -> dict:
    project = (project or get_setting(db, "jira:project") or "").strip().upper()
    issue_type = (issue_type or get_setting(db, "jira:issue_type") or "Task").strip()
    summary = " ".join((summary or "").split())[:250]
    if not PROJECT_RE.match(project):
        raise JiraError("Pick a Jira project (or set a default one in Settings > Jira)")
    if not summary:
        raise JiraError("The summary can't be empty")
    labels = sorted({x for x in ["netinv", *labels] if x})
    r = _call(db, "POST", "/rest/api/3/issue", {"fields": {
        "project": {"key": project}, "issuetype": {"name": issue_type}, "summary": summary,
        "description": adf(description, link, link_title), "labels": labels}})
    key = r.get("key")
    if link and key:
        try:   # the link in Jira's "Web links" section; the description already has it, so a failure here is fine
            _call(db, "POST", f"/rest/api/3/issue/{key}/remotelink",
                  {"globalId": f"netinv:{link}", "object": {"url": link, "title": link_title or "NetInventory"}})
        except JiraError:
            pass
    return {"key": key, "url": f"{get_setting(db, 'jira:site')}/browse/{key}"}


def _q(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def related_jql(db, kind: str, name: str, account_id: str | None = None) -> str:
    if not NAME_RE.match(name or ""):
        raise JiraError("That name can't be searched in Jira")
    parts = [f"labels = {_q(label(kind, name))}"]
    if get_setting(db, "jira:match_text", "1") == "1":
        parts.append(f"text ~ {_q(_q(name))}")      # exact phrase: text ~ "\"PC01\""
    if account_id:
        parts.append(f"reporter = {_q(account_id)}")
    return f"({' OR '.join(parts)}) ORDER BY updated DESC"


def find_account(db, email: str | None) -> str | None:
    """The user's Jira account, by e-mail, to include issues they reported. None if not exactly one match."""
    if not email:
        return None
    try:
        r = _call(db, "GET", "/rest/api/3/user/search", query={"query": email, "maxResults": 2})
    except JiraError:
        return None
    hits = [u for u in r if u.get("accountType") in ("atlassian", "customer", None)]
    exact = [u for u in hits if (u.get("emailAddress") or "").lower() == email.lower()]
    pick = exact or (hits if len(hits) == 1 else [])
    return pick[0]["accountId"] if pick else None


def search(db, jql: str, limit: int = 25) -> list[dict]:
    r = _call(db, "POST", "/rest/api/3/search/jql", {"jql": jql, "fields": FIELDS, "maxResults": limit})
    site = get_setting(db, "jira:site")
    out = []
    for i in r.get("issues", []):
        f = i.get("fields") or {}
        st = f.get("status") or {}
        out.append({"key": i.get("key"), "url": f"{site}/browse/{i.get('key')}", "summary": f.get("summary"),
                    "status": st.get("name"), "status_cat": (st.get("statusCategory") or {}).get("key"),
                    "assignee": (f.get("assignee") or {}).get("displayName"),
                    "reporter": (f.get("reporter") or {}).get("displayName"),
                    "type": (f.get("issuetype") or {}).get("name"), "priority": (f.get("priority") or {}).get("name"),
                    "updated": (f.get("updated") or "")[:16].replace("T", " "), "created": (f.get("created") or "")[:10]})
    return out


# ------------------------------------------------------------------ drafts (what the Create dialog starts with)
def _lines(pairs) -> str:
    return "\n".join(f"{k}: {v}" for k, v in pairs if v not in (None, ""))


def draft_pc(dev: dict) -> dict:
    h = dev["hostname"]
    os_ = " ".join(x for x in ((dev.get("os") or "").replace("Microsoft ", ""), dev.get("os_display_version") or "") if x)
    port = f"{dev.get('switch_name')} {dev.get('switch_port') or ''}".strip() if dev.get("switch_name") else None
    body = _lines([("Computer", h), ("OS", os_), ("IP", dev.get("ip")), ("Model", " ".join(
        x for x in (dev.get("manufacturer"), dev.get("model")) if x)), ("Serial", dev.get("serial")),
        ("Last user", dev.get("last_user")), ("Switch port", port), ("Last seen", str(dev.get("last_seen") or "")[:16])])
    last = (dev.get("last_user") or "").split("\\")[-1].lower()
    labels = [label("pc", h)] + ([label("user", last)] if last and NAME_RE.match(last) else [])
    return {"summary": f"{h}: ", "description": "Describe the problem here.\n\n" + body, "labels": labels,
            "path": f"#asset/{urllib.parse.quote(h)}", "link_title": f"{h} in NetInventory"}


def draft_user(u: dict, last_pc: str | None) -> dict:
    name = u["username"]
    who = u.get("display_name") or name
    body = _lines([("User", f"{who} ({name})"), ("E-mail", u.get("email")), ("Title", u.get("title")),
                   ("Department", u.get("department")), ("Phone", u.get("phone")), ("Last computer", last_pc),
                   ("Account", "locked out" if u.get("locked") else ("disabled" if u.get("enabled") is False else None))])
    labels = [label("user", name)] + ([label("pc", last_pc)] if last_pc else [])
    return {"summary": f"{who}: ", "description": "Describe the problem here.\n\n" + body, "labels": labels,
            "path": f"#user/{urllib.parse.quote(name)}", "link_title": f"{who} in NetInventory"}


def draft_alert(a: dict, limit: int = 50) -> dict:
    rows = a.get("rows") or []
    hosts = sorted({r["hostname"] for r in rows if r.get("hostname")})
    users = sorted({r["username"] for r in rows if r.get("username")})
    items = hosts or users
    sev = {"high": "High priority", "important": "Important", "info": "Informational"}.get(a.get("severity"), "")
    listing = "\n".join(f"- {x}" for x in items[:limit]) + (f"\n- ...and {len(items) - limit} more" if len(items) > limit else "")
    body = f"NetInventory alert ({sev}): {a.get('title')}\n{len(rows)} result(s)." + (f"\n\n{listing}" if listing else "")
    labels = [f"netinv-alert-{re.sub(r'[^a-z0-9_-]', '_', a['id'].lower())}"]
    if len(hosts) <= 20:
        labels += [label("pc", h) for h in hosts]
    return {"summary": f"{a.get('title')} ({len(rows)})", "description": body, "labels": labels,
            "path": "#overview", "link_title": "NetInventory dashboard"}
