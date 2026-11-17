"""Per-machine audit report: one printable HTML page with everything NetInventory knows about a PC.

Built from the stored inventory (works for offline PCs). With live=True it also asks the PC now, over WinRM, for its
local administrators, security state, shares, startup programs and automatic services that aren't running; a PC that
doesn't answer just gets a note in those sections.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from .db import AuditLog

import re

YESNO = {"ad_enabled", "pending_reboot", "av_enabled", "av_up_to_date", "enabled", "realtime", "tamper", "present", "ready", "secure_boot"}


def fmt(v, key: str = ""):
    if v is None or v == "":
        return ""
    if key in YESNO or isinstance(v, bool):
        return "Yes" if v in (True, 1, "1", "True", "true") else "No"
    s = str(v)
    if re.match(r"^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d", s):
        return s[:16].replace("T", " ")
    return s


e = lambda v, key="": html.escape(fmt(v, key))   # noqa: E731

SUMMARY = [("hostname", "Name"), ("fqdn", "DNS name"), ("ip", "IP address"), ("os", "Operating system"), ("os_display_version", "Version"),
           ("os_build", "Build"), ("manufacturer", "Manufacturer"), ("model", "Model"), ("serial", "Serial number"),
           ("cpu", "Processor"), ("gpu", "Graphics"), ("ram_gb", "Memory (GB)"), ("c_free_gb", "C: free (GB)"), ("current_user", "Signed in now"),
           ("last_user", "Last user"), ("ou", "AD OU"), ("ad_dn", "AD object"), ("ad_description", "AD description"), ("ad_location", "AD location"),
           ("ad_enabled", "AD account enabled"), ("ad_created", "Joined to AD"), ("ad_last_logon", "AD last logon"), ("last_boot", "Last boot"),
           ("last_seen", "Last seen"), ("inventory_last_collected", "Inventory collected"), ("last_patch_installed", "Last patch"),
           ("pending_updates", "Pending updates"), ("pending_reboot", "Reboot pending"), ("av_name", "Antivirus"), ("av_enabled", "Antivirus on"),
           ("av_up_to_date", "Antivirus up to date"), ("agent_status", "Agent"), ("agent_version", "Agent version"),
           ("switch_name", "Switch"), ("switch_port", "Switch port"), ("vlan", "VLAN"),
           ("purchase_date", "Purchased"), ("warranty_end", "Warranty ends"), ("asset_location", "Location"), ("state", "State")]

CSS = """
body { font: 13px/1.45 -apple-system, Segoe UI, Roboto, sans-serif; color: #1d2330; margin: 24px auto; max-width: 1100px; padding: 0 16px; }
h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 15px; margin: 22px 0 6px; border-bottom: 2px solid #1d2330; padding-bottom: 3px; }
.meta { color: #667; margin-bottom: 12px; } table { border-collapse: collapse; width: 100%; margin: 4px 0; }
th, td { text-align: left; padding: 3px 6px; border-bottom: 1px solid #dde; vertical-align: top; } th { background: #f2f4f8; font-weight: 600; }
.kv { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0 24px; } .kv div { display: flex; border-bottom: 1px solid #eef; padding: 2px 0; }
.kv span { color: #667; width: 170px; flex: none; } .note { color: #667; font-style: italic; } .bad { color: #b3261e; font-weight: 600; }
.bar { position: sticky; top: 0; background: #fff; padding: 6px 0; } button { font: inherit; padding: 6px 12px; }
@media print { .bar { display: none; } body { margin: 0; max-width: none; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
"""


def _table(rows: list[dict], cols: list[tuple[str, str]], limit: int = 2000) -> str:
    if not rows:
        return '<p class="note">None.</p>'
    head = "".join(f"<th>{e(lbl)}</th>" for _, lbl in cols)
    body = "".join("<tr>" + "".join(f"<td>{e(r.get(k), k)}</td>" for k, _ in cols) + "</tr>" for r in rows[:limit])
    more = f'<p class="note">{len(rows) - limit} more not shown.</p>' if len(rows) > limit else ""
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{more}"


def _live(db, dev) -> str:
    from . import pctools, remote
    out = []

    def section(title, fn):
        try:
            out.append(f"<h2>{e(title)} <small class='note'>(asked the PC just now)</small></h2>" + fn())
        except Exception as exc:
            out.append(f"<h2>{e(title)}</h2><p class='note'>Couldn't ask the PC: {e(str(exc).splitlines()[0][:200] if str(exc) else exc)}</p>")

    section("Local Administrators", lambda: _table(pctools.local_accounts(db, dev)["members"], [("name", "Member"), ("type", "Type"), ("sid", "SID")]))

    def sec():
        s = remote.view(db, dev, "security")
        d = s.get("defender") or {}
        bits = [_table(s.get("bitlocker") or [], [("volume", "Volume"), ("status", "BitLocker"), ("protection", "Protection"), ("method", "Method")]),
                _table(s.get("firewall") or [], [("profile", "Firewall profile"), ("enabled", "Enabled"), ("inbound", "Inbound"), ("outbound", "Outbound")])]
        if d:
            bits.append(f"<p>Defender: real-time {e(d.get('realtime'), 'realtime')}, tamper protection {e(d.get('tamper'), 'tamper')}, signatures "
                        f"{e(d.get('signature'))} ({e(d.get('signature_age_days'))} day(s) old), last full scan {e(d.get('full_scan') or 'never')}.</p>")
        tpm = s.get("tpm")
        tpm_s = f"TPM present {e(tpm.get('present'), 'present')}, ready {e(tpm.get('ready'), 'ready')}" if tpm else "No TPM found"
        sb = "unknown" if s.get("secure_boot") is None else e(s.get("secure_boot"), "secure_boot")
        bits.append(f"<p>{tpm_s} · Secure Boot {sb} · UAC {'on' if s.get('uac') == 1 else 'off'}</p>")
        return "".join(bits)
    section("Security", sec)
    section("Shared folders", lambda: _table(remote.view(db, dev, "shares"), [("name", "Share"), ("path", "Path"), ("access", "Permissions")]))
    section("Startup programs", lambda: _table(remote.view(db, dev, "startup"), [("name", "Name"), ("where", "For"), ("command", "Command")]))
    section("Automatic services not running", lambda: _table(
        [s for s in pctools.services(db, dev) if s.get("start") == "Auto" and s.get("state") != "Running"],
        [("display", "Service"), ("name", "Name"), ("state", "State"), ("account", "Runs as")]))
    return "".join(out)


def render(db, dev, d: dict, live: bool, who: str) -> str:
    v = d["device"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    kv = "".join(f"<div><span>{e(lbl)}</span>{e(v.get(k), k)}</div>" for k, lbl in SUMMARY if v.get(k) not in (None, ""))
    kv += "".join(f"<div><span>{e(k)}</span>{e(val)}</div>" for k, val in (d.get("custom_fields") or {}).items())
    live_link = "" if live else '<a href="?live=1">Include live checks (asks the PC now)</a>'
    parts = [f"<div class='bar'><button onclick='print()'>Print or save as PDF</button> {live_link}</div>",
             f"<h1>Audit report: {e(v.get('hostname'))}</h1><div class='meta'>Generated {now} by {e(who)} · NetInventory</div>",
             f"<h2>Summary</h2><div class='kv'>{kv}</div>",
             "<h2>Groups</h2>" + (e(", ".join(d.get("groups") or [])) or '<p class="note">None.</p>'),
             "<h2>Disks</h2>" + _table(d.get("disks") or [], [(k, k.replace("_", " ")) for k in (d["disks"][0].keys() if d.get("disks") else []) if k not in ("hostname", "device_id")]),
             "<h2>Network adapters</h2>" + _table(d.get("nics") or [], [("description", "Adapter"), ("mac", "MAC"), ("ip", "IP")]),
             "<h2>Switch port</h2>" + _table(d.get("location") or [], [("switch_name", "Switch"), ("port", "Port"), ("vlan", "VLAN"), ("last_seen", "Last seen")], 5)]
    if live:
        parts.append(_live(db, dev))
    sw_cols = [("name", "Name"), ("version", "Version"), ("publisher", "Publisher"), ("install_date", "Installed")]
    parts += [f"<h2>Installed software ({len(d.get('software') or [])})</h2>" + _table(d.get("software") or [], sw_cols),
              "<h2>Windows updates</h2>" + _table(d.get("updates") or [], [(k, k.replace("_", " ")) for k in (d["updates"][0].keys() if d.get("updates") else [])
                                                                           if k not in ("hostname", "device_id")], 300),
              "<h2>Users of this PC</h2>" + _table(d.get("users") or [], [("username", "User"), ("last_logon", "Last logon"), ("logon_count", "Logons")], 100),
              "<h2>Recent logons</h2>" + _table(d.get("logons") or [], [("time", "Time"), ("username", "User"), ("logon_type", "Type"), ("source", "Source")], 50),
              "<h2>Deployments and fixes</h2>" + _table(d.get("deployments") or [], [("created", "Queued"), ("label", "What"), ("status", "Status"), ("who", "By"), ("message", "Result")], 100),
              "<h2>History</h2>" + _table(d.get("history") or [], [("time", "Time"), ("kind", "Kind"), ("detail", "Change")], 200),
              "<h2>Comments</h2>" + _table(d.get("comments") or [], [("created", "When"), ("author", "Who"), ("text", "Comment")])]
    db.add(AuditLog(actor=who[:64], action="pc.audit_report", target=f"computer:{dev.hostname}", result="with live checks" if live else "stored data"))
    db.commit()
    return (f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>Audit {e(v.get('hostname'))}</title><style>{CSS}</style></head><body>{''.join(parts)}</body></html>")
