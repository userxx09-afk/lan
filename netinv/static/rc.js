// NetInventory remote control viewer (rcontrol.py). Screen: JPEG tiles over the WebSocket; input: checked JSON messages.
"use strict";
const $ = (s) => document.querySelector(s);
const host = new URLSearchParams(location.search).get("host") || "";
const cv = $("#screen"), ctx = cv.getContext("2d");
let ws = null, connected = false, viewOnly = false, mons = [], ending = false;

document.title = `Remote control: ${host}`;
$("#host").textContent = host;
$("#h2host").textContent = host;

function state(text, cls = "") { const s = $("#state"); s.textContent = text; s.className = cls; }
function message(text) { const m = $("#msg"); m.textContent = text || ""; m.hidden = !text; }
async function api(url, opts = {}) {
  const r = await fetch(url, { credentials: "same-origin", headers: { "Content-Type": "application/json" }, ...opts });
  if (r.status === 401) { location.href = "/login"; throw new Error("Sign in first."); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof j.detail === "string" ? j.detail : `Error ${r.status}`);
  return j;
}

async function prepare() {
  try {
    const [chk, st] = await Promise.all([api("/api/rc/check", { method: "POST", body: "{}" }), api(`/api/devices/${encodeURIComponent(host)}/rc`)]);
    const settings = await api("/api/rc").then((d) => d.settings).catch(() => ({}));
    let how = chk.output;
    if (!st.installed) how = "The remote control agent isn't installed on this PC. Install it from the PC's page first.";
    else if (st.status !== "active") how = "This PC's remote control agent is waiting for approval (Settings > Remote control).";
    else if (!st.online) how = "The PC's remote control agent isn't connected: the PC is off, asleep or can't reach the server.";
    else if (st.disabled) how = "Remote control is turned off on this PC by its own policy.";
    else if (chk.allowed && st.always_ask && chk.direct) how = "This PC's policy always asks the user first.";
    if (chk.allowed && st.online && !chk.direct && st.user) how += ` Signed in there: ${st.user}.`;
    if (chk.allowed && st.online && !st.user) how += " Nobody is signed in at the PC right now.";
    $("#how").textContent = how;
    if (settings.require_reason) { $("#reasonhint").textContent = "(required, shown to the user and kept in the log)"; $("#reason").required = true; }
    $("#go").disabled = !(chk.allowed && st.online && st.status === "active" && !st.disabled);
  } catch (e) { $("#how").textContent = e.message; $("#go").disabled = true; }
}

$("#start").onsubmit = async (e) => {
  e.preventDefault();
  $("#go").disabled = true;
  viewOnly = $("#viewonly").checked;
  try {
    const r = await api("/api/rc/sessions", { method: "POST", body: JSON.stringify({ hostname: host, reason: $("#reason").value, view_only: viewOnly }) });
    $("#start").hidden = true;
    open(r);
  } catch (er) { $("#how").textContent = er.message; $("#go").disabled = false; }
};

function send(m) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(m)); }

function open(r) {
  state(r.direct ? "Connecting…" : `Asking the user at the PC (up to ${r.ask_seconds} s)…`, "warn");
  message(r.direct ? "Connecting…" : `Waiting for ${r.pc_user || "the user"} to accept…`);
  $("#endbtn").hidden = false;
  ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/rc/view/${encodeURIComponent(r.sid)}?t=${encodeURIComponent(r.token)}`);
  ws.binaryType = "arraybuffer";
  ws.onmessage = (ev) => (typeof ev.data === "string" ? onText(JSON.parse(ev.data)) : onFrame(ev.data));
  ws.onclose = () => {
    connected = false;
    $("#tools").hidden = true; $("#endbtn").hidden = true;
    if (!/ended|refused|denied|answer|offline/i.test($("#state").textContent)) state("Disconnected", "bad");
    if (!ending) message($("#msg").textContent || "Disconnected.");
  };
}

function onText(m) {
  if (m.t === "status") {
    if (m.s === "connected") {
      connected = true; state(viewOnly ? "Connected (view only)" : "Connected", "good"); message("");
      $("#tools").hidden = false; ["#cad", "#win", "#alttab"].forEach((b) => ($(b).disabled = viewOnly));
      cv.style.display = "block"; cv.focus(); send({ t: "full" });
    } else if (m.s === "denied") { state(m.msg, "bad"); message(m.msg); }
    else if (m.s === "ended") { state(`Session ended: ${m.msg}`, "mute"); message(`Session ended: ${m.msg}`); cv.style.display = "none"; }
    else { state(m.msg, "warn"); message(m.msg); }
  } else if (m.t === "info") {
    mons = m.mons || [];
    $("#mon").innerHTML = mons.map((x, i) => `<option value="${i}">Display ${i + 1}${x.primary ? " (main)" : ""} · ${x.w}×${x.h}</option>`).join("");
    $("#mon").value = String(m.mon || 0);
    $("#mon").hidden = mons.length < 2;
    if (m.desk && m.desk !== "Default") state(`Connected · ${m.desk === "Winlogon" ? "sign-in or secure screen" : m.desk}`, "good");
    else if (connected) state(viewOnly ? "Connected (view only)" : "Connected", "good");
  }
}

// 'F', u16 width, u16 height, u16 count, then count x (u16 x, u16 y, u16 w, u16 h, u32 length, JPEG)
async function onFrame(buf) {
  const dv = new DataView(buf);
  if (dv.getUint8(0) !== 70) return;
  const W = dv.getUint16(1, true), H = dv.getUint16(3, true), n = dv.getUint16(5, true);
  if (cv.width !== W || cv.height !== H) { cv.width = W; cv.height = H; }
  let off = 7;
  const parts = [];
  for (let i = 0; i < n && off + 12 <= buf.byteLength; i++) {
    const x = dv.getUint16(off, true), y = dv.getUint16(off + 2, true), len = dv.getUint32(off + 8, true);
    off += 12;
    if (off + len > buf.byteLength) break;
    parts.push(createImageBitmap(new Blob([new Uint8Array(buf, off, len)], { type: "image/jpeg" })).then((b) => ({ x, y, b })).catch(() => null));
    off += len;
  }
  for (const p of await Promise.all(parts)) if (p) { ctx.drawImage(p.b, p.x, p.y); p.b.close && p.b.close(); }
  send({ t: "ack" });
}

// ---------------------------------------------------------------- input
function pos(e) {
  const r = cv.getBoundingClientRect();
  return { x: Math.max(0, Math.min(cv.width - 1, Math.round((e.clientX - r.left) * cv.width / r.width))),
           y: Math.max(0, Math.min(cv.height - 1, Math.round((e.clientY - r.top) * cv.height / r.height))) };
}
let pending = null;
cv.addEventListener("mousemove", (e) => {
  if (!connected || viewOnly) return;
  const first = !pending; pending = pos(e);
  if (first) requestAnimationFrame(() => { if (pending) send({ t: "mm", ...pending }); pending = null; });
});
cv.addEventListener("mousedown", (e) => { if (!connected || viewOnly) return; e.preventDefault(); cv.focus(); if (e.button <= 2) send({ t: "md", b: e.button, ...pos(e) }); });
cv.addEventListener("mouseup", (e) => { if (!connected || viewOnly) return; e.preventDefault(); if (e.button <= 2) send({ t: "mu", b: e.button, ...pos(e) }); });
cv.addEventListener("contextmenu", (e) => e.preventDefault());
cv.addEventListener("wheel", (e) => {
  if (!connected || viewOnly) return;
  e.preventDefault();
  const k = e.deltaMode === 1 ? 40 : e.deltaMode === 2 ? 800 : 1;
  const c = (v) => Math.max(-1200, Math.min(1200, Math.round(v * k)));
  send({ t: "wh", dx: c(e.deltaX), dy: c(e.deltaY) });
}, { passive: false });
cv.addEventListener("keydown", (e) => { if (!connected || viewOnly || !e.code) return; e.preventDefault(); send({ t: "kd", c: e.code }); });
cv.addEventListener("keyup", (e) => { if (!connected || viewOnly || !e.code) return; e.preventDefault(); send({ t: "ku", c: e.code }); });
cv.addEventListener("blur", () => connected && send({ t: "rel" }));

const combo = (codes) => { codes.forEach((c) => send({ t: "kd", c })); [...codes].reverse().forEach((c) => send({ t: "ku", c })); cv.focus(); };
$("#cad").onclick = () => { send({ t: "cad" }); cv.focus(); };
$("#win").onclick = () => combo(["MetaLeft"]);
$("#alttab").onclick = () => combo(["AltLeft", "Tab"]);
$("#mon").onchange = () => { send({ t: "mon", i: +$("#mon").value }); cv.focus(); };
$("#quality").onchange = () => { send({ t: "q", v: +$("#quality").value }); cv.focus(); };
$("#fit").onclick = () => { const m = $("#main"); m.classList.toggle("fit"); $("#fit").textContent = m.classList.contains("fit") ? "Actual size" : "Fit to window"; cv.focus(); };
$("#full").onclick = () => (document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen().catch(() => {}));
$("#endbtn").onclick = () => { ending = true; send({ t: "end" }); state("Session ended by you", "mute"); message("Session ended."); };
window.addEventListener("beforeunload", () => { if (ws && ws.readyState === 1) send({ t: "end" }); });

if (!host) { $("#how").textContent = "No computer given."; $("#go").disabled = true; } else prepare();
