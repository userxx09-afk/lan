// NetInventory dashboard. Plain JS, no build step.
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => (v === null || v === undefined ? "" : String(v)).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const api = async (path, opts = {}) => {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (r.status === 401 && !path.startsWith("/api/auth/test")) { location.href = "/login"; throw new Error("Signed out"); }
  if (!r.ok) throw new Error(await r.text());
  return r.json();
};
const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body) });
const fmtDate = (v) => (v ? String(v).slice(0, 16).replace("T", " ") : "");
const ago = (v) => {
  if (!v) return "";
  const d = (Date.now() - new Date(String(v).replace(" ", "T") + "Z")) / 86400000;
  return d < 1 ? "today" : d < 2 ? "1 day ago" : `${Math.floor(d)} days ago`;
};

// ------------------------------------------------------------ generic table
function table(el, rows, cols, opts = {}) {
  cols = cols || (rows[0] ? Object.keys(rows[0]) : []);
  let sortKey = opts.sort, dir = 1;
  const render = () => {
    const f = (opts.filterEl?.value || "").toLowerCase();
    let data = f ? rows.filter((r) => cols.some((c) => String(r[c] ?? "").toLowerCase().includes(f))) : rows.slice();
    if (sortKey) data.sort((a, b) => (a[sortKey] ?? "") > (b[sortKey] ?? "") ? dir : (a[sortKey] ?? "") < (b[sortKey] ?? "") ? -dir : 0);
    const head = cols.map((c) => `<th data-k="${c}">${esc(opts.labels?.[c] ?? c.replaceAll("_", " "))}${sortKey === c ? (dir > 0 ? " ▲" : " ▼") : ""}</th>`).join("");
    const body = data.slice(0, 2000).map((r) => `<tr>${cols.map((c) => {
      const v = r[c];
      const cell = opts.cell?.[c] ? opts.cell[c](v, r) : esc(/(_seen|logon|_report|_patch|_boot|time|collected|polled|created)/.test(c) ? fmtDate(v) : v);
      return `<td class="${typeof v === "number" ? "num" : ""}">${cell}</td>`;
    }).join("")}</tr>`).join("");
    el.innerHTML = rows.length ? `<div class="tablewrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>
      <p class="muted">${data.length} row${data.length === 1 ? "" : "s"}</p>` : `<p class="muted">No data yet.</p>`;
    el.querySelectorAll("th").forEach((th) => th.onclick = () => { dir = sortKey === th.dataset.k ? -dir : 1; sortKey = th.dataset.k; render(); });
    el.querySelectorAll("[data-host]").forEach((a) => a.onclick = () => openDevice(a.dataset.host));
    el.querySelectorAll("[data-user]").forEach((a) => a.onclick = () => openUser(a.dataset.user));
  };
  if (opts.filterEl) opts.filterEl.oninput = render;
  render();
}
const hostLink = (v) => (v ? `<a class="link" data-host="${esc(v)}">${esc(v)}</a>` : `<span class="pill mute">unknown</span>`);
const userLink = (v) => (v ? `<a class="link" data-user="${esc(v)}">${esc(v)}</a>` : "");
const diskPill = (v) => (v === null || v === undefined ? "" : `<span class="pill ${v < 10 ? "bad" : v < 20 ? "warn" : "good"}">${v}%</span>`);

// ------------------------------------------------------------ tabs
const loaders = {};
document.querySelectorAll("#tabs button").forEach((b) => b.onclick = () => showTab(b.dataset.tab));
function showTab(name) {
  if (/^#(asset|user)\//.test(location.hash)) history.pushState(null, "", location.pathname);
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === name));
  loaders[name]?.();
  try { localStorage.setItem("tab", name); } catch {}
}

// ------------------------------------------------------------ dashboard: KPIs + alerts grouped by priority
const SEV = [["high", "High priority"], ["important", "Important"], ["info", "Informational"]];
let alertCache = [];
loaders.overview = async () => {
  const [s, al] = await Promise.all([api("/api/summary"), api("/api/alerts")]);
  const c = s.counts;
  const KPI = [["Computers", c.pcs, "pcs"], ["Inventoried", c.inventoried, "inv"], ["Not inventoried yet", c.not_inventoried, "noinv"],
    ["Mapped to a switch port", c.mapped_to_port, "port"], ["Users seen", c.users, "users"], ["Domain controllers", c.domain_controllers, "dcs"],
    ["Network devices", c.network_devices, "net"]];
  $("#kpis").innerHTML = KPI.map(([l, v, k]) => `<div class="kpi" data-go="${k}" title="Show them"><div class="v">${v ?? 0}</div><div class="l">${l}</div><div class="go">View list ›</div></div>`).join("");
  $("#kpis").querySelectorAll("[data-go]").forEach((el) => el.onclick = () => ({
    pcs: () => showComputers([]),
    inv: () => showComputers([{ field: "inventory_last_collected", op: "not_empty" }], "Inventoried computers"),
    noinv: () => showComputers([{ field: "inventory_last_collected", op: "empty" }], "Not inventoried yet"),
    port: () => showComputers([{ field: "switch_name", op: "not_empty" }], "Mapped to a switch port"),
    users: () => { $("#ustate").value = ""; showTab("users"); },
    dcs: () => showTab("network"), net: () => showTab("network"),
  })[el.dataset.go]());
  alertCache = al;
  renderAlerts();
  const max = Math.max(1, ...s.os_breakdown.map((r) => r.n));
  $("#osbreak").innerHTML = s.os_breakdown.map((r, i) => `<div class="bar" data-os="${i}" title="Show the ${r.n} computer${r.n === 1 ? "" : "s"} with ${esc(r.os)} ${esc(r.version)}"><div class="name">${esc(r.os.replace("Microsoft ", ""))} ${esc(r.version)}</div>
    <div class="track"><div class="fill" style="width:${(r.n / max) * 100}%"></div></div><div class="c">${r.n}</div></div>`).join("");
  $("#osbreak").querySelectorAll("[data-os]").forEach((el) => el.onclick = () => {
    const r = s.os_breakdown[+el.dataset.os];
    showComputers([r.os === "Unknown" ? { field: "os", op: "empty" } : { field: "os", op: "eq", value: r.os },
      r.version ? { field: "os_display_version", op: "eq", value: r.version } : { field: "os_display_version", op: "empty" }],
      `${r.os.replace("Microsoft ", "")} ${r.version}`.trim());
  });
  table($("#runs"), s.runs, ["collector", "started", "ok", "message"], {
    cell: { ok: (v) => `<span class="pill ${v ? "good" : v === false ? "bad" : "mute"}">${v ? "ok" : v === false ? "failed" : "running"}</span>`, started: fmtDate } });
};
function renderAlerts() {
  const hide = $("#hidezero").checked;
  const total = alertCache.reduce((n, a) => n + (a.count || 0), 0);
  $("#alertnote").textContent = `${alertCache.filter((a) => a.count).length} of ${alertCache.length} checks have results`;
  $("#alerts").innerHTML = SEV.map(([sev, label]) => {
    const list = alertCache.filter((a) => a.severity === sev && (!hide || a.count || a.error));
    const n = alertCache.filter((a) => a.severity === sev).reduce((t, a) => t + (a.count || 0), 0);
    return `<div class="agroup ${sev}"><div class="gh"><span>${label}</span><span class="muted">${n}</span></div>
      ${list.map((a) => `<div class="arow ${a.error ? "err" : ""}" data-alert="${a.id}" title="${esc(a.error || "")}">
        <span>${esc(a.title)}</span><span class="c ${a.count ? "n" : "z"}">${a.error ? "!" : a.count}</span></div>`).join("")
        || `<div class="arow"><span class="muted">Nothing to report.</span></div>`}</div>`;
  }).join("");
  document.querySelectorAll("[data-alert]").forEach((el) => el.onclick = () => openAlert(el.dataset.alert));
  return total;
}
$("#hidezero").onchange = renderAlerts;
const LINKS = { hostname: hostLink, username: userLink, last_user: userLink };
async function openAlert(id) {
  const a = await api(`/api/alerts/${id}`);
  drawer(`<h2>${esc(a.title)}</h2><div class="libbar"><span class="pill ${a.severity === "high" ? "bad" : a.severity === "important" ? "warn" : "mute"}">${esc(SEV.find((s) => s[0] === a.severity)[1])}</span>
    <span class="muted">${a.rows.length} result${a.rows.length === 1 ? "" : "s"}</span><span style="margin-left:auto"></span>${exportLinks(`/api/alerts/${id}/export`)}</div><div id="altable"></div>`);
  table($("#altable"), a.rows, a.columns, { cell: LINKS });
  const hosts = [...new Set(a.rows.map((r) => r.hostname).filter(Boolean))];
  if (hosts.length) {
    $("#altable").insertAdjacentHTML("beforebegin", `<p><button class="ghost" id="alhosts">Open these ${hosts.length} computer${hosts.length === 1 ? "" : "s"} in the Computers list</button>
      <span class="muted small">to select them all and rescan, wake, update or export them</span></p>`);
    $("#alhosts").onclick = () => { $("#drawer").hidden = true; showComputers([{ field: "hostname", op: "in", value: hosts }], a.title); };
  }
  $("#altable").querySelectorAll("[data-host]").forEach((x) => x.onclick = () => { $("#drawer").hidden = true; openDevice(x.dataset.host); });
}
const exportLinks = (base) => ["xlsx", "csv", "xml"].map((f) => `<a class="link small" href="${base}/${f}" download>${{ xlsx: "Excel", csv: "CSV", xml: "XML" }[f]}</a>`).join(" · ");
document.querySelectorAll("[data-collect]").forEach((b) => b.onclick = async () => {
  await post(`/api/collect/${b.dataset.collect}`, {}); setTimeout(pollStatus, 500);
});

// ------------------------------------------------------------ asset grid (server-side paging + per-column filters)
const GRID_COLS = [
  ["hostname", "Name"], ["uptime", "Uptime"], ["os", "OS"], ["os_display_version", "Version"], ["last_user", "Last user"], ["model", "Model"],
  ["manufacturer", "Manufacturer"], ["ip", "IP address"], ["mac", "MAC address"], ["switch_name", "Switch"],
  ["switch_port", "Port"], ["ou", "OU"], ["groups", "Groups"], ["state", "State"], ["min_disk_pct_free", "Disk free"],
  ["pending_updates", "Updates"], ["first_seen", "First seen"], ["last_seen", "Last seen"], ["inventory_last_collected", "Last scan"],
  ["agent_status", "Agent"],
];
const grid = { page: 0, size: 100, sort: "hostname", desc: false, filters: {}, preset: [], selected: new Set(), total: 0, rows: [] };
// Drill-down from the dashboard: open the Computers list narrowed to what was clicked. Each preset is a filter
// ({field, op, value}) with a label shown as a removable chip.
function showComputers(preset = [], title = "") {
  grid.preset = preset.map((p) => ({ ...p, title })); grid.filters = {}; grid.page = 0;
  document.querySelectorAll("#gridhead [data-f]").forEach((i) => (i.value = ""));
  showTab("computers");
}
function renderPresets() {
  const el = $("#presets");
  const titles = [...new Set(grid.preset.map((p) => p.title || p.label))];
  el.hidden = !grid.preset.length;
  el.innerHTML = grid.preset.length ? `<span class="muted">Showing</span><span class="chip">${esc(titles.join(", "))} <a title="Show all computers" id="clearpreset">×</a></span>` : "";
  if (grid.preset.length) $("#clearpreset").onclick = () => { grid.preset = []; grid.page = 0; loaders.computers(); };
}
const gridSpec = (extra = {}) => ({
  dataset: "v_devices", fields: [...GRID_COLS.map((c) => c[0]), "online", "online_checked", "online_changed", "online_via", "agent_last_seen", "agent_version"],
  filters: [...Object.entries(grid.filters).filter(([, v]) => v.trim()).map(([field, value]) => ({ field, op: "contains", value: value.trim() })),
    ...grid.preset.map(({ field, op, value }) => ({ field, op, value }))],
  sort: grid.sort, desc: grid.desc, ...extra,
});
let gridTimer;
loaders.computers = async () => {
  if (!$("#gridhead").innerHTML) buildGridHead();
  renderPresets();
  const r = await post("/api/query", gridSpec({ limit: grid.size, offset: grid.page * grid.size, count: true }));
  grid.rows = r.rows; grid.total = r.total;
  const from = r.total ? grid.page * grid.size + 1 : 0, to = Math.min(r.total, (grid.page + 1) * grid.size);
  $("#pageinfo").textContent = `${from}–${to} of ${r.total}`;
  $("#prev").disabled = grid.page === 0; $("#next").disabled = to >= r.total;
  $("#selinfo").textContent = grid.selected.size ? `${grid.selected.size} selected` : "";
  $("#gridbody").innerHTML = r.rows.map((row) => `<tr class="${grid.selected.has(row.hostname) ? "sel" : ""}">
    <td class="chk"><input type="checkbox" data-sel="${esc(row.hostname)}" ${grid.selected.has(row.hostname) ? "checked" : ""}></td>
    ${GRID_COLS.map(([c]) => `<td class="${typeof row[c] === "number" ? "num" : ""}">${gridCell(c, row[c], row)}</td>`).join("")}</tr>`).join("")
    || `<tr><td colspan="${GRID_COLS.length + 1}" class="muted">No computers match these filters.</td></tr>`;
  $("#gridbody").querySelectorAll("[data-sel]").forEach((cb) => cb.onchange = () => {
    cb.checked ? grid.selected.add(cb.dataset.sel) : grid.selected.delete(cb.dataset.sel);
    cb.closest("tr").classList.toggle("sel", cb.checked);
    $("#selinfo").textContent = grid.selected.size ? `${grid.selected.size} selected` : "";
  });
  $("#gridbody").querySelectorAll("[data-host]").forEach((a) => a.onclick = () => openDevice(a.dataset.host));
  $("#gridbody").querySelectorAll("[data-user]").forEach((a) => a.onclick = () => openUser(a.dataset.user));
  $("#selall").checked = r.rows.length > 0 && r.rows.every((x) => grid.selected.has(x.hostname));
};
function gridCell(c, v, row) {
  if (c === "hostname") return `${statusDot(row)} ${hostLink(v)}`;
  if (c === "last_user") return userLink(v);
  if (c === "uptime") return uptimeCell(row);
  if (c === "min_disk_pct_free") return diskPill(v);
  if (c === "pending_updates") return v ? `<span class="pill warn">${v}</span>` : v === 0 ? `<span class="pill good">0</span>` : "";
  if (c === "os") return esc((v || "").replace("Microsoft ", ""));
  if (c === "agent_status") return agentPill(row);
  if (c === "ou") return `<span title="${esc(v)}">${esc((v || "").split(",")[0].replace("OU=", ""))}</span>`;
  if (/seen|scan|collected/.test(c)) return esc(fmtDate(v));
  return esc(v);
}
// Agent column: active (and still reporting), silent (active but no heartbeat for an hour), installing, pending, failed.
function agentPill(row) {
  const st = row.agent_status;
  if (!st) return "";
  const seen = row.agent_last_seen ? `last report ${agoUtc(row.agent_last_seen)}` : "";
  if (st === "active") {
    const quiet = row.agent_last_seen && Date.now() - utc(row.agent_last_seen) > 3600e3;
    return `<span class="pill ${quiet ? "warn" : "good"}" title="${esc(`Agent ${row.agent_version || ""}, ${seen}`)}">${quiet ? "silent" : "active"}</span>`;
  }
  const map = { installing: ["", "installing", "Push in progress or waiting for the PC: see Software > Deployments"],
    pending: ["warn", "pending", "Enrolled, waiting for approval in Settings > Agent"],
    failed: ["bad", "push failed", "The last push failed: see the PC's deployments for why"],
    revoked: ["", "removed", "Revoked or removed"] };
  const [cls, label, tip] = map[st] || ["", st, ""];
  return `<span class="pill ${cls}" title="${esc(tip)}">${label}</span>`;
}
// Live status: green = answered the last reachability check (or a scan/agent report), red = didn't, orange = not checked yet.
const utc = (v) => v ? new Date(String(v).replace(" ", "T") + (/[zZ]|[+-]\d\d:?\d\d$/.test(v) ? "" : "Z")) : null;
const agoUtc = (v) => { const t = utc(v); if (!t) return ""; const s = Math.max(0, (Date.now() - t) / 1000);
  return s < 90 ? "just now" : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} days ago`; };
const VIA = { ping: "answered ping", tcp: "answered on TCP", winrm: "scanned over WinRM", scan: "recently scanned", agent: "agent heartbeat", dns: "name not found in DNS" };
function statusDot(row) {
  if (row.online == null) return `<span class="dot warn" title="Not checked yet"></span>`;
  const since = row.online_changed ? ` since ${fmtDate(utcLocal(row.online_changed))}` : "";
  const t = row.online ? `Online${since} (${VIA[row.online_via] || "reachable"}, checked ${agoUtc(row.online_checked)})`
    : `Offline${since}${row.online_via === "dns" ? " (name not found in DNS)" : ""}, checked ${agoUtc(row.online_checked)}`;
  return `<span class="dot ${row.online ? "good live" : "bad"}" title="${esc(t)}"></span>`;
}
const utcLocal = (v) => { const t = utc(v); return t ? new Date(t - t.getTimezoneOffset() * 60000).toISOString() : v; };
const span = (sec) => sec < 3600 ? `${Math.max(1, Math.round(sec / 60))} min` : sec < 172800 ? `${Math.floor(sec / 3600)} h ${Math.floor(sec % 3600 / 60)} min` : `${Math.floor(sec / 86400)} days ${Math.floor(sec % 86400 / 3600)} h`;
const isOff = (r) => r.online != null && !r.online;     // SQLite sends 0/1, PostgreSQL true/false
function uptimeCell(row) {
  if (isOff(row)) return `<span class="muted" title="Last boot ${esc(fmtDate(row.uptime))}">offline</span>`;
  const b = utc(row.uptime || row.last_boot);
  if (!b) return "";
  const sec = (Date.now() - b) / 1000;
  return `<span class="${sec > 30 * 86400 ? "pill warn" : ""}" title="Booted ${esc(fmtDate(row.uptime || row.last_boot))} UTC">${span(sec)}</span>`;
}
function buildGridHead() {
  $("#gridhead").innerHTML = `<tr><th class="chk"><input type="checkbox" id="selall" title="Select page"></th>${GRID_COLS.map(([c, l]) =>
    `<th data-k="${c}">${l}<span class="arrow"></span></th>`).join("")}</tr>
    <tr class="filters"><th></th>${GRID_COLS.map(([c]) => `<th><input data-f="${c}" placeholder="Filter"></th>`).join("")}</tr>`;
  $("#gridhead").querySelectorAll("th[data-k]").forEach((th) => th.onclick = () => {
    grid.desc = grid.sort === th.dataset.k ? !grid.desc : false; grid.sort = th.dataset.k; grid.page = 0; markSort(); loaders.computers();
  });
  $("#gridhead").querySelectorAll("[data-f]").forEach((inp) => inp.oninput = () => {
    grid.filters[inp.dataset.f] = inp.value; grid.page = 0;
    clearTimeout(gridTimer); gridTimer = setTimeout(loaders.computers, 300);
  });
  $("#selall").onchange = (e) => { grid.rows.forEach((r) => e.target.checked ? grid.selected.add(r.hostname) : grid.selected.delete(r.hostname)); loaders.computers(); };
  markSort();
}
function markSort() { $("#gridhead").querySelectorAll("th[data-k]").forEach((th) => th.querySelector(".arrow").textContent = th.dataset.k === grid.sort ? (grid.desc ? " ▼" : " ▲") : ""); }
$("#prev").onclick = () => { grid.page--; loaders.computers(); };
$("#next").onclick = () => { grid.page++; loaders.computers(); };
$("#pagesize").onchange = (e) => { grid.size = +e.target.value; grid.page = 0; loaders.computers(); };
$("#clearfilters").onclick = () => { grid.filters = {}; grid.preset = []; $("#gridhead").querySelectorAll("[data-f]").forEach((i) => (i.value = "")); grid.page = 0; loaders.computers(); };
$("#clearsel").onclick = () => { grid.selected.clear(); loaders.computers(); };

async function download(path, spec) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(spec) });
  if (r.status === 401) { location.href = "/login"; return; }
  if (!r.ok) return toast(await r.text(), true);
  const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "export";
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(await r.blob()), download: name });
  a.click();
}
document.querySelectorAll("[data-export]").forEach((b) => b.onclick = () => {
  const spec = gridSpec();
  if (grid.selected.size) spec.filters = [{ field: "hostname", op: "in", value: [...grid.selected] }];
  download(`/api/export/${b.dataset.export}`, spec);
});
document.querySelectorAll("[data-bulk]").forEach((b) => b.onclick = async () => {
  if (!grid.selected.size) return toast("Select one or more computers first.", true);
  const action = b.dataset.bulk;
  let value = null;
  if (["add_group", "remove_group", "set_state"].includes(action)) {
    value = await ask(action === "set_state" ? "New state (for example Active, Stock, Retired)" : "Group name");
    if (!value) return;
  }
  const r = await post("/api/bulk", { hostnames: [...grid.selected], action, value });
  toast(`${b.textContent.trim()}: ${r.count} computer${r.count === 1 ? "" : "s"}`);
  loaders.computers(); pollStatus();
});

// ------------------------------------------------------------ asset page
let current = null;
async function openDevice(host) {
  if (location.hash !== `#asset/${host}`) history.pushState(null, "", `#asset/${encodeURIComponent(host)}`);
  current = host;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === "computers"));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === "asset"));
  $("#drawer").hidden = true;
  const d = await api(`/api/devices/${encodeURIComponent(host)}`);
  const v = d.device;
  const live = v.online == null ? `<span class="pill warn">not checked yet</span>` : v.online
    ? `<span class="pill good">online</span>` : `<span class="pill bad">offline${v.online_changed ? ` since ${esc(fmtDate(utcLocal(v.online_changed)))}` : ""}</span>`;
  const up = !isOff(v) && (v.uptime || v.last_boot) ? `<span class="uptime"><b>Up ${span((Date.now() - utc(v.uptime || v.last_boot)) / 1000)}</b> <span class="muted">since ${esc(fmtDate(utcLocal(v.uptime || v.last_boot)))}</span></span>` : "";
  $("#assettitle").innerHTML = `<div class="atitle">${statusDot(v)}${esc(v.hostname)}
    <span class="muted">${esc((v.os || "").replace("Microsoft ", ""))} ${esc(v.os_display_version || "")}</span></div>
    <div class="muted">${live} ${up} · ${esc(v.ip || "no IP")} · ${esc(v.fqdn || "")} ${v.state ? `· <span class="pill ${v.state === "Active" ? "good" : "mute"}">${esc(v.state)}</span>` : ""}
      ${v.online_checked ? `<span class="small">· checked ${agoUtc(v.online_checked)}</span>` : ""}</div>`;
  renderAssetTab(d, $("#assettabs .active")?.dataset.atab || "summary");
  $("#assettabs").querySelectorAll("button").forEach((b) => b.onclick = () => renderAssetTab(d, b.dataset.atab));
}
const kvRow = (k, v) => (v === null || v === undefined || v === "" ? "" : `<div class="kvr"><span>${k}</span><div>${v}</div></div>`);
function renderAssetTab(d, tab) {
  $("#assettabs").querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.atab === tab));
  const v = d.device, el = $("#assetbody");
  const counts = { software: d.software.length, updates: d.updates.filter((u) => u.status === "pending").length, logons: d.logons.length,
    history: d.history.length, comments: d.comments.length, location: d.location.length,
    deployments: (d.deployments || []).filter((x) => ["queued", "sending", "running"].includes(x.status)).length || (d.deployments || []).length };
  $("#assettabs").querySelectorAll("button").forEach((b) => { const n = counts[b.dataset.atab]; b.querySelector("i") && (b.querySelector("i").textContent = n ? ` ${n}` : ""); });
  if (tab === "summary") {
    const running = d.fixes_running?.length ? `<div class="banner">Running on this PC: ${d.fixes_running.map(esc).join(", ")}. The result appears in History.</div>` : "";
    const wEnd = v.warranty_end ? new Date(v.warranty_end.replace(" ", "T")) : null;
    const wCls = wEnd ? (wEnd < new Date() ? "bad" : wEnd - new Date() < 90 * 864e5 ? "warn" : "good") : "";
    el.innerHTML = `${running}<div class="summary">
      <div class="panel"><h3>Hardware</h3>
        ${kvRow("Manufacturer", esc(v.manufacturer))}${kvRow("Model", esc(v.model))}${kvRow("Serial", esc(v.serial))}
        ${kvRow("Processor", esc(v.cpu))}${kvRow("Memory", v.ram_gb ? `${v.ram_gb} GB` : "")}${kvRow("Graphics", esc(v.gpu))}
        <h3>Operating system</h3>
        ${kvRow("OS", esc(v.os))}${kvRow("Version", esc(v.os_display_version))}${kvRow("Build", esc(v.os_build))}
        ${kvRow("Last boot", `${fmtDate(v.last_boot)} <span class="muted">${ago(v.last_boot)}</span>`)}
        ${kvRow("Last patch", `${fmtDate(v.last_patch_installed)} ${v.pending_updates ? `<span class="pill warn">${v.pending_updates} pending</span>` : ""} ${v.pending_reboot ? `<span class="pill warn">reboot pending</span>` : ""}`)}
        <h3>Network</h3>
        ${d.nics.map((n) => kvRow("Adapter", `${esc(n.description || "")}<br>${esc(n.mac)} · ${esc(n.ip || "")}`)).join("") || kvRow("Adapter", `${esc(v.mac || "unknown")}`)}
        ${kvRow("Switch port", v.switch_name ? `<b>${esc(v.switch_name)}</b> ${esc(v.switch_port)} · VLAN ${esc(v.vlan ?? "?")} <span class="muted">seen ${fmtDate(v.port_last_seen)}</span>` : `<span class="muted">not found on any switch</span>`)}
        <h3>Disks</h3>
        ${d.disks.map((k) => `<div class="disk"><div class="dl"><b>${esc(k.drive)}</b> ${k.free_gb} GB free of ${k.size_gb} GB</div>
          <div class="track"><div class="fill ${k.pct_free < 10 ? "bad" : k.pct_free < 20 ? "warn" : ""}" style="width:${100 - (k.pct_free || 0)}%"></div></div></div>`).join("") || `<p class="muted">No disk data yet.</p>`}
      </div>
      <div class="panel"><h3>Users</h3>
        ${kvRow("Signed in now", esc(v.current_user))}${kvRow("Last user", `${userLink(v.last_user)} <span class="muted">${fmtDate(v.last_user_logon)}</span>`)}
        <h3>Directory</h3>
        ${kvRow("AD enabled", v.ad_enabled === null ? "" : v.ad_enabled ? "Yes" : "No")}${kvRow("AD last logon", fmtDate(v.ad_last_logon))}
        ${kvRow("OU", esc(v.ou))}
        <h3>Lifecycle</h3>
        ${kvRow("Agent", v.agent_status ? `${agentPill(v)} <span class="muted small">${v.agent_version ? `v${esc(v.agent_version)} · ` : ""}${v.agent_last_seen ? `last report ${agoUtc(v.agent_last_seen)}` : ""}</span>` : `<span class="muted">not installed</span>`)}
        ${kvRow("First seen", fmtDate(v.first_seen))}${kvRow("Last seen", fmtDate(v.last_seen))}${kvRow("Last scan", `${fmtDate(v.inventory_last_collected)} <span class="muted">${ago(v.inventory_last_collected)}</span>`)}
        <form id="lifeform" class="lifeform">
          <label>State <select name="state">${["Active", "Stock", "In repair", "Retired"].map((s) => `<option ${v.state === s ? "selected" : ""}>${s}</option>`).join("")}</select></label>
          <label>Location <input name="asset_location" value="${esc(v.asset_location || "")}"></label>
          <label>Purchased <input type="date" name="purchase_date" value="${(v.purchase_date || "").slice(0, 10)}"></label>
          <label>Warranty end <input type="date" name="warranty_end" value="${(v.warranty_end || "").slice(0, 10)}"> ${wEnd ? `<span class="pill ${wCls}">${wCls === "bad" ? "expired" : wCls === "warn" ? "expiring" : "in warranty"}</span>` : ""}</label>
          <button>Save</button>
        </form>
      </div>
      <div class="panel"><h3>Groups</h3>
        <div class="chips">${d.groups.map((g) => `<span class="chip">${esc(g)} <a data-rmgroup="${esc(g)}" title="Remove">×</a></span>`).join("") || `<span class="muted">None</span>`}</div>
        <form id="groupform" class="inline"><input name="g" placeholder="Add to group"><button class="ghost">Add</button></form>
        <h3>Custom fields</h3>
        ${Object.entries(d.custom_fields).map(([k, x]) => kvRow(esc(k), `${esc(x)} <a class="link" data-rmfield="${esc(k)}">remove</a>`)).join("") || `<p class="muted">None</p>`}
        <form id="fieldform" class="inline"><input name="n" placeholder="Field (e.g. Asset tag)"><input name="v" placeholder="Value"><button class="ghost">Set</button></form>
      </div></div>`;
    $("#lifeform").onsubmit = async (e) => {
      e.preventDefault(); const f = new FormData(e.target);
      await api(`/api/devices/${current}`, { method: "PATCH", body: JSON.stringify(Object.fromEntries(f)) }); toast("Saved"); openDevice(current);
    };
    $("#groupform").onsubmit = async (e) => { e.preventDefault(); const g = e.target.g.value.trim(); if (g) { await post(`/api/devices/${current}/groups`, { name: g }); openDevice(current); } };
    $("#fieldform").onsubmit = async (e) => { e.preventDefault(); const n = e.target.n.value.trim(); if (n) { await api(`/api/devices/${current}/fields`, { method: "PUT", body: JSON.stringify({ name: n, value: e.target.v.value }) }); openDevice(current); } };
    el.querySelectorAll("[data-rmgroup]").forEach((a) => a.onclick = async () => { await api(`/api/devices/${current}/groups/${encodeURIComponent(a.dataset.rmgroup)}`, { method: "DELETE" }); openDevice(current); });
    el.querySelectorAll("[data-rmfield]").forEach((a) => a.onclick = async () => { await api(`/api/devices/${current}/fields`, { method: "PUT", body: JSON.stringify({ name: a.dataset.rmfield, value: "" }) }); openDevice(current); });
  } else if (tab === "software") {
    const behind = d.software.filter((s) => s.status === "outdated").length;
    el.innerHTML = `<div class="toolbar"><input id="swf" placeholder="Filter software">
      <span class="muted">${behind ? `${behind} behind the latest version` : "Nothing behind the latest version"}</span></div><div id="swt"></div>`;
    table($("#swt"), d.software, ["name", "version", "latest_version", "status", "publisher", "scope", "fix"], { filterEl: $("#swf"), sort: "name",
      labels: { latest_version: "latest", fix: "" },
      cell: { status: swPill, fix: (_, r) => `${swFixCell(r)} ${r.product_code && r.scope !== "user" ? `<span class="swmore">
        ${/^\{[0-9A-Fa-f-]{36}\}$/.test(r.product_code) ? `<a class="link small" data-swrep="${esc(r.product_code)}" data-name="${esc(r.name)}">Repair</a> · ` : ""}<a class="link small" data-swrm="${esc(r.product_code)}" data-name="${esc(r.name)}">Uninstall</a></span>` : ""}` } });
    const swact = (action, code, name, q) => async () => {
      if (!(await confirmBox(q))) return;
      try { const r = await post(`/api/devices/${encodeURIComponent(current)}/fix`, { action, value: code }); toast(r.output, !r.ok); } catch (e) { toast(errText(e), true); }
    };
    el.onclick = (e) => {
      const a = e.target.closest("[data-swupd],[data-swrm],[data-swrep]"); if (!a) return;
      if (a.dataset.swupd) return appUpdate([current], a.dataset.swupd, a.dataset.name);
      if (a.dataset.swrm) return swact("app_uninstall", a.dataset.swrm, a.dataset.name, `Uninstall ${a.dataset.name} from ${current}? It runs silently as SYSTEM; anyone using it loses unsaved work in it. Programs without a silent uninstaller are refused, not half-removed.`)();
      swact("app_repair", a.dataset.swrep, a.dataset.name, `Repair ${a.dataset.name} on ${current}? Windows Installer reinstalls its files.`)();
    };
  } else if (tab === "updates") {
    const npend = d.updates.filter((u) => u.status === "pending").length;
    el.innerHTML = `<h2>Pending ${npend ? `<button class="small" id="wuinstall">Install ${npend} pending update${npend === 1 ? "" : "s"}</button>` : ""}</h2>
      <div id="up1"></div><h2>Installed</h2><div id="up2"></div>`;
    $("#wuinstall") && ($("#wuinstall").onclick = () => runFix("windows_updates"));
    table($("#up1"), d.updates.filter((u) => u.status === "pending"), ["kb", "title", "severity"]);
    table($("#up2"), d.updates.filter((u) => u.status === "installed"), ["kb", "title", "installed_on"], { sort: "installed_on" });
  } else if (tab === "location") {
    el.innerHTML = `<p class="muted">Every access port this PC's network adapters have been seen on (uplinks excluded).</p><div id="loc"></div>`;
    table($("#loc"), d.location, ["switch_name", "port", "port_alias", "vlan", "mac", "first_seen", "last_seen"]);
  } else if (tab === "logons") {
    el.innerHTML = `<h2>Users on this PC</h2><div id="lg1"></div><h2>Logon events</h2><div id="lg2"></div>`;
    table($("#lg1"), d.users, ["username", "last_logon", "first_logon", "logon_count"], { cell: { username: userLink } });
    table($("#lg2"), d.logons, ["time", "username", "logon_type", "ip", "source"], { cell: { username: userLink,
      logon_type: (t) => ({ 0: "Kerberos (DC)", 2: "Interactive", 3: "Network", 10: "Remote desktop", 11: "Cached" }[t] ?? esc(t)) } });
  } else if (tab === "processes") {
    loadProcesses(el);
  } else if (tab === "services") {
    loadServices(el);
  } else if (tab === "registry") {
    loadRegistry(el);
  } else if (tab === "printers") {
    loadPrinters(el);
  } else if (tab === "accounts") {
    loadAccounts(el);
  } else if (tab === "deployments") {
    el.innerHTML = `<p class="muted">Software and fixes pushed to this PC, newest first. Waiting items run when the PC is online.</p><div id="pcdep"></div>`;
    depTable($("#pcdep"), d.deployments || [], false);
  } else if (tab === "history") {
    el.innerHTML = `<div id="hist"></div>`;
    table($("#hist"), d.history, ["time", "kind", "detail"], { cell: { kind: (k) => `<span class="pill mute">${esc(k.replaceAll("_", " "))}</span>` } });
  } else if (tab === "comments") {
    el.innerHTML = `<form id="cform" class="cform"><textarea name="t" rows="3" placeholder="Add a note about this computer"></textarea><button>Add comment</button></form>
      ${d.comments.map((c) => `<div class="comment"><div class="muted">${esc(c.author || "")} · ${esc(c.created)}</div>${esc(c.text)}</div>`).join("") || `<p class="muted">No comments yet.</p>`}`;
    $("#cform").onsubmit = async (e) => { e.preventDefault(); const t = e.target.t.value.trim(); if (t) { await post(`/api/devices/${current}/comments`, { text: t }); openDevice(current); } };
  }
}
document.querySelectorAll("[data-act]").forEach((b) => b.onclick = async () => {
  const act = b.dataset.act, host = current;
  if (act === "rdp") { location.href = `/api/devices/${encodeURIComponent(host)}/rdp`; return; }
  if (act === "cshare" || act === "admin") {
    const path = `\\\\${host}\\${act === "cshare" ? "c$" : "admin$"}`;
    try { await navigator.clipboard.writeText(path); toast(`Copied ${path}. Paste it into File Explorer.`); } catch { toast(path); }
    return;
  }
  if (act === "back") { showTab("computers"); return; }
  if (act === "dameware") { dameware(host); return; }
  if (act === "reboot" && !(await confirmBox(`Reboot ${host} now? Anyone signed in will lose unsaved work.`))) return;
  b.disabled = true;
  try {
    const r = await post(`/api/devices/${encodeURIComponent(host)}/action/${act}`, {});
    toast(r.output, !r.ok);
    if (act === "rescan") pollStatus();
  } catch (e) { toast(e.message, true); }
  b.disabled = false;
});

// ------------------------------------------------------------ app catalog and one-click fixes
const SW_PILL = { current: "good", outdated: "warn", unknown: "mute", ignored: "mute" };
const swPill = (v) => (v ? `<span class="pill ${SW_PILL[v] || "mute"}">${v === "unknown" ? "not in catalog" : esc(v)}</span>` : "");
function swFixCell(r) {
  if (r.status !== "outdated" || !r.catalog_id) return "";
  if (r.scope === "user") return `<span class="muted small" title="Installed for one user only. Update it from that user's session, or install it machine-wide.">per-user install</span>`;
  if (r.match_method === "family") return `<span class="muted small" title="Several catalog packages fit (for example 32-bit and 64-bit). Add a rule in Settings > App catalog to pick one.">pick package</span>`;
  return `<button class="small" data-swupd="${esc(r.catalog_id)}" data-name="${esc(r.name)}">Update</button>`;
}
async function appUpdate(hosts, pkg, name) {
  const n = hosts.length;
  if (!(await confirmBox(`Update ${name} to the latest version with winget (${pkg}) on ${n === 1 ? hosts[0] : `${n} computers`}? ` +
    "The app is closed and updated silently; anyone using it loses unsaved work in it.")) ) return;
  try {
    const r = n === 1 ? await post(`/api/devices/${encodeURIComponent(hosts[0])}/fix`, { action: "app_update", value: pkg })
      : await post("/api/fix/bulk", { action: "app_update", value: pkg, hostnames: hosts });
    toast(r.output, !r.ok);
  } catch (e) { toast(errText(e), true); }
}
const SERVICES = { WinDefend: "Microsoft Defender Antivirus", wuauserv: "Windows Update", BITS: "Background Intelligent Transfer (BITS)" };
async function runFix(action) {
  const host = current;
  let value = null, ask = "";
  if (action === "windows_updates") ask = `Install all pending Windows updates on ${host} now? It does not restart the PC; if an update needs a restart, the PC shows “reboot pending”.`;
  if (action === "cancel_reboot") ask = `Cancel a reboot scheduled on ${host}?`;
  if (action === "start_service") {
    const f = await formModal(`<h3>Start a service on ${esc(host)}</h3><label>Service <select name="svc">${Object.entries(SERVICES).map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join("")}</select></label>
      <p class="muted">Only starts it if it is stopped. A service disabled by policy is left alone.</p>`);
    if (!f) return; value = f.svc;
  } else if (action === "reboot") {
    const h = String((await getSettings())?.["fix:reboot_hour"] ?? 2).padStart(2, "0");
    const f = await formModal(`<h3>Schedule a reboot of ${esc(host)}</h3>
      <label>When <select name="when"><option value="tonight">Tonight at ${h}:00 (PC local time)</option><option value="soon">In 5 minutes</option></select></label>
      <p class="muted">The signed-in user sees a notice and can save their work. You can cancel it until then.</p>`);
    if (!f) return; value = f.when;
  } else if (!(await confirmBox(ask))) return;
  try {
    const r = await post(`/api/devices/${encodeURIComponent(host)}/fix`, { action, value });
    toast(r.output, !r.ok);
    openDevice(host);
  } catch (e) { toast(errText(e), true); }
}
document.querySelectorAll("[data-fix]").forEach((b) => b.onclick = async () => { b.disabled = true; try { await runFix(b.dataset.fix); } finally { b.disabled = false; } });

// ------------------------------------------------------------ scripts: a library, and running one on one PC or many
const LANGS = { powershell: "PowerShell", cmd: "Command prompt" };
let scriptData = null;
const getScripts = async () => (scriptData = await api("/api/scripts"));
async function loadScripts() {
  const d = await getScripts();
  const render = () => {
    const f = $("#scf").value.toLowerCase();
    const rows = d.scripts.filter((x) => [x.name, x.description, x.body].some((v) => String(v || "").toLowerCase().includes(f)));
    table($("#sctable"), rows.map((x) => ({ ...x, act: x.id })), ["name", "language", "description", "runs", "timeout_min", "updated", "who", "act"], {
      labels: { timeout_min: "time limit", who: "by", act: "" },
      cell: { name: (v, r) => `<a class="link" data-scedit="${r.id}">${esc(v)}</a>`, language: (v) => esc(LANGS[v] || v),
        description: (v) => `<span class="longtext small">${esc(v || "")}</span>`, timeout_min: (v) => `${esc(v)} min`, updated: (v) => esc(v || ""),
        runs: (v, r) => (v ? `${v} <span class="muted small">(${r.ok} ok, ${r.failed} failed)</span>` : `<span class="muted">never</span>`),
        act: (id) => `<a class="link" data-scrun="${id}">Run…</a> &nbsp; <a class="link" data-scdel="${id}">Delete</a>` } });
    const byId = (id) => d.scripts.find((x) => String(x.id) === String(id));
    $("#sctable").querySelectorAll("[data-scedit]").forEach((a) => a.onclick = () => editScript(byId(a.dataset.scedit)));
    $("#sctable").querySelectorAll("[data-scrun]").forEach((a) => a.onclick = () => runScriptDialog({ scriptId: +a.dataset.scrun, hosts: [...grid.selected] }));
    $("#sctable").querySelectorAll("[data-scdel]").forEach((a) => a.onclick = async () => {
      if (!(await confirmBox(`Delete the script ${byId(a.dataset.scdel).name}? Pushes already queued still run the text they were queued with.`))) return;
      try { await api(`/api/scripts/${a.dataset.scdel}`, { method: "DELETE" }); toast("Deleted."); } catch (e) { toast(errText(e), true); }
      loadScripts();
    });
  };
  $("#scf").oninput = render;
  render();
}
const langSelect = (v) => `<select name="language">${Object.entries(LANGS).map(([k, l]) => `<option value="${k}" ${v === k ? "selected" : ""}>${l}</option>`).join("")}</select>`;
const SCRIPT_HELP = `<p class="muted small">Runs as SYSTEM on the PC, with no window and nobody to answer prompts, so make it silent.
  Exit code 0 counts as success, anything else as failed (in PowerShell, <code>exit 1</code> or an error with <code>-ErrorAction Stop</code>).
  Everything it prints is kept (the last 3,500 characters).</p>`;
async function editScript(x = {}) {
  const f = await formModal(`<h3>${x.id ? "Edit script" : "New script"}</h3>
    <label>Name <input name="name" value="${esc(x.name || "")}" maxlength="128" required></label>
    <label>What it does <input name="description" value="${esc(x.description || "")}" placeholder="optional"></label>
    <div class="row"><label>Language ${langSelect(x.language || "powershell")}</label>
      <label>Time limit (minutes) <input name="timeout_min" type="number" min="1" max="240" value="${esc(x.timeout_min || 30)}"></label></div>
    <label>Script <textarea name="body" class="code" rows="16" spellcheck="false" required>${esc(x.body || "")}</textarea></label>${SCRIPT_HELP}`, true);
  if (!f) return;
  try {
    await (x.id ? api(`/api/scripts/${x.id}`, { method: "PUT", body: JSON.stringify(f) }) : post("/api/scripts", f));
    toast("Saved."); loadScripts();
  } catch (e) { toast(errText(e), true); }
}
$("#scnew").onclick = () => editScript();
const splitHosts = (t) => String(t || "").split(/[\s,;]+/).map((h) => h.trim()).filter(Boolean);
async function runScriptDialog({ scriptId = null, hosts = [] } = {}) {
  const d = scriptData || (await getScripts().catch(() => ({ scripts: [], groups: [] })));
  const one = hosts.length === 1 && !scriptId ? hosts[0] : null;
  const f = await formModal(`<h3>Run a script${one ? ` on ${esc(one)}` : ""}</h3>
    <label>Script <select name="sid"><option value="">A one-off command (type it below)</option>
      ${d.scripts.map((x) => `<option value="${x.id}" ${x.id === scriptId ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label>
    <div id="sc-adhoc"><div class="row"><label>Language ${langSelect("powershell")}</label>
        <label>Time limit (minutes) <input name="timeout" type="number" min="1" max="240" value="10"></label></div>
      <label>Command <textarea name="body" class="code" rows="8" spellcheck="false" placeholder="for example: ipconfig /flushdns"></textarea></label></div>
    <pre id="sc-preview" class="code small" hidden></pre>
    ${one ? "" : `<label>On <select name="on">
        <option value="sel" ${hosts.length ? "selected" : ""}>the ${hosts.length} computer${hosts.length === 1 ? "" : "s"} selected in Computers</option>
        <option value="group" ${hosts.length ? "" : "selected"}>every computer in a group</option><option value="list">these computers</option></select></label>
      <label id="sc-group">Group <select name="group">${(d.groups || []).map((g) => `<option>${esc(g)}</option>`).join("") || "<option value=''>(no groups yet)</option>"}</select></label>
      <label id="sc-list">Computer names (one per line, or separated by commas) <textarea name="list" rows="4">${esc(hosts.join("\n"))}</textarea></label>`}
    ${SCRIPT_HELP}<p class="muted small">Offline PCs get it when they come back online. Follow it in Software &gt; Deployments.</p>`, true, (form) => {
    const sync = () => {
      const x = d.scripts.find((s) => String(s.id) === form.sid.value);
      form.querySelector("#sc-adhoc").hidden = !!x;
      const pv = form.querySelector("#sc-preview"); pv.hidden = !x; pv.textContent = x ? `${LANGS[x.language]}, stops after ${x.timeout_min} min\n\n${x.body}` : "";
      if (form.on) { form.querySelector("#sc-group").hidden = form.on.value !== "group"; form.querySelector("#sc-list").hidden = form.on.value !== "list"; }
    };
    form.sid.onchange = sync; if (form.on) form.on.onchange = sync; sync();
  });
  if (!f) return;
  const x = d.scripts.find((s) => String(s.id) === f.sid);
  const req = { action: "script", value: x ? String(x.id) : null, adhoc: x ? null : { language: f.language, body: f.body, timeout: +f.timeout || 10 } };
  if (!x && !f.body.trim()) return toast("Type a command, or pick a saved script.", true);
  const what = x ? x.name : `the command “${f.body.trim().split("\n")[0].slice(0, 60)}”`;
  let where, body;
  if (one) where = one;
  else if (f.on === "group") { if (!f.group) return toast("Pick a group.", true); body = { ...req, group: f.group }; where = `every computer in the group ${f.group}`; }
  else { const h = f.on === "list" ? splitHosts(f.list) : hosts; if (!h.length) return toast("No computers picked.", true); body = { ...req, hostnames: h }; where = h.length === 1 ? h[0] : `${h.length} computers`; }
  if (!(await confirmBox(`Run ${what} as SYSTEM on ${where}?`))) return;
  try {
    const r = one ? await post(`/api/devices/${encodeURIComponent(one)}/fix`, req) : await post("/api/fix/bulk", body);
    toast(r.output, !r.ok);
    if (one && current === one) openDevice(one);
  } catch (e) { toast(errText(e), true); }
}
$("#runscript").onclick = () => runScriptDialog({ hosts: [current] });
// ------------------------------------------------------------ push the NetInventory Agent over WinRM (agentpush.py)
async function pushAgentDialog(hosts) {
  let d;
  try { d = await api("/api/agents/push"); } catch (e) { return toast(errText(e), true); }
  if (!d.https) return toast("This server isn't on HTTPS yet. Agents only talk HTTPS: set up the certificate in Settings first.", true);
  const one = hosts.length === 1 ? hosts[0] : null;
  const f = await formModal(`<h3>Push the agent to ${one ? esc(one) : `${hosts.length} computers`}</h3>
    <p class="muted small">Installs (or updates) the NetInventory Agent over WinRM with the scan credential, the same way as other
      deployments: no download on the PC and no enrollment token needed. Each PC gets a one-time ticket, is approved
      automatically, and only counts as done once its agent has reported to this server.</p>
    ${d.credential ? "" : `<p class="pill bad longtext">No Windows credential is set up (Settings > Credentials): pushes will fail.</p>`}
    <label>Server address the PCs use <input name="server_url" value="${esc(d.server)}" required></label>
    ${d.saved ? "" : `<p class="muted small">Check this: it's the name and port PCs reach this server on (not localhost). It's saved for later pushes.</p>`}
    <label>Agent runs as <select name="run_as"><option value="LOCALSERVICE">Local Service (least rights, recommended)</option>
      <option value="SYSTEM">SYSTEM (also collects pending updates, per-user apps, local logons)</option></select></label>
    <label><input type="checkbox" name="remove"> Remove the agent instead</label>
    <p class="muted small">Package: ${d.package === "msi" ? "the agent MSI that came with this server" : "the agent scripts (this server has no MSI)"}.
      Offline PCs get it when they come back online. Follow it in Software &gt; Deployments or the Agent column.</p>`, true);
  if (!f) return;
  const what = f.remove ? "Remove the agent from" : "Install the agent on";
  if (!(await confirmBox(`${what} ${one || `${hosts.length} computers`}?`))) return;
  try {
    const r = await post("/api/agents/push", { hostnames: hosts, server_url: f.server_url, run_as: f.run_as, remove: !!f.remove });
    toast(r.output, !r.ok);
    if (one && current === one) openDevice(one); else loaders.computers();
  } catch (e) { toast(errText(e), true); }
}
$("#pushagent").onclick = () => pushAgentDialog([current]);
$("#bulkagent").onclick = () => grid.selected.size ? pushAgentDialog([...grid.selected]) : toast("Select one or more computers first.", true);
$("#bulkscript").onclick = () => grid.selected.size ? runScriptDialog({ hosts: [...grid.selected] }) : toast("Select one or more computers first.", true);
async function viewDeployment(id) {
  const r = await api(`/api/deployments/${id}`);
  const sc = r.script;
  await modal(`<h3>${esc(r.label)} on ${esc(r.hostname)}</h3><p>${depStatus(r.status, r)} queued ${esc(r.created || "")} by ${esc(r.who || "?")}${r.finished ? `, finished ${esc(r.finished)}` : ""}</p>
    <h4>Result</h4><pre class="code small">${esc(r.message || "(nothing yet)")}</pre>
    ${sc ? `<h4>What ran (${esc(LANGS[sc.language] || sc.language)}, up to ${esc(sc.timeout)} min)</h4><pre class="code small">${esc(sc.body)}</pre>` : ""}`);
}

// ------------------------------------------------------------ live tools: processes and services (over WinRM)
async function loadProcesses(el) {
  el.innerHTML = `<div class="toolbar"><input id="prf" placeholder="Filter by name, user or path"><button class="ghost" id="prref">Refresh</button>
    <span class="muted small">Live from ${esc(current)} over WinRM, sorted by memory.</span></div><div id="prt"><p class="muted"><span class="spinner tiny"></span> Asking ${esc(current)}…</p></div>`;
  $("#prref").onclick = () => loadProcesses(el);
  let rows;
  try { rows = await api(`/api/devices/${encodeURIComponent(current)}/processes`); } catch (e) { $("#prt").innerHTML = `<p class="pill bad longtext">${esc(errText(e))}</p>`; return; }
  table($("#prt"), rows.map((r) => ({ ...r, act: r.pid })), ["name", "pid", "user", "cpu_pct", "mem_mb", "threads", "session", "started", "path", "act"], { filterEl: $("#prf"),
    labels: { cpu_pct: "CPU %", mem_mb: "memory MB", act: "" },
    cell: { started: (v) => esc(fmtDate(utcLocal(v))), path: (v, r) => `<span class="small muted" title="${esc(r.cmd || "")}">${esc(v || "")}</span>`,
      act: (pid, r) => r.protected ? `<span class="muted small" title="Windows system process">system</span>` : `<a class="link" data-kill="${pid}" data-name="${esc(r.name)}">End</a>` } });
  $("#prt").addEventListener("click", async (e) => {
    const a = e.target.closest("[data-kill]"); if (!a) return;
    if (!(await confirmBox(`End ${a.dataset.name} (PID ${a.dataset.kill}) on ${current}? Unsaved work in it is lost.`))) return;
    try { const r = await post(`/api/devices/${encodeURIComponent(current)}/processes/kill`, { pid: +a.dataset.kill, name: a.dataset.name }); toast(r.output, !r.ok); }
    catch (er) { toast(errText(er), true); }
    loadProcesses(el);
  });
}
const SVC_ACT = [["start", "Start"], ["stop", "Stop"], ["restart", "Restart"], ["auto", "Automatic"], ["delayed", "Automatic (delayed)"], ["manual", "Manual"], ["disabled", "Disabled"]];
async function loadServices(el) {
  el.innerHTML = `<div class="toolbar"><input id="svf" placeholder="Filter services"><label class="muted">Show <select id="svshow"><option value="">All</option>
    <option value="Running">Running</option><option value="Stopped">Stopped</option><option value="autostop">Automatic but stopped</option></select></label>
    <button class="ghost" id="svref">Refresh</button></div><div id="svt"><p class="muted"><span class="spinner tiny"></span> Asking ${esc(current)}…</p></div>`;
  $("#svref").onclick = () => loadServices(el);
  let rows;
  try { rows = await api(`/api/devices/${encodeURIComponent(current)}/services`); } catch (e) { $("#svt").innerHTML = `<p class="pill bad longtext">${esc(errText(e))}</p>`; return; }
  const draw = () => {
    const sh = $("#svshow").value;
    const list = rows.filter((r) => !sh || (sh === "autostop" ? r.start === "Auto" && r.state !== "Running" : r.state === sh));
    table($("#svt"), list.map((r) => ({ ...r, act: r.name })), ["display", "name", "state", "start", "account", "act"], { filterEl: $("#svf"),
      labels: { display: "service", start: "start type", account: "runs as", act: "" },
      cell: { display: (v, r) => `<span title="${esc(r.description || "")}">${esc(v)}</span>`,
        state: (v) => `<span class="pill ${v === "Running" ? "good" : v === "Stopped" ? "mute" : "warn"}">${esc(v)}</span>`,
        start: (v, r) => esc(v) + (r.delayed ? " (delayed)" : ""),
        act: (n, r) => `<select class="small" data-svc="${esc(n)}"><option value="">Action…</option>${SVC_ACT.filter(([k]) => !(r.protected && ["stop", "restart", "manual", "disabled"].includes(k)))
          .map(([k, l]) => `<option value="${k}">${l}</option>`).join("")}</select>` } });
  };
  draw();
  $("#svshow").onchange = draw;
  $("#svt").addEventListener("change", async (e) => {
    const sel = e.target.closest("[data-svc]"); if (!sel || !sel.value) return;
    const act = sel.value, label = SVC_ACT.find((x) => x[0] === act)[1];
    if (!(await confirmBox(`${["auto", "delayed", "manual", "disabled"].includes(act) ? `Set the start type of ${sel.dataset.svc} to ${label}` : `${label} the service ${sel.dataset.svc}`} on ${current}?`))) { sel.value = ""; return; }
    sel.disabled = true;
    try { const r = await post(`/api/devices/${encodeURIComponent(current)}/services/action`, { name: sel.dataset.svc, action: act }); toast(r.output, !r.ok); }
    catch (er) { toast(errText(er), true); }
    loadServices(el);
  });
}

// ------------------------------------------------------------ registry, printers and drives, local accounts (live, over WinRM)
const asking = () => `<p class="muted"><span class="spinner tiny"></span> Asking ${esc(current)}…</p>`;
const toolErr = (el, e) => { el.innerHTML = `<p class="pill bad longtext">${esc(errText(e))}</p>`; };
const hostApi = (p) => `/api/devices/${encodeURIComponent(current)}/${p}`;
let regPath = "HKLM\\SOFTWARE";
const REG_KIND = { String: "String (REG_SZ)", ExpandString: "Expandable string (REG_EXPAND_SZ)", DWord: "DWORD (32-bit number)", QWord: "QWORD (64-bit number)", MultiString: "Multi-string (one per line)" };
async function regChange(el, body, ask) {
  if (ask && !(await confirmBox(ask))) return;
  try { const r = await post(hostApi("registry"), { path: regPath, ...body }); toast(r.output, !r.ok); } catch (e) { toast(errText(e), true); }
  loadRegistry(el);
}
async function regEdit(el, v = {}) {
  const f = await formModal(`<h3>${v.name !== undefined ? "Edit value" : "New value"} in ${esc(regPath)}</h3>
    <label>Name <input name="name" value="${esc(v.name ?? "")}" placeholder="empty = (Default)" ${v.name !== undefined ? "readonly" : ""}></label>
    <label>Type <select name="kind">${Object.entries(REG_KIND).filter(([k]) => !v.type || v.type === k || !REG_KIND[v.type]).map(([k, l]) => `<option value="${k}" ${v.type === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
    <label>Data <textarea name="data" class="code" rows="4" spellcheck="false">${esc(v.type === "DWord" ? String(v.data || "").split(" ")[0] : v.data ?? "")}</textarea></label>
    <p class="muted small">Numbers can be decimal or hex (0x1F). The old value is kept in the PC's History and the audit log.</p>`, true);
  if (!f) return;
  regChange(el, { op: "set", name: f.name, kind: f.kind, data: f.data }, `Set ${regPath}\\${f.name || "(Default)"} on ${current}?`);
}
async function loadRegistry(el) {
  el.innerHTML = `<div class="toolbar"><input id="regpath" class="wide" value="${esc(regPath)}" spellcheck="false"><button id="reggo">Open</button>
    <button class="ghost" id="regup">Up</button><button class="ghost" id="regnewk">New key</button><button class="ghost" id="regnewv">New value</button>
    <button class="ghost danger" id="regdelk">Delete this key</button></div>
    <p class="muted small">HKLM, HKU (each user by SID) and HKCR, live from ${esc(current)}. Every change is confirmed and logged with the old value. Account and security-policy keys (SAM, SECURITY, Lsa) are read-only here.</p>
    <div class="regcols"><div id="regkeys">${asking()}</div><div id="regvals"></div></div>`;
  const go = (p) => { regPath = p; loadRegistry(el); };
  $("#reggo").onclick = () => go($("#regpath").value.trim());
  $("#regpath").onkeydown = (e) => { if (e.key === "Enter") go($("#regpath").value.trim()); };
  $("#regup").onclick = () => regPath.includes("\\") && go(regPath.slice(0, regPath.lastIndexOf("\\")));
  $("#regnewv").onclick = () => regEdit(el);
  $("#regnewk").onclick = async () => { const n = await ask(`New key under ${regPath}`); if (n) regChange(el, { op: "new_key", name: n }); };
  $("#regdelk").onclick = () => regChange(el, { op: "delete_key" }, `Delete ${regPath} and everything under it on ${current}? This can't be undone from here.`);
  let d;
  try { d = await api(hostApi(`registry?path=${encodeURIComponent(regPath)}`)); } catch (e) { return toolErr($("#regkeys"), e); }
  regPath = d.path; $("#regpath").value = d.path;
  $("#regkeys").innerHTML = `<div class="regkeys">${d.subkeys.map((k) => `<a class="link" data-rk="${esc(k)}">${esc(k)}</a>`).join("") || `<span class="muted">No subkeys</span>`}</div>`;
  $("#regkeys").querySelectorAll("[data-rk]").forEach((a) => a.onclick = () => go(`${regPath}\\${a.dataset.rk}`));
  table($("#regvals"), d.values.map((v) => ({ ...v, act: v.name })), ["name", "type", "data", "act"], {
    labels: { act: "" },
    cell: { name: (v) => esc(v || "(Default)"), data: (v) => `<span class="longtext small code">${esc(v)}</span>`,
      act: (n, r) => `${REG_KIND[r.type] ? `<a class="link" data-rv="${esc(n)}">Edit</a> &nbsp; ` : ""}<a class="link" data-rdel="${esc(n)}">Delete</a>` } });
  $("#regvals").querySelectorAll("[data-rv]").forEach((a) => a.onclick = () => regEdit(el, d.values.find((v) => v.name === a.dataset.rv)));
  $("#regvals").querySelectorAll("[data-rdel]").forEach((a) => a.onclick = () => regChange(el, { op: "delete_value", name: a.dataset.rdel }, `Delete the value ${a.dataset.rdel || "(Default)"} in ${regPath} on ${current}?`));
}
async function loadPrinters(el) {
  el.innerHTML = `<div class="toolbar"><button id="pradd">Add a shared printer for every user</button><button class="ghost" id="prref2">Refresh</button></div>
    <h2>Printers</h2><div id="prtab">${asking()}</div>
    <h2>Mapped drives of users who are signed in</h2><p class="muted small">Persistent drive mappings (and shares used recently) from the registry of each signed-in user.</p><div id="drtab"></div>`;
  $("#prref2").onclick = () => loadPrinters(el);
  $("#pradd").onclick = async () => {
    const n = await ask("Shared printer, as \\\\server\\printer. It's added for every user of this PC (at their next sign-in).");
    if (!n) return;
    try { const r = await post(hostApi("printers"), { op: "add", name: n.trim() }); toast(r.output, !r.ok); } catch (e) { toast(errText(e), true); }
    loadPrinters(el);
  };
  let d;
  try { d = await api(hostApi("printers")); } catch (e) { return toolErr($("#prtab"), e); }
  table($("#prtab"), d.printers.map((p) => ({ ...p, act: p.name })), ["name", "status", "jobs", "driver", "port", "shared", "location", "act"], {
    labels: { act: "" },
    cell: { name: (v, r) => esc(v) + (r.machine_wide ? ` <span class="pill mute small">every user</span>` : r.network ? ` <span class="pill mute small">network</span>` : ""),
      shared: (v, r) => (v ? `yes (${esc(r.share || "")})` : ""), status: (v) => `<span class="pill ${v === "ready" ? "good" : v === "offline" || v === "stopped" ? "bad" : "mute"}">${esc(v || "")}</span>`,
      act: (n, r) => [!r.machine_wide && `<a class="link" data-pr="test" data-n="${esc(n)}">Test page</a>`, r.jobs && `<a class="link" data-pr="clear" data-n="${esc(n)}">Clear queue</a>`,
        `<a class="link" data-pr="remove" data-n="${esc(n)}">Remove</a>`].filter(Boolean).join(" &nbsp; ") } });
  $("#prtab").querySelectorAll("[data-pr]").forEach((a) => a.onclick = async () => {
    const op = a.dataset.pr, n = a.dataset.n;
    const q = { test: `Print a test page on ${n}?`, clear: `Delete every job waiting in the ${n} queue?`, remove: `Remove the printer ${n} from ${current}?` }[op];
    if (!(await confirmBox(q))) return;
    try { const r = await post(hostApi("printers"), { op, name: n }); toast(r.output, !r.ok); } catch (e) { toast(errText(e), true); }
    loadPrinters(el);
  });
  table($("#drtab"), d.drives, ["user", "drive", "path", "kind"], { cell: { user: (v) => esc(v || "") } });
}
async function loadAccounts(el) {
  el.innerHTML = `<div class="toolbar"><button id="admadd">Add to Administrators</button><button class="ghost" id="accref">Refresh</button></div>
    <h2>Members of the local Administrators group</h2><div id="admtab">${asking()}</div><h2>Local user accounts</h2><div id="lutab"></div>`;
  $("#accref").onclick = () => loadAccounts(el);
  const act = async (op, name, q) => {
    if (!(await confirmBox(q))) return;
    try { const r = await post(hostApi("accounts"), { op, name }); toast(r.output, !r.ok); } catch (e) { toast(errText(e), true); }
    loadAccounts(el);
  };
  $("#admadd").onclick = async () => {
    const n = await ask("User or group to add, as DOMAIN\\name (for example CORP\\Helpdesk)");
    if (n) act("add_admin", n.trim(), `Make ${n.trim()} a local administrator of ${current}?`);
  };
  let d;
  try { d = await api(hostApi("accounts")); } catch (e) { return toolErr($("#admtab"), e); }
  table($("#admtab"), d.members.map((m) => ({ ...m, act: m.name })), ["name", "type", "sid", "act"], {
    labels: { act: "" },
    cell: { name: (v, r) => esc(v) + (r.builtin ? ` <span class="pill mute small">built-in</span>` : r.local ? ` <span class="pill mute small">local</span>` : ""),
      sid: (v) => `<span class="muted small">${esc(v || "")}</span>`,
      act: (n, r) => (r.builtin ? "" : `<a class="link" data-rmadm="${esc(n)}">Remove</a>`) } });
  $("#admtab").querySelectorAll("[data-rmadm]").forEach((a) => a.onclick = () => act("remove_admin", a.dataset.rmadm, `Remove ${a.dataset.rmadm} from the local Administrators of ${current}? It takes effect at their next sign-in.`));
  table($("#lutab"), d.users.map((u) => ({ ...u, act: u.name })), ["name", "full_name", "enabled", "admin", "last_logon", "description", "act"], {
    labels: { act: "", last_logon: "last sign-in" },
    cell: { enabled: (v, r) => `<span class="pill ${v ? "good" : "mute"}">${v ? "enabled" : "disabled"}</span>` + (r.locked ? ` <span class="pill bad">locked</span>` : ""),
      admin: (v) => (v ? "yes" : ""), last_logon: (v) => esc(v ? fmtDate(utcLocal(v)) : "never"), description: (v) => `<span class="small muted">${esc(v || "")}</span>`,
      act: (n, r) => `<a class="link" data-lu="${r.enabled ? "disable" : "enable"}" data-n="${esc(n)}">${r.enabled ? "Disable" : "Enable"}</a>` } });
  $("#lutab").querySelectorAll("[data-lu]").forEach((a) => a.onclick = () => act(a.dataset.lu, a.dataset.n, `${a.dataset.lu === "disable" ? "Disable" : "Enable"} the local account ${a.dataset.n} on ${current}?`));
}

// ------------------------------------------------------------ deployment queue and log
const DEP_PILL = { queued: "warn", sending: "warn", running: "warn", success: "good", failed: "bad", expired: "bad", cancelled: "mute" };
const depStatus = (v, r) => `<span class="pill ${DEP_PILL[v] || "mute"}">${r.waiting_offline ? "waiting (PC offline)" : v === "sending" ? "sending" : esc(v)}</span>`;
function depTable(el, rows, withHost = true) {
  const cols = [...(withHost ? ["hostname"] : []), "label", "status", "message", "who", "created", "finished", "attempts", "act"];
  table(el, rows.map((r) => ({ ...r, act: r.id })), cols, {
    labels: { label: "what", message: "result", who: "by", created: "queued", attempts: "tries", act: "" },
    cell: { hostname: hostLink, status: depStatus, label: (v, r) => r.action === "script" ? `<a class="link" data-dview="${r.id}" title="Show the script and its full output">${esc(v)}</a>` : esc(v),
      message: (v, r) => `<span class="longtext small">${esc(r.action === "script" && v ? v.split("\n").slice(0, 3).join(" · ").slice(0, 300) : v || "")}</span>${r.status === "queued" && r.expires ? `<div class="muted small">gives up ${esc(r.expires)}</div>` : ""}`,
      act: (id, r) => r.status === "queued" ? `<a class="link" data-dcancel="${id}">Cancel</a>` : ["failed", "expired", "cancelled"].includes(r.status) ? `<a class="link" data-dretry="${id}">Retry</a>` : "" } });
  el.querySelectorAll("[data-host]").forEach((a) => a.onclick = () => openDevice(a.dataset.host));
  el.querySelectorAll("[data-dview]").forEach((a) => a.onclick = () => viewDeployment(a.dataset.dview));
  el.querySelectorAll("[data-dcancel]").forEach((a) => a.onclick = async () => { try { toast((await post(`/api/deployments/${a.dataset.dcancel}/cancel`, {})).output); } catch (e) { toast(errText(e), true); } refreshDeploy(); });
  el.querySelectorAll("[data-dretry]").forEach((a) => a.onclick = async () => { try { toast((await post(`/api/deployments/${a.dataset.dretry}/retry`, {})).output); } catch (e) { toast(errText(e), true); } refreshDeploy(); });
}
const refreshDeploy = () => (document.querySelector(".tab.active")?.id === "asset" ? openDevice(current) : loadDeploy());
let depTimer;
async function loadDeploy() {
  clearTimeout(depTimer);
  const d = await api(`/api/deployments?status=${encodeURIComponent($("#depshow").value)}`);
  const c = d.counts, waiting = (c.queued || 0) + (c.sending || 0) + (c.running || 0);
  $("#depbadge").textContent = waiting ? ` ${waiting}` : "";
  $("#depcounts").innerHTML = [["queued", "waiting"], ["running", "running"], ["success", "succeeded"], ["failed", "failed"], ["expired", "expired"]]
    .map(([k, l]) => `<span class="pill ${DEP_PILL[k]}">${c[k] || 0} ${l}</span>`).join(" ");
  depTable($("#deptable"), d.rows);
  $("#depf").oninput = () => { const f = $("#depf").value.toLowerCase(); depTable($("#deptable"), d.rows.filter((r) => [r.hostname, r.label, r.who, r.message].some((x) => String(x || "").toLowerCase().includes(f)))); };
  $("#depset").queue_days.value = d.queue_days; $("#depset").parallel.value = d.parallel;
  if (!$("#deploypane").hidden && $("#apps").classList.contains("active")) depTimer = setTimeout(loadDeploy, waiting ? 10000 : 60000);
}
$("#depshow").onchange = loadDeploy;
$("#depset").onsubmit = async (e) => {
  e.preventDefault();
  try { await api("/api/deployments/settings", { method: "PUT", body: JSON.stringify({ queue_days: +e.target.queue_days.value, parallel: +e.target.parallel.value }) }); toast("Saved."); }
  catch (er) { toast(errText(er), true); }
};
function appTab(t) {
  $("#apptabs").querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.ptab === t));
  $("#deploypane").hidden = t !== "deploy"; $("#scriptspane").hidden = t !== "scripts"; $("#programspane").hidden = t !== "programs";
  if (t === "deploy") loadDeploy();
  if (t === "scripts") loadScripts();
}
$("#apptabs").querySelectorAll("button").forEach((b) => b.onclick = () => appTab(b.dataset.ptab));

let appRows = [];
loaders.apps = async () => {
  if (!$("#deploypane").hidden) return loadDeploy();
  if (!$("#scriptspane").hidden) return loadScripts();
  api("/api/deployments?status=queued,sending,running").then((d) => { $("#depbadge").textContent = d.rows.length ? ` ${d.rows.length}` : ""; }).catch(() => {});
  const r = await api("/api/apps");
  appRows = r.apps;
  const c = r.catalog || {};
  $("#appcat").innerHTML = c.updated ? `App catalog: ${esc(c.packages)} packages, downloaded ${fmtDate(c.updated)}` + (c.error ? ` · <span class="pill bad">${esc(c.error)}</span>` : "")
    : c.error ? `<span class="pill bad">App catalog download failed: ${esc(c.error)}</span>` : "App catalog not downloaded yet (Settings > App catalog).";
  renderApps();
};
function renderApps() {
  const show = $("#appshow").value;
  const rows = appRows.filter((a) => show === "all" || a.status === show).map((a) => ({ ...a, computers: a.installed, actions: "" }));
  table($("#apptable"), rows, ["name", "publisher", "computers", "outdated", "oldest", "newest", "latest_version", "catalog_id", "status", "actions"], {
    filterEl: $("#appf"), labels: { outdated: "behind", latest_version: "latest", catalog_id: "winget package" },
    cell: { status: swPill, outdated: (v) => (v ? `<span class="pill warn">${v}</span>` : "0"),
      name: (v, r) => `<a class="link" data-appname="${esc(v)}">${esc(v)}</a>`,
      actions: (_, r) => {
        const n = r.outdated - r.outdated_user;
        const upd = r.status === "outdated" && r.catalog_id && r.match_method !== "family" && n > 0
          ? `<button class="small" data-appupd="${esc(r.name)}">Update ${n}</button> ` : "";
        return `${upd}<a class="link small" data-apprule="${esc(r.name)}">rule</a>`;
      } } });
  const find = (n) => appRows.find((a) => a.name === n);
  $("#apptable").querySelectorAll("[data-appname]").forEach((a) => a.onclick = () => appComputers(a.dataset.appname));
  $("#apptable").querySelectorAll("[data-apprule]").forEach((a) => a.onclick = () => ruleModal(a.dataset.apprule));
  $("#apptable").querySelectorAll("[data-appupd]").forEach((b) => b.onclick = async () => {
    const a = find(b.dataset.appupd);
    const list = (await api(`/api/apps/computers?name=${encodeURIComponent(a.name)}&status=outdated`)).filter((x) => x.scope !== "user" && x.catalog_id === a.catalog_id);
    await appUpdate([...new Set(list.map((x) => x.hostname))], a.catalog_id, a.name);
  });
}
$("#appshow").onchange = renderApps;
async function appComputers(name) {
  const rows = await api(`/api/apps/computers?name=${encodeURIComponent(name)}`);
  const m = Object.assign(document.createElement("div"), { className: "modal" });
  m.innerHTML = `<div class="box wide"><h3>${esc(name)}</h3><div id="appc"></div><div class="row"><button class="ghost">Close</button></div></div>`;
  document.body.appendChild(m);
  table(m.querySelector("#appc"), rows, ["hostname", "version", "latest_version", "status", "scope"], { cell: { hostname: hostLink, status: swPill }, sort: "hostname" });
  m.querySelector("#appc").addEventListener("click", (e) => { if (e.target.dataset.host) m.remove(); });
  m.querySelector(".ghost").onclick = () => m.remove();
}
async function ruleModal(name = "") {
  const esc_re = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const f = await formModal(`<h3>App catalog rule</h3>
    <label>Programs whose name matches <input name="match" value="${esc(name ? `^${esc_re(name)}$` : "")}" placeholder="^Adobe Acrobat Reader"></label>
    <p class="muted small">A regular expression, not case sensitive. ^ and $ mean the whole name.</p>
    <label>Rule <select name="action"><option value="package">Use this winget package</option><option value="target">Treat this version as up to date</option><option value="ignore">Ignore (don't report as behind)</option></select></label>
    <label>Package id or version <input name="value" list="catpkgs" placeholder="Adobe.Acrobat.Reader.64-bit, or 8.0.4510"></label><datalist id="catpkgs"></datalist>
    <label>Note <input name="note" placeholder="optional, e.g. why"></label>`);
  if (!f) return;
  try { await post("/api/catalog/rules", f); toast("Rule saved. Statuses update in a few seconds."); setTimeout(() => { loaders.apps(); loadCatalog(); }, 3000); }
  catch (e) { toast(errText(e), true); }
}
document.addEventListener("input", async (e) => {   // package suggestions while typing in the rule form
  if (e.target.name !== "value" || !e.target.getAttribute("list") || e.target.value.length < 3) return;
  const sel = e.target.form.querySelector("[name=action]");
  if (sel.value !== "package") return;
  const r = await api(`/api/catalog/search?q=${encodeURIComponent(e.target.value)}`);
  $("#catpkgs").innerHTML = r.map((p) => `<option value="${esc(p.id)}">${esc(p.name)} ${esc(p.latest_version)}</option>`).join("");
});
const RULE_LABEL = { ignore: "ignore", package: "use package", target: "up to date from version" };
async function loadCatalog() {
  const c = await api("/api/catalog");
  $("#catinfo").innerHTML = c.updated ? `${esc(c.packages)} packages, downloaded ${fmtDate(c.updated)}; last matched ${fmtDate(c.reconciled)}.` : "Not downloaded yet.";
  if (c.error) $("#catinfo").innerHTML += ` <span class="pill bad">${esc(c.error)}</span>`;
  table($("#catrules"), c.rules.map((r) => ({ ...r, rule: `${RULE_LABEL[r.action]} ${r.value || ""}`, del: r.id })), ["match", "rule", "note", "created_by", "del"], {
    labels: { del: "" }, cell: { del: (id) => `<a class="link small" data-rdel="${id}">delete</a>` } });
  $("#catrules").querySelectorAll("[data-rdel]").forEach((a) => a.onclick = async () => {
    if (await confirmBox("Delete this rule?")) { await api(`/api/catalog/rules/${a.dataset.rdel}`, { method: "DELETE" }); setTimeout(loadCatalog, 1500); }
  });
  $("#rebootform")["fix:reboot_hour"].value = appSettings?.["fix:reboot_hour"] ?? 2;
}
$("#catrefresh").onclick = async () => { const r = await post("/api/catalog/refresh", {}); toast(r.output); setTimeout(loadCatalog, 15000); };
$("#catrule").onclick = () => ruleModal();
$("#rebootform").onsubmit = async (e) => {
  e.preventDefault();
  try { appSettings = await api("/api/settings", { method: "PUT", body: JSON.stringify(Object.fromEntries(new FormData(e.target))) }); toast("Saved."); }
  catch (er) { toast(errText(er), true); }
};

// ------------------------------------------------------------ small UI helpers: toast, prompt, confirm, scan banner
function toast(msg, bad = false) {
  const t = Object.assign(document.createElement("div"), { className: `toast ${bad ? "bad" : ""}`, textContent: msg });
  document.body.appendChild(t); setTimeout(() => t.remove(), 6000);
}
function modal(html) {
  return new Promise((resolve) => {
    const m = Object.assign(document.createElement("div"), { className: "modal" });
    m.innerHTML = `<form class="box">${html}<div class="row"><button type="submit">OK</button><button type="button" class="ghost">Cancel</button></div></form>`;
    document.body.appendChild(m);
    const done = (v) => { m.remove(); resolve(v); };
    m.querySelector(".ghost").onclick = () => done(null);
    m.querySelector("form").onsubmit = (e) => { e.preventDefault(); done(m.querySelector("input")?.value ?? true); };
    (m.querySelector("input") || m.querySelector("button")).focus();
  });
}
const ask = (label) => modal(`<label>${esc(label)}<input></label>`);
const confirmBox = (text) => modal(`<p>${esc(text)}</p>`);

const JOB_LABEL = { ad: "Active Directory", snmp: "switches", pcs: "PCs", pcs_updates: "PCs and Windows Update", dc_logons: "domain controller logs" };
let statusTimer;
// Header indicator for every scan (links to the Scanning view); the big banner only for scans started by hand.
async function pollStatus() {
  clearTimeout(statusTimer);
  try {
    const s = await api("/api/status");
    const b = $("#scanbanner"), ind = $("#scanind");
    const manual = s.running.filter((r) => !r.job.startsWith("job: "));
    const busy = s.running.length || s.queued;
    ind.hidden = !busy;
    if (busy) $("#scanindtext").textContent = `Scanning${s.running.length ? ` ${s.running.length}` : ""}${s.queued ? ` · ${s.queued} queued` : ""}`;
    ind.title = s.running.map((r) => r.job.replace(/^job: /, "")).join(", ") || "Jobs waiting for a free slot";
    if (manual.length) {
      const names = manual.map((r) => r.job.startsWith("rescan:") ? r.job.slice(7) : JOB_LABEL[r.job] || r.job);
      b.innerHTML = `<span class="spinner"></span><div><b>Scanning ${esc(names.join(", "))}…</b>
        <div class="muted">This can take a few minutes depending on the size of your network. Results appear as they come in.</div></div>
        <button class="ghost" id="scanview">Show progress</button><button class="ghost" id="refreshnow">Refresh</button>`;
      b.hidden = false;
      $("#refreshnow").onclick = refreshActive;
      $("#scanview").onclick = () => showTab("scanning");
      b.dataset.was = "1";
    } else {
      if (b.dataset.was) { b.dataset.was = ""; refreshActive(); }
      b.hidden = true;
    }
    statusTimer = setTimeout(pollStatus, busy ? 4000 : 15000);
  } catch { statusTimer = setTimeout(pollStatus, 30000); }
}
$("#scanind").onclick = () => showTab("scanning");
// keep status dots and uptime live without a manual refresh
setInterval(() => {
  if (document.hidden || document.querySelector(".modal")) return;
  const t = document.querySelector(".tab.active")?.id;
  if (t === "computers") loaders.computers();
}, 60000);

// ------------------------------------------------------------ Scanning view: running (with progress), queue, upcoming, recent
const dur = (sec) => sec == null ? "" : sec < 60 ? `${sec}s` : sec < 3600 ? `${Math.floor(sec / 60)}m ${String(sec % 60).padStart(2, "0")}s` : `${Math.floor(sec / 3600)}h ${String(Math.floor(sec % 3600 / 60)).padStart(2, "0")}m`;
const STEP_LABEL = { ad: "AD import", snmp: "IP ranges (SNMP + sweep)", pcs: "PC inventory", pcs_updates: "PC inventory + updates", dc_logons: "DC logons" };
let scanTimer;
loaders.scanning = async () => {
  clearTimeout(scanTimer);
  if (!$("#scanning").classList.contains("active")) return;
  let d;
  try { d = await api("/api/scanning"); } catch (e) { scanTimer = setTimeout(loaders.scanning, 10000); return; }
  $("#scancap").textContent = `At most ${d.max_concurrent} job${d.max_concurrent > 1 ? "s" : ""} at once (Settings, Scan schedule).`;
  $("#scanrunning").innerHTML = d.running.length ? d.running.map((r) => {
    const pct = r.total ? Math.round(100 * r.done / r.total) : null;
    const steps = r.steps.length > 1 ? `<div class="steps">${r.steps.map((st, i) => `<span class="${i + 1 < r.step_i ? "done" : i + 1 === r.step_i ? "now" : ""}">${esc(STEP_LABEL[st] || st)}</span>`).join("")}</div>` : "";
    const hosts = r.total ? `<b>${r.done}</b> of ${r.total} ${r.step === "dc_logons" ? "DCs" : "PCs"} done${r.failed ? `, <span class="bad">${r.failed} failed</span>` : ""} (${pct}%)` :
      `<span class="muted">${esc(STEP_LABEL[r.step] || r.step || "starting")}…</span>`;
    const cur = r.current.length ? `<div class="muted small">Now scanning: ${esc(r.current.join(", "))}${r.in_flight > r.current.length ? ` and ${r.in_flight - r.current.length} more` : ""}</div>` : "";
    return `<div class="runcard"><div class="top"><b>${esc(r.name)}</b>
        <span class="muted">${r.who ? `started by ${esc(r.who)}` : r.job_id ? "scheduled" : "scan now"} · running ${dur(r.elapsed)}${r.eta != null ? ` · about ${dur(r.eta)} left` : ""}</span>
        ${r.cancelling ? `<span class="pill warn">stopping…</span>` : ""}
        <span class="actions">${r.job_id && !r.cancelling ? `<button class="ghost" data-scancel="${r.job_id}">Cancel</button>` : ""}</span></div>
      ${steps}<div class="pbar ${pct == null ? "indet" : ""}"><i style="width:${pct ?? 0}%"></i></div>${hosts}${cur}</div>`;
  }).join("") : `<p class="muted">Nothing is scanning right now.</p>`;
  table($("#scanqueue"), d.queued.map((q) => ({ ...q, act: q.job_id })), ["position", "name", "waiting", "starts_in", "expected", "act"], {
    labels: { position: "#", waiting: "waiting for", starts_in: "should start", expected: "takes about", act: "" },
    cell: { waiting: (v) => dur(v), starts_in: (v) => v ? `in about ${dur(v)}` : "next free slot", expected: (v) => v ? dur(v) : "",
      act: (id, r) => `${r.position > 1 ? `<a class="link" data-sfront="${id}">Move to front</a> · ` : ""}<a class="link" data-scancel="${id}">Remove</a>` } });
  if (!d.queued.length) $("#scanqueue").innerHTML = `<p class="muted">The queue is empty.</p>`;
  table($("#scanupcoming"), d.upcoming, ["next_run", "name", "schedule", "expected"], { labels: { next_run: "starts", expected: "takes about" },
    cell: { next_run: fmtDate, expected: (v) => v ? dur(v) : "" } });
  if (!d.upcoming.length) $("#scanupcoming").innerHTML = `<p class="muted">No scheduled jobs. Add them in Settings, Scan schedule.</p>`;
  table($("#scanrecent"), d.recent, ["finished", "name", "seconds", "ok", "result"], { labels: { seconds: "took", ok: "" },
    cell: { finished: fmtDate, seconds: (v) => dur(v), name: (v) => esc(JOB_LABEL[v] ? `Scan now: ${JOB_LABEL[v]}` : String(v).replace(/^job: /, "")),
      ok: (v, r) => `<span class="pill ${r.cancelled ? "warn" : v ? "good" : "bad"}">${r.cancelled ? "cancelled" : v ? "ok" : "failed"}</span>`,
      result: (v) => `<span class="longtext small">${esc(v || "")}</span>` } });
  $("#scanning").querySelectorAll("[data-scancel]").forEach((a) => a.onclick = async () => {
    if (!(await confirmBox("Cancel this scan? PCs already being scanned finish; the rest are skipped until the next run."))) return;
    try { const r = await post(`/api/scanning/${a.dataset.scancel}/cancel`, {}); toast(r.output); } catch (e) { toast(errText(e), true); }
    loaders.scanning(); pollStatus();
  });
  $("#scanning").querySelectorAll("[data-sfront]").forEach((a) => a.onclick = async () => {
    try { const r = await post(`/api/scanning/${a.dataset.sfront}/front`, {}); toast(r.output); } catch (e) { toast(errText(e), true); }
    loaders.scanning();
  });
  scanTimer = setTimeout(loaders.scanning, d.running.length || d.queued.length ? 3000 : 15000);
};

// #asset/<pc> and #user/<name> deep links
function route(fallback) {
  const m = location.hash.match(/^#(asset|user)\/(.+)$/);
  if (m) return m[1] === "asset" ? openDevice(decodeURIComponent(m[2])) : openUser(decodeURIComponent(m[2]));
  showTab(fallback || document.querySelector("#tabs .active")?.dataset.tab || "computers");
}
const refreshActive = () => { const t = document.querySelector(".tab.active")?.id; t === "asset" ? openDevice(current) : t === "userpage" ? openUser(curUser) : loaders[t]?.(); };
window.addEventListener("popstate", () => route());

// ------------------------------------------------------------ DameWare Mini Remote Control (dameware:// handler on the tech PC)
let appSettings = null;
const getSettings = async () => (appSettings = appSettings || await api("/api/settings"));
async function dameware(host) {
  if (!host) return toast("No computer known for this user yet.", true);
  const s = await getSettings();
  toast(`Opening DameWare to ${host}… If nothing happens, install the NetInventory DameWare launcher on this PC.`);
  location.href = `dameware://connect/?host=${encodeURIComponent(host)}&mode=${s.dameware_mode === "saved" ? "saved" : "windows"}`;
}

// ------------------------------------------------------------ users list (AD users) + user page
const yesNo = (v, bad) => (v === null || v === undefined ? "" : `<span class="pill ${v ? (bad ? "bad" : "good") : "mute"}">${v ? "Yes" : "No"}</span>`);
const shortOu = (v) => `<span title="${esc(v)}">${esc((v || "").split(",")[0].replace("OU=", ""))}</span>`;
let userRows = [];
loaders.users = async () => {
  const r = await post("/api/query", { dataset: "v_users", sort: "username", limit: 50000 });
  userRows = r.rows; renderUsers();
};
function renderUsers() {
  const st = $("#ustate").value;
  const rows = userRows.filter((u) => !st || (st === "enabled" ? u.enabled : st === "disabled" ? !u.enabled : u.locked));
  table($("#utable"), rows, ["username", "display_name", "department", "title", "email", "ou", "enabled", "locked", "last_logon", "last_computer", "computer_count"], {
    filterEl: $("#ufilter"), labels: { computer_count: "PCs", last_computer: "last PC" },
    cell: { username: userLink, last_computer: hostLink, ou: shortOu, enabled: (v) => yesNo(v), locked: (v) => (v ? `<span class="pill bad">Locked</span>` : ""),
      last_logon: (v) => `${esc(fmtDate(v))} <span class="muted">${ago(v)}</span>` } });
}
$("#ustate").onchange = renderUsers;

let curUser = null, userData = null;
function showSection(id, tab) {
  $("#drawer").hidden = true;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === id));
}
async function openUser(user) {
  user = String(user).replace(/^.*\\/, "").toLowerCase();
  if (location.hash !== `#user/${encodeURIComponent(user)}`) history.pushState(null, "", `#user/${encodeURIComponent(user)}`);
  curUser = user;
  showSection("userpage", "users");
  const d = userData = await api(`/api/users/${encodeURIComponent(user)}`);
  const u = d.user;
  const state = !d.in_ad ? `<span class="pill mute">not in AD data</span>` : `${u.enabled ? `<span class="pill good">Enabled</span>` : `<span class="pill mute">Disabled</span>`}
    ${u.locked ? `<span class="pill bad">Locked out</span>` : ""}${u.password_never_expires ? ` <span class="pill warn">Password never expires</span>` : ""}`;
  $("#usertitle").innerHTML = `<div class="atitle"><span class="dot ${u.locked ? "bad" : u.enabled ? "good" : "warn"}"></span>${esc(u.display_name || u.username)}
    <span class="muted">${esc(u.domain ? u.domain + "\\" : "")}${esc(u.username)}</span></div>
    <div class="muted">${esc(u.title || "")}${u.department ? " · " + esc(u.department) : ""} ${state}</div>`;
  document.querySelectorAll("[data-uact]").forEach((b) => {
    const a = b.dataset.uact;
    b.hidden = (a === "unlock" && !u.locked) || (a === "enable" && (u.enabled || !d.in_ad)) || (a === "disable" && (!u.enabled || !d.in_ad))
      || (["reset_password", "must_change"].includes(a) && !d.in_ad) || (a === "copy_email" && !u.email) || (a === "copy_dn" && !d.dn);
  });
  renderUserTab($("#usertabs .active")?.dataset.utab || "general");
}
function renderUserTab(tab) {
  const d = userData, u = d.user, el = $("#userbody");
  $("#usertabs").querySelectorAll("button").forEach((b) => {
    b.classList.toggle("active", b.dataset.utab === tab);
    const n = { computers: d.computers.length, groups: d.groups.length, logons: d.logons.length, audit: d.audit.length }[b.dataset.utab];
    if (b.querySelector("i")) b.querySelector("i").textContent = n ? ` ${n}` : "";
  });
  if (tab === "general") {
    const pwdAge = u.password_last_set ? Math.floor((Date.now() - new Date(u.password_last_set.replace(" ", "T") + "Z")) / 864e5) : null;
    el.innerHTML = `<div class="ugrid">
      <div class="panel"><h3>General</h3>
        ${kvRow("Display name", esc(u.display_name))}${kvRow("First name", esc(u.first_name))}${kvRow("Last name", esc(u.last_name))}
        ${kvRow("Username", esc(u.username))}${kvRow("UPN", esc(u.upn))}${kvRow("E-mail", u.email ? `<a class="link" href="mailto:${esc(u.email)}">${esc(u.email)}</a>` : "")}
        ${kvRow("Telephone", esc(u.phone))}${kvRow("Mobile", esc(u.mobile))}${kvRow("Description", esc(u.description))}
        <h3>Organization</h3>
        ${kvRow("Title", esc(u.title))}${kvRow("Department", esc(u.department))}${kvRow("Company", esc(u.company))}
        ${kvRow("Office", esc(u.office))}${kvRow("Manager", esc(u.manager))}
      </div>
      <div class="panel"><h3>Account</h3>
        ${kvRow("Enabled", yesNo(u.enabled))}${kvRow("Locked out", yesNo(u.locked, true))}${kvRow("Bad passwords", u.bad_pwd_count ?? "")}
        ${kvRow("Password set", u.password_last_set ? `${fmtDate(u.password_last_set)} <span class="muted">${pwdAge} days ago</span>` : "")}
        ${kvRow("Never expires", yesNo(u.password_never_expires, true))}
        ${kvRow("Last logon", u.last_logon ? `${fmtDate(u.last_logon)} <span class="muted">${ago(u.last_logon)}</span>` : "")}
        ${kvRow("Created", fmtDate(u.created))}${kvRow("Changed", fmtDate(u.changed))}
        <h3>Directory</h3>
        ${kvRow("OU", esc(u.ou))}${kvRow("Logon script", esc(u.logon_script))}${kvRow("Home folder", esc(u.home_directory))}${kvRow("SID", `<span class="small">${esc(u.sid)}</span>`)}
      </div>
      <div class="panel"><h3>Last computer</h3>
        ${d.computers[0] ? `${kvRow("Computer", hostLink(d.computers[0].hostname))}${kvRow("Logged on", `${fmtDate(d.computers[0].last_logon)} <span class="muted">${ago(d.computers[0].last_logon)}</span>`)}
          ${kvRow("OS", esc((d.computers[0].os || "").replace("Microsoft ", "") + " " + (d.computers[0].os_display_version || "")))}${kvRow("IP", esc(d.computers[0].ip))}
          ${kvRow("Switch port", d.computers[0].switch_name ? `<b>${esc(d.computers[0].switch_name)}</b> ${esc(d.computers[0].switch_port)}` : "")}
          <div class="row" style="margin-top:8px"><button data-dw="${esc(d.computers[0].hostname)}">Remote control</button></div>` : `<p class="muted">No logons seen yet.</p>`}
        <h3>Groups</h3><div class="chips">${d.groups.slice(0, 12).map((g) => `<span class="chip">${esc(g.name)}</span>`).join("") || `<span class="muted">None</span>`}</div>
      </div></div>`;
  } else if (tab === "computers") {
    el.innerHTML = `<p class="muted">Computers this user logged on to, newest first (from DC and PC logon events).</p><div id="ucomp"></div>`;
    table($("#ucomp"), d.computers.map((c) => ({ ...c, remote: c.hostname })), ["hostname", "last_logon", "logon_count", "os", "os_display_version", "ip", "switch_name", "switch_port", "remote"], {
      labels: { os_display_version: "version", remote: "" },
      cell: { hostname: hostLink, os: (v) => esc((v || "").replace("Microsoft ", "")), remote: (v) => `<a class="link" data-dw="${esc(v)}">Remote</a>`,
        last_logon: (v) => `${esc(fmtDate(v))} <span class="muted">${ago(v)}</span>` } });
  } else if (tab === "groups") {
    el.innerHTML = `<div id="ugroups"></div>`;
    table($("#ugroups"), d.groups, ["name", "type"], { sort: "name" });
  } else if (tab === "logons") {
    el.innerHTML = `<div id="ulogons"></div>`;
    table($("#ulogons"), d.logons, ["time", "hostname", "logon_type", "ip", "source"], { cell: { hostname: hostLink,
      logon_type: (t) => ({ 0: "Kerberos (DC)", 2: "Interactive", 3: "Network", 10: "Remote desktop", 11: "Cached" }[t] ?? esc(t)) } });
  } else if (tab === "audit") {
    el.innerHTML = `<p class="muted">Actions taken on this account from NetInventory.</p><div id="uaudit"></div>`;
    table($("#uaudit"), d.audit, ["time", "actor", "action", "result"], { cell: { result: (v) => `<span class="longtext ${/^Failed/.test(v || "") ? "pill bad" : ""}">${esc(v)}</span>` } });
  }
  el.querySelectorAll("[data-dw]").forEach((b) => b.onclick = () => dameware(b.dataset.dw));
}
$("#usertabs").querySelectorAll("button").forEach((b) => b.onclick = () => renderUserTab(b.dataset.utab));
document.querySelectorAll("[data-uact]").forEach((b) => b.onclick = async () => {
  const a = b.dataset.uact, d = userData, u = d.user, last = d.computers[0]?.hostname || u.last_computer;
  if (a === "back") return showTab("users");
  if (a === "remote") return dameware(last);
  if (a === "rdp") { if (!last) return toast("No computer known for this user yet.", true); location.href = `/api/devices/${encodeURIComponent(last)}/rdp`; return; }
  if (a === "copy_email" || a === "copy_dn") {
    const v = a === "copy_email" ? u.email : d.dn;
    try { await navigator.clipboard.writeText(v); toast(`Copied ${v}`); } catch { toast(v); }
    return;
  }
  let body = {};
  if (a === "reset_password") {
    const f = await formModal(`<h3>Reset password for ${esc(u.display_name || u.username)}</h3>
      <label>New password<input name="password" type="password" autocomplete="new-password" required minlength="8"></label>
      <label>Confirm<input name="confirm" type="password" autocomplete="new-password" required></label>
      <label class="chk"><input type="checkbox" name="must_change" checked> User must change password at next logon</label>
      <p class="hint">Needs LDAPS (636) on the domain controller and a credential allowed to reset passwords.</p>`);
    if (!f) return;
    if (f.password !== f.confirm) return toast("The passwords don't match.", true);
    body = { password: f.password, must_change: !!f.must_change };
  } else {
    const q = { unlock: `Unlock ${u.username}?`, must_change: `Make ${u.username} change their password at next logon?`,
      enable: `Enable the account ${u.username}?`, disable: `Disable the account ${u.username}? They will be signed out of new sessions and can't log on.` }[a];
    if (!(await confirmBox(q))) return;
  }
  b.disabled = true;
  try { const r = await post(`/api/users/${encodeURIComponent(curUser)}/action/${a}`, body); toast(r.output, !r.ok); openUser(curUser); }
  catch (e) { toast(e.message, true); }
  b.disabled = false;
});
// a modal with a form; resolves to {name: value} (checkboxes true/false) or null
function formModal(html, wide = false, init = null) {
  return new Promise((resolve) => {
    const m = Object.assign(document.createElement("div"), { className: "modal" });
    m.innerHTML = `<form class="box ${wide ? "wide" : ""}">${html}<div class="row"><button type="submit">OK</button><button type="button" class="ghost">Cancel</button></div></form>`;
    document.body.appendChild(m);
    const form = m.querySelector("form");
    const done = (v) => { m.remove(); resolve(v); };
    m.querySelector(".ghost").onclick = () => done(null);
    form.onsubmit = (e) => {
      e.preventDefault();
      const out = {};
      form.querySelectorAll("input, select, textarea").forEach((i) => {
        if (!i.name) return;
        if (i.type === "checkbox") { if (i.dataset.multi) { (out[i.name] = out[i.name] || []); if (i.checked) out[i.name].push(i.value); } else out[i.name] = i.checked; }
        else out[i.name] = i.value;
      });
      done(out);
    };
    if (init) init(form);
    form.querySelector("input:not([type=checkbox]), select")?.focus();
  });
}

// ------------------------------------------------------------ port map / network
loaders.portmap = async () => {
  const r = await post("/api/query", { dataset: "v_port_map", fields: ["switch_name", "port", "port_alias", "vlan", "hostname", "ip", "mac", "last_seen"], sort: "switch_name", limit: 50000 });
  table($("#pmtable"), r.rows, r.columns, { filterEl: $("#pmfilter"), cell: { hostname: hostLink } });
};
loaders.network = async () => {
  const [dc, nd, sp] = await Promise.all([post("/api/query", { dataset: "v_domain_controllers" }), post("/api/query", { dataset: "v_network_devices" }),
    post("/api/query", { dataset: "v_switch_ports", sort: "switch_name", limit: 50000 })]);
  table($("#dctable"), dc.rows, ["hostname", "os", "site", "is_gc", "fsmo_roles", "last_seen"]);
  table($("#ndtable"), nd.rows, ["sysname", "ip", "vendor", "location", "port_count", "uptime_s", "last_polled", "poll_error"],
    { cell: { uptime_s: (v) => (v ? `${Math.floor(v / 86400)} days` : "") }, labels: { uptime_s: "uptime" } });
  table($("#sptable"), sp.rows, ["switch_name", "port", "alias", "oper_up", "speed_mbps", "is_uplink", "neighbor", "devices_on_port"],
    { filterEl: $("#spfilter"), cell: { oper_up: (v) => `<span class="pill ${v ? "good" : "mute"}">${v ? "up" : "down"}</span>`,
      is_uplink: (v) => (v ? `<span class="pill mute">uplink</span>` : "") } });
};

// ------------------------------------------------------------ report builder
let datasets = [];
const OPS = [["eq", "equals"], ["ne", "not equal"], ["contains", "contains"], ["not_contains", "doesn't contain"],
  ["lt", "<"], ["le", "≤"], ["gt", ">"], ["ge", "≥"], ["empty", "is empty"], ["not_empty", "is not empty"]];
loaders.reports = async () => {
  loadLibrary();
  if (!datasets.length) {
    datasets = await api("/api/datasets");
    $("#dataset").innerHTML = datasets.map((d) => `<option value="${d.name}">${esc(d.label)}</option>`).join("");
    $("#dataset").onchange = () => setSpec({ dataset: $("#dataset").value });
    setSpec({ dataset: "v_devices", fields: ["hostname", "os", "last_user", "switch_port", "c_free_gb"] });
  }
  const reps = await api("/api/reports");
  $("#reportlist").innerHTML = reps.map((r) => `<li data-id="${r.id}"><span>${esc(r.name)}</span>${r.builtin ? "" : `<span class="x" data-del="${r.id}">×</span>`}</li>`).join("");
  $("#reportlist").querySelectorAll("li").forEach((li) => li.onclick = (e) => {
    const r = reps.find((x) => x.id === li.dataset.id);
    if (e.target.dataset.del) { api(`/api/reports/${r.id}`, { method: "DELETE" }).then(loaders.reports); return; }
    setSpec(r.spec); $("#rname").value = r.builtin ? "" : r.name; runReport();
  });
};
const cols = () => datasets.find((d) => d.name === $("#dataset").value)?.columns || [];
function setSpec(spec) {
  $("#dataset").value = spec.dataset;
  const c = cols(), sel = spec.fields?.length ? spec.fields : c;
  $("#fields").innerHTML = c.map((f) => `<label><input type="checkbox" value="${f}" ${sel.includes(f) ? "checked" : ""}> ${f}</label>`).join("");
  $("#sort").innerHTML = `<option value="">(none)</option>` + c.map((f) => `<option ${spec.sort === f ? "selected" : ""}>${f}</option>`).join("");
  $("#desc").checked = !!spec.desc;
  $("#filters").innerHTML = "";
  (spec.filters || []).forEach(addFilter);
  $("#result").innerHTML = "";
}
function addFilter(f = {}) {
  const row = document.createElement("div");
  row.className = "filter";
  row.innerHTML = `<select class="ff">${cols().map((c) => `<option ${f.field === c ? "selected" : ""}>${c}</option>`).join("")}</select>
    <select class="fo">${OPS.map(([k, l]) => `<option value="${k}" ${f.op === k ? "selected" : ""}>${l}</option>`).join("")}</select>
    <input class="fv" value="${esc(f.value ?? "")}" placeholder="value"><button class="ghost">×</button>`;
  row.querySelector("button").onclick = () => row.remove();
  $("#filters").appendChild(row);
}
$("#addfilter").onclick = () => addFilter();
const spec = () => ({
  dataset: $("#dataset").value,
  fields: [...document.querySelectorAll("#fields input:checked")].map((i) => i.value),
  filters: [...document.querySelectorAll(".filter")].map((r) => ({ field: $(".ff", r).value, op: $(".fo", r).value, value: $(".fv", r).value })),
  sort: $("#sort").value || null, desc: $("#desc").checked, limit: 5000,
});
async function runReport() {
  try {
    const r = await post("/api/query", spec());
    table($("#result"), r.rows, r.columns, { cell: { hostname: hostLink, username: userLink } });
  } catch (e) { $("#result").innerHTML = `<p class="pill bad">${esc(e.message)}</p>`; }
}
$("#run").onclick = runReport;
$("#csv").onclick = () => download("/api/export/csv", spec());
$("#xlsx").onclick = () => download("/api/export/xlsx", spec());
$("#save").onclick = async () => {
  const name = $("#rname").value.trim();
  if (!name) { $("#rname").focus(); return; }
  await post("/api/reports", { name, spec: spec() }); loaders.reports();
};

// ------------------------------------------------------------ standard report library
let library = [], libCurrent = null;
document.querySelectorAll("#reptabs button").forEach((b) => b.onclick = () => repTab(b.dataset.rtab));
function repTab(t) {
  document.querySelectorAll("#reptabs button").forEach((b) => b.classList.toggle("active", b.dataset.rtab === t));
  $("#replib").hidden = t !== "library"; $("#repbuilder").hidden = t !== "builder";
}
async function loadLibrary() {
  if (!library.length) library = await api("/api/library");
  const f = $("#libfilter").value.toLowerCase();
  const cats = [...new Set(library.map((r) => r.category))];
  $("#libcats").innerHTML = cats.map((c) => {
    const items = library.filter((r) => r.category === c && (!f || (r.name + " " + c).toLowerCase().includes(f)));
    return items.length ? `<h3>${esc(c)}</h3><ul>${items.map((r) => `<li data-lib="${r.id}" class="${r.id === libCurrent ? "active" : ""}"><span>${esc(r.name)}</span></li>`).join("")}</ul>` : "";
  }).join("") || `<p class="muted">No report matches.</p>`;
  $("#libcats").querySelectorAll("[data-lib]").forEach((li) => li.onclick = () => runLibrary(li.dataset.lib));
}
$("#libfilter").oninput = loadLibrary;
async function runLibrary(id) {
  libCurrent = id; loadLibrary();
  const meta = library.find((r) => r.id === id);
  $("#libtitle").innerHTML = `<div class="libbar"><b>${esc(meta.name)}</b><span class="muted">${esc(meta.category)}</span></div>`;
  $("#libresult").innerHTML = `<p class="muted">Running…</p>`;
  try {
    const r = await api(`/api/library/${id}`);
    $("#libtitle").innerHTML = `<div class="libbar"><b>${esc(meta.name)}</b><span class="muted">${r.rows.length} row${r.rows.length === 1 ? "" : "s"}</span>
      ${exportLinks(`/api/library/${id}/export`)}${meta.kind === "spec" ? ` <button class="ghost" id="tobuilder">Open in report builder</button>` : ""}</div>`;
    table($("#libresult"), r.rows, r.columns, { cell: LINKS });
    if ($("#tobuilder")) $("#tobuilder").onclick = async () => { repTab("builder"); await loaders.reports(); setSpec(meta.spec); $("#rname").value = ""; runReport(); };
  } catch (e) { $("#libresult").innerHTML = `<p class="pill bad">${esc(e.message)}</p>`; }
}

// ------------------------------------------------------------ settings: credentials, scan targets, schedule, DameWare
const KIND = { windows: "Windows / AD (LDAP + WinRM)", snmp2: "SNMP v2c", snmp3: "SNMP v3" };
const IPM = { ping: "Ping sweep: find which addresses are up, and mark known PCs online or offline",
  snmp: "SNMP: poll switches and routers (needs an SNMP credential)",
  winrm: "WinRM sweep: find Windows PCs on port 5985 for the PC inventory (needs a Windows credential)" };
const IPM_SHORT = { ping: "ping", snmp: "SNMP", winrm: "WinRM sweep" };
const TKIND = { ad_domain: "Whole AD domain", ad_computer_path: "AD OU of computers", ad_user_path: "AD OU of users", ip_range: "IP range" };
const THELP = {
  ad_domain: ["corp.example.com", "The whole domain: tick below whether to read its computers, its users or both. Domain controllers are always read. To scan only part of AD, pick an OU instead."],
  ad_computer_path: ["corp.example.com/Sites/Office/PCs", "Only computers in this OU and the OUs below it are imported and scanned over WinRM. No users are read. Type the path as Active Directory Users and Computers shows it (domain/OU/OU), or a DN like OU=PCs,OU=Office,OU=Sites,DC=corp,DC=example,DC=com."],
  ad_user_path: ["corp.example.com/Staff/Office", "Only user accounts in this OU and the OUs below it are imported. No computers are read. Path as domain/OU/OU, or a DN like OU=Office,OU=Staff,DC=corp,DC=example,DC=com."],
  ip_range: ["10.0.0.0/24, 10.1.0.1-10.1.0.50", "Tick below what runs on these addresses. Only the ticked methods run, and each needs its credential."],
};
let creds = [];
loaders.settings = async () => {
  loadUpdate(); loadAuth(); loadExclusions(); loadTls(); loadAgents();
  const [c, t, s] = await Promise.all([api("/api/credentials"), api("/api/targets"), api("/api/settings")]);
  creds = c; appSettings = s; loadCatalog();
  table($("#credtable"), c.map((x) => ({ ...x, secret: x.has_secret, edit: x.id })), ["name", "kind", "username", "secret", "edit"], {
    labels: { edit: "" }, cell: { kind: (v) => esc(KIND[v] || v), secret: (v) => (v ? `<span class="pill good">stored</span>` : `<span class="pill warn">missing</span>`),
      edit: (id) => `<a class="link" data-cedit="${id}">Edit</a> · <a class="link" data-ctest="${id}">Test</a> · <a class="link" data-cdel="${id}">Delete</a>` } });
  table($("#targettable"), t.map((x) => ({ ...x, credentials: x.credential_ids, edit: x.id })), ["kind", "value", "search_base", "server", "credentials", "enabled", "last_run", "last_result", "edit"], {
    labels: { edit: "", last_result: "result", search_base: "searches" },
    cell: { kind: (v, r) => esc(TKIND[v] || v) + (r.collect ? `<div class="muted small">${esc(r.collect.map((m) => IPM_SHORT[m] || m).join(r.kind === "ip_range" ? ", " : " and "))}</div>` : ""),
      search_base: (v, r) => r.scope_error ? `<span class="pill bad longtext">${esc(r.scope_error)}</span>` : v ? `<code class="small">${esc(v)}</code>` : r.kind === "ip_range" ? `<span class="muted">addresses</span>` : "", credentials: (ids) => esc(ids.map((i) => creds.find((c) => c.id === i)?.name || `#${i}`).join(", ") || "none"),
      enabled: (v) => yesNo(v), last_run: fmtDate,
      // Full text, wrapped: errors are only useful whole. A run that worked but reached no Windows hosts is a warning.
      last_result: (v, r) => (v ? `<span class="pill longtext ${!r.last_ok ? "bad" : /(^|[;:] )0 hosts answer on WinRM/.test(v) ? "warn" : "good"}">${esc(v)}</span>` : ""),
      edit: (id) => `<a class="link" data-tscan="${id}">Scan now</a> · <a class="link" data-tedit="${id}">Edit</a> · <a class="link" data-tdel="${id}">Delete</a>` } });
  $("#credtable").querySelectorAll("[data-cedit]").forEach((a) => a.onclick = () => editCred(c.find((x) => x.id === +a.dataset.cedit)));
  $("#credtable").querySelectorAll("[data-cdel]").forEach((a) => a.onclick = async () => {
    const x = c.find((y) => y.id === +a.dataset.cdel);
    if (await confirmBox(`Delete the credential “${x.name}”? Scan targets using it will skip it.`)) { await api(`/api/credentials/${x.id}`, { method: "DELETE" }); loaders.settings(); }
  });
  $("#credtable").querySelectorAll("[data-ctest]").forEach((a) => a.onclick = async () => {
    const x = c.find((y) => y.id === +a.dataset.ctest);
    const host = await ask(x.kind === "windows" ? "Test against which domain controller or PC?" : "Test against which switch or router (IP or name)?");
    if (!host) return;
    toast(`Testing ${x.name} against ${host}…`);
    try { const r = await post(`/api/credentials/${x.id}/test`, { host }); toast(r.output, !r.ok); } catch (e) { toast(e.message, true); }
  });
  $("#targettable").querySelectorAll("[data-tedit]").forEach((a) => a.onclick = () => editTarget(t.find((x) => x.id === +a.dataset.tedit)));
  $("#targettable").querySelectorAll("[data-tdel]").forEach((a) => a.onclick = async () => {
    const x = t.find((y) => y.id === +a.dataset.tdel);
    if (await confirmBox(`Stop scanning ${TKIND[x.kind]} ${x.value}? Data already collected is kept.`)) { await api(`/api/targets/${x.id}`, { method: "DELETE" }); loaders.settings(); }
  });
  $("#targettable").querySelectorAll("[data-tscan]").forEach((a) => a.onclick = async () => { await post(`/api/targets/${a.dataset.tscan}/scan`, {}); toast("Scan started."); setTimeout(pollStatus, 500); });
  loadJobs(t);
  $("#dwform").dameware_mode.value = s.dameware_mode;
};
const kick = () => document.querySelector(".modal [name=kind]")?.dispatchEvent(new Event("change", { bubbles: true }));
async function editCred(x = {}) {
  const pending = formModal(`<h3>${x.id ? "Edit" : "Add"} credential</h3>
    <label>Name<input name="name" required value="${esc(x.name || "")}" placeholder="for example CORP scan account"></label>
    <label>Type<select name="kind">${Object.entries(KIND).map(([k, l]) => `<option value="${k}" ${x.kind === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
    <label class="cu">Username<input name="username" value="${esc(x.username || "")}" placeholder="CORP\\svc-netinv"></label>
    <label class="cs">Password<input name="secret" type="password" autocomplete="new-password" placeholder="${x.has_secret ? "leave blank to keep the stored one" : ""}"></label>
    <label class="cs2">Privacy key (AES)<input name="secret2" type="password" autocomplete="new-password" placeholder="${x.has_secret2 ? "leave blank to keep the stored one" : ""}"></label>
    <p class="hint">Stored encrypted on the server. It is never sent back to the browser.</p>`, true);
  kick();
  const f = await pending;
  if (!f) return;
  try { await post(`/api/credentials${x.id ? `?cid=${x.id}` : ""}`, f); toast("Credential saved."); loaders.settings(); } catch (e) { toast(e.message, true); }
}
// relabel credential fields to match the type while the modal is open
document.addEventListener("change", (e) => {
  if (e.target.name !== "kind" || !e.target.closest(".modal")) return;
  const m = e.target.closest(".modal"), k = e.target.value;
  if (!m.querySelector(".cu")) return;
  m.querySelector(".cu").firstChild.textContent = k === "snmp2" ? "(not used)" : k === "snmp3" ? "SNMPv3 user" : "Username";
  m.querySelector(".cs").firstChild.textContent = k === "snmp2" ? "Community" : k === "snmp3" ? "Auth key (SHA)" : "Password";
  m.querySelector(".cs2").hidden = k !== "snmp3";
});
async function editTarget(x = {}) {
  const kind = x.kind || "ad_domain";
  const pending = formModal(`<h3>${x.id ? "Edit" : "Add"} scan target</h3>
    <label>Scan<select name="kind" id="tkind">${Object.entries(TKIND).map(([k, l]) => `<option value="${k}" ${kind === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
    <label>Value<input name="value" required value="${esc(x.value || "")}" id="tvalue" placeholder="${esc(THELP[kind][0])}"></label>
    <p class="hint" id="thelp">${esc(THELP[kind][1])}</p>
    <div id="tcollect" class="checks" ${kind === "ad_domain" ? "" : "hidden"}><span class="muted">Read from the domain:</span>
      <label><input type="checkbox" data-multi="1" name="collect" value="computers" ${!x.collect || x.collect.includes("computers") ? "checked" : ""}> Computers (and scan them over WinRM)</label>
      <label><input type="checkbox" data-multi="1" name="collect" value="users" ${!x.collect || x.collect.includes("users") ? "checked" : ""}> User accounts and groups</label></div>
    <div id="tmethods" class="checks" ${kind === "ip_range" ? "" : "hidden"}><span class="muted">On these addresses, run:</span>
      ${Object.entries(IPM).map(([k, l]) => `<label><input type="checkbox" data-multi="1" name="methods" value="${k}" ${!x.collect || x.kind !== "ip_range" || x.collect.includes(k) ? "checked" : ""}> ${l}</label>`).join("")}</div>
    <label id="tserver">Domain controller (optional)<input name="server" value="${esc(x.server || "")}" placeholder="dc01.corp.example.com, blank = find one"></label>
    <label>Credentials to try, in order</label>
    <div class="checks">${creds.map((c) => `<label><input type="checkbox" data-multi="1" name="credential_ids" value="${c.id}" ${(x.credential_ids || []).includes(c.id) ? "checked" : ""}> ${esc(c.name)} <span class="muted">${esc(KIND[c.kind])}</span></label>`).join("") || `<span class="muted">Add a credential first.</span>`}</div>
    <label class="chk"><input type="checkbox" name="enabled" ${x.enabled === false ? "" : "checked"}> Enabled</label>`, true);
  kick();
  const f = await pending;
  if (!f) return;
  f.credential_ids = (f.credential_ids || []).map(Number);
  if (f.kind === "ip_range") f.collect = f.methods;
  else if (f.kind !== "ad_domain") delete f.collect;
  delete f.methods;
  try { await post(`/api/targets${x.id ? `?tid=${x.id}` : ""}`, f); toast("Scan target saved."); loaders.settings(); } catch (e) { toast(errText(e), true); }
}
document.addEventListener("change", (e) => {
  if (e.target.id !== "tkind") return;
  const k = e.target.value;
  $("#tvalue").placeholder = THELP[k][0]; $("#thelp").textContent = THELP[k][1]; $("#tserver").hidden = k === "ip_range"; $("#tcollect").hidden = k !== "ad_domain"; $("#tmethods").hidden = k !== "ip_range";
});
const errText = (e) => { try { return JSON.parse(e.message).detail || e.message; } catch { return e.message; } };
$("#addcred").onclick = () => editCred();
$("#addtarget").onclick = () => editTarget();
$("#scanall").onclick = async () => { await post("/api/scan/all", {}); toast("Full scan started."); setTimeout(pollStatus, 500); };
// ------------------------------------------------------------ scan schedule (jobs)
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
let jobData = { jobs: [], collectors: {} }, jobTargets = [];
async function loadJobs(targets) {
  if (targets) jobTargets = targets;
  jobData = await api("/api/jobs");
  $("#jobcap").max_concurrent.value = jobData.max_concurrent;
  $("#jobcap").reach_interval.value = jobData.reach_interval;
  const stateCell = (v, r) => r.state ? `<span class="pill warn">${r.state}</span>` : !r.enabled ? `<span class="pill mute">off</span>` : fmtDate(r.next_run);
  table($("#jobtable"), jobData.jobs.map((j) => ({ ...j, what: j.collectors.map((c) => JOB_LABEL[c] || c).join(", "), next: j.id, act: j.id })),
    ["name", "scope", "what", "schedule", "next", "last_run", "last_result", "act"], {
      labels: { what: "scans", next: "next run", last_result: "result", act: "" },
      cell: { next: stateCell, last_run: (v, r) => v ? `${fmtDate(v)}${r.last_seconds != null ? ` <span class="muted small">(${Math.round(r.last_seconds / 60)} min)</span>` : ""}` : "never",
        last_result: (v, r) => v ? `<span class="pill longtext ${r.last_ok ? "good" : "bad"}">${esc(v)}</span>` : "",
        act: (id) => `<a class="link" data-jrun="${id}">Run now</a> · <a class="link" data-jhist="${id}">History</a> · <a class="link" data-jedit="${id}">Edit</a> · <a class="link" data-jdel="${id}">Delete</a>` } });
  const byId = (a, k) => jobData.jobs.find((j) => j.id === +a.dataset[k]);
  $("#jobtable").querySelectorAll("[data-jrun]").forEach((a) => a.onclick = async () => {
    try { const r = await post(`/api/jobs/${a.dataset.jrun}/run`, {}); toast(r.output); setTimeout(() => { loadJobs(); pollStatus(); }, 1000); } catch (e) { toast(errText(e), true); }
  });
  $("#jobtable").querySelectorAll("[data-jedit]").forEach((a) => a.onclick = () => editJob(byId(a, "jedit")));
  $("#jobtable").querySelectorAll("[data-jdel]").forEach((a) => a.onclick = async () => {
    const j = byId(a, "jdel");
    if (await confirmBox(`Delete the scan job "${j.name}"? Data already collected is kept.`)) { await api(`/api/jobs/${j.id}`, { method: "DELETE" }); loadJobs(); }
  });
  $("#jobtable").querySelectorAll("[data-jhist]").forEach((a) => a.onclick = async () => {
    const j = byId(a, "jhist"), h = await api(`/api/jobs/${j.id}/history`);
    drawer(`<h2>${esc(j.name)}</h2><p class="muted">${esc(j.schedule)} · ${esc(j.scope)}</p><div id="jobhist"></div>`);
    table($("#jobhist"), h, ["started", "seconds", "ok", "result"], { labels: { seconds: "took (s)" },
      cell: { ok: (v) => `<span class="pill ${v ? "good" : v === false ? "bad" : "mute"}">${v ? "ok" : v === false ? "failed" : "running"}</span>`,
        result: (v) => `<span class="longtext">${esc(v || "")}</span>` } });
  });
}
async function editJob(j = null) {
  const v = j || { name: "", enabled: true, target_ids: [], collectors: ["ad", "pcs"], every_min: 30, at_time: null, days: "0123456", window_start: null, window_end: null, max_parallel: null };
  const mode = v.at_time ? "daily" : v.every_min ? "every" : "manual";
  const f = await formModal(`<h3>${j ? "Edit" : "New"} scan job</h3>
    <label>Name <input name="name" value="${esc(v.name)}" placeholder="Front office PCs, every 30 minutes" required></label>
    <fieldset><legend>Scan these targets <span class="muted small">(none ticked = all targets)</span></legend>
      ${jobTargets.length ? jobTargets.map((t) => `<label class="check"><input type="checkbox" data-multi="1" name="t" value="${t.id}" ${v.target_ids.includes(t.id) ? "checked" : ""}> ${esc(TKIND[t.kind] || t.kind)}: ${esc(t.value)}</label>`).join("")
        : `<p class="muted small">No scan targets yet: add them under "What to scan".</p>`}
      <p class="muted small">To scan one OU on its own schedule, add it under "What to scan" as an OU of computers, then pick it here.</p></fieldset>
    <fieldset><legend>Collect</legend>
      ${Object.entries(jobData.collectors).map(([k, l]) => `<label class="check"><input type="checkbox" data-multi="1" name="c" value="${k}" ${v.collectors.includes(k) ? "checked" : ""}> ${esc(l)}</label>`).join("")}</fieldset>
    <fieldset><legend>On IP ranges, run <span class="muted small">(none ticked = what each range has ticked)</span></legend>
      ${Object.entries(IPM_SHORT).map(([k, l]) => `<label class="check"><input type="checkbox" data-multi="1" name="ipm" value="${k}" ${(v.ip_methods || []).includes(k) ? "checked" : ""}> ${l}</label>`).join("")}
      <p class="muted small">Applies when this job scans IP ranges. A method also needs to be ticked on the range itself.</p></fieldset>
    <fieldset><legend>When</legend>
      <label>Run <select name="mode"><option value="every" ${mode === "every" ? "selected" : ""}>repeatedly</option><option value="daily" ${mode === "daily" ? "selected" : ""}>once a day</option><option value="manual" ${mode === "manual" ? "selected" : ""}>only when started by hand</option></select></label>
      <label class="m-every">Every <input name="every_n" type="number" min="1" value="${v.every_min ? (v.every_min % 60 === 0 ? v.every_min / 60 : v.every_min) : 30}" style="width:5em">
        <select name="every_u"><option value="1" ${v.every_min && v.every_min % 60 ? "selected" : ""}>minutes</option><option value="60" ${v.every_min && v.every_min % 60 === 0 ? "selected" : ""}>hours</option></select></label>
      <label class="m-daily">At <input name="at_time" type="time" value="${esc(v.at_time || "02:00")}"></label>
      <div class="days">${DAYS.map((d, i) => `<label class="check"><input type="checkbox" data-multi="1" name="d" value="${i}" ${v.days.includes(String(i)) ? "checked" : ""}> ${d}</label>`).join("")}</div>
      <label class="m-every">Only between <input name="window_start" type="number" min="0" max="23" placeholder="any" value="${v.window_start ?? ""}" style="width:4em">:00 and
        <input name="window_end" type="number" min="0" max="23" placeholder="any" value="${v.window_end ?? ""}" style="width:4em">:00 <span class="muted small">(server time; 18 and 6 means overnight)</span></label></fieldset>
    <label>PCs scanned at once over WinRM <input name="max_parallel" type="number" min="1" max="64" placeholder="16" value="${v.max_parallel ?? ""}" style="width:5em"></label>
    <label class="check"><input type="checkbox" name="enabled" ${v.enabled ? "checked" : ""}> Enabled</label>`, true, (form) => {
      const sync = () => { const m = form.mode.value; form.querySelectorAll(".m-every").forEach((e) => e.hidden = m !== "every"); form.querySelectorAll(".m-daily").forEach((e) => e.hidden = m !== "daily"); };
      form.mode.onchange = sync; sync();
    });
  if (!f) return;
  const num = (x) => (x === "" || x == null ? null : +x);
  const body = { name: f.name, enabled: f.enabled, target_ids: f.t.map(Number), collectors: f.c, days: f.d.join(""),
    every_min: f.mode === "every" ? (+f.every_n) * (+f.every_u) : null, at_time: f.mode === "daily" ? f.at_time : null,
    window_start: f.mode === "every" ? num(f.window_start) : null, window_end: f.mode === "every" ? num(f.window_end) : null, max_parallel: num(f.max_parallel), ip_methods: f.ipm };
  try { await post(`/api/jobs${j ? `?jid=${j.id}` : ""}`, body); toast("Scan job saved."); loadJobs(); }
  catch (e) { toast(errText(e), true); }
}
$("#addjob").onclick = () => editJob();
$("#jobcap").onsubmit = async (e) => {
  e.preventDefault();
  try { await api("/api/jobs/settings", { method: "PUT", body: JSON.stringify({ max_concurrent: +e.target.max_concurrent.value, reach_interval: +e.target.reach_interval.value }) }); toast("Saved."); }
  catch (er) { toast(errText(er), true); }
};
$("#dwform").onsubmit = async (e) => {
  e.preventDefault();
  appSettings = await api("/api/settings", { method: "PUT", body: JSON.stringify(Object.fromEntries(new FormData(e.target))) });
  toast("DameWare setting saved.");
};

// ------------------------------------------------------------ software updates
async function loadUpdate(force = false) {
  let u;
  try { u = force ? await post("/api/update/check", {}) : await api("/api/update"); } catch { return; }
  $("#updbadge").hidden = !u.available;
  $("#updbadge").title = u.available ? `Version ${u.latest} is available (you have ${u.current})` : "";
  const when = u.checked ? `Last checked ${fmtDate(u.checked)}.` : "Not checked yet.";
  $("#updinfo").innerHTML = `<div class="kvr"><span>This version</span><div><b>${esc(u.current)}</b></div></div>
    ${u.latest ? `<div class="kvr"><span>Newest</span><div>${esc(u.latest)} ${u.published ? `<span class="muted">published ${fmtDate(u.published)}</span>` : ""}
      ${u.available ? `<span class="pill warn">update available</span>` : `<span class="pill good">up to date</span>`}</div></div>` : ""}
    ${u.available && u.notes ? `<div class="kvr"><span>What's new</span><div class="longtext">${esc(u.notes)}</div></div>` : ""}
    <p class="muted">${when} ${u.error ? `<span class="pill bad longtext">${esc(u.error)}</span>` : ""}</p>
    ${u.message ? `<p class="pill warn longtext">${esc(u.message)}</p>` : ""}
    ${u.available && !u.can_install ? `<p class="muted">Install updates with the installer on the Windows server. For Docker, pull the new image.</p>` : ""}`;
  $("#updinstall").hidden = !(u.available && u.can_install) || u.installing;
  $("#updinstall").textContent = `Install ${u.latest || "update"} now`;
  $("#updreinstall").hidden = !u.can_install || u.installing;
  if (force) toast(u.error ? `Check failed: ${u.error}` : u.available ? `Version ${u.latest} is available.` : `Up to date (${u.current}).`, !!u.error);
}
$("#updcheck").onclick = async () => { $("#updcheck").disabled = true; $("#updcheck").textContent = "Checking…"; await loadUpdate(true); $("#updcheck").disabled = false; $("#updcheck").textContent = "Check for updates now"; };
// After an install starts: show progress, ride out the restart, and say when the new version answers.
async function watchUpdate(from) {
  const started = Date.now();
  let down = false;
  const tick = async () => {
    try {
      const u = await api("/api/update");
      if (down || (from && u.current !== from)) { toast(`NetInventory ${u.current} is running.`); loadUpdate(); return; }
      $("#updinfo").querySelector(".updprog")?.remove();
      $("#updinfo").insertAdjacentHTML("beforeend", `<p class="pill warn longtext updprog">${esc(u.message || "Waiting for setup to start…")}</p>`);
    } catch {
      down = true;
      $("#updinfo").querySelector(".updprog")?.remove();
      $("#updinfo").insertAdjacentHTML("beforeend", `<p class="pill warn longtext updprog">Setup is running; NetInventory is restarting…</p>`);
    }
    if (Date.now() - started < 15 * 60000) setTimeout(tick, 5000);
    else toast("The update is taking longer than expected. Check the update log in the data folder's logs.", true);
  };
  setTimeout(tick, 3000);
}
$("#updbadge").onclick = () => showTab("settings");
async function startInstall(force) {
  const q = force
    ? "Reinstall the newest published version now? Use this to repair a broken install. NetInventory stops for a minute or two; running scans are interrupted. Your data, settings and credentials are kept."
    : "Install the update now? NetInventory stops for a minute or two while it upgrades. Running scans are interrupted. Your data, settings and credentials are kept.";
  if (!(await confirmBox(q))) return;
  const from = (await api("/api/update")).current;
  try { const r = await post("/api/update/install", { force }); toast(r.output); watchUpdate(force ? null : from); }
  catch (e) { toast(errText(e), true); }
  loadUpdate();
}
$("#updinstall").onclick = () => startInstall(false);
$("#updreinstall").onclick = () => startInstall(true);

// ------------------------------------------------------------ signed-in user, sign-in settings
api("/api/me").then((m) => { $("#whoami").textContent = m.user; }).catch(() => {});
$("#logout").onclick = async () => { await fetch("/api/logout", { method: "POST" }); location.href = "/login"; };
// ------------------------------------------------------------ HTTPS certificate
// ------------------------------------------------------------ NetInventory Agent: enrollment, approvals, revoke
async function loadAgents(newToken = null) {
  const d = await api("/api/agents");
  const cmd = (tok) => `msiexec /i NetInventory-Agent.msi /qn SERVER=${d.server} TOKEN=${tok}${d.pin ? ` PIN=${d.pin}` : ""}`;
  $("#agentinfo").innerHTML = `
    ${!d.https ? `<p class="pill bad longtext">This server isn't on HTTPS. Agents only talk HTTPS: set up the certificate below first.</p>` : ""}
    <div class="kvr"><span>Push</span><div>Select PCs in Computers and click <b>Push agent</b>: installs it over WinRM, no download needed.</div></div>
    <div class="kvr"><span>Download</span><div><a class="link" href="${esc(d.msi_url)}" download="NetInventory-Agent.msi">NetInventory-Agent.msi</a> <span class="muted small">(for GPO software installation, Intune or a script${d.msi_local ? `; served by this server, and also on it in <code>${esc(d.msi_folder)}</code>` : ""})</span></div></div>
    <div class="kvr"><span>Server</span><div><code>${esc(d.server)}</code></div></div>
    <div class="kvr"><span>Certificate pin</span><div>${d.pin ? `<code class="small">${esc(d.pin)}</code> <span class="muted small">SHA-256 of this server's certificate. Agents refuse any other server. After changing the certificate, update the pin (GPO) and reinstall or re-enroll.</span>` : `<span class="muted">none (no certificate)</span>`}</div></div>
    <div class="kvr"><span>Enrollment token</span><div>${newToken ? `<code>${esc(newToken)}</code> <span class="pill warn">shown once: copy it now</span>`
      : d.token.set ? `set ${esc(fmtDate(d.token.created))}, ends in <code>…${esc(d.token.hint)}</code>` : `<span class="muted">none: agents can't enroll</span>`}
      <button class="ghost small" id="agtok">${d.token.set ? "New token" : "Create token"}</button>${d.token.set ? ` <button class="ghost small" id="agtokoff">Turn off enrollment</button>` : ""}
      <div class="muted small">Only used once per PC, to get that PC's own secret. A new token doesn't affect enrolled PCs.</div></div></div>
    ${newToken ? `<div class="kvr"><span>Install command</span><div><code class="small">${esc(cmd(newToken))}</code></div></div>` : ""}
    <form id="agset" class="inline row"><label>New PCs <select name="approve">
        <option value="ad" ${d.approve === "ad" ? "selected" : ""}>are approved if they're in Active Directory</option>
        <option value="all" ${d.approve === "all" ? "selected" : ""}>are always approved</option>
        <option value="manual" ${d.approve === "manual" ? "selected" : ""}>wait for my approval</option></select></label>
      <label>Inventory every <input name="inventory_hours" type="number" min="1" max="336" value="${d.inventory_hours}" style="width:4.5em"> hours</label><button class="ghost">Save</button></form>
    <p class="muted small">GPO without command line: deploy the MSI, then set <code>Server</code>, <code>EnrollToken</code> and <code>Pin</code> (strings) in
      <code>HKLM\\SOFTWARE\\Policies\\NetInventory\\Agent</code> with Group Policy Preferences > Registry. A PC that's already enrolled, or a revoked one, always waits for approval.</p>`;
  $("#agtok").onclick = async () => {
    if (d.token.set && !(await confirmBox("Make a new enrollment token? The old one stops working for new PCs (enrolled PCs are not affected); update it in your GPO or install command."))) return;
    const r = await post("/api/agents/token", {}); loadAgents(r.token);
  };
  if ($("#agtokoff")) $("#agtokoff").onclick = async () => { if (await confirmBox("Turn off enrollment? New PCs can't enroll until you create a token. Enrolled PCs keep reporting.")) { await api("/api/agents/token", { method: "DELETE" }); loadAgents(); } };
  $("#agset").onsubmit = async (e) => { e.preventDefault(); try { await api("/api/agents/settings", { method: "PUT", body: JSON.stringify({ approve: e.target.approve.value, inventory_hours: +e.target.inventory_hours.value }) }); toast("Saved."); } catch (er) { toast(errText(er), true); } };
  const AST = { active: "good", pending: "warn", revoked: "bad" };
  table($("#agenttable"), d.agents.map((a) => ({ ...a, act: a.id })), ["hostname", "status", "last_seen", "last_inventory", "version", "run_as", "last_ip", "enrolled", "act"], {
    labels: { last_seen: "heartbeat", last_inventory: "inventory", run_as: "runs as", last_ip: "from", act: "" },
    cell: { hostname: hostLink, status: (v, r) => `<span class="pill ${AST[v] || "mute"}">${esc(v)}</span>${r.note ? `<div class="muted small">${esc(r.note)}</div>` : ""}`,
      last_seen: (v) => v ? `${esc(fmtDate(v))}` : "", last_inventory: (v, r) => `${esc(fmtDate(v) || "not yet")}${r.inventory_requested ? ` <span class="muted small">(due)</span>` : ""}`,
      act: (id, r) => [r.status === "pending" ? `<a class="link" data-ag="approve" data-id="${id}">Approve</a>` : "",
        r.status === "active" ? `<a class="link" data-ag="inventory" data-id="${id}">Inventory now</a>` : "",
        r.status !== "revoked" ? `<a class="link" data-ag="revoke" data-id="${id}">Revoke</a>` : `<a class="link" data-ag="delete" data-id="${id}">Remove</a>`].filter(Boolean).join(" · ") } });
  if (!d.agents.length) $("#agenttable").innerHTML = `<p class="muted">No agents enrolled yet.</p>`;
  $("#agenttable").querySelectorAll("[data-ag]").forEach((a) => a.onclick = async () => {
    if (a.dataset.ag === "revoke" && !(await confirmBox("Revoke this agent? It can't report any more; if it tries to enroll again it waits for your approval."))) return;
    try { toast((await post(`/api/agents/${a.dataset.id}/${a.dataset.ag}`, {})).output); } catch (e) { toast(errText(e), true); }
    loadAgents();
  });
}

async function loadTls() {
  const t = await api("/api/tls");
  if (!t.https) { $("#tlsinfo").textContent = "HTTPS is off (no certificate in config.toml)."; return; }
  $("#tlsinfo").innerHTML = `${t.self_signed ? `<span class="pill warn">self-signed</span> Browsers warn until PCs trust it (see below).` : `<span class="pill good">issued by ${esc(t.issuer)}</span>`}
    <br>${esc(t.subject)} · valid until ${fmtDate(t.not_after)} · names: ${esc(t.names.join(", "))}
    ${t.pending_request ? `<br><span class="pill mute">a certificate request is waiting for its certificate</span>` : ""}`;
}
$("#tlscsr").onclick = async () => {
  try {
    const r = await fetch("/api/tls/csr", { method: "POST", credentials: "same-origin" });
    if (!r.ok) throw new Error(await r.text());
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(await r.blob()), download: "NetInventory.req" });
    a.click(); toast("Request downloaded. Submit it to your CA, then install the certificate it returns."); loadTls();
  } catch (e) { toast(errText(e), true); }
};
$("#tlsform").onsubmit = async (e) => {
  e.preventDefault();
  const f = e.target.file.files[0];
  if (!f) return;
  const buf = new Uint8Array(await f.arrayBuffer());
  let bin = ""; for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  try { const r = await post("/api/tls/import", { data: btoa(bin), password: e.target.password.value || null }); toast(r.output); e.target.reset(); setTimeout(loadTls, 30000); }
  catch (er) { toast(errText(er), true); }
};

// ------------------------------------------------------------ scanning exclusions
const EXCL_HINT = { event: "Microsoft-Windows-DistributedCOM 10009", ip: "10.0.5.0/24, 10.0.5.10-10.0.5.50 or 10.0.5.7",
  host: "KIOSK-* or lab-pc01.corp.example.com", ou: "OU=Lab,DC=corp,DC=example,DC=com", mac: "00:15:5D:01:02:03 or 00:15:5D*" };
let exclRows = [], exclKinds = {};
async function loadExclusions() {
  const d = await api("/api/exclusions");
  exclRows = d.rows; exclKinds = d.kinds;
  const opts = Object.entries(exclKinds).map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join("");
  if (!$("#exclkind").options.length) {
    $("#exclkind").innerHTML = opts;
    $("#exclfiltkind").innerHTML += opts;
    $("#exclvalue").placeholder = EXCL_HINT[$("#exclkind").value];
  }
  drawExclusions();
}
function drawExclusions() {
  const k = $("#exclfiltkind").value;
  table($("#excltable"), exclRows.filter((r) => !k || r.kind === k).map((r) => ({ ...r, type: exclKinds[r.kind] || r.kind, del: r.id })),
    ["type", "value", "note", "created_by", "created", "del"], {
      filterEl: $("#exclfilter"), labels: { value: "exclude", created_by: "added by", created: "added", del: "" },
      cell: { del: (id) => `<a class="link small" data-xdel="${id}">delete</a>` } });
  $("#excltable").querySelectorAll("[data-xdel]").forEach((a) => a.onclick = async () => {
    if (!(await confirmBox("Delete this exclusion? Matching items are scanned again from the next scan."))) return;
    try { await api(`/api/exclusions/${a.dataset.xdel}`, { method: "DELETE" }); loadExclusions(); } catch (e) { toast(errText(e), true); }
  });
}
$("#exclkind").onchange = () => { $("#exclvalue").placeholder = EXCL_HINT[$("#exclkind").value]; };
$("#exclfiltkind").onchange = drawExclusions;
$("#exclfilter").oninput = drawExclusions;
$("#exclform").onsubmit = async (e) => {
  e.preventDefault();
  try { await post("/api/exclusions", Object.fromEntries(new FormData(e.target))); e.target.value.value = ""; e.target.note.value = ""; toast("Exclusion added. It applies from the next scan."); loadExclusions(); }
  catch (er) { toast(errText(er), true); }
};

async function loadAuth() {
  const a = await api("/api/auth");
  const f = $("#authform");
  f.ad_domain.value = a.ad_domain || ""; f.ad_group.value = a.ad_group || ""; f.ad_server.value = a.ad_server || "";
  $("#authstate").innerHTML = `${kvRow("Local admin", a.local_user ? (a.local_enabled ? `<span class="pill warn">on</span> ${esc(a.local_user)}`
      : `<span class="pill good">off</span> turned back on by deleting <code>${esc(a.local_disabled_file)}</code>`) : "not configured")}
    ${kvRow("AD sign-in", a.ad_group ? `<span class="pill good">on</span> members of ${esc(a.ad_group)} in ${esc(a.ad_domain)}` : `<span class="pill mute">off</span>`)}
    ${kvRow("HTTPS", a.https ? `<span class="pill good">on</span>` : `<span class="pill bad">off</span> passwords cross the network unencrypted`)}`;
  if (!f.ad_domain.value) {   // suggest the domain from an AD scan target
    try { const t = (await api("/api/targets")).find((x) => x.kind === "ad_domain"); if (t) f.ad_domain.placeholder = t.value; } catch {}
  }
}
$("#authform").onsubmit = async (e) => {
  e.preventDefault();
  try { await api("/api/auth", { method: "PUT", body: JSON.stringify(Object.fromEntries(new FormData(e.target))) }); toast("Sign-in settings saved. Test an AD sign-in before signing out."); loadAuth(); }
  catch (er) { toast(errText(er), true); }
};
$("#authtest").onclick = async () => {
  const f = await formModal(`<h3>Test an AD sign-in</h3><p class="hint">Checks the password and group membership. It doesn't sign you in or turn off the local admin.</p>
    <label>AD username<input name="username" autocomplete="off" required></label><label>Password<input name="password" type="password" autocomplete="off" required></label>`);
  if (!f) return;
  try { const r = await post("/api/auth/test", f); toast(r.output, !r.ok); } catch (er) { toast(errText(er), true); }
};

// ------------------------------------------------------------ search + drawer
$("#search").onsubmit = async (e) => {
  e.preventDefault();
  const q = $("#q").value.trim();
  if (!q) return;
  const r = await api(`/api/search?q=${encodeURIComponent(q)}`);
  drawer(`<h2>Results for “${esc(q)}”</h2>${r.port_map?.length ? `<h3>Switch location</h3><div id="sp"></div>` : ""}
    <h3>Computers</h3><div id="sd"></div><h3>Users</h3><div id="su"></div>`);
  if (r.port_map?.length) table($("#sp"), r.port_map, ["mac", "hostname", "ip", "switch_name", "port", "vlan", "last_seen"], { cell: { hostname: hostLink } });
  table($("#sd"), r.devices, null, { cell: { hostname: hostLink, last_user: userLink } });
  table($("#su"), r.users, ["username", "hostname", "last_logon", "logon_count"], { cell: { username: userLink, hostname: hostLink } });
};
function drawer(html) { $("#detail").innerHTML = html; $("#drawer").hidden = false; }
$("#close").onclick = () => ($("#drawer").hidden = true);
$("#drawer").onclick = (e) => { if (e.target.id === "drawer") $("#drawer").hidden = true; };
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#drawer").hidden = true; });

let start = "overview";
try { start = localStorage.getItem("tab") || start; } catch {}
route(start);
pollStatus();
loadUpdate();
