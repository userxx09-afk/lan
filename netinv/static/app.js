// NetInventory dashboard. Plain JS, no build step.
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => (v === null || v === undefined ? "" : String(v)).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const api = async (path, opts = {}) => {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
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
  $("#kpis").innerHTML = [["Computers", c.pcs], ["Inventoried", c.inventoried], ["Mapped to a switch port", c.mapped_to_port],
    ["Users seen", c.users], ["Domain controllers", c.domain_controllers], ["Network devices", c.network_devices]]
    .map(([l, v]) => `<div class="kpi"><div class="v">${v ?? 0}</div><div class="l">${l}</div></div>`).join("");
  alertCache = al;
  renderAlerts();
  const max = Math.max(1, ...s.os_breakdown.map((r) => r.n));
  $("#osbreak").innerHTML = s.os_breakdown.map((r) => `<div class="bar"><div class="name" title="${esc(r.os)} ${esc(r.version)}">${esc(r.os.replace("Microsoft ", ""))} ${esc(r.version)}</div>
    <div class="track"><div class="fill" style="width:${(r.n / max) * 100}%"></div></div><div class="c">${r.n}</div></div>`).join("");
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
}
const exportLinks = (base) => ["xlsx", "csv", "xml"].map((f) => `<a class="link small" href="${base}/${f}" download>${{ xlsx: "Excel", csv: "CSV", xml: "XML" }[f]}</a>`).join(" · ");
document.querySelectorAll("[data-collect]").forEach((b) => b.onclick = async () => {
  await post(`/api/collect/${b.dataset.collect}`, {}); setTimeout(pollStatus, 500);
});

// ------------------------------------------------------------ asset grid (server-side paging + per-column filters)
const GRID_COLS = [
  ["hostname", "Name"], ["os", "OS"], ["os_display_version", "Version"], ["last_user", "Last user"], ["model", "Model"],
  ["manufacturer", "Manufacturer"], ["ip", "IP address"], ["mac", "MAC address"], ["switch_name", "Switch"],
  ["switch_port", "Port"], ["ou", "OU"], ["groups", "Groups"], ["state", "State"], ["min_disk_pct_free", "Disk free"],
  ["pending_updates", "Updates"], ["first_seen", "First seen"], ["last_seen", "Last seen"], ["inventory_last_collected", "Last scan"],
];
const grid = { page: 0, size: 100, sort: "hostname", desc: false, filters: {}, selected: new Set(), total: 0, rows: [] };
const gridSpec = (extra = {}) => ({
  dataset: "v_devices", fields: GRID_COLS.map((c) => c[0]),
  filters: Object.entries(grid.filters).filter(([, v]) => v.trim()).map(([field, value]) => ({ field, op: "contains", value: value.trim() })),
  sort: grid.sort, desc: grid.desc, ...extra,
});
let gridTimer;
loaders.computers = async () => {
  if (!$("#gridhead").innerHTML) buildGridHead();
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
  if (c === "min_disk_pct_free") return diskPill(v);
  if (c === "pending_updates") return v ? `<span class="pill warn">${v}</span>` : v === 0 ? `<span class="pill good">0</span>` : "";
  if (c === "os") return esc((v || "").replace("Microsoft ", ""));
  if (c === "ou") return `<span title="${esc(v)}">${esc((v || "").split(",")[0].replace("OU=", ""))}</span>`;
  if (/seen|scan|collected/.test(c)) return esc(fmtDate(v));
  return esc(v);
}
function statusDot(row) {
  const scanned = row.inventory_last_collected && (Date.now() - new Date(row.inventory_last_collected.replace(" ", "T") + "Z")) < 7 * 864e5;
  return `<span class="dot ${scanned ? "good" : "warn"}" title="${scanned ? "Scanned in the last 7 days" : "Not scanned recently"}"></span>`;
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
$("#clearfilters").onclick = () => { grid.filters = {}; $("#gridhead").querySelectorAll("[data-f]").forEach((i) => (i.value = "")); grid.page = 0; loaders.computers(); };
$("#clearsel").onclick = () => { grid.selected.clear(); loaders.computers(); };

async function download(path, spec) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(spec) });
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
  $("#assettitle").innerHTML = `<div class="atitle"><span class="dot ${v.inventory_last_collected ? "good" : "warn"}"></span>${esc(v.hostname)}
    <span class="muted">${esc((v.os || "").replace("Microsoft ", ""))} ${esc(v.os_display_version || "")}</span></div>
    <div class="muted">${esc(v.ip || "no IP")} · ${esc(v.fqdn || "")} ${v.state ? `· <span class="pill ${v.state === "Active" ? "good" : "mute"}">${esc(v.state)}</span>` : ""}</div>`;
  renderAssetTab(d, $("#assettabs .active")?.dataset.atab || "summary");
  $("#assettabs").querySelectorAll("button").forEach((b) => b.onclick = () => renderAssetTab(d, b.dataset.atab));
}
const kvRow = (k, v) => (v === null || v === undefined || v === "" ? "" : `<div class="kvr"><span>${k}</span><div>${v}</div></div>`);
function renderAssetTab(d, tab) {
  $("#assettabs").querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.atab === tab));
  const v = d.device, el = $("#assetbody");
  const counts = { software: d.software.length, updates: d.updates.filter((u) => u.status === "pending").length, logons: d.logons.length,
    history: d.history.length, comments: d.comments.length, location: d.location.length };
  $("#assettabs").querySelectorAll("button").forEach((b) => { const n = counts[b.dataset.atab]; b.querySelector("i") && (b.querySelector("i").textContent = n ? ` ${n}` : ""); });
  if (tab === "summary") {
    const wEnd = v.warranty_end ? new Date(v.warranty_end.replace(" ", "T")) : null;
    const wCls = wEnd ? (wEnd < new Date() ? "bad" : wEnd - new Date() < 90 * 864e5 ? "warn" : "good") : "";
    el.innerHTML = `<div class="summary">
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
    el.innerHTML = `<div class="toolbar"><input id="swf" placeholder="Filter software"></div><div id="swt"></div>`;
    table($("#swt"), d.software, ["name", "version", "publisher", "install_date"], { filterEl: $("#swf"), sort: "name" });
  } else if (tab === "updates") {
    el.innerHTML = `<h2>Pending</h2><div id="up1"></div><h2>Installed</h2><div id="up2"></div>`;
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
async function pollStatus() {
  clearTimeout(statusTimer);
  try {
    const s = await api("/api/status");
    const b = $("#scanbanner");
    if (s.running.length) {
      const names = s.running.map((r) => r.job.startsWith("rescan:") ? r.job.slice(7) : JOB_LABEL[r.job] || r.job);
      b.innerHTML = `<span class="spinner"></span><div><b>Scanning ${esc(names.join(", "))}…</b>
        <div class="muted">This can take a few minutes depending on the size of your network. Results appear as they come in.</div></div>
        <button class="ghost" id="refreshnow">Refresh</button>`;
      b.hidden = false;
      $("#refreshnow").onclick = refreshActive;
      statusTimer = setTimeout(pollStatus, 4000);
      b.dataset.was = "1";
    } else {
      if (b.dataset.was) { b.dataset.was = ""; refreshActive(); }
      b.hidden = true;
      statusTimer = setTimeout(pollStatus, 15000);
    }
  } catch { statusTimer = setTimeout(pollStatus, 30000); }
}
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
function formModal(html, wide = false) {
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
const TKIND = { ad_domain: "AD domain", ad_computer_path: "AD computer path", ad_user_path: "AD user path", ip_range: "IP range" };
const THELP = {
  ad_domain: ["corp.example.com", "Reads every computer, user and domain controller in the domain."],
  ad_computer_path: ["OU=Workstations,DC=corp,DC=example,DC=com", "Only computers in this OU (and below) are imported and scanned over WinRM."],
  ad_user_path: ["OU=Staff,DC=corp,DC=example,DC=com", "Only users in this OU (and below) are imported."],
  ip_range: ["10.0.0.0/24, 10.1.0.1-10.1.0.50", "Switches and routers are polled over SNMP; Windows PCs that answer WinRM are scanned too."],
};
let creds = [];
loaders.settings = async () => {
  loadUpdate();
  const [c, t, s] = await Promise.all([api("/api/credentials"), api("/api/targets"), api("/api/settings")]);
  creds = c; appSettings = s;
  table($("#credtable"), c.map((x) => ({ ...x, secret: x.has_secret, edit: x.id })), ["name", "kind", "username", "secret", "edit"], {
    labels: { edit: "" }, cell: { kind: (v) => esc(KIND[v] || v), secret: (v) => (v ? `<span class="pill good">stored</span>` : `<span class="pill warn">missing</span>`),
      edit: (id) => `<a class="link" data-cedit="${id}">Edit</a> · <a class="link" data-ctest="${id}">Test</a> · <a class="link" data-cdel="${id}">Delete</a>` } });
  table($("#targettable"), t.map((x) => ({ ...x, credentials: x.credential_ids, edit: x.id })), ["kind", "value", "server", "credentials", "enabled", "last_run", "last_result", "edit"], {
    labels: { edit: "", last_result: "result" },
    cell: { kind: (v) => esc(TKIND[v] || v), credentials: (ids) => esc(ids.map((i) => creds.find((c) => c.id === i)?.name || `#${i}`).join(", ") || "none"),
      enabled: (v) => yesNo(v), last_run: fmtDate,
      last_result: (v, r) => (v ? `<span class="pill ${r.last_ok ? "good" : "bad"}" title="${esc(v)}">${esc(v.length > 70 ? v.slice(0, 70) + "…" : v)}</span>` : ""),
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
  $("#intervals").innerHTML = Object.entries(JOB_LABEL).map(([k, l]) => `<label>${esc(l[0].toUpperCase() + l.slice(1))}
    <input name="interval:${k}" inputmode="numeric" placeholder="${s.intervals[k]}" value="${esc(s["interval:" + k] || "")}"></label>`).join("") + `<button>Save schedule</button>`;
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
    <label id="tserver">Domain controller (optional)<input name="server" value="${esc(x.server || "")}" placeholder="dc01.corp.example.com, blank = find one"></label>
    <label>Credentials to try, in order</label>
    <div class="checks">${creds.map((c) => `<label><input type="checkbox" data-multi="1" name="credential_ids" value="${c.id}" ${(x.credential_ids || []).includes(c.id) ? "checked" : ""}> ${esc(c.name)} <span class="muted">${esc(KIND[c.kind])}</span></label>`).join("") || `<span class="muted">Add a credential first.</span>`}</div>
    <label class="chk"><input type="checkbox" name="enabled" ${x.enabled === false ? "" : "checked"}> Enabled</label>`, true);
  kick();
  const f = await pending;
  if (!f) return;
  f.credential_ids = (f.credential_ids || []).map(Number);
  try { await post(`/api/targets${x.id ? `?tid=${x.id}` : ""}`, f); toast("Scan target saved."); loaders.settings(); } catch (e) { toast(errText(e), true); }
}
document.addEventListener("change", (e) => {
  if (e.target.id !== "tkind") return;
  const k = e.target.value;
  $("#tvalue").placeholder = THELP[k][0]; $("#thelp").textContent = THELP[k][1]; $("#tserver").hidden = k === "ip_range";
});
const errText = (e) => { try { return JSON.parse(e.message).detail || e.message; } catch { return e.message; } };
$("#addcred").onclick = () => editCred();
$("#addtarget").onclick = () => editTarget();
$("#scanall").onclick = async () => { await post("/api/scan/all", {}); toast("Full scan started."); setTimeout(pollStatus, 500); };
$("#intervals").onsubmit = async (e) => {
  e.preventDefault();
  try { await api("/api/settings", { method: "PUT", body: JSON.stringify(Object.fromEntries(new FormData(e.target))) }); toast("Schedule saved."); loaders.settings(); }
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
  $("#updinstall").textContent = `Install ${u.latest || "update"}`;
}
$("#updcheck").onclick = () => loadUpdate(true);
$("#updbadge").onclick = () => showTab("settings");
$("#updinstall").onclick = async () => {
  if (!(await confirmBox("Install the update now? NetInventory stops for a minute or two while it upgrades. Running scans are interrupted. Your data, settings and credentials are kept."))) return;
  try { const r = await post("/api/update/install", {}); toast(r.output); } catch (e) { toast(errText(e), true); }
  loadUpdate();
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
