"""The optional, self-hosted monitoring dashboard — one self-contained HTML page.

No template engine, no build step, no external assets: inline CSS/JS and inline
SVG charts, so it works fully offline. The page is a thin client — it polls
`/stats` (aggregated server-side) and `/findings`, reads `/catalog` once for
human-readable rule names/descriptions, and renders. Submitted data is untrusted
(any agent can POST), so the client escapes every value it injects.
"""


def render_dashboard(refresh_seconds: int) -> str:
    """Return the dashboard as one self-contained HTML document."""
    return _PAGE.replace("__REFRESH_MS__", str(max(1, refresh_seconds) * 1000))


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guardana — collector</title>
<style>
  :root {
    --bg: #f6f7f9; --card: #ffffff; --ink: #1b1f24; --muted: #5f6673;
    --line: #e3e6ea; --accent: #c2410c;
    --sev-critical: #c0392b; --sev-high: #e07b00; --sev-medium: #b7950b;
    --sev-low: #2e7d32; --sev-info: #5f6368;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0e1116; --card: #171b21; --ink: #e6e9ee; --muted: #9aa0a6;
      --line: #2a2f37; --accent: #f97316;
      --sev-critical: #ff6b5e; --sev-high: #ffa54f; --sev-medium: #e6c34a;
      --sev-low: #66bb6a; --sev-info: #9aa0a6;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--ink);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  a { color: var(--accent); }
  header { padding: 20px 24px; border-bottom: 1px solid var(--line); }
  h1 { margin: 0; font-size: 18px; } h1 span { color: var(--muted); font-weight: 400; }
  .sub { color: var(--muted); font-size: 12px; margin-top: 2px; }
  main { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
  h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .04em;
    color: var(--muted); margin: 0 0 10px; }
  .grid { display: grid; gap: 16px; }
  .tiles { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
  .cols { grid-template-columns: 1fr 1fr; }
  @media (max-width: 720px) { .cols { grid-template-columns: 1fr; } }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
    padding: 16px; }
  .tile .n { font-size: 28px; font-weight: 600; font-variant-numeric: tabular-nums; }
  .tile .l { color: var(--muted); font-size: 12px; }
  .tile.warn .n { color: var(--sev-high); }
  .bar-row { display: grid; grid-template-columns: 92px 1fr 44px; align-items: center;
    gap: 8px; margin: 6px 0; }
  .bar-row .k { font-size: 12px; color: var(--muted); overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap; }
  .bar-row .k.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
  .bar { height: 12px; border-radius: 4px; min-width: 2px; }
  .bar-row .v { text-align: right; font-variant-numeric: tabular-nums; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line);
    vertical-align: top; }
  th { color: var(--muted); font-weight: 500; }
  td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .pill { display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 11px;
    font-weight: 600; color: #fff; }
  .sev-CRITICAL { background: var(--sev-critical); } .sev-HIGH { background: var(--sev-high); }
  .sev-MEDIUM { background: var(--sev-medium); } .sev-LOW { background: var(--sev-low); }
  .sev-INFO { background: var(--sev-info); }
  .legend { display: flex; gap: 14px; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
  .legend b { display: inline-block; width: 10px; height: 10px; border-radius: 2px;
    margin-right: 4px; vertical-align: middle; }
  .row { display: flex; justify-content: space-between; align-items: center; gap: 12px;
    flex-wrap: wrap; }
  select { background: var(--card); color: var(--ink); border: 1px solid var(--line);
    border-radius: 6px; padding: 4px 8px; font-size: 12px; }
  .empty { color: var(--muted); font-style: italic; padding: 8px 0; }
  footer { color: var(--muted); font-size: 11px; padding: 16px 24px;
    border-top: 1px solid var(--line); max-width: 1100px; margin: 0 auto; }
  .mt { margin-top: 20px; }
  /* Bounded so the page height stays stable as findings accumulate — the footer
     is always reachable, and the list scrolls within its own box. */
  #findings { max-height: 460px; overflow-y: auto; margin-top: 8px; }
  #sources { max-height: 300px; overflow-y: auto; }
  details.f { border-bottom: 1px solid var(--line); }
  details.f > summary { list-style: none; cursor: pointer; padding: 7px 4px; display: grid;
    grid-template-columns: 76px 1fr 34%; gap: 10px; align-items: baseline; }
  details.f > summary::-webkit-details-marker { display: none; }
  details.f > summary:hover { background: var(--bg); }
  .fname { font-weight: 500; }
  .fname .rid { display: block; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11px; color: var(--muted); font-weight: 400; }
  .fsrc { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px;
    color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .det { padding: 2px 10px 14px 86px; font-size: 12px; }
  .det p { margin: 5px 0; } .det .lbl { color: var(--muted); }
  .det code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px;
    background: var(--bg); padding: 1px 4px; border-radius: 4px; word-break: break-all; }
  .tax { display: inline-block; border: 1px solid var(--line); border-radius: 4px;
    padding: 0 5px; font-size: 10px; color: var(--muted); margin-right: 4px; }
</style>
</head>
<body>
<header>
  <h1>Guardana <span>· collector</span></h1>
  <div class="sub">Findings forwarded by your agents. Read-only · auto-refreshing ·
    <span id="updated">loading…</span></div>
</header>
<main>
  <div class="grid tiles" id="tiles"></div>

  <div class="card mt">
    <h2>Findings by severity</h2>
    <div id="severity"></div>
  </div>

  <div class="grid cols mt">
    <div class="card">
      <h2>By source</h2>
      <div id="sources"></div>
    </div>
    <div class="card">
      <h2>Top rules</h2>
      <div id="rules"></div>
    </div>
  </div>

  <div class="card mt">
    <h2>Activity over time (recent window)</h2>
    <div class="legend">
      <span><b style="background:var(--sev-high)"></b>findings</span>
      <span><b style="background:var(--sev-info)"></b>unverified</span>
    </div>
    <div id="series"></div>
  </div>

  <div class="card mt">
    <div class="row">
      <h2 style="margin:0">Recent findings</h2>
      <label>source
        <select id="source-filter"><option value="">all sources</option></select>
      </label>
    </div>
    <div id="findings" class="mt"></div>
  </div>
</main>
<footer>
  guardana-server · this dashboard is read-only and unauthenticated — do not expose
  it to an untrusted network (see SECURITY.md). The time window covers the
  collector's in-memory buffer, not long-range history.
</footer>

<script>
const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_VAR = s => getComputedStyle(document.documentElement)
  .getPropertyValue("--sev-" + s.toLowerCase()).trim() || "var(--sev-info)";
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const el = id => document.getElementById(id);
let CATALOG = {};  // rule_id -> {name, description}, from /catalog
const friendlyName = f => (CATALOG[f.rule_id] || {}).name || f.title || f.rule_id;

function barRow(key, value, max, color, mono) {
  const w = max > 0 ? Math.round((value / max) * 100) : 0;
  return `<div class="bar-row"><div class="k${mono ? " mono" : ""}" title="${esc(key)}">`
    + `${esc(key)}</div><div class="bar" style="width:${w}%;background:${color}"`
    + ` title="${esc(key)}: ${value}"></div><div class="v">${value}</div></div>`;
}

function renderTiles(t) {
  const tile = (n, l, warn) => `<div class="card tile${warn ? " warn" : ""}">`
    + `<div class="n">${n}</div><div class="l">${l}</div></div>`;
  el("tiles").innerHTML = tile(t.findings, "findings")
    + tile(t.unverified, "unverified", t.unverified > 0)
    + tile(t.sources, "sources") + tile(t.submissions, "submissions");
}

function renderSeverity(by) {
  const max = Math.max(1, ...SEVS.map(s => by[s] || 0));
  const any = SEVS.some(s => by[s]);
  el("severity").innerHTML = any
    ? SEVS.map(s => barRow(s, by[s] || 0, max, SEV_VAR(s))).join("")
    : `<div class="empty">No findings yet.</div>`;
}

function renderSources(rows) {
  if (!rows.length) {
    el("sources").innerHTML = `<div class="empty">No sources yet.</div>`; return; }
  el("sources").innerHTML = "<table><thead><tr><th>source</th><th>find.</th>"
    + "<th>unver.</th><th>worst</th></tr></thead><tbody>"
    + rows.map(r => `<tr><td class="mono" title="${esc(r.source)}">${esc(r.source)}</td>`
      + `<td>${r.findings}</td><td>${r.unverified}</td><td>${sevPill(r.worst_severity)}</td></tr>`)
      .join("") + "</tbody></table>";
}

function sevPill(s) { return s ? `<span class="pill sev-${esc(s)}">${esc(s)}</span>` : "—"; }

function renderRules(rows) {
  if (!rows.length) { el("rules").innerHTML = `<div class="empty">No findings yet.</div>`; return; }
  const max = Math.max(1, ...rows.map(r => r.count));
  el("rules").innerHTML = rows.map(r => {
    const name = (CATALOG[r.rule_id] || {}).name || r.rule_id.replace(/^guardana\\./, "");
    return barRow(name, r.count, max, "var(--accent)");
  }).join("");
}

function renderSeries(series) {
  if (series.length < 2) { el("series").innerHTML =
    `<div class="empty">Not enough activity yet to plot a trend.</div>`; return; }
  const W = 640, H = 120, P = 6;
  const maxY = Math.max(1, ...series.map(b => Math.max(b.findings, b.unverified)));
  const x = i => P + (i / (series.length - 1)) * (W - 2 * P);
  const y = v => H - P - (v / maxY) * (H - 2 * P);
  const path = key => series.map((b, i) => (i ? "L" : "M") + x(i).toFixed(1)
    + " " + y(b[key]).toFixed(1)).join(" ");
  const dots = key => series.map((b, i) =>
    `<circle cx="${x(i).toFixed(1)}" cy="${y(b[key]).toFixed(1)}" r="2.5"
      fill="${key === "findings" ? "var(--sev-high)" : "var(--sev-info)"}">`
    + `<title>${b[key]} ${key}</title></circle>`).join("");
  el("series").innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}"
    role="img" aria-label="findings and unverified over time">
    <path d="${path("findings")}" fill="none" stroke="var(--sev-high)" stroke-width="2"/>
    <path d="${path("unverified")}" fill="none" stroke="var(--sev-info)" stroke-width="2"
      stroke-dasharray="4 3"/>${dots("findings")}${dots("unverified")}</svg>`;
}

function renderFindings(items) {
  if (!items.length) { el("findings").innerHTML = `<div class="empty">No findings.</div>`; return; }
  el("findings").innerHTML = items.map(f => {
    const c = CATALOG[f.rule_id] || {}, ev = f.evidence || {}, v = f.verdict;
    const tax = (f.taxonomy || []).map(t => `<span class="tax">${esc(t.id)}</span>`).join("");
    const det = `<div class="det">`
      + (c.description ? `<p>${esc(c.description)}</p>` : "")
      + (ev.summary ? `<p><span class="lbl">evidence:</span> ${esc(ev.summary)}</p>` : "")
      + (ev.detail ? `<p><span class="lbl">detail:</span> <code>${esc(ev.detail)}</code></p>` : "")
      + `<p><span class="lbl">target:</span> <code>${esc(f.target_ref)}</code></p>`
      + (v ? `<p><span class="lbl">verdict:</span> ${esc(v.outcome)} (confidence `
          + `${Number(v.confidence).toFixed(2)}, ${esc(v.evaluator_id)})`
          + (v.rationale ? ` — ${esc(v.rationale)}` : "") + `</p>` : "")
      + (tax ? `<p>${tax}</p>` : "") + `</div>`;
    return `<details class="f"><summary><span>${sevPill(f.severity)}</span>`
      + `<span class="fname">${esc(friendlyName(f))}`
      + `<span class="rid">${esc(f.rule_id)}</span></span>`
      + `<span class="fsrc" title="${esc(f.target_ref)}">${esc(f.target_ref)}</span>`
      + `</summary>${det}</details>`;
  }).join("");
}

function populateSourceFilter(rows) {
  const sel = el("source-filter"), cur = sel.value;
  sel.innerHTML = `<option value="">all sources</option>`
    + rows.map(r => `<option value="${esc(r.source)}">${esc(r.source)}</option>`).join("");
  sel.value = cur;
}

async function loadCatalog() {
  try { CATALOG = await (await fetch("catalog")).json(); } catch (e) { CATALOG = {}; }
}

async function loadFindings() {
  const src = el("source-filter").value;
  const url = "findings?limit=100" + (src ? "&source=" + encodeURIComponent(src) : "");
  const box = el("findings"), innerScroll = box.scrollTop;
  const items = (await (await fetch(url)).json())
    .flatMap(sub => (sub.findings || []).concat(sub.unverified || []));
  renderFindings(items.slice(0, 100));
  box.scrollTop = innerScroll;  // keep the reader's place across refresh
}

async function loadStats() {
  const s = await (await fetch("stats")).json();
  renderTiles(s.totals); renderSeverity(s.by_severity);
  renderSources(s.by_source); renderRules(s.by_rule); renderSeries(s.series);
  populateSourceFilter(s.by_source);
  el("updated").textContent = "updated " + new Date().toLocaleTimeString();
}

async function refresh() {
  const pageScroll = window.scrollY;
  try { await loadStats(); await loadFindings(); window.scrollTo(0, pageScroll); }
  catch (e) { el("updated").textContent = "collector unreachable"; }
}

el("source-filter").addEventListener("change", loadFindings);
loadCatalog().then(refresh);
setInterval(refresh, __REFRESH_MS__);
</script>
</body>
</html>
"""
