"""The inspector web page — a single self-contained HTML document.

No CDN, no build step, no external fonts. The page talks to the JSON API in
:mod:`webhooks.server`:

* lists captures with filters (provider, signature state, path) and paging,
  showing the true total;
* expands a capture into its signature diagnosis (reason and hints), body and
  headers;
* replays it to any URL, optionally re-signed and with an edited body or extra
  headers, and shows the handler's answer;
* copies the same replay as a ``curl`` command, downloads the raw bytes,
  deletes one capture or clears them all;
* shows per-target forwarding counters when ``forward`` is running.

Captured data is attacker-controlled (anyone can POST to the receiver), so the
page never inserts it as HTML: every value goes through ``textContent`` or
``setAttribute``. Existing cards are kept across refreshes, so an open replay
form is never wiped while you type.
"""

INSPECTOR_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>webhook-toolkit inspector</title>
<link rel="icon" href="/favicon.ico" type="image/svg+xml">
<style>
  :root {
    --bg: #f6f6f7; --panel: #ffffff; --panel-2: #fafafa; --border: #e4e4e7; --border-strong: #d4d4d8;
    --text: #18181b; --muted: #5f5f69; --accent: #2563eb; --accent-text: #ffffff; --accent-soft: #eff4ff;
    --ok: #15803d; --ok-soft: #ecfdf3; --fail: #b91c1c; --fail-soft: #fef2f2; --warn: #92400e; --warn-soft: #fffbeb;
    --code-bg: #f4f4f5; --chip: #f1f1f3; --shadow: 0 1px 2px rgba(24, 24, 27, .06), 0 1px 1px rgba(24, 24, 27, .04);
    --mono: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0c0c0e; --panel: #151518; --panel-2: #1a1a1e; --border: #2a2a30; --border-strong: #3a3a42;
      --text: #f4f4f5; --muted: #a1a1aa; --accent: #6b9bff; --accent-text: #0b1020; --accent-soft: #16203a;
      --ok: #4ade80; --ok-soft: #0f2418; --fail: #f87171; --fail-soft: #2a1414; --warn: #fbbf24; --warn-soft: #2a2110;
      --code-bg: #101013; --chip: #232329; --shadow: none;
    }
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  a { color: var(--accent); }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }
  .skip { position: absolute; left: -9999px; top: 8px; background: var(--panel); padding: 6px 10px; z-index: 50; }
  .skip:focus { left: 8px; }
  .visually-hidden { position: absolute !important; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }

  .topbar {
    position: sticky; top: 0; z-index: 20; background: var(--panel); border-bottom: 1px solid var(--border);
    padding: 10px 20px; display: flex; align-items: center; gap: 8px 16px; flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .brand h1 { font-size: 15px; margin: 0; font-weight: 650; letter-spacing: -.01em; }
  .brand .version { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }
  .count { margin: 0; color: var(--muted); font-variant-numeric: tabular-nums; flex: 1 1 auto; min-width: 12rem; }
  .top-actions { display: flex; align-items: center; gap: 10px; }
  .live { display: inline-flex; align-items: center; gap: 6px; color: var(--muted); cursor: pointer; user-select: none; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--border-strong); }
  .live.on .dot { background: var(--ok); animation: pulse 2s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: .35; } }

  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 32px;
    padding: 5px 12px; border-radius: 8px; border: 1px solid var(--border-strong); background: var(--panel);
    color: var(--text); font: inherit; font-size: 13px; font-weight: 550; cursor: pointer; text-decoration: none;
    transition: background-color .15s, border-color .15s;
  }
  .btn:hover { background: var(--panel-2); border-color: var(--muted); }
  .btn:disabled { opacity: .55; cursor: not-allowed; }
  .btn.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
  .btn.primary:hover { filter: brightness(1.07); }
  .btn.danger { color: var(--fail); }
  .btn.danger:hover { background: var(--fail-soft); border-color: var(--fail); }

  .secrets { max-width: 1040px; margin: 14px auto 0; padding: 0 20px; display: flex; flex-wrap: wrap; gap: 6px 14px; color: var(--muted); font-size: 12.5px; }
  .secret-state { display: inline-flex; align-items: center; gap: 6px; }
  .secret-state i { width: 7px; height: 7px; border-radius: 50%; display: inline-block; background: var(--border-strong); }
  .secret-state.set i { background: var(--ok); }
  .secret-state.placeholder i { background: var(--warn); }

  main { max-width: 1040px; margin: 0 auto; padding: 14px 20px 40px; }
  .filters {
    display: grid; grid-template-columns: repeat(2, minmax(0, 11rem)) minmax(0, 1fr); gap: 10px; align-items: end;
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 12px; box-shadow: var(--shadow);
  }
  label.field { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--muted); font-weight: 550; min-width: 0; }
  input[type=text], input[type=url], input[type=search], select, textarea {
    font: inherit; font-size: 13.5px; color: var(--text); background: var(--panel-2); border: 1px solid var(--border-strong);
    border-radius: 8px; padding: 6px 9px; min-height: 34px; width: 100%; min-width: 0;
  }
  textarea { font-family: var(--mono); font-size: 12.5px; line-height: 1.45; resize: vertical; }

  .forward { margin-top: 14px; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; box-shadow: var(--shadow); }
  .forward h2, .section-title { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 8px; }
  .table-wrap { overflow-x: auto; }
  table.data { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  table.data th { text-align: left; color: var(--muted); font-weight: 600; padding: 4px 8px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  table.data td { padding: 5px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  table.data td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .mono { font-family: var(--mono); }
  .break { overflow-wrap: anywhere; word-break: break-word; }

  .list { margin-top: 14px; display: flex; flex-direction: column; gap: 8px; }
  .empty { color: var(--muted); text-align: center; padding: 56px 20px; background: var(--panel); border: 1px dashed var(--border-strong); border-radius: 12px; }
  .empty code { font-family: var(--mono); font-size: 12.5px; background: var(--code-bg); padding: 2px 6px; border-radius: 6px; }
  .event { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow); min-width: 0; }
  .event.fresh { animation: fresh 1.6s ease-out 1; }
  @keyframes fresh { from { box-shadow: 0 0 0 3px var(--accent-soft), var(--shadow); border-color: var(--accent); } }
  .event summary { list-style: none; cursor: pointer; padding: 10px 14px; display: flex; align-items: center; gap: 6px 10px; flex-wrap: wrap; border-radius: 12px; }
  .event summary::-webkit-details-marker { display: none; }
  .event summary::before { content: ""; width: 7px; height: 7px; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: rotate(-45deg); transition: transform .15s; flex: none; margin-right: 2px; }
  .event details[open] > summary::before { transform: rotate(45deg); }
  .event details[open] > summary { border-bottom: 1px solid var(--border); border-radius: 12px 12px 0 0; }
  .method { font: 700 11.5px/1 var(--mono); padding: 4px 7px; border-radius: 6px; background: var(--chip); color: var(--text); }
  .method.POST { background: var(--accent); color: var(--accent-text); }
  .path { font-family: var(--mono); font-size: 13px; flex: 1 1 14rem; min-width: 0; overflow-wrap: anywhere; }
  .chip { font-size: 11.5px; padding: 2px 8px; border-radius: 999px; background: var(--chip); color: var(--muted); white-space: nowrap; }
  .chip.ok { background: var(--ok-soft); color: var(--ok); }
  .chip.fail { background: var(--fail-soft); color: var(--fail); }
  .chip.warn { background: var(--warn-soft); color: var(--warn); }
  .meta { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; white-space: nowrap; }

  .detail { padding: 12px 14px 14px; display: flex; flex-direction: column; gap: 12px; min-width: 0; }
  .diag { border-radius: 10px; padding: 10px 12px; border: 1px solid var(--border); background: var(--panel-2); }
  .diag.ok { border-color: color-mix(in srgb, var(--ok) 35%, transparent); background: var(--ok-soft); }
  .diag.fail { border-color: color-mix(in srgb, var(--fail) 35%, transparent); background: var(--fail-soft); }
  .diag.warn { border-color: color-mix(in srgb, var(--warn) 35%, transparent); background: var(--warn-soft); }
  .diag strong { display: block; font-size: 13px; }
  .diag .reason { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }
  .diag ul { margin: 6px 0 0; padding-left: 18px; }
  .diag li { margin: 2px 0; }
  .diag .code { color: var(--muted); font-size: 12px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .replay { border: 1px solid var(--border); border-radius: 10px; padding: 12px; display: grid; gap: 10px; background: var(--panel-2); min-width: 0; }
  .replay .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .check { display: inline-flex; gap: 8px; align-items: flex-start; font-size: 13px; }
  .check input { margin-top: 3px; }
  .note { font-size: 12px; color: var(--muted); margin: 0; }
  .result { margin: 0; font-size: 13px; overflow-wrap: anywhere; }
  .result.ok { color: var(--ok); } .result.fail { color: var(--fail); }
  .result .warn { color: var(--warn); display: block; }
  pre {
    background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; margin: 0;
    overflow: auto; max-height: 420px; max-width: 100%; font: 12.5px/1.5 var(--mono); white-space: pre;
  }
  pre.wrap { white-space: pre-wrap; overflow-wrap: anywhere; }
  .kv td.k { color: var(--muted); white-space: nowrap; font-family: var(--mono); }
  .kv td.v { font-family: var(--mono); overflow-wrap: anywhere; word-break: break-all; }

  .pager { display: flex; justify-content: center; align-items: center; gap: 12px; margin-top: 16px; color: var(--muted); font-variant-numeric: tabular-nums; }
  .pager[hidden] { display: none; }

  .forward td:first-child { min-width: 16rem; }
  @media (max-width: 640px) {
    .kv tr, .kv td { display: block; }
    .kv tr { border-bottom: 1px solid var(--border); padding: 5px 0; }
    .kv td { border-bottom: 0; padding: 0 4px; }
    .kv td.k { white-space: normal; overflow-wrap: anywhere; font-size: 11.5px; }
    .topbar { padding: 10px 14px; }
    .secrets, main { padding-left: 14px; padding-right: 14px; }
    .filters { grid-template-columns: 1fr 1fr; }
    .filters .grow { grid-column: 1 / -1; }
    .meta { order: 5; }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
  }
</style>
</head>
<body>
<a class="skip" href="#list">Skip to events</a>
<header class="topbar">
  <div class="brand">
    <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#2563eb"/><path d="M9 17.5l4.5 4.5L23 11" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <h1>webhook-toolkit</h1><span class="version" id="version"></span>
  </div>
  <p class="count" id="count" role="status" aria-live="polite">Loading&hellip;</p>
  <div class="top-actions">
    <label class="live on" id="live-label"><input type="checkbox" id="auto" checked><span class="dot" aria-hidden="true"></span><span>Live</span></label>
    <button type="button" class="btn danger" id="clear">Clear all</button>
  </div>
</header>
<section class="secrets" id="secrets" aria-label="Signing secrets"></section>
<main>
  <form class="filters" id="filters" role="search" aria-label="Filter events">
    <label class="field">Provider
      <select id="f-provider">
        <option value="">All providers</option>
        <option value="github">GitHub</option>
        <option value="stripe">Stripe</option>
        <option value="slack">Slack</option>
        <option value="shopify">Shopify</option>
        <option value="generic">Generic HMAC</option>
        <option value="unsigned">Unsigned</option>
      </select>
    </label>
    <label class="field">Signature
      <select id="f-verified">
        <option value="">Any result</option>
        <option value="1">Verified</option>
        <option value="0">Invalid</option>
        <option value="none">Not checked</option>
      </select>
    </label>
    <label class="field grow">Path contains
      <input type="search" id="f-q" placeholder="/webhooks/stripe" autocomplete="off">
    </label>
  </form>
  <section class="forward" id="forward" hidden aria-labelledby="forward-title">
    <h2 id="forward-title">Forward targets</h2>
    <div class="table-wrap">
      <table class="data">
        <thead><tr><th scope="col">Target</th><th scope="col">Delivered</th><th scope="col">Failed</th><th scope="col">Last</th><th scope="col">Avg</th><th scope="col">Last error</th></tr></thead>
        <tbody id="forward-rows"></tbody>
      </table>
    </div>
  </section>
  <div class="list" id="list"></div>
  <nav class="pager" id="pager" aria-label="Pages" hidden>
    <button type="button" class="btn" id="prev">&larr; Newer</button>
    <span id="page"></span>
    <button type="button" class="btn" id="next">Older &rarr;</button>
  </nav>
</main>
<script>
(function () {
  "use strict";
  var PAGE = 50;
  var state = { offset: 0, provider: "", verified: "", q: "", count: 0, total: 0, status: null, first: true };
  var cards = new Map();
  var listEl = document.getElementById("list");
  var countEl = document.getElementById("count");
  var autoEl = document.getElementById("auto");
  var liveLabel = document.getElementById("live-label");

  function store(key, value) { try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (e) { return null; } }

  // Build DOM safely: attributes via setAttribute, text via text nodes.
  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    });
    (children || []).forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
    });
    return el;
  }

  function api(method, url, body) {
    var opts = { method: method, headers: {} };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    return fetch(url, opts).then(function (r) {
      return r.text().then(function (t) {
        var data = null; try { data = t ? JSON.parse(t) : null; } catch (e) { data = { detail: t }; }
        if (!r.ok) { var d = data && data.detail; throw new Error(typeof d === "string" ? d : ("HTTP " + r.status)); }
        return data;
      });
    });
  }

  function size(n) { return n < 1024 ? n + " B" : (n / 1024).toFixed(n < 10240 ? 1 : 0) + " KB"; }
  function when(iso) {
    var d = new Date(iso); if (isNaN(d)) return iso;
    var today = new Date().toDateString() === d.toDateString();
    return today ? d.toLocaleTimeString() : d.toLocaleString();
  }
  function stateOf(ev) {
    if (ev.verified === 1) return { cls: "ok", label: "verified" };
    if (ev.verified === 0) return { cls: "fail", label: "invalid" };
    if (!ev.provider) return { cls: "", label: "unsigned" };
    return { cls: "warn", label: "not checked" };
  }

  // ---- list ----------------------------------------------------------------
  function query() {
    var p = new URLSearchParams({ limit: PAGE, offset: state.offset, summary: "true" });
    if (state.provider) p.set("provider", state.provider);
    if (state.verified) p.set("verified", state.verified);
    if (state.q) p.set("q", state.q);
    return "/api/events?" + p.toString();
  }

  function refresh() {
    return api("GET", query()).then(function (data) {
      state.count = data.count; state.total = data.total;
      if (state.offset && state.offset >= data.count) { state.offset = Math.max(0, Math.floor((data.count - 1) / PAGE) * PAGE); return refresh(); }
      renderList(data.events || []);
      renderCount(data.events.length);
      state.first = false;
    }).catch(function (e) { countEl.textContent = "Cannot reach the receiver: " + e.message; });
  }

  function renderCount(shown) {
    var filtered = state.provider || state.verified || state.q;
    var text;
    if (!state.count) text = filtered ? "No events match the filters (" + state.total + " stored)" : "No events yet";
    else {
      var from = state.offset + 1, to = state.offset + shown;
      text = "Showing " + from + "–" + to + " of " + state.count + (filtered ? " matching (" + state.total + " stored)" : " events");
    }
    countEl.textContent = text;
    var pages = Math.max(1, Math.ceil(state.count / PAGE));
    var page = Math.floor(state.offset / PAGE) + 1;
    document.getElementById("pager").hidden = pages <= 1;
    document.getElementById("page").textContent = "Page " + page + " of " + pages;
    document.getElementById("prev").disabled = state.offset === 0;
    document.getElementById("next").disabled = state.offset + PAGE >= state.count;
  }

  function renderList(events) {
    var seen = new Set(); var prev = null;
    events.forEach(function (ev) {
      var card = cards.get(ev.id);
      if (!card) {
        card = createCard(ev); cards.set(ev.id, card);
        if (!state.first) card.classList.add("fresh");
      }
      seen.add(ev.id);
      var next = prev ? prev.nextSibling : listEl.firstChild;
      if (card !== next) listEl.insertBefore(card, next);
      prev = card;
    });
    cards.forEach(function (card, id) { if (!seen.has(id)) { card.remove(); cards.delete(id); } });
    var empty = listEl.querySelector(".empty");
    if (!events.length && !empty) {
      var filtered = state.provider || state.verified || state.q;
      listEl.appendChild(h("div", { class: "empty" }, filtered
        ? ["No captured request matches these filters."]
        : ["Waiting for the first webhook. Point a provider here, or run ",
           h("code", { text: "python cli.py send github push --to " + location.origin + " --sign" })]));
    } else if (events.length && empty) empty.remove();
  }

  function createCard(ev) {
    var st = stateOf(ev);
    var details = h("details", { ontoggle: function () { if (details.open && !details.dataset.loaded) loadDetail(ev.id, card, body); } });
    var summary = h("summary", null, [
      h("span", { class: "method " + ev.method, text: ev.method }),
      h("span", { class: "path", text: ev.path }),
      ev.provider ? h("span", { class: "chip", text: ev.provider }) : null,
      h("span", { class: "chip " + st.cls, title: ev.verify_reason || "", text: st.label }),
      h("span", { class: "meta", text: "#" + ev.id + " · " + size(ev.size) }),
      h("time", { class: "meta", datetime: ev.received_at, title: ev.received_at, text: when(ev.received_at) })
    ]);
    var body = h("div", { class: "detail" }, [h("p", { class: "note", text: "Loading…" })]);
    details.appendChild(summary); details.appendChild(body);
    var card = h("article", { class: "event", "data-id": ev.id, "aria-label": ev.method + " " + ev.path + ", event " + ev.id }, [details]);
    return card;
  }

  // ---- detail ------------------------------------------------------------------
  function loadDetail(id, card, body) {
    api("GET", "/api/events/" + id).then(function (ev) {
      card.querySelector("details").dataset.loaded = "1";
      body.textContent = "";
      renderDetail(ev, card, body);
    }).catch(function (e) { body.textContent = "Could not load event: " + e.message; });
  }

  function diagBox(ev) {
    var a = ev.assessment || {}; var d = a.diagnosis;
    var st = stateOf({ verified: a.verified, provider: ev.provider });
    var title = { ok: "Signature verified", fail: "Signature invalid", warn: "Signature not checked", "": "Unsigned request" }[st.cls];
    var hints = (d && !d.ok ? d.hints : []) || [];
    return h("div", { class: "diag " + st.cls, role: "note" }, [
      h("strong", { text: title }),
      h("span", { class: "reason", text: a.reason || "" }),
      d && !d.ok ? h("div", { class: "code", text: "code: " + d.code + (d.skew_seconds !== null && d.skew_seconds !== undefined ? " · timestamp skew " + d.skew_seconds + " s" : "") }) : null,
      hints.length ? h("ul", null, hints.map(function (t) { return h("li", { text: t }); })) : null
    ]);
  }

  function prettyBody(ev) {
    if (ev.is_json) { try { return JSON.stringify(JSON.parse(ev.body_text), null, 2); } catch (e) {} }
    return ev.body_text || "(empty body)";
  }

  function headerTable(headers) {
    var keys = Object.keys(headers || {}).sort();
    return h("div", { class: "table-wrap" }, [h("table", { class: "data kv" }, [h("tbody", null,
      keys.length ? keys.map(function (k) { return h("tr", null, [h("td", { class: "k", text: k }), h("td", { class: "v", text: headers[k] })]); })
                  : [h("tr", null, [h("td", { class: "k", text: "(no headers)" })])]
    )])]);
  }

  function parseHeaderLines(text) {
    var out = {}; var bad = null;
    text.split("\n").forEach(function (line) {
      if (!line.trim()) return;
      var i = line.indexOf(":");
      if (i < 1) { bad = line; return; }
      out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
    if (bad !== null) throw new Error("header lines must look like 'Name: value' (got '" + bad + "')");
    return out;
  }

  function renderDetail(ev, card, body) {
    var id = ev.id;
    var provider = ev.provider;
    var secret = provider && state.status && state.status.providers[provider];
    var canSign = !!(secret && secret.state !== "unset");
    var original = (ev.body_text || "").replace(/\r\n?/g, "\n");
    var formId = "replay-" + id;
    var targetKey = "wt.target." + (provider || "unsigned");

    var toInput = h("input", { type: "url", name: "to", required: true, placeholder: "http://127.0.0.1:3001" + ev.path, value: store(targetKey) || store("wt.target") || "" });
    var signBox = h("input", { type: "checkbox", name: "sign", checked: canSign, disabled: !canSign });
    var bodyArea = h("textarea", { name: "body", rows: Math.min(14, Math.max(4, original.split("\n").length + 1)), spellcheck: "false" });
    bodyArea.value = original;
    var headersArea = h("textarea", { name: "headers", rows: 2, spellcheck: "false", placeholder: "X-Debug: 1" });
    var result = h("p", { class: "result", role: "status", "aria-live": "polite" });
    var curlPre = h("pre", { class: "wrap", hidden: true, "aria-label": "curl command" });
    var signNote = !provider ? "No provider detected: the request is replayed unsigned."
      : !canSign ? (secret ? secret.env_var : provider) + " is not set, so it cannot be re-signed."
      : "Uses " + secret.env_var + (secret.state === "placeholder" ? " (a placeholder value)" : "") + " and a fresh timestamp.";

    function options() {
      var to = toInput.value.trim();
      if (!to) { toInput.focus(); throw new Error("enter the URL of your handler first"); }
      var opts = { to: to, sign: signBox.checked && canSign, headers: parseHeaderLines(headersArea.value) };
      if (bodyArea.value !== original) opts.body = bodyArea.value;
      store(targetKey, to); store("wt.target", to);
      return opts;
    }
    function show(el, cls, text, extra) {
      el.className = "result " + (cls || ""); el.textContent = text;
      (extra || []).forEach(function (w) { el.appendChild(h("span", { class: "warn", text: w })); });
    }

    var form = h("form", { class: "replay", id: formId, hidden: true, novalidate: true, "aria-label": "Replay event " + id }, [
      h("label", { class: "field" }, ["Target URL", toInput]),
      h("label", { class: "check" }, [signBox, h("span", null, ["Re-sign with the provider secret", h("br"), h("span", { class: "note", text: signNote })])]),
      h("label", { class: "field" }, ["Body (edit to modify-then-replay)", bodyArea]),
      /�/.test(original) ? h("p", { class: "note", text: "This body is not valid UTF-8; editing it sends the text shown." }) : null,
      h("label", { class: "field" }, ["Extra headers, one 'Name: value' per line", headersArea]),
      h("div", { class: "row" }, [
        h("button", { type: "submit", class: "btn primary", text: "Send replay" }),
        h("button", { type: "button", class: "btn", text: "Reset body", onclick: function () { bodyArea.value = original; } })
      ]),
      result
    ]);
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var opts; try { opts = options(); } catch (err) { show(result, "fail", err.message); return; }
      var button = form.querySelector("button[type=submit]"); button.disabled = true;
      show(result, "", "Sending…");
      api("POST", "/api/events/" + id + "/replay", opts).then(function (r) {
        var line = (r.status_code ? r.status_code : "no response") + " · " + r.elapsed_ms + " ms" + (r.resigned ? " · re-signed" : "") + " · " + r.url;
        show(result, r.ok ? "ok" : "fail", (r.ok ? "Accepted: " : "Rejected: ") + line + (r.error ? " — " + r.error : r.response_snippet ? " — " + r.response_snippet : ""), r.warnings);
      }).catch(function (err) { show(result, "fail", err.message); })
        .then(function () { button.disabled = false; });
    });

    var replayBtn = h("button", { type: "button", class: "btn", "aria-expanded": "false", "aria-controls": formId, text: "Replay…" });
    replayBtn.addEventListener("click", function () {
      form.hidden = !form.hidden; replayBtn.setAttribute("aria-expanded", String(!form.hidden));
      if (!form.hidden) toInput.focus();
    });
    var curlBtn = h("button", { type: "button", class: "btn", text: "Copy as curl" });
    curlBtn.addEventListener("click", function () {
      if (form.hidden) { form.hidden = false; replayBtn.setAttribute("aria-expanded", "true"); }
      var opts; try { opts = options(); } catch (err) { show(result, "fail", err.message); return; }
      api("POST", "/api/events/" + id + "/curl", opts).then(function (r) {
        curlPre.hidden = false; curlPre.textContent = r.curl;
        var done = function (ok) { show(result, ok ? "ok" : "", ok ? "curl command copied to the clipboard." : "Select the command below to copy it.", r.warnings); };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(r.curl).then(function () { done(true); }, function () { done(false); });
        else done(false);
      }).catch(function (err) { show(result, "fail", err.message); });
    });
    var deleteBtn = h("button", { type: "button", class: "btn danger", text: "Delete" });
    deleteBtn.addEventListener("click", function () {
      api("DELETE", "/api/events/" + id).then(function () { cards.delete(id); card.remove(); refresh(); })
        .catch(function (err) { show(result, "fail", err.message); });
    });

    [
      diagBox(ev),
      h("div", { class: "actions", role: "group", "aria-label": "Actions for event " + id }, [
        replayBtn, curlBtn,
        h("a", { class: "btn", href: "/api/events/" + id + "/raw", download: "event-" + id + ".bin", text: "Download raw" }),
        deleteBtn
      ]),
      form, curlPre,
      h("section", null, [h("h3", { class: "section-title", text: "Body · " + (ev.content_type || "no content type") + " · " + size(ev.size) }), h("pre", { text: prettyBody(ev) })]),
      h("section", null, [h("h3", { class: "section-title", text: "Headers" }), headerTable(ev.headers)]),
      Object.keys(ev.query || {}).length ? h("section", null, [h("h3", { class: "section-title", text: "Query" }), headerTable(ev.query)]) : null
    ].forEach(function (el) { if (el) body.appendChild(el); });
  }

  // ---- status, forward targets -----------------------------------------------
  function loadStatus() {
    return api("GET", "/api/status").then(function (s) {
      state.status = s;
      document.getElementById("version").textContent = "v" + s.version;
      var box = document.getElementById("secrets"); box.textContent = "";
      box.appendChild(h("span", { text: "Secrets:" }));
      Object.keys(s.providers).forEach(function (name) {
        var p = s.providers[name];
        if (name === "generic" && !s.generic && p.state === "unset") return;
        var label = { set: "set", placeholder: "placeholder", unset: "not set" }[p.state] || p.state;
        box.appendChild(h("span", { class: "secret-state " + p.state, title: p.env_var }, [h("i", { "aria-hidden": "true" }), name + " " + label]));
      });
      document.getElementById("forward").hidden = !s.forward_targets.length;
    }).catch(function () {});
  }

  function loadForward() {
    if (!state.status || !state.status.forward_targets.length) return Promise.resolve();
    return api("GET", "/api/forward").then(function (data) {
      var rows = document.getElementById("forward-rows"); rows.textContent = "";
      data.targets.forEach(function (t) {
        rows.appendChild(h("tr", null, [
          h("td", { class: "mono break", text: t.target }),
          h("td", { class: "num", text: t.delivered }),
          h("td", { class: "num", text: t.failed }),
          h("td", { class: "num", text: t.last_status === null ? (t.last_error ? "error" : "–") : t.last_status }),
          h("td", { class: "num", text: t.avg_ms === null ? "–" : t.avg_ms + " ms" }),
          h("td", { class: "break", text: t.last_error || "" })
        ]));
      });
    }).catch(function () {});
  }

  // ---- controls -------------------------------------------------------------------
  function onFilter() {
    state.provider = document.getElementById("f-provider").value;
    state.verified = document.getElementById("f-verified").value;
    state.q = document.getElementById("f-q").value.trim();
    state.offset = 0; refresh();
  }
  var qTimer = null;
  document.getElementById("f-provider").addEventListener("change", onFilter);
  document.getElementById("f-verified").addEventListener("change", onFilter);
  document.getElementById("f-q").addEventListener("input", function () { clearTimeout(qTimer); qTimer = setTimeout(onFilter, 250); });
  document.getElementById("filters").addEventListener("submit", function (e) { e.preventDefault(); onFilter(); });
  document.getElementById("prev").addEventListener("click", function () { state.offset = Math.max(0, state.offset - PAGE); refresh(); });
  document.getElementById("next").addEventListener("click", function () { state.offset += PAGE; refresh(); });
  autoEl.addEventListener("change", function () { liveLabel.classList.toggle("on", autoEl.checked); if (autoEl.checked) refresh(); });
  document.getElementById("clear").addEventListener("click", function () {
    if (!state.total) return;
    if (!window.confirm("Delete all " + state.total + " captured events? This cannot be undone.")) return;
    api("DELETE", "/api/events").then(function () { state.offset = 0; refresh(); }).catch(function (e) { countEl.textContent = e.message; });
  });

  loadStatus().then(function () { refresh(); loadForward(); });
  setInterval(function () { if (autoEl.checked && !document.hidden) { refresh(); loadForward(); } }, 2000);
  setInterval(function () { if (!document.hidden) loadStatus(); }, 15000);
})();
</script>
</body>
</html>
"""
