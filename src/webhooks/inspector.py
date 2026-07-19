"""The inspector web page — a single self-contained HTML document.

No CDN, no build step, no external fonts. The page polls ``/api/events`` and
renders recent captures with expandable payloads. Styling follows a clean light
palette (zinc greys, a single blue accent) with a dark-mode fallback.
"""

# The page is a plain constant so there is no templating to escape. All dynamic
# data arrives via fetch('/api/events') as JSON.
INSPECTOR_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>webhook-toolkit inspector</title>
<style>
  :root {
    --bg: #fafafa; --panel: #ffffff; --border: #e4e4e7; --text: #18181b;
    --muted: #71717a; --accent: #2563eb; --ok: #16a34a; --fail: #dc2626;
    --code-bg: #f4f4f5; --chip: #f4f4f5;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b0b0d; --panel: #18181b; --border: #27272a; --text: #f4f4f5;
      --muted: #a1a1aa; --accent: #60a5fa; --ok: #4ade80; --fail: #f87171;
      --code-bg: #111113; --chip: #27272a;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px; line-height: 1.5;
  }
  header {
    position: sticky; top: 0; z-index: 10; background: var(--panel);
    border-bottom: 1px solid var(--border); padding: 14px 20px;
    display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  }
  header h1 { font-size: 15px; margin: 0; font-weight: 650; letter-spacing: -0.01em; }
  header .count { color: var(--muted); font-variant-numeric: tabular-nums; }
  header .spacer { flex: 1; }
  label.toggle { color: var(--muted); display: flex; align-items: center; gap: 6px; cursor: pointer; }
  main { max-width: 980px; margin: 0 auto; padding: 20px; }
  .empty { color: var(--muted); text-align: center; padding: 60px 20px; }
  .event { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px; overflow: hidden; }
  .event summary { list-style: none; cursor: pointer; padding: 12px 14px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .event summary::-webkit-details-marker { display: none; }
  .method { font-weight: 700; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 12px; padding: 2px 8px; border-radius: 6px; background: var(--chip); }
  .method.POST { color: #fff; background: var(--accent); }
  .path { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 13px; }
  .chip { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: var(--chip); color: var(--muted); }
  .chip.provider { text-transform: capitalize; }
  .chip.ok { color: #fff; background: var(--ok); }
  .chip.fail { color: #fff; background: var(--fail); }
  .chip.unknown { border: 1px dashed var(--border); }
  .when { margin-left: auto; color: var(--muted); font-variant-numeric: tabular-nums; font-size: 12px; }
  .body { padding: 0 14px 14px; }
  h4 { margin: 12px 0 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
  pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; overflow-x: auto; margin: 0; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 12.5px; }
  table.headers { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  table.headers td { padding: 3px 8px; vertical-align: top; border-bottom: 1px solid var(--border); }
  table.headers td.k { color: var(--muted); white-space: nowrap; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  table.headers td.v { word-break: break-all; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  .id { color: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
</style>
</head>
<body>
<header>
  <h1>webhook-toolkit</h1>
  <span class="count" id="count">0 events</span>
  <span class="spacer"></span>
  <label class="toggle"><input type="checkbox" id="auto" checked /> Auto-refresh</label>
</header>
<main>
  <div id="list"><div class="empty">Waiting for the first webhook. Point a provider at this URL, or replay a stored event.</div></div>
</main>
<script>
  var listEl = document.getElementById("list");
  var countEl = document.getElementById("count");
  var autoEl = document.getElementById("auto");
  var openIds = {};

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function verifiedChip(v) {
    if (v === 1) return '<span class="chip ok">verified</span>';
    if (v === 0) return '<span class="chip fail">invalid</span>';
    return '<span class="chip unknown">no secret</span>';
  }

  function prettyBody(ev) {
    if (ev.is_json) {
      try { return JSON.stringify(JSON.parse(ev.body_text), null, 2); } catch (e) {}
    }
    return ev.body_text || "(empty body)";
  }

  function headerRows(headers) {
    var keys = Object.keys(headers).sort();
    if (!keys.length) return "<tr><td class='k'>(none)</td><td class='v'></td></tr>";
    return keys.map(function (k) {
      return "<tr><td class='k'>" + esc(k) + "</td><td class='v'>" + esc(headers[k]) + "</td></tr>";
    }).join("");
  }

  function render(events) {
    countEl.textContent = events.length + (events.length === 1 ? " event" : " events");
    if (!events.length) {
      listEl.innerHTML = '<div class="empty">No events captured yet.</div>';
      return;
    }
    listEl.innerHTML = events.map(function (ev) {
      var provider = ev.provider ? '<span class="chip provider">' + esc(ev.provider) + "</span>" : "";
      var open = openIds[ev.id] ? " open" : "";
      return (
        '<details class="event" data-id="' + ev.id + '"' + open + ">" +
          "<summary>" +
            '<span class="method ' + esc(ev.method) + '">' + esc(ev.method) + "</span>" +
            '<span class="path">' + esc(ev.path) + "</span>" +
            provider + verifiedChip(ev.verified) +
            '<span class="id">#' + ev.id + " &middot; " + ev.size + " B</span>" +
            '<span class="when">' + esc(ev.received_at) + "</span>" +
          "</summary>" +
          '<div class="body">' +
            "<h4>Body</h4><pre>" + esc(prettyBody(ev)) + "</pre>" +
            "<h4>Headers</h4><table class='headers'>" + headerRows(ev.headers) + "</table>" +
          "</div>" +
        "</details>"
      );
    }).join("");
    Array.prototype.forEach.call(listEl.querySelectorAll("details.event"), function (d) {
      d.addEventListener("toggle", function () {
        openIds[d.getAttribute("data-id")] = d.open;
      });
    });
  }

  function refresh() {
    fetch("/api/events?limit=100")
      .then(function (r) { return r.json(); })
      .then(function (data) { render(data.events || []); })
      .catch(function () {});
  }

  refresh();
  setInterval(function () { if (autoEl.checked) refresh(); }, 2000);
</script>
</body>
</html>
"""
