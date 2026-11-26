"""Self-contained HTML report (no CDN, no external assets)."""

from __future__ import annotations

import html
from typing import Any

from layersecops.normalize import SEVERITY_DISPLAY_ORDER, normalize_severity
from layersecops.util import human_bytes

_CSS = """
:root { color-scheme: light dark; --bg:#0f141a; --panel:#161d26; --panel2:#1d2733;
  --text:#e6edf3; --muted:#8b98a8; --line:#2a3644; --accent:#4da3ff;
  --critical:#ff4d6d; --high:#ff8a4c; --medium:#ffd166; --low:#4dd4ac; --negligible:#8b98a8;
  --unknown:#6b7785; --pass:#3ddc84; --fail:#ff5d5d; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
  font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1440px; margin: 0 auto; padding: 28px 22px 60px; }
header { display:flex; flex-wrap:wrap; gap:16px; align-items:flex-start; justify-content:space-between;
  border-bottom:1px solid var(--line); padding-bottom:18px; margin-bottom:22px; }
h1 { margin:0 0 4px; font-size:22px; letter-spacing:-0.02em; }
h2 { margin:28px 0 12px; font-size:16px; letter-spacing:0.02em; text-transform:uppercase; color:var(--muted); }
.sub { color:var(--muted); font-size:13px; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px;
  font-weight:700; letter-spacing:0.04em; text-transform:uppercase; }
.badge.critical { background:var(--critical); color:#1a0508; }
.badge.high { background:var(--high); color:#211006; }
.badge.medium { background:var(--medium); color:#211b05; }
.badge.low { background:var(--low); color:#04211a; }
.badge.negligible { background:var(--negligible); color:#10151b; }
.badge.unknown { background:var(--unknown); color:#f4f7fa; }
.pill { display:inline-block; border:1px solid var(--line); border-radius:999px;
  padding:3px 10px; font-size:12px; color:var(--muted); }
.pass { color:var(--pass); border-color:var(--pass); }
.fail { color:var(--fail); border-color:var(--fail); }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(132px,1fr)); gap:12px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
.card .n { font-size:26px; font-weight:750; letter-spacing:-0.03em; }
.card .l { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:0.08em; }
.card.critical .n { color:var(--critical); } .card.high .n { color:var(--high); }
.card.medium .n { color:var(--medium); } .card.low .n { color:var(--low); }
.card.pass .n { color:var(--pass); } .card.fail .n { color:var(--fail); }
.meta { display:flex; flex-wrap:wrap; gap:8px 20px; color:var(--muted); font-size:12px; }
.meta b { color:var(--text); font-weight:600; }
table { width:100%; border-collapse:collapse; background:var(--panel);
  border:1px solid var(--line); border-radius:12px; overflow:hidden; }
th, td { text-align:left; padding:9px 11px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:0.06em;
  background:var(--panel2); position:sticky; top:0; }
tr:last-child td { border-bottom:0; }
tr.finding:hover { background:var(--panel2); }
.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size:12px; }
.muted { color:var(--muted); }
.small { font-size:12px; }
.truncate { max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.bar { height:6px; background:var(--panel2); border-radius:999px; overflow:hidden; min-width:80px; }
.bar > span { display:block; height:100%; background:linear-gradient(90deg,var(--accent),var(--high)); }
.controls { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin:14px 0; }
input[type=search], select { background:var(--panel); color:var(--text); border:1px solid var(--line);
  border-radius:8px; padding:8px 10px; font:inherit; }
input[type=search] { min-width:280px; }
label.check { color:var(--muted); font-size:12px; display:flex; gap:6px; align-items:center; }
details summary { cursor:pointer; color:var(--accent); }
pre { white-space:pre-wrap; word-break:break-word; background:var(--panel2); border:1px solid var(--line);
  border-radius:8px; padding:10px; font-size:12px; }
.notice { border:1px solid var(--line); border-left:3px solid var(--medium); background:var(--panel);
  border-radius:8px; padding:10px 12px; margin:8px 0; }
.notice.error { border-left-color:var(--fail); }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
@media (max-width: 900px) { .grid2 { grid-template-columns:1fr; } }
footer { margin-top:36px; color:var(--muted); font-size:12px; border-top:1px solid var(--line); padding-top:14px; }
"""

_JS = """
(function () {
  const rows = Array.from(document.querySelectorAll('tr.finding'));
  const search = document.getElementById('search');
  const severity = document.getElementById('severity');
  const layer = document.getElementById('layer');
  const kind = document.getElementById('kind');
  const fixable = document.getElementById('fixable');
  const count = document.getElementById('visible-count');
  function apply() {
    const q = (search.value || '').toLowerCase().trim();
    let shown = 0;
    rows.forEach(function (row) {
      const text = row.getAttribute('data-text') || '';
      let ok = !q || text.indexOf(q) !== -1;
      if (ok && severity.value) ok = row.getAttribute('data-severity') === severity.value;
      if (ok && layer.value) ok = row.getAttribute('data-layer') === layer.value;
      if (ok && kind.value) ok = row.getAttribute('data-kind') === kind.value;
      if (ok && fixable.checked) ok = row.getAttribute('data-fixable') === '1';
      row.style.display = ok ? '' : 'none';
      if (ok) shown += 1;
    });
    count.textContent = shown + ' of ' + rows.length + ' findings';
  }
  [search, severity, layer, kind, fixable].forEach(function (el) {
    el.addEventListener('input', apply);
    el.addEventListener('change', apply);
  });
  apply();
})();
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _url(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        return value
    return None


def _vuln_link(finding: dict[str, Any]) -> str:
    vuln_id = finding.get("vulnerabilityId") or finding.get("id") or ""
    url = _url(finding.get("primaryUrl"))
    if not url and str(vuln_id).upper().startswith("CVE-"):
        url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    label = _e(vuln_id)
    if url:
        return f'<a href="{_e(url)}" target="_blank" rel="noreferrer noopener">{label}</a>'
    return label


def _layer_cell(finding: dict[str, Any]) -> str:
    layer = finding.get("layer") or {}
    index = layer.get("index")
    confidence = layer.get("confidence") or "unknown"
    path = layer.get("path")
    parts = [
        f"<b>#{_e(index if index is not None else '?')}</b>",
        f'<span class="pill">{_e(confidence)}</span>',
    ]
    if path:
        parts.append(f'<div class="mono muted truncate" title="{_e(path)}">{_e(path)}</div>')
    return "<br>".join(parts)


def _sources(finding: dict[str, Any]) -> str:
    sources = finding.get("sources") or []
    names = sorted({str(source.get("tool")) for source in sources if source.get("tool")})
    return _e(", ".join(names))


def _finding_row(finding: dict[str, Any]) -> str:
    package = finding.get("package") or {}
    layer = finding.get("layer") or {}
    severity = normalize_severity(finding.get("severity"))
    fixed = ", ".join(package.get("fixedVersions") or []) or "—"
    risk = (finding.get("risk") or {}).get("score")
    aliases = [alias for alias in finding.get("aliases") or [] if alias]
    alias_text = f'<div class="small muted">alias: {_e(", ".join(aliases))}</div>' if aliases else ""
    title = finding.get("title") or ""
    description = finding.get("description") or ""
    refs = finding.get("references") or []
    detail_bits = []
    if title:
        detail_bits.append(f"<p>{_e(title)}</p>")
    if description:
        detail_bits.append(f"<pre>{_e(description)}</pre>")
    if refs:
        detail_bits.append(
            "<p class=\"small\">"
            + " · ".join(
                f'<a href="{_e(url)}" target="_blank" rel="noreferrer noopener">{_e(url)}</a>'
                for url in refs[:6]
                if _url(url)
            )
            + "</p>"
        )
    detail_bits.append(
        '<p class="small muted">'
        f"Sources: {_sources(finding)} · Status: {_e(finding.get('status'))} · "
        f"Layer confidence: {_e(layer.get('confidence'))} · "
        f"Layer evidence: {_e(layer.get('evidence'))}"
        "</p>"
    )
    if finding.get("knownExploited"):
        detail_bits.append('<p class="small" style="color:var(--critical)">Known exploited vulnerability (KEV)</p>')
    if finding.get("epss") is not None:
        detail_bits.append(f'<p class="small muted">EPSS: {_e(finding.get("epss"))}</p>')
    search_text = " ".join(
        [
            str(finding.get("vulnerabilityId") or ""),
            str(package.get("name") or ""),
            str(package.get("version") or ""),
            str(layer.get("index") if layer.get("index") is not None else ""),
            str(layer.get("command") or ""),
            str(layer.get("path") or ""),
            title,
            _sources(finding),
        ]
    )
    return (
        f'<tr class="finding" data-severity="{_e(severity)}" '
        f'data-layer="{_e(layer.get("index") if layer.get("index") is not None else "unknown")}" '
        f'data-kind="{_e(finding.get("kind"))}" '
        f'data-fixable="{"1" if package.get("fixedVersions") else "0"}" '
        f'data-text="{_e(search_text.lower())}">'
        f'<td><span class="badge {_e(severity)}">{_e(severity)}</span></td>'
        f'<td>{_vuln_link(finding)}{alias_text}'
        f'<div class="small muted">{_e(finding.get("kind"))}</div></td>'
        f'<td><span class="mono">{_e(package.get("name"))}</span>'
        f'<div class="small muted">{_e(package.get("type"))}</div></td>'
        f'<td class="mono">{_e(package.get("version"))}</td>'
        f'<td class="mono">{_e(fixed)}</td>'
        f'<td>{_layer_cell(finding)}</td>'
        f'<td>{_e(risk if risk is not None else "—")}</td>'
        f'<td>{_sources(finding)}</td>'
        f'<td><details><summary>details</summary>{"".join(detail_bits)}</details></td>'
        "</tr>"
    )


def build_html(document: dict[str, Any]) -> str:
    scan = document.get("scan") or {}
    image = scan.get("image") or {}
    summary = document.get("summary") or {}
    validation = document.get("validation") or {}
    findings = document.get("findings") or []
    by_severity = summary.get("bySeverity") or {}
    by_layer = summary.get("byLayer") or []
    passed = validation.get("passed")
    verdict = "PASS" if passed else "FAIL"
    image_ref = image.get("reference") or "unknown"

    cards = [
        ("total", summary.get("total", 0), "findings"),
        ("critical", by_severity.get("critical", 0), "critical"),
        ("high", by_severity.get("high", 0), "high"),
        ("medium", by_severity.get("medium", 0), "medium"),
        ("low", by_severity.get("low", 0), "low"),
        ("fixable", summary.get("fixable", 0), "fixable"),
        ("kev", summary.get("knownExploited", 0), "known exploited"),
        ("pass" if passed else "fail", verdict, "policy"),
    ]
    card_html = "".join(
        f'<div class="card {_e(css)}"><div class="n">{_e(value)}</div>'
        f'<div class="l">{_e(label)}</div></div>'
        for css, value, label in cards
    )

    severity_bars = ""
    max_severity = max([by_severity.get(s, 0) for s in SEVERITY_DISPLAY_ORDER] + [1])
    for severity in SEVERITY_DISPLAY_ORDER:
        count = by_severity.get(severity, 0)
        width = max(2, round(count / max_severity * 100)) if count else 0
        severity_bars += (
            f'<tr><td><span class="badge {severity}">{severity}</span></td>'
            f'<td class="mono">{count}</td>'
            f'<td><div class="bar"><span style="width:{width}%"></span></div></td></tr>'
        )

    max_layer = max([layer.get("findings", 0) for layer in by_layer] + [1])
    layer_rows = ""
    for layer in by_layer:
        count = layer.get("findings", 0)
        width = max(2, round(count / max_layer * 100)) if count else 0
        layer_rows += (
            "<tr>"
            f'<td class="mono">#{_e(layer.get("index") if layer.get("index") is not None else "?")}</td>'
            f'<td class="mono">{_e(count)}</td>'
            f'<td class="mono">{_e(layer.get("critical", 0))}</td>'
            f'<td class="mono">{_e(layer.get("high", 0))}</td>'
            f'<td class="mono">{_e(layer.get("fixable", 0))}</td>'
            f'<td>{human_bytes(layer.get("sizeBytes"))}</td>'
            f'<td><div class="bar"><span style="width:{width}%"></span></div></td>'
            f'<td class="mono small truncate" title="{_e(layer.get("command"))}">'
            f'{_e(layer.get("command") or "")}</td>'
            "</tr>"
        )

    finding_rows = "".join(_finding_row(finding) for finding in findings)
    if not findings:
        finding_rows = '<tr><td colspan="9" class="muted">No findings. 🎉</td></tr>'

    layer_options = "".join(
        f'<option value="{_e(layer.get("index") if layer.get("index") is not None else "unknown")}">'
        f'Layer {_e(layer.get("index") if layer.get("index") is not None else "unknown")} '
        f'({_e(layer.get("findings", 0))} findings)</option>'
        for layer in by_layer
    )
    severity_options = "".join(
        f'<option value="{severity}">{severity}</option>' for severity in SEVERITY_DISPLAY_ORDER
    )

    violations = validation.get("violations") or []
    violation_html = ""
    if violations:
        items = "".join(f"<li>{_e(item.get('message'))}</li>" for item in violations[:100])
        violation_html = (
            '<h2>Policy violations</h2><div class="notice error"><ul>' + items + "</ul></div>"
        )

    masked = validation.get("maskedFindings") or []
    masked_html = ""
    if masked:
        items = "".join(
            f"<li><b>{_e(m.get('vulnerabilityId'))}</b> in {_e(m.get('package'))} "
            f"{_e(m.get('version'))} ({_e(m.get('severity'))}) — {_e(m.get('reason') or 'no reason')}"
            f"{' (expires ' + _e(m.get('expires')) + ')' if m.get('expires') else ''}</li>"
            for m in masked[:100]
        )
        masked_html = (
            f'<h2>Masked findings ({len(masked)})</h2>'
            f'<div class="notice"><ul>{items}</ul></div>'
        )

    warnings = scan.get("warnings") or []
    errors = scan.get("errors") or []
    notes = ""
    for warning in warnings:
        notes += f'<div class="notice">warning: {_e(warning)}</div>'
    for error in errors:
        notes += f'<div class="notice error">error: {_e(error)}</div>'

    tools = scan.get("tools") or []
    tool_rows = "".join(
        "<tr>"
        f'<td class="mono">{_e(tool.get("name"))}</td>'
        f'<td>{_e(tool.get("status"))}</td>'
        f'<td class="mono">{_e(tool.get("version") or "—")}</td>'
        f'<td class="mono small">{_e(tool.get("durationMs") or "—")}</td>'
        f'<td class="small muted">{_e(tool.get("error") or "")}</td>'
        "</tr>"
        for tool in tools
    )

    distro = image.get("distro") or {}
    efficiency = image.get("efficiency") or {}
    efficiency_text = ""
    if efficiency.get("score") is not None:
        try:
            efficiency_text = f"{float(efficiency['score']) * 100:.1f}%"
        except (TypeError, ValueError):
            efficiency_text = str(efficiency.get("score"))
    meta = [
        ("Image ID", image.get("id")),
        ("Digest", image.get("digest")),
        ("Distro", distro.get("prettyName") or distro.get("name")),
        ("Architecture", image.get("architecture")),
        ("Size", human_bytes(image.get("sizeBytes"))),
        ("Layers", len(image.get("layers") or [])),
        ("Efficiency", efficiency_text),
        ("Wasted", human_bytes(efficiency.get("wastedBytes")) if efficiency else None),
        ("Scan ID", scan.get("id")),
        ("Started", scan.get("startedAt")),
        ("Duration", f"{round((scan.get('durationMs') or 0) / 1000, 1)}s"),
        ("Scan status", scan.get("status")),
    ]
    meta_html = "".join(
        f"<span>{_e(label)} <b>{_e(value if value not in (None, '') else '—')}</b></span>"
        for label, value in meta
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LayerSecOps — {_e(image_ref)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <div>
    <h1>LayerSecOps report</h1>
    <div class="sub"><span class="mono">{_e(image_ref)}</span> · schema {_e(document.get("schemaVersion"))}</div>
  </div>
  <div>
    <span class="pill {'pass' if passed else 'fail'}">{_e(verdict)}</span>
    <span class="pill">fail on {_e((validation.get("policy") or {}).get("failOn"))}</span>
  </div>
</header>
<div class="meta">{meta_html}</div>

<h2>Summary</h2>
<div class="cards">{card_html}</div>

<div class="grid2">
  <div>
    <h2>Severity</h2>
    <table><thead><tr><th>Severity</th><th>Count</th><th>Distribution</th></tr></thead>
    <tbody>{severity_bars}</tbody></table>
  </div>
  <div>
    <h2>Layer attribution</h2>
    <table><thead><tr><th>Layer</th><th>Findings</th><th>Critical</th><th>High</th>
    <th>Fixable</th><th>Size</th><th>Share</th><th>Created by</th></tr></thead>
    <tbody>{layer_rows}</tbody></table>
  </div>
</div>

{violation_html}
{masked_html}
{notes}

<h2>Findings</h2>
<div class="controls">
  <input id="search" type="search" placeholder="Search CVE, package, path, layer command…">
  <select id="severity"><option value="">All severities</option>{severity_options}</select>
  <select id="layer"><option value="">All layers</option>{layer_options}</select>
  <select id="kind"><option value="">All kinds</option><option value="vulnerability">vulnerability</option>
  <option value="secret">secret</option></select>
  <label class="check"><input id="fixable" type="checkbox"> Fixable only</label>
  <span id="visible-count" class="muted small"></span>
</div>
<table>
<thead><tr><th>Severity</th><th>Vulnerability</th><th>Package</th><th>Installed</th>
<th>Fixed</th><th>Layer</th><th>Risk</th><th>Sources</th><th>Details</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>

<h2>Tools</h2>
<table><thead><tr><th>Tool</th><th>Status</th><th>Version</th><th>Duration (ms)</th><th>Error</th></tr></thead>
<tbody>{tool_rows}</tbody></table>

<footer>
Generated by LayerSecOps {_e(scan.get("generator", {}).get("version"))} ·
Scan {_e(scan.get("id"))} ·
Policy {_e((validation.get("policy") or {}).get("failOn"))} ·
Findings are attributed to the layer that owns the final package file; see the
<span class="mono">confidence</span> field for evidence strength.
</footer>
</div>
<script>{_JS}</script>
</body>
</html>
"""
