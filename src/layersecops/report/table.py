"""Plain-text and console rendering."""

from __future__ import annotations

import sys
from typing import Any

from layersecops.normalize import SEVERITY_DISPLAY_ORDER
from layersecops.util import human_bytes, truncate

_ANSI = {
    "critical": "\x1b[1;97;41m",
    "high": "\x1b[1;31m",
    "medium": "\x1b[1;33m",
    "low": "\x1b[36m",
    "negligible": "\x1b[2m",
    "unknown": "\x1b[2m",
    "pass": "\x1b[1;32m",
    "fail": "\x1b[1;31m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "reset": "\x1b[0m",
}


def _color(text: str, key: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI.get(key, '')}{text}{_ANSI['reset']}"


def _finding_rows(document: dict[str, Any], limit: int | None = None) -> list[str]:
    findings = document.get("findings") or []
    if limit is not None:
        findings = findings[:limit]
    rows: list[str] = []
    for finding in findings:
        package = finding.get("package") or {}
        layer = finding.get("layer") or {}
        fixed = ", ".join(package.get("fixedVersions") or []) or "-"
        sources = ",".join(
            sorted({source.get("tool", "") for source in finding.get("sources") or []})
        )
        rows.append(
            "  ".join(
                [
                    truncate(finding.get("severity", "unknown").upper(), 10).ljust(10),
                    truncate(finding.get("vulnerabilityId", ""), 20).ljust(20),
                    truncate(package.get("name", ""), 26).ljust(26),
                    truncate(package.get("version", ""), 18).ljust(18),
                    truncate(fixed, 20).ljust(20),
                    str(layer.get("index") if layer.get("index") is not None else "?").rjust(4),
                    truncate(sources, 14).ljust(14),
                    truncate((finding.get("risk") or {}).get("score", ""), 4).rjust(4),
                ]
            )
        )
    return rows


def render_text(document: dict[str, Any], *, color: bool = False) -> str:
    scan = document.get("scan") or {}
    image = scan.get("image") or {}
    summary = document.get("summary") or {}
    validation = document.get("validation") or {}
    lines: list[str] = []

    title = f"LayerSecOps {scan.get('generator', {}).get('version', '')}".strip()
    lines.append(_color(title, "bold", color))
    lines.append(f"Image     {image.get('reference', 'unknown')}")
    if image.get("id"):
        lines.append(f"Image ID  {image.get('id')}")
    if image.get("digest"):
        lines.append(f"Digest    {image.get('digest')}")
    distro = image.get("distro") or {}
    if distro.get("prettyName") or distro.get("name"):
        lines.append(f"Distro    {distro.get('prettyName') or distro.get('name')}")
    lines.append(
        f"Size      {human_bytes(image.get('sizeBytes'))}  |  "
        f"Layers {len(image.get('layers') or [])}  |  "
        f"Status {scan.get('status', 'unknown')}"
    )
    efficiency = image.get("efficiency") or {}
    if efficiency.get("score") is not None:
        score = efficiency.get("score")
        try:
            score_text = f"{float(score) * 100:.1f}%"
        except (TypeError, ValueError):
            score_text = str(score)
        lines.append(
            f"Efficiency {score_text}  |  Wasted {human_bytes(efficiency.get('wastedBytes'))}"
        )

    passed = validation.get("passed")
    verdict = "PASS" if passed else "FAIL"
    lines.append(
        "Validation "
        + _color(verdict, "pass" if passed else "fail", color)
        + f"  (fail on {validation.get('policy', {}).get('failOn', '?')})"
    )
    if validation.get("ignored"):
        lines.append(f"Ignored   {validation.get('ignored')} findings by policy")
    if validation.get("masked"):
        lines.append(f"Masked    {validation.get('masked')} findings by mask rules")
        for mf in (validation.get("maskedFindings") or [])[:10]:
            lines.append(f"  - {mf.get('vulnerabilityId')} in {mf.get('package')} ({mf.get('reason') or 'no reason'})")

    lines.append("")
    lines.append(_color("FINDINGS", "bold", color))
    total = summary.get("total", 0)
    lines.append(
        f"Total {total}  |  Unique {summary.get('uniqueVulnerabilities', 0)}  |  "
        f"Fixable {summary.get('fixable', 0)}  |  KEV {summary.get('knownExploited', 0)}  |  "
        f"Unknown layer {summary.get('unknownLayer', 0)}"
    )
    by_severity = summary.get("bySeverity") or {}
    severity_line = "  ".join(
        f"{severity.upper()}:{by_severity.get(severity, 0)}"
        for severity in SEVERITY_DISPLAY_ORDER
        if by_severity.get(severity, 0) or severity in {"critical", "high", "medium", "low"}
    )
    lines.append(severity_line)

    layers = summary.get("byLayer") or []
    if layers:
        lines.append("")
        lines.append(_color("LAYERS", "bold", color))
        lines.append(
            "  IDX  FINDINGS  CRIT  HIGH  MED  LOW  UNKNOWN  FIXABLE  SIZE       COMMAND"
        )
        for layer in layers:
            index = layer.get("index")
            lines.append(
                "  "
                + str(index if index is not None else "?").rjust(3)
                + "  "
                + str(layer.get("findings", 0)).rjust(8)
                + "  "
                + str(layer.get("critical", 0)).rjust(4)
                + "  "
                + str(layer.get("high", 0)).rjust(4)
                + "  "
                + str(layer.get("medium", 0)).rjust(3)
                + "  "
                + str(layer.get("low", 0)).rjust(3)
                + "  "
                + str(layer.get("unknown", 0)).rjust(7)
                + "  "
                + str(layer.get("fixable", 0)).rjust(7)
                + "  "
                + human_bytes(layer.get("sizeBytes")).ljust(9)
                + "  "
                + truncate(layer.get("command") or "", 44)
            )

    rows = _finding_rows(document, limit=30)
    if rows:
        lines.append("")
        lines.append(_color("TOP FINDINGS", "bold", color))
        lines.append(
            "  SEVERITY    VULNERABILITY         PACKAGE                    "
            "VERSION            FIXED                LAYER  SOURCES        RISK"
        )
        lines.extend(rows)
        if len(document.get("findings") or []) > len(rows):
            lines.append(
                f"  ... {len(document.get('findings') or []) - len(rows)} more findings "
                "in report.json / report.html"
            )

    violations = validation.get("violations") or []
    if violations:
        lines.append("")
        lines.append(_color("POLICY VIOLATIONS", "fail", color))
        for violation in violations[:20]:
            lines.append(f"  - {violation.get('message')}")
        if len(violations) > 20:
            lines.append(f"  ... {len(violations) - 20} more")

    errors = scan.get("errors") or []
    warnings = scan.get("warnings") or []
    if errors or warnings:
        lines.append("")
        lines.append(_color("SCAN NOTES", "bold", color))
        for warning in warnings:
            lines.append(f"  warning: {warning}")
        for error in errors:
            lines.append(f"  error: {error}")

    tools = scan.get("tools") or []
    if tools:
        lines.append("")
        lines.append(_color("TOOLS", "bold", color))
        for tool in tools:
            lines.append(
                f"  {tool.get('name', '?'):<7} {tool.get('status', '?'):<8} "
                f"{tool.get('version') or '-':<12} {truncate(tool.get('error') or '', 70)}"
            )

    return "\n".join(lines).rstrip() + "\n"


def print_console(document: dict[str, Any], *, color: bool | None = None) -> None:
    if color is None:
        color = sys.stdout.isatty() and not bool(__import__("os").environ.get("NO_COLOR"))
    sys.stdout.write(render_text(document, color=color))
