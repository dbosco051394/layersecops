"""Prometheus text-exposition metrics for CI gates and dashboards.

The metrics are derived from the same report document as every other writer, so
a pipeline can scrape or upload a single small file instead of parsing JSON.
The output follows the Prometheus text format (version 0.0.4).
"""

from __future__ import annotations

from typing import Any


def _label(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _metric(name: str, value: Any, labels: dict[str, str] | None = None, help_text: str | None = None, mtype: str = "gauge") -> list[str]:
    lines: list[str] = []
    if help_text is not None:
        lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} {mtype}")
    label_text = ""
    if labels:
        label_text = "{" + ",".join(f'{key}="{_label(val)}"' for key, val in labels.items()) + "}"
    lines.append(f"{name}{label_text} {value}")
    return lines


def build_metrics(document: dict[str, Any]) -> str:
    scan = document.get("scan") or {}
    image = scan.get("image") or {}
    summary = document.get("summary") or {}
    validation = document.get("validation") or {}
    findings = document.get("findings") or []
    image_ref = image.get("reference") or "unknown"

    lines: list[str] = []
    lines.extend(_metric("layersecops_scan_info", 1, {
        "image": image_ref,
        "image_id": str(image.get("id") or ""),
        "digest": str(image.get("digest") or ""),
        "schema": str(document.get("schemaVersion") or ""),
        "status": str(scan.get("status") or "unknown"),
    }, "One for the image that was scanned", "gauge"))

    lines.extend(_metric("layersecops_findings", summary.get("total", 0), {
        "image": image_ref,
    }, "Total findings in the report", "gauge"))

    by_severity = summary.get("bySeverity") or {}
    for severity in ("critical", "high", "medium", "low", "negligible", "unknown"):
        lines.extend(_metric("layersecops_findings_by_severity", by_severity.get(severity, 0), {
            "image": image_ref, "severity": severity,
        }, "Findings grouped by severity", "gauge"))

    by_kind = summary.get("byKind") or {}
    for kind, count in sorted(by_kind.items()):
        lines.extend(_metric("layersecops_findings_by_kind", count, {
            "image": image_ref, "kind": kind,
        }, "Findings grouped by kind", "gauge"))

    by_source = summary.get("bySource") or {}
    for tool, count in sorted(by_source.items()):
        lines.extend(_metric("layersecops_findings_by_source", count, {
            "image": image_ref, "tool": tool,
        }, "Findings reported by each tool", "gauge"))

    lines.extend(_metric("layersecops_unique_vulnerabilities",
                         summary.get("uniqueVulnerabilities", 0), {"image": image_ref},
                         "Distinct vulnerability IDs", "gauge"))
    lines.extend(_metric("layersecops_fixable", summary.get("fixable", 0), {"image": image_ref},
                         "Findings with a fix available", "gauge"))
    lines.extend(_metric("layersecops_known_exploited", summary.get("knownExploited", 0),
                         {"image": image_ref}, "Findings flagged as known exploited", "gauge"))
    lines.extend(_metric("layersecops_unknown_layer", summary.get("unknownLayer", 0),
                         {"image": image_ref}, "Findings not attributed to a layer", "gauge"))

    for layer in summary.get("byLayer") or []:
        layer_index = layer.get("index")
        layer_id = "unknown" if layer_index is None else str(layer_index)
        lines.extend(_metric("layersecops_layer_findings", layer.get("findings", 0), {
            "image": image_ref, "layer": layer_id,
        }, "Findings attributed to each layer", "gauge"))
        lines.extend(_metric("layersecops_layer_size_bytes", layer.get("sizeBytes") or 0, {
            "image": image_ref, "layer": layer_id,
        }, "Uncompressed layer size in bytes", "gauge"))
        for severity in ("critical", "high", "medium", "low", "negligible", "unknown"):
            count = layer.get(severity, 0)
            if count:
                lines.extend(_metric("layersecops_layer_findings_by_severity", count, {
                    "image": image_ref, "layer": layer_id, "severity": severity,
                }, "Per-layer findings by severity", "gauge"))

    passed = bool(validation.get("passed"))
    lines.extend(_metric("layersecops_policy_passed", 1 if passed else 0, {"image": image_ref},
                         "Whether the scan passed policy", "gauge"))
    lines.extend(_metric("layersecops_policy_violations", len(validation.get("violations") or []), {
        "image": image_ref,
    }, "Policy violations", "gauge"))

    lines.extend(_metric("layersecops_scan_duration_seconds",
                         round((scan.get("durationMs") or 0) / 1000, 3), {"image": image_ref},
                         "Scan duration in seconds", "gauge"))
    lines.extend(_metric("layersecops_image_size_bytes", image.get("sizeBytes") or 0, {"image": image_ref},
                         "Image size in bytes", "gauge"))
    lines.extend(_metric("layersecops_image_layers", len(image.get("layers") or []), {"image": image_ref},
                         "Number of layers in the image", "gauge"))

    efficiency = image.get("efficiency") or {}
    if efficiency.get("score") is not None:
        lines.extend(_metric("layersecops_image_efficiency_score", efficiency.get("score"), {
            "image": image_ref,
        }, "Dive efficiency score (0-1)", "gauge"))

    for tool in scan.get("tools") or []:
        name = tool.get("name") or "unknown"
        status = tool.get("status") or "unknown"
        lines.extend(_metric("layersecops_tool_up", 1 if status == "ok" else 0, {
            "image": image_ref, "tool": name,
        }, "Whether the tool completed successfully", "gauge"))
        lines.extend(_metric("layersecops_tool_duration_seconds", round((tool.get("durationMs") or 0) / 1000, 3), {
            "image": image_ref, "tool": name,
        }, "Tool runtime in seconds", "gauge"))
        lines.extend(_metric("layersecops_tool_info", 1, {
            "image": image_ref, "tool": name, "version": str(tool.get("version") or ""),
            "status": status,
        }, "Tool version and status", "gauge"))

    # Per-finding detail is intentionally omitted from the text format: it belongs
    # in the JSON/SARIF reports. Keeping the file small makes it safe to upload
    # on every pipeline run.
    _ = findings
    return "\n".join(lines) + "\n"
