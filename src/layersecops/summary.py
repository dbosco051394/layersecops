"""Summary and final report document construction."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from layersecops import SCHEMA_VERSION, __version__
from layersecops.models import Finding, ImageInfo, ToolStatus
from layersecops.normalize import (
    SEVERITY_DISPLAY_ORDER,
    normalize_severity,
    severity_rank,
)


def filter_by_min_severity(
    findings: Iterable[Finding], min_severity: str | None
) -> list[Finding]:
    if not min_severity:
        return list(findings)
    threshold = severity_rank(min_severity)
    return [finding for finding in findings if severity_rank(finding.severity) >= threshold]


def build_summary(
    findings: list[Finding],
    image: ImageInfo,
    tool_statuses: Iterable[ToolStatus],
) -> dict[str, Any]:
    by_severity = {severity: 0 for severity in SEVERITY_DISPLAY_ORDER}
    by_kind: dict[str, int] = {}
    by_package_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    layer_counts: dict[int | None, dict[str, Any]] = {}
    fixable = 0
    known_exploited = 0

    for finding in findings:
        severity = normalize_severity(finding.severity)
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
        package_type = finding.package.type or "unknown"
        by_package_type[package_type] = by_package_type.get(package_type, 0) + 1
        for tool in {source.tool for source in finding.sources}:
            by_source[tool] = by_source.get(tool, 0) + 1
        if finding.package.fixed_versions:
            fixable += 1
        if finding.known_exploited:
            known_exploited += 1

        layer_index = finding.layer.index if finding.layer else None
        bucket = layer_counts.setdefault(
            layer_index,
            {
                "index": layer_index,
                "findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
                "fixable": 0,
            },
        )
        bucket["findings"] += 1
        bucket[severity] = bucket.get(severity, 0) + 1
        if finding.package.fixed_versions:
            bucket["fixable"] += 1

    by_layer: list[dict[str, Any]] = []
    seen: set[int | None] = set()
    for layer in image.layers:
        entry = layer_counts.get(
            layer.index,
            {
                "index": layer.index,
                "findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
                "fixable": 0,
            },
        )
        entry.update(
            {
                "digest": layer.digest,
                "sizeBytes": layer.size_bytes,
                "command": layer.command,
            }
        )
        by_layer.append(entry)
        seen.add(layer.index)
    for index, entry in layer_counts.items():
        if index not in seen:
            entry.update({"digest": None, "sizeBytes": None, "command": None})
            by_layer.append(entry)

    top_risks = sorted(
        findings,
        key=lambda item: (
            item.known_exploited,
            float(item.risk_score),
            severity_rank(item.severity),
        ),
        reverse=True,
    )[:10]

    unique_vulnerabilities = len({finding.vulnerability_id for finding in findings})
    tools = list(tool_statuses)
    return {
        "total": len(findings),
        "uniqueVulnerabilities": unique_vulnerabilities,
        "bySeverity": by_severity,
        "byKind": by_kind,
        "byPackageType": dict(sorted(by_package_type.items())),
        "bySource": dict(sorted(by_source.items())),
        "byLayer": by_layer,
        "fixable": fixable,
        "knownExploited": known_exploited,
        "unknownLayer": layer_counts.get(None, {}).get("findings", 0),
        "tools": [status.to_dict() for status in tools],
        "topRisks": [
            {
                "id": finding.id,
                "vulnerabilityId": finding.vulnerability_id,
                "severity": finding.severity,
                "riskScore": finding.risk_score,
                "package": finding.package.name,
                "version": finding.package.version,
                "layer": finding.layer.index if finding.layer else None,
            }
            for finding in top_risks
        ],
    }


def build_document(
    *,
    scan_id: str,
    started_at: datetime,
    finished_at: datetime,
    status: str,
    image: ImageInfo,
    settings: Any,
    findings: list[Finding],
    validation: dict[str, Any],
    tool_statuses: Iterable[ToolStatus],
    warnings: list[str],
    errors: list[str],
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tool_list = list(tool_statuses)
    document_summary = summary or build_summary(findings, image, tool_list)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "scan": {
            "id": scan_id,
            "generator": {"name": "layersecops", "version": __version__},
            "startedAt": started_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "finishedAt": finished_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "durationMs": int((finished_at - started_at).total_seconds() * 1000),
            "status": status,
            "image": image.to_dict(),
            "options": settings.to_dict() if hasattr(settings, "to_dict") else {},
            "tools": [tool.to_dict() for tool in tool_list],
            "warnings": warnings,
            "errors": errors,
        },
        "summary": document_summary,
        "validation": validation,
        "findings": [finding.to_dict() for finding in findings],
    }
