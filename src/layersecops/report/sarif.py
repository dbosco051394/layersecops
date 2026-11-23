"""SARIF 2.1.0 output for code-scanning and CI integrations."""

from __future__ import annotations

from typing import Any

from layersecops import __version__
from layersecops.normalize import normalize_severity

_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "negligible": "note",
    "unknown": "note",
}


def _short(text: str | None, limit: int = 300) -> str:
    if not text:
        return ""
    value = " ".join(str(text).split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def build_sarif(document: dict[str, Any]) -> dict[str, Any]:
    scan = document.get("scan") or {}
    image = scan.get("image") or {}
    image_ref = image.get("reference") or "image"
    findings = document.get("findings") or []

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    for finding in findings:
        rule_id = finding.get("vulnerabilityId") or finding.get("id")
        if rule_id in rule_index:
            continue
        rule_index[rule_id] = len(rules)
        severity = normalize_severity(finding.get("severity"))
        references = finding.get("references") or []
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {
                    "text": _short(finding.get("title")) or rule_id,
                },
                "fullDescription": {
                    "text": _short(finding.get("description"), 2000)
                    or _short(finding.get("title"))
                    or rule_id,
                },
                "helpUri": finding.get("primaryUrl")
                or (references[0] if references else None)
                or f"https://nvd.nist.gov/vuln/detail/{rule_id}",
                "defaultConfiguration": {"level": _LEVELS.get(severity, "note")},
                "properties": {
                    "tags": ["security", "vulnerability", severity],
                    "precision": "high" if finding.get("layer") else "medium",
                },
            }
        )

    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding.get("vulnerabilityId") or finding.get("id")
        package = finding.get("package") or {}
        layer = finding.get("layer") or {}
        severity = normalize_severity(finding.get("severity"))
        path = package.get("path")
        uri = path or f"image:{image_ref}"
        fixed = ", ".join(package.get("fixedVersions") or []) or "no fix available"
        message = (
            f"{rule_id} ({severity}) in {package.get('name', 'unknown')} "
            f"{package.get('version', '')}. Fixed: {fixed}. "
            f"Layer: {layer.get('index') if layer.get('index') is not None else 'unknown'} "
            f"({layer.get('confidence', 'unknown')} attribution)."
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index.get(rule_id, 0),
            "level": _LEVELS.get(severity, "note"),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1, "startColumn": 1},
                    },
                    "logicalLocations": [
                        {
                            "name": package.get("name") or "unknown",
                            "kind": "package",
                            "fullyQualifiedName": package.get("purl")
                            or package.get("name"),
                        }
                    ],
                }
            ],
            "partialFingerprints": {"layersecopsFinding/v1": finding.get("id")},
            "properties": {
                "severity": severity,
                "riskScore": (finding.get("risk") or {}).get("score"),
                "package": package.get("name"),
                "installedVersion": package.get("version"),
                "fixedVersions": package.get("fixedVersions") or [],
                "packageType": package.get("type"),
                "purl": package.get("purl"),
                "layerIndex": layer.get("index"),
                "layerDigest": layer.get("digest"),
                "layerConfidence": layer.get("confidence"),
                "layerEvidence": layer.get("evidence"),
                "knownExploited": finding.get("knownExploited"),
                "epss": finding.get("epss"),
                "aliases": finding.get("aliases") or [],
                "sources": [
                    {
                        "tool": source.get("tool"),
                        "scanner": source.get("scanner"),
                        "vulnerabilityId": source.get("vulnerabilityId"),
                    }
                    for source in finding.get("sources") or []
                ],
            },
        }
        results.append(result)

    errors = scan.get("errors") or []
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "layersecops",
                "informationUri": "https://github.com/",
                "version": __version__,
                "rules": rules,
            }
        },
        "invocations": [
            {
                "executionSuccessful": scan.get("status") != "failed",
                "startTimeUtc": scan.get("startedAt"),
                "endTimeUtc": scan.get("finishedAt"),
                "toolExecutionNotifications": [
                    {
                        "level": "error",
                        "message": {"text": error},
                    }
                    for error in errors
                ],
            }
        ],
        "properties": {
            "image": image_ref,
            "imageId": image.get("id"),
            "imageDigest": image.get("digest"),
            "scanId": scan.get("id"),
            "validationPassed": (document.get("validation") or {}).get("passed"),
        },
        "results": results,
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
