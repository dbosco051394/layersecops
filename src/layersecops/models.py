"""Unified data model for scan results.

Every scanner is reduced to these objects before reports are written. The
serialized shape is the stable contract consumed by CI systems and the HTML
report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Cvss:
    version: str
    score: float
    vector: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "score": round(float(self.score), 1),
            "vector": self.vector,
            "source": self.source,
        }


@dataclass
class Layer:
    index: int
    digest: str | None = None
    diff_id: str | None = None
    size_bytes: int | None = None
    command: str | None = None
    created_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "digest": self.digest,
            "diffId": self.diff_id,
            "sizeBytes": self.size_bytes,
            "command": self.command,
            "createdAt": self.created_at,
        }


@dataclass
class LayerAttribution:
    index: int | None
    digest: str | None = None
    diff_id: str | None = None
    command: str | None = None
    confidence: str = "unknown"
    evidence: str | None = None
    path: str | None = None
    introduced_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "digest": self.digest,
            "diffId": self.diff_id,
            "command": self.command,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "path": self.path,
            "introducedIndex": self.introduced_index,
        }


@dataclass
class PackageRef:
    name: str
    version: str
    type: str = "unknown"
    purl: str | None = None
    ecosystem: str | None = None
    path: str | None = None
    fixed_versions: list[str] = field(default_factory=list)
    src_name: str | None = None
    src_version: str | None = None
    # Internal: candidate file paths and layer ids used for attribution.
    files: list[str] = field(default_factory=list, repr=False)
    layer_hints: list[str] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "type": self.type,
            "ecosystem": self.ecosystem,
            "purl": self.purl,
            "path": self.path,
            "fixedVersions": self.fixed_versions,
            "srcName": self.src_name,
            "srcVersion": self.src_version,
        }


@dataclass
class FindingSource:
    tool: str
    scanner: str
    vulnerability_id: str
    severity: str
    fixed_versions: list[str] = field(default_factory=list)
    target: str | None = None
    path: str | None = None
    layer_hint: str | None = None
    url: str | None = None
    status: str = "unknown"
    cvss: list[Cvss] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "scanner": self.scanner,
            "vulnerabilityId": self.vulnerability_id,
            "severity": self.severity,
            "fixedVersions": self.fixed_versions,
            "target": self.target,
            "path": self.path,
            "layerHint": self.layer_hint,
            "url": self.url,
            "status": self.status,
            "cvss": [score.to_dict() for score in self.cvss],
        }


@dataclass
class Finding:
    id: str
    kind: str
    vulnerability_id: str
    aliases: list[str]
    severity: str
    status: str
    package: PackageRef
    title: str | None = None
    description: str | None = None
    cvss: list[Cvss] = field(default_factory=list)
    epss: float | None = None
    known_exploited: bool = False
    risk_score: float = 0.0
    risk_source: str = "none"
    layer: LayerAttribution | None = None
    sources: list[FindingSource] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    primary_url: str | None = None
    cwe_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "vulnerabilityId": self.vulnerability_id,
            "aliases": self.aliases,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "risk": {"score": round(float(self.risk_score), 1), "source": self.risk_source},
            "cvss": [score.to_dict() for score in self.cvss],
            "epss": self.epss,
            "knownExploited": self.known_exploited,
            "cweIds": self.cwe_ids,
            "package": self.package.to_dict(),
            "layer": self.layer.to_dict() if self.layer else None,
            "sources": [source.to_dict() for source in self.sources],
            "references": self.references,
            "primaryUrl": self.primary_url,
        }


@dataclass
class ToolStatus:
    name: str
    path: str | None = None
    version: str | None = None
    status: str = "not-run"  # ok | failed | skipped | missing | not-run
    duration_ms: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "version": self.version,
            "status": self.status,
            "durationMs": self.duration_ms,
            "error": self.error,
        }


@dataclass
class ImageInfo:
    reference: str
    id: str | None = None
    digest: str | None = None
    tags: list[str] = field(default_factory=list)
    architecture: str | None = None
    os: str | None = None
    distro: dict[str, Any] = field(default_factory=dict)
    size_bytes: int | None = None
    layers: list[Layer] = field(default_factory=list)
    efficiency: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reference": self.reference,
            "id": self.id,
            "digest": self.digest,
            "tags": self.tags,
            "architecture": self.architecture,
            "os": self.os,
            "distro": self.distro,
            "sizeBytes": self.size_bytes,
            "layers": [layer.to_dict() for layer in self.layers],
            "efficiency": self.efficiency,
        }
