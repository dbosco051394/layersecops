"""Normalization, canonicalization and deduplication of scanner output."""

from __future__ import annotations

import re
from typing import Iterable

from layersecops.models import Cvss, Finding, FindingSource, PackageRef
from layersecops.util import split_versions, unique

SEVERITY_RANK = {
    "unknown": 0,
    "negligible": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

SEVERITY_DISPLAY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"]

SEVERITY_FALLBACK_SCORE = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.0,
    "negligible": 0.5,
    "unknown": 0.0,
}

_SEVERITY_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "important": "high",
    "moderate": "medium",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "minor": "low",
    "negligible": "negligible",
    "info": "low",
    "informational": "low",
    "none": "unknown",
    "unknown": "unknown",
    "unspecified": "unknown",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)
_ADVISORY_RE = re.compile(
    r"^(?:USN|DSA|DLA|RHSA|RHBA|RHEA|ALAS|ALSA|ELSA|SUSE-SU|openSUSE-SU|"
    r"MGASA|MSRC|GO|PYPA|GMS|SNYK|CGA|GHSA)-",
    re.IGNORECASE,
)

_OS_TYPE_MAP = {
    "debian": "deb",
    "ubuntu": "deb",
    "linuxmint": "deb",
    "raspbian": "deb",
    "alpine": "apk",
    "wolfi": "apk",
    "chainguard": "apk",
    "redhat": "rpm",
    "rhel": "rpm",
    "centos": "rpm",
    "rocky": "rpm",
    "almalinux": "rpm",
    "alma": "rpm",
    "amazon": "rpm",
    "amzn": "rpm",
    "oracle": "rpm",
    "ol": "rpm",
    "sles": "rpm",
    "suse": "rpm",
    "opensuse": "rpm",
    "opensuse-leap": "rpm",
    "opensuse-tumbleweed": "rpm",
    "photon": "rpm",
    "mariner": "rpm",
    "azurelinux": "rpm",
    "fedora": "rpm",
}

_TYPE_MAP = {
    # OS package manager names
    **_OS_TYPE_MAP,
    # language ecosystems (Trivy / Grype / Syft spellings)
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "bun": "npm",
    "python": "python",
    "pip": "python",
    "poetry": "python",
    "python-pkg": "python",
    "go": "go",
    "gomod": "go",
    "go-module": "go",
    "gobinary": "go",
    "java": "java",
    "jar": "java",
    "maven": "java",
    "gradle": "java",
    "java-archive": "java",
    "gem": "gem",
    "ruby": "gem",
    "rubygems": "gem",
    "cargo": "rust",
    "rust": "rust",
    "rust-crate": "rust",
    "composer": "php",
    "php": "php",
    "php-composer": "php",
    "nuget": "dotnet",
    "dotnet": "dotnet",
    ".net": "dotnet",
    "binary": "binary",
    "bin": "binary",
    "conda": "conda",
    "conda-pkg": "conda",
    "nix": "nix",
    "portage": "portage",
    "apk": "apk",
    "deb": "deb",
    "rpm": "rpm",
    "linux-kernel": "kernel",
    "kernel": "kernel",
}

_ECOSYSTEM_MAP = {
    "deb": "debian",
    "apk": "alpine",
    "rpm": "rpm",
    "python": "pypi",
    "npm": "npm",
    "java": "maven",
    "go": "golang",
    "gem": "rubygems",
    "rust": "cargo",
    "php": "packagist",
    "dotnet": "nuget",
    "conda": "conda",
}


def normalize_severity(value: str | None) -> str:
    if not value:
        return "unknown"
    key = str(value).strip().lower()
    return _SEVERITY_ALIASES.get(key, key if key in SEVERITY_RANK else "unknown")


def severity_rank(value: str | None) -> int:
    return SEVERITY_RANK.get(normalize_severity(value), 0)


def max_severity(values: Iterable[str | None]) -> str:
    best = "unknown"
    for value in values:
        normalized = normalize_severity(value)
        if SEVERITY_RANK[normalized] > SEVERITY_RANK[best]:
            best = normalized
    return best


def normalize_package_type(value: str | None) -> str:
    if not value:
        return "unknown"
    key = str(value).strip().lower().replace(" ", "-")
    if key in _TYPE_MAP:
        return _TYPE_MAP[key]
    if key.startswith("python"):
        return "python"
    if key.startswith("node"):
        return "npm"
    return key


def normalize_ecosystem(pkg_type: str | None, distro: str | None = None) -> str | None:
    pkg_type = normalize_package_type(pkg_type)
    if pkg_type in {"deb", "apk", "rpm"}:
        if distro:
            distro_key = distro.strip().lower().replace(" ", "-")
            if distro_key in _OS_TYPE_MAP:
                return distro_key
            return distro_key
    return _ECOSYSTEM_MAP.get(pkg_type)


def is_cve(value: str) -> bool:
    return bool(_CVE_RE.match(value.strip()))


def is_ghsa(value: str) -> bool:
    return bool(_GHSA_RE.match(value.strip()))


def normalize_identifier(value: str | None) -> str:
    if not value:
        return ""
    identifier = str(value).strip()
    if is_cve(identifier) or is_ghsa(identifier) or _ADVISORY_RE.match(identifier):
        return identifier.upper()
    return identifier


def canonical_vulnerability_id(primary: str, aliases: Iterable[str] = ()) -> str:
    """Pick the most portable identifier, preferring a CVE when one exists."""
    candidates = unique([primary, *aliases])
    candidates = [normalize_identifier(item) for item in candidates if item]
    if not candidates:
        return "UNKNOWN"
    for candidate in candidates:
        if is_cve(candidate):
            return candidate.upper()
    for candidate in candidates:
        if is_ghsa(candidate):
            return candidate.upper()
    for candidate in candidates:
        if _ADVISORY_RE.match(candidate):
            return candidate.upper()
    return candidates[0]


def severity_fallback_score(severity: str) -> float:
    return SEVERITY_FALLBACK_SCORE.get(normalize_severity(severity), 0.0)


def finding_risk(finding: Finding) -> tuple[float, str]:
    scores = [float(score.score) for score in finding.cvss if score.score is not None]
    if scores:
        return round(max(scores), 1), "cvss"
    return round(severity_fallback_score(finding.severity), 1), "severity-fallback"


def _safe_id_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9:._@/+~-]+", "-", value.strip())


def make_finding_id(canonical: str, package: PackageRef) -> str:
    return _safe_id_part(
        f"{canonical}:{package.type}:{package.name}@{package.version or 'unknown'}"
    )


def make_secret_id(rule_id: str, path: str | None) -> str:
    return _safe_id_part(f"secret:{rule_id}:{path or 'unknown'}")


def _cvss_key(score: Cvss) -> tuple:
    return (score.version, score.vector or "", round(float(score.score), 1), score.source or "")


def _merge_package(primary: PackageRef, others: Iterable[PackageRef]) -> PackageRef:
    merged = PackageRef(
        name=primary.name,
        version=primary.version,
        type=primary.type,
        purl=primary.purl,
        ecosystem=primary.ecosystem,
        path=primary.path,
        fixed_versions=list(primary.fixed_versions),
        src_name=primary.src_name,
        src_version=primary.src_version,
        files=list(primary.files),
        layer_hints=list(primary.layer_hints),
    )
    for other in others:
        if not merged.purl and other.purl:
            merged.purl = other.purl
        if not merged.ecosystem and other.ecosystem:
            merged.ecosystem = other.ecosystem
        if not merged.path and other.path:
            merged.path = other.path
        if not merged.src_name and other.src_name:
            merged.src_name = other.src_name
        if not merged.src_version and other.src_version:
            merged.src_version = other.src_version
        if merged.type == "unknown" and other.type != "unknown":
            merged.type = other.type
        merged.fixed_versions = unique([*merged.fixed_versions, *other.fixed_versions])
        merged.files = unique([*merged.files, *other.files])
        merged.layer_hints = unique([*merged.layer_hints, *other.layer_hints])
    return merged


def _merge_findings(group: list[Finding]) -> Finding:
    group = sorted(
        group,
        key=lambda item: (
            severity_rank(item.severity),
            len(item.sources),
            len(item.description or ""),
        ),
        reverse=True,
    )
    primary = group[0]
    others = group[1:]

    all_ids = unique(
        [
            *(
                [normalize_identifier(primary.vulnerability_id)]
                if primary.vulnerability_id
                else []
            ),
            *[normalize_identifier(alias) for alias in primary.aliases],
            *[normalize_identifier(item.vulnerability_id) for item in others],
            *[
                normalize_identifier(alias)
                for item in others
                for alias in item.aliases
            ],
        ]
    )
    canonical = canonical_vulnerability_id(primary.vulnerability_id, all_ids)

    package = _merge_package(primary.package, [item.package for item in others])
    severity = max_severity([item.severity for item in group])
    fixed_versions = unique(
        [
            *package.fixed_versions,
            *[version for item in group for version in item.package.fixed_versions],
        ]
    )
    package.fixed_versions = fixed_versions

    sources: list[FindingSource] = []
    source_keys: set[tuple] = set()
    for item in group:
        for source in item.sources:
            key = (source.tool, source.scanner, source.vulnerability_id, source.target)
            if key in source_keys:
                continue
            source_keys.add(key)
            sources.append(source)

    cvss: list[Cvss] = []
    cvss_keys: set[tuple] = set()
    for item in group:
        for score in item.cvss:
            key = _cvss_key(score)
            if key not in cvss_keys:
                cvss_keys.add(key)
                cvss.append(score)
    cvss.sort(key=lambda score: (score.version, score.score), reverse=True)

    references = unique([reference for item in group for reference in item.references])
    cwe_ids = unique([cwe for item in group for cwe in item.cwe_ids])
    primary_url = next((item.primary_url for item in group if item.primary_url), None)
    title = next((item.title for item in group if item.title), None)
    description = max(
        (item.description for item in group if item.description),
        key=len,
        default=None,
    )
    epss_values = [item.epss for item in group if item.epss is not None]
    epss = max(epss_values) if epss_values else None

    statuses = {source.status for source in sources}
    if fixed_versions:
        status = "fixed"
    elif "wont-fix" in statuses:
        status = "wont-fix"
    elif "affected" in statuses or "detected" in statuses:
        status = "affected"
    else:
        status = primary.status or "unknown"

    if primary.kind == "secret":
        finding_id = make_secret_id(canonical, package.path or primary.package.path)
    else:
        finding_id = make_finding_id(canonical, package)

    merged = Finding(
        id=finding_id,
        kind=primary.kind,
        vulnerability_id=canonical,
        aliases=[item for item in all_ids if item.upper() != canonical.upper()],
        title=title,
        description=description,
        severity=severity,
        status=status,
        package=package,
        cvss=cvss,
        epss=epss,
        known_exploited=any(item.known_exploited for item in group),
        layer=None,
        sources=sources,
        references=references,
        primary_url=primary_url,
        cwe_ids=cwe_ids,
    )
    merged.risk_score, merged.risk_source = finding_risk(merged)
    return merged


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Merge findings that describe the same vulnerability in the same package.

    Two passes are used: an exact key, then a compatibility merge so that a
    package typed ``unknown`` by one scanner still merges with ``deb`` from
    another.
    """
    buckets: dict[tuple, list[Finding]] = {}
    for finding in findings:
        canonical = canonical_vulnerability_id(finding.vulnerability_id, finding.aliases)
        if finding.kind == "secret":
            key = ("secret", canonical, finding.package.path or "")
        else:
            key = (
                "vulnerability",
                canonical,
                finding.package.name.lower(),
                finding.package.version,
            )
        buckets.setdefault(key, []).append(finding)

    merged: list[Finding] = []
    for bucket in buckets.values():
        by_type: dict[str, list[Finding]] = {}
        for item in bucket:
            by_type.setdefault(item.package.type, []).append(item)
        if len(by_type) == 1:
            merged.append(_merge_findings(bucket))
            continue

        # Merge unknown-typed findings into the first concrete type only, so a
        # single unknown finding never produces duplicate merged findings.
        known_types = sorted(key for key in by_type if key != "unknown")
        if not known_types:
            merged.append(_merge_findings(bucket))
            continue
        unknown_group = by_type.pop("unknown", [])
        for position, pkg_type in enumerate(known_types):
            group = list(by_type[pkg_type])
            if position == 0:
                group.extend(unknown_group)
            merged.append(_merge_findings(group))

    # Defensive: identical IDs can appear if identifiers collide.
    final: dict[str, Finding] = {}
    for finding in merged:
        base = finding.id
        suffix = 2
        while finding.id in final:
            finding.id = f"{base}-{suffix}"
            suffix += 1
        final[finding.id] = finding

    return sorted(
        final.values(),
        key=lambda item: (
            -severity_rank(item.severity),
            -float(item.risk_score),
            item.vulnerability_id,
            item.package.name,
        ),
    )


def merge_fixed_versions(*values: str | Iterable[str] | None) -> list[str]:
    collected: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            collected.extend(split_versions(value))
        else:
            collected.extend(str(item) for item in value)
    return unique([item for item in collected if item])
