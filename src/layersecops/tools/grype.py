"""Grype adapter: command construction and JSON normalization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from layersecops.errors import ToolExecutionError
from layersecops.models import Finding, FindingSource, PackageRef
from layersecops.normalize import (
    normalize_ecosystem,
    normalize_package_type,
    normalize_severity,
)
from layersecops.tools.base import ParsedScan
from layersecops.tools.common import (
    first_non_db_path,
    grype_cvss,
    has_kev,
    layer_id_from_location,
    max_epss,
    normalize_path,
    references_from,
    string_list,
)
from layersecops.util import deep_get, read_json, split_versions, unique


def build_args(
    *,
    output: Path,
    image_tar: Path | None = None,
    sbom: Path | None = None,
    scope: str = "squashed",
) -> list[str]:
    if sbom is not None:
        target = f"sbom:{sbom}"
    elif image_tar is not None:
        target = f"docker-archive:{image_tar}"
    else:
        raise ValueError("Grype needs either an SBOM or an image archive")

    # Offline mode is controlled with GRYPE_DB_AUTO_UPDATE=false (see pipeline);
    # recent Grype releases no longer accept a --db-auto-update flag.
    return [target, "-o", "json", "--file", str(output), "--scope", scope]


def _fix_info(vulnerability: dict[str, Any]) -> tuple[list[str], str]:
    fix = vulnerability.get("fix") or {}
    versions = split_versions(fix.get("versions"))
    state = str(fix.get("state") or "").strip().lower()
    if state in {"wont-fix", "wont_fix", "will-not-fix"}:
        return versions, "wont-fix"
    if state in {"fixed", "fix-available"} or versions:
        return versions, "fixed"
    if state in {"not-fixed", "unfixed", "affected"}:
        return versions, "affected"
    return versions, "affected"


def parse(path: Path) -> ParsedScan:
    try:
        data = read_json(path)
    except (OSError, ValueError) as exc:
        raise ToolExecutionError(f"Could not parse Grype JSON at {path}: {exc}") from exc

    target = deep_get(data, "source", "target", default={}) or {}
    distro = data.get("distro") or {}
    distro_name = distro.get("name") or distro.get("id")
    parsed = ParsedScan(
        distro={
            "name": distro_name,
            "version": distro.get("version") or distro.get("versionID"),
            "prettyName": distro.get("prettyName")
            or " ".join(part for part in (distro_name, distro.get("version")) if part)
            or None,
        }
        if distro
        else {},
        image_id=target.get("imageID") or target.get("imageId"),
        metadata={
            "manifestDigest": target.get("manifestDigest"),
            "tags": string_list(target.get("tags")),
            "imageSize": target.get("imageSize"),
            "descriptor": data.get("descriptor"),
        },
    )

    for match in data.get("matches") or []:
        if not isinstance(match, dict):
            continue
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vulnerability_id = str(vulnerability.get("id") or "").strip()
        if not vulnerability_id:
            continue

        related = vulnerability.get("relatedVulnerabilities") or match.get(
            "relatedVulnerabilities"
        ) or []
        related_ids = [
            str(item.get("id")).strip()
            for item in related
            if isinstance(item, dict) and item.get("id")
        ]
        advisories = vulnerability.get("advisories") or []
        advisory_ids = [
            str(item.get("id")).strip()
            for item in advisories
            if isinstance(item, dict) and item.get("id")
        ]
        aliases = unique([*related_ids, *advisory_ids])

        severity = normalize_severity(vulnerability.get("severity"))
        fixed_versions, status = _fix_info(vulnerability)
        cvss = grype_cvss(vulnerability.get("cvss"))
        epss = max_epss(vulnerability.get("epss"))
        kev = has_kev(vulnerability.get("kev"))

        locations = [
            location
            for location in (artifact.get("locations") or [])
            if isinstance(location, dict)
        ]
        paths = [normalize_path(location.get("path")) for location in locations]
        layer_hints = unique(
            [
                hint
                for hint in (layer_id_from_location(location) for location in locations)
                if hint
            ]
        )
        pkg_type = normalize_package_type(artifact.get("type"))
        purl = artifact.get("purl") if isinstance(artifact.get("purl"), str) else None
        package_path = first_non_db_path(paths)
        references = references_from(
            vulnerability.get("urls"),
            vulnerability.get("dataSource"),
            [item.get("link") for item in advisories if isinstance(item, dict)],
        )
        primary_url = next(
            (url for url in string_list(vulnerability.get("urls")) if url.startswith("http")),
            vulnerability.get("dataSource")
            if str(vulnerability.get("dataSource", "")).startswith("http")
            else None,
        )

        package = PackageRef(
            name=str(artifact.get("name") or ""),
            version=str(artifact.get("version") or ""),
            type=pkg_type,
            purl=purl,
            ecosystem=normalize_ecosystem(pkg_type, distro_name),
            path=package_path,
            fixed_versions=fixed_versions,
            files=unique([path for path in paths if path]),
            layer_hints=layer_hints,
        )
        source = FindingSource(
            tool="grype",
            scanner="vuln",
            vulnerability_id=vulnerability_id,
            severity=severity,
            fixed_versions=fixed_versions,
            target=target.get("userInput") if isinstance(target, dict) else None,
            path=package_path,
            layer_hint=layer_hints[0] if layer_hints else None,
            url=primary_url,
            status=status,
            cvss=cvss,
        )
        parsed.findings.append(
            Finding(
                id="",
                kind="vulnerability",
                vulnerability_id=vulnerability_id,
                aliases=aliases,
                title=None,
                description=vulnerability.get("description"),
                severity=severity,
                status=status,
                package=package,
                cvss=cvss,
                epss=epss,
                known_exploited=kev,
                sources=[source],
                references=references,
                primary_url=primary_url,
            )
        )

    return parsed
