"""Trivy adapter: command construction and JSON normalization."""

from __future__ import annotations

from pathlib import Path

from layersecops.errors import ToolExecutionError
from layersecops.models import Finding, FindingSource, PackageRef
from layersecops.normalize import (
    normalize_ecosystem,
    normalize_package_type,
    normalize_severity,
)
from layersecops.tools.base import ParsedScan
from layersecops.tools.common import (
    distro_from_trivy,
    layer_hint_from_trivy,
    layer_hints_from_trivy,
    nested_purl,
    normalize_path,
    references_from,
    string_list,
    trivy_cvss,
)
from layersecops.util import read_json, split_versions, unique


def build_args(
    image_tar: Path,
    output: Path,
    *,
    scanners: list[str],
    cache_dir: Path | None = None,
    offline: bool = False,
    timeout: str = "15m",
) -> list[str]:
    args = [
        "image",
        "--input",
        str(image_tar),
        "--format",
        "json",
        "--output",
        str(output),
        "--scanners",
        ",".join(scanners),
        "--timeout",
        timeout,
        "--no-progress",
        "--quiet",
    ]
    if cache_dir:
        args.extend(["--cache-dir", str(cache_dir)])
    if offline:
        args.append("--skip-db-update")
    return args


def parse(path: Path) -> ParsedScan:
    try:
        data = read_json(path)
    except (OSError, ValueError) as exc:
        raise ToolExecutionError(f"Could not parse Trivy JSON at {path}: {exc}") from exc

    metadata = data.get("Metadata") or {}
    distro = distro_from_trivy(metadata)
    distro_name = distro.get("name")
    parsed = ParsedScan(
        distro=distro,
        image_id=metadata.get("ImageID"),
        metadata={
            "artifactName": data.get("ArtifactName"),
            "artifactType": data.get("ArtifactType"),
            "schemaVersion": data.get("SchemaVersion"),
            "repoTags": string_list(metadata.get("RepoTags")),
            "repoDigests": string_list(metadata.get("RepoDigests")),
            "architecture": (metadata.get("ImageConfig") or {}).get("architecture")
            or metadata.get("Architecture"),
            "os": (metadata.get("ImageConfig") or {}).get("os")
            or (metadata.get("OS") or {}).get("Family"),
            "layerDigests": {},
        },
    )
    layer_digests: dict[str, str] = parsed.metadata["layerDigests"]

    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target")
        result_type = normalize_package_type(result.get("Type"))
        ecosystem = normalize_ecosystem(result_type, distro_name)

        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vulnerability_id = str(vuln.get("VulnerabilityID") or "").strip()
            if not vulnerability_id:
                continue
            package_name = str(vuln.get("PkgName") or vuln.get("PkgID") or "").strip()
            installed = str(vuln.get("InstalledVersion") or "").strip()
            fixed_versions = split_versions(vuln.get("FixedVersion"))
            purl = nested_purl(vuln)
            pkg_path = normalize_path(vuln.get("PkgPath"))
            severity = normalize_severity(vuln.get("Severity"))
            vendor_ids = string_list(vuln.get("VendorIDs"))
            cvss = trivy_cvss(vuln.get("CVSS"))
            hint = layer_hint_from_trivy(vuln.get("Layer"))
            hints = layer_hints_from_trivy(vuln.get("Layer"))
            layer_data = vuln.get("Layer") if isinstance(vuln.get("Layer"), dict) else {}
            diff_id = layer_data.get("DiffID") or layer_data.get("diff_id")
            digest_id = layer_data.get("Digest") or layer_data.get("digest")
            if diff_id and digest_id:
                layer_digests[str(diff_id)] = str(digest_id)
            status_value = str(vuln.get("Status") or "").lower()
            if status_value == "fixed" or fixed_versions:
                status = "fixed"
            elif status_value in {"will_not_fix", "wont-fix", "wont_fix"}:
                status = "wont-fix"
            else:
                status = "affected"

            package = PackageRef(
                name=package_name,
                version=installed,
                type=result_type,
                purl=purl,
                ecosystem=ecosystem,
                path=pkg_path,
                fixed_versions=fixed_versions,
                src_name=vuln.get("SrcName"),
                src_version=vuln.get("SrcVersion"),
                files=unique([item for item in (pkg_path,) if item]),
                layer_hints=unique(hints),
            )
            references = references_from(
                vuln.get("PrimaryURL"),
                vuln.get("References"),
            )
            source = FindingSource(
                tool="trivy",
                scanner="vuln",
                vulnerability_id=vulnerability_id,
                severity=severity,
                fixed_versions=fixed_versions,
                target=target,
                path=pkg_path,
                layer_hint=hint,
                url=vuln.get("PrimaryURL"),
                status=status,
                cvss=cvss,
            )
            parsed.findings.append(
                Finding(
                    id="",
                    kind="vulnerability",
                    vulnerability_id=vulnerability_id,
                    aliases=vendor_ids,
                    title=vuln.get("Title"),
                    description=vuln.get("Description"),
                    severity=severity,
                    status=status,
                    package=package,
                    cvss=cvss,
                    sources=[source],
                    references=references,
                    primary_url=vuln.get("PrimaryURL"),
                    cwe_ids=string_list(vuln.get("CweIDs")),
                )
            )

        # Secrets are reported per file. Never include the matched value.
        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            rule_id = str(secret.get("RuleID") or "").strip()
            if not rule_id:
                continue
            severity = normalize_severity(secret.get("Severity"))
            path_value = normalize_path(target)
            hint = layer_hint_from_trivy(secret.get("Layer"))
            hints = layer_hints_from_trivy(secret.get("Layer"))
            layer_data = secret.get("Layer") if isinstance(secret.get("Layer"), dict) else {}
            diff_id = layer_data.get("DiffID") or layer_data.get("diff_id")
            digest_id = layer_data.get("Digest") or layer_data.get("digest")
            if diff_id and digest_id:
                layer_digests[str(diff_id)] = str(digest_id)
            package = PackageRef(
                name="(secret)",
                version="",
                type="secret",
                path=path_value,
                files=unique([item for item in (path_value,) if item]),
                layer_hints=unique(hints),
            )
            source = FindingSource(
                tool="trivy",
                scanner="secret",
                vulnerability_id=rule_id,
                severity=severity,
                target=target,
                path=path_value,
                layer_hint=hint,
                status="detected",
            )
            parsed.findings.append(
                Finding(
                    id="",
                    kind="secret",
                    vulnerability_id=rule_id,
                    aliases=[],
                    title=secret.get("Title") or rule_id,
                    description=secret.get("Category"),
                    severity=severity,
                    status="detected",
                    package=package,
                    sources=[source],
                    references=[],
                )
            )

    return parsed
