"""Syft adapter: SBOM generation and package inventory parsing."""

from __future__ import annotations

from pathlib import Path

from layersecops.errors import ToolExecutionError
from layersecops.models import PackageRef
from layersecops.normalize import normalize_ecosystem, normalize_package_type
from layersecops.tools.base import ParsedScan
from layersecops.tools.common import (
    distro_from_syft,
    first_non_db_path,
    image_metadata_from_syft,
    layer_id_from_location,
    normalize_path,
    package_files_from_metadata,
)
from layersecops.util import read_json, unique


def build_args(
    *,
    image_tar: Path,
    output: Path,
    scope: str = "squashed",
    quiet: bool = True,
) -> list[str]:
    args = [
        f"docker-archive:{image_tar}",
        "-o",
        "json",
        "--file",
        str(output),
        "--scope",
        scope,
    ]
    if quiet:
        args.append("--quiet")
    return args


def parse(path: Path) -> ParsedScan:
    try:
        data = read_json(path)
    except (OSError, ValueError) as exc:
        raise ToolExecutionError(f"Could not parse Syft JSON at {path}: {exc}") from exc

    distro = distro_from_syft(data.get("distro") or {})
    source = data.get("source") or {}
    image_meta = image_metadata_from_syft(source)
    distro_name = distro.get("name")
    parsed = ParsedScan(
        distro=distro,
        image_id=image_meta.get("imageID"),
        metadata={
            **image_meta,
            "descriptor": data.get("descriptor"),
            "schema": data.get("schema"),
            "sourceName": source.get("name"),
            "sourceVersion": source.get("version"),
        },
    )

    for artifact in data.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        name = str(artifact.get("name") or "").strip()
        if not name:
            continue
        version = str(artifact.get("version") or "").strip()
        pkg_type = normalize_package_type(artifact.get("type"))
        metadata = artifact.get("metadata") or {}
        locations = [
            location
            for location in (artifact.get("locations") or [])
            if isinstance(location, dict)
        ]
        location_paths = [
            normalize_path(location.get("path")) for location in locations
        ]
        metadata_files = package_files_from_metadata(metadata)
        layer_hints = unique(
            [
                hint
                for hint in (layer_id_from_location(location) for location in locations)
                if hint
            ]
        )
        all_paths = unique(
            [path for path in [*location_paths, *metadata_files] if path]
        )
        purl = artifact.get("purl") if isinstance(artifact.get("purl"), str) else None

        source_name = metadata.get("source") or metadata.get("origin")
        source_version = metadata.get("sourceVersion")
        package = PackageRef(
            name=name,
            version=version,
            type=pkg_type,
            purl=purl,
            ecosystem=normalize_ecosystem(pkg_type, distro_name),
            path=first_non_db_path(all_paths),
            src_name=source_name if isinstance(source_name, str) else None,
            src_version=source_version if isinstance(source_version, str) else None,
            files=all_paths,
            layer_hints=layer_hints,
        )
        parsed.packages.append(package)

    return parsed
