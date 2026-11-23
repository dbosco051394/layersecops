"""Shared parsing helpers for scanner output."""

from __future__ import annotations

import posixpath
from typing import Any, Iterable

from layersecops.models import Cvss
from layersecops.util import deep_get, unique

# Files whose layer location identifies where a package manager recorded an
# installed package. They are useful attribution evidence, but weaker than the
# actual files owned by the package.
PACKAGE_DB_PATHS = (
    "var/lib/dpkg/status",
    "var/lib/dpkg/status.d/",
    "lib/apk/db/installed",
    "var/lib/rpm/",
    "usr/lib/sysimage/rpm/",
    "var/lib/pacman/local/",
    "var/lib/portage/",
    "var/db/pkg/",
)


def normalize_path(path: str | None) -> str | None:
    if not path:
        return None
    value = str(path).replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    value = value.lstrip("/")
    if not value:
        return None
    value = posixpath.normpath(value)
    if value in (".", ""):
        return None
    return value


def is_package_db_path(path: str | None) -> bool:
    normalized = normalize_path(path)
    if not normalized:
        return False
    return any(
        normalized == candidate or normalized.startswith(candidate)
        for candidate in PACKAGE_DB_PATHS
    )


def trivy_cvss(data: Any) -> list[Cvss]:
    scores: list[Cvss] = []
    if not isinstance(data, dict):
        return scores

    def add_entry(entry: dict[str, Any], source: str | None) -> None:
        for score_key, vector_key, default_version in (
            ("V4Score", "V4Vector", "4.0"),
            ("V3Score", "V3Vector", "3.1"),
            ("V2Score", "V2Vector", "2.0"),
        ):
            raw_score = entry.get(score_key)
            if raw_score is None:
                continue
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                continue
            vector = entry.get(vector_key) or entry.get("Vector")
            version = default_version
            if isinstance(vector, str) and vector.upper().startswith("CVSS:"):
                version = vector.split(":", 1)[1].split("/", 1)[0]
            scores.append(Cvss(version=version, score=score, vector=vector, source=source))

    # Trivy normally returns {"nvd": {...}, "redhat": {...}}, but tolerate a
    # flat {"V3Score": ...} object as well.
    if any(key.endswith("Score") for key in data):
        add_entry(data, None)
    else:
        for vendor, entry in data.items():
            if isinstance(entry, dict):
                add_entry(entry, vendor)
            elif isinstance(entry, (int, float)) and "score" in vendor.lower():
                scores.append(Cvss(version="unknown", score=float(entry), source=vendor))
    return scores


def grype_cvss(data: Any) -> list[Cvss]:
    scores: list[Cvss] = []
    if not isinstance(data, list):
        return scores
    for entry in data:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics") or {}
        raw_score = metrics.get("baseScore") if isinstance(metrics, dict) else None
        if raw_score is None:
            raw_score = entry.get("score")
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            continue
        scores.append(
            Cvss(
                version=str(entry.get("version") or "unknown"),
                score=score,
                vector=entry.get("vector"),
                source=entry.get("vendor") or entry.get("source"),
            )
        )
    return scores


def max_epss(data: Any) -> float | None:
    values: list[float] = []
    if isinstance(data, list):
        for entry in data:
            raw = entry.get("epss") if isinstance(entry, dict) else entry
            try:
                values.append(float(raw))
            except (TypeError, ValueError):
                continue
    elif isinstance(data, dict):
        try:
            values.append(float(data.get("epss")))
        except (TypeError, ValueError):
            pass
    return max(values) if values else None


def has_kev(data: Any) -> bool:
    if isinstance(data, list):
        return bool(data)
    if isinstance(data, dict):
        return bool(data.get("kev") or data.get("knownExploited"))
    return bool(data)


def layer_hints_from_trivy(layer: Any) -> list[str]:
    if not isinstance(layer, dict):
        return []
    hints = [
        layer.get("DiffID"),
        layer.get("diff_id"),
        layer.get("Digest"),
        layer.get("digest"),
    ]
    return [hint for hint in hints if hint]


def layer_hint_from_trivy(layer: Any) -> str | None:
    hints = layer_hints_from_trivy(layer)
    return hints[0] if hints else None


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def references_from(*values: Any) -> list[str]:
    refs: list[str] = []
    for value in values:
        refs.extend(string_list(value))
    return unique([ref for ref in refs if ref.startswith(("http://", "https://"))])


def distro_from_trivy(metadata: dict[str, Any]) -> dict[str, Any]:
    os_info = metadata.get("OS") or {}
    family = os_info.get("Family")
    version = os_info.get("Name")
    if not family and not version:
        return {}
    return {
        "name": family,
        "version": version,
        "prettyName": " ".join(part for part in (family, version) if part) or None,
    }


def distro_from_syft(distro: dict[str, Any]) -> dict[str, Any]:
    if not distro:
        return {}
    return {
        "name": distro.get("id") or distro.get("name"),
        "version": distro.get("versionID") or distro.get("version"),
        "prettyName": distro.get("prettyName") or distro.get("name"),
        "idLike": distro.get("idLike"),
    }


def image_metadata_from_syft(source: dict[str, Any]) -> dict[str, Any]:
    target = (source or {}).get("target") or {}
    return {
        "imageID": target.get("imageID"),
        "manifestDigest": target.get("manifestDigest"),
        "tags": string_list(target.get("tags")),
        "imageSize": target.get("imageSize"),
        "userInput": target.get("userInput"),
    }


def package_files_from_metadata(metadata: dict[str, Any]) -> list[str]:
    files: list[str] = []
    raw_files = metadata.get("files")
    if isinstance(raw_files, list):
        for item in raw_files:
            if isinstance(item, str):
                files.append(item)
            elif isinstance(item, dict):
                path = item.get("path") or item.get("Path")
                if path:
                    files.append(str(path))
    # Some catalogers expose a single package database file instead.
    for key in ("file", "path", "installedFile"):
        value = metadata.get(key)
        if isinstance(value, str):
            files.append(value)
    return unique([normalize_path(item) for item in files if item])


def first_non_db_path(paths: Iterable[str | None]) -> str | None:
    normalized = [normalize_path(path) for path in paths]
    for path in normalized:
        if path and not is_package_db_path(path):
            return path
    return next((path for path in normalized if path), None)


def layer_id_from_location(location: dict[str, Any]) -> str | None:
    return (
        location.get("layerID")
        or location.get("layerId")
        or location.get("layer")
        or None
    )


def purl_from(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith("pkg:"):
        return value
    return None


def nested_purl(data: dict[str, Any]) -> str | None:
    return (
        purl_from(deep_get(data, "PkgIdentifier", "PURL"))
        or purl_from(data.get("purl"))
        or purl_from(data.get("PURL"))
    )
