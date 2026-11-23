"""Dive adapter: layer metadata, file trees and image efficiency."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from layersecops.errors import ToolExecutionError
from layersecops.models import Layer
from layersecops.tools.common import normalize_path
from layersecops.util import read_json, unique


@dataclass
class DiveResult:
    layers: list[Layer] = field(default_factory=list)
    files_by_layer: dict[int, list[str]] = field(default_factory=dict)
    efficiency: dict[str, Any] = field(default_factory=dict)
    image: dict[str, Any] = field(default_factory=dict)


def build_args(image_tar: Path, output: Path) -> list[str]:
    return [
        str(image_tar),
        "--source",
        "docker-archive",
        "--json",
        str(output),
    ]


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


def _files_from_tree(node: Any, base: str = "", files: list[str] | None = None) -> list[str]:
    if files is None:
        files = []
    if isinstance(node, list):
        for child in node:
            _files_from_tree(child, base, files)
        return files
    if not isinstance(node, dict):
        return files

    raw_name = node.get("path") or node.get("name")
    current = base
    if isinstance(raw_name, str) and raw_name:
        if raw_name.startswith("/"):
            current = raw_name
        else:
            current = posixpath.join(base, raw_name) if base else raw_name

    is_dir = bool(node.get("isDir") or node.get("is_dir") or node.get("dir"))
    normalized = normalize_path(current)
    if normalized and not is_dir:
        files.append(normalized)

    children = node.get("children")
    if children is None:
        children = node.get("files")
    for child in _as_list(children):
        _files_from_tree(child, current, files)
    return files


def _files_from_layer(layer: dict[str, Any]) -> list[str]:
    files: list[str] = []

    for key in ("fileList", "files"):
        raw = layer.get(key)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    files.append(item)
                elif isinstance(item, dict):
                    if item.get("isDir") or item.get("is_dir"):
                        continue
                    path = item.get("path") or item.get("name")
                    if path:
                        files.append(str(path))
            if files:
                break

    tree = layer.get("fileTree")
    if tree:
        tree_files = _files_from_tree(tree)
        files.extend(tree_files)

    normalized = [normalize_path(item) for item in files]
    return unique([item for item in normalized if item])


def parse(path: Path) -> DiveResult:
    try:
        data = read_json(path)
    except (OSError, ValueError) as exc:
        raise ToolExecutionError(f"Could not parse Dive JSON at {path}: {exc}") from exc

    image = data.get("image") if isinstance(data.get("image"), dict) else data
    raw_layers = None
    if isinstance(data.get("layer"), list):
        raw_layers = data["layer"]
    elif isinstance(data.get("layers"), list):
        raw_layers = data["layers"]
    elif isinstance(image, dict) and isinstance(image.get("layers"), list):
        raw_layers = image["layers"]
    raw_layers = raw_layers or []

    result = DiveResult(image=image or {})
    for position, raw_layer in enumerate(raw_layers):
        if not isinstance(raw_layer, dict):
            continue
        raw_index = raw_layer.get("index")
        index = raw_index if isinstance(raw_index, int) else position
        layer = Layer(
            index=index,
            digest=raw_layer.get("digest"),
            diff_id=raw_layer.get("diffId")
            or raw_layer.get("diffID")
            or raw_layer.get("digestId"),
            size_bytes=raw_layer.get("size") or raw_layer.get("sizeBytes"),
            command=raw_layer.get("command"),
            created_at=raw_layer.get("created") or raw_layer.get("createdAt"),
        )
        result.layers.append(layer)
        result.files_by_layer[index] = _files_from_layer(raw_layer)

    result.layers.sort(key=lambda item: item.index)
    efficiency = image.get("efficiency") or data.get("efficiency") or {}
    if not isinstance(efficiency, dict):
        efficiency = {}
    score = efficiency.get("score")
    wasted_bytes = efficiency.get("wastedBytes") or efficiency.get("wasted_bytes")
    wasted_percent = efficiency.get("wastedPercent") or efficiency.get("wasted_percent")
    if score is None and isinstance(image, dict):
        score = image.get("efficiencyScore")
    if wasted_bytes is None and isinstance(image, dict):
        wasted_bytes = image.get("inefficientBytes")
    if wasted_percent is None and wasted_bytes is not None:
        total = image.get("sizeBytes") if isinstance(image, dict) else None
        try:
            if total:
                wasted_percent = round(float(wasted_bytes) / float(total) * 100, 2)
        except (TypeError, ValueError, ZeroDivisionError):
            wasted_percent = None
    result.efficiency = {
        "score": score,
        "wastedBytes": wasted_bytes,
        "wastedPercent": wasted_percent,
    }
    return result
