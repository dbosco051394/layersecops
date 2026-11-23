"""Map files in the final image back to the layer that owns them."""

from __future__ import annotations

import posixpath
import re
from bisect import bisect_left
from dataclasses import dataclass
from typing import Iterable

from layersecops.models import Layer, LayerAttribution, PackageRef
from layersecops.tools.common import is_package_db_path, normalize_path
from layersecops.util import unique

_WHITEOUT_PREFIX = ".wh."
_OPAQUE_WHITEOUT = ".wh..wh..opq"


@dataclass
class LayerFileSet:
    index: int
    files: list[str]


class LayerIndex:
    """Ownership index for the final rootfs, plus per-layer file history."""

    def __init__(
        self,
        layers: Iterable[Layer],
        files_by_layer: dict[int, Iterable[str]] | None = None,
    ) -> None:
        self.layers = sorted(layers, key=lambda layer: layer.index)
        self.by_index = {layer.index: layer for layer in self.layers}
        self.by_digest: dict[str, int] = {}
        self.by_diff_id: dict[str, int] = {}
        for layer in self.layers:
            self._index_identifier(self.by_digest, layer.digest, layer.index)
            self._index_identifier(self.by_diff_id, layer.diff_id, layer.index)

        self.file_owner: dict[str, int] = {}
        self.file_introduced: dict[str, int] = {}
        self.owner_history: dict[str, list[int]] = {}
        self.files_by_layer: dict[int, list[str]] = {}
        self.warnings: list[str] = []
        self._basename_index: dict[str, list[tuple[int, str]]] | None = None
        self._segment_index: dict[str, list[tuple[int, str]]] | None = None
        self._basename_sorted: list[str] = []

        for index in sorted(files_by_layer or {}):
            self._apply_layer(index, files_by_layer[index])

    @staticmethod
    def _index_identifier(mapping: dict[str, int], value: str | None, index: int) -> None:
        if not value:
            return
        mapping[value] = index
        if ":" in value:
            mapping[value.split(":", 1)[1]] = index
        else:
            mapping[f"sha256:{value}"] = index

    def _apply_layer(self, index: int, paths: Iterable[str]) -> None:
        normalized_paths: list[str] = []
        for raw_path in paths:
            path = normalize_path(raw_path)
            if not path:
                continue
            basename = posixpath.basename(path)
            if basename.startswith(_WHITEOUT_PREFIX):
                directory = posixpath.dirname(path)
                if basename == _OPAQUE_WHITEOUT:
                    prefix = f"{directory}/" if directory else ""
                    for existing in [key for key in self.file_owner if key.startswith(prefix)]:
                        self.file_owner.pop(existing, None)
                else:
                    target = posixpath.join(directory, basename[len(_WHITEOUT_PREFIX) :])
                    self._remove(target)
                continue

            normalized_paths.append(path)
            self.file_owner[path] = index
            self.file_introduced.setdefault(path, index)
            history = self.owner_history.setdefault(path, [])
            if not history or history[-1] != index:
                history.append(index)

        self.files_by_layer[index] = normalized_paths

    def _remove(self, target: str) -> None:
        self.file_owner.pop(target, None)
        prefix = f"{target}/"
        for existing in [key for key in self.file_owner if key.startswith(prefix)]:
            self.file_owner.pop(existing, None)

    def owner_of(self, path: str | None) -> int | None:
        normalized = normalize_path(path)
        return self.file_owner.get(normalized) if normalized else None

    def historical_owner(self, path: str | None) -> int | None:
        normalized = normalize_path(path)
        if not normalized:
            return None
        history = self.owner_history.get(normalized)
        return history[-1] if history else None

    def owner_by_hint(self, hint: str | None) -> int | None:
        if not hint:
            return None
        value = str(hint).strip()
        candidates = [value]
        if value.startswith("sha256:"):
            candidates.append(value.split(":", 1)[1])
        else:
            candidates.append(f"sha256:{value}")
        for candidate in candidates:
            if candidate in self.by_digest:
                return self.by_digest[candidate]
            if candidate in self.by_diff_id:
                return self.by_diff_id[candidate]
        return None

    def layer(self, index: int | None) -> Layer | None:
        return self.by_index.get(index) if index is not None else None

    def _attribution(
        self,
        index: int | None,
        *,
        confidence: str,
        evidence: str | None,
        path: str | None,
    ) -> LayerAttribution:
        layer = self.layer(index)
        introduced = self.file_introduced.get(path) if path else None
        return LayerAttribution(
            index=index,
            digest=layer.digest if layer else None,
            diff_id=layer.diff_id if layer else None,
            command=layer.command if layer else None,
            confidence=confidence,
            evidence=evidence,
            path=path,
            introduced_index=introduced if introduced is not None else index,
        )

    def attribute(
        self,
        package: PackageRef,
        *,
        hints: Iterable[str | None] = (),
        path_hint: str | None = None,
        tool: str | None = None,
    ) -> LayerAttribution:
        """Attribute a package to a layer using evidence, strongest first.

        Evidence order:
        1. exact ownership of a package file (from Syft metadata/locations)
        2. a layer id/digest reported by Trivy or Grype
        3. ownership of the package-manager database file
        4. a path that existed earlier but was deleted later
        5. a conservative filename/directory-name heuristic
        """
        candidates = unique(
            [path_hint, package.path, *package.files]
        )
        exact_file: tuple[int, str] | None = None
        exact_db: tuple[int, str] | None = None
        historical: tuple[int, str] | None = None
        for candidate in candidates:
            normalized = normalize_path(candidate)
            if not normalized:
                continue
            owner = self.file_owner.get(normalized)
            if owner is not None:
                if is_package_db_path(normalized):
                    exact_db = exact_db or (owner, normalized)
                else:
                    exact_file = exact_file or (owner, normalized)
            previous = self.owner_history.get(normalized)
            if previous and historical is None:
                historical = (previous[-1], normalized)

        if exact_file:
            index, path = exact_file
            return self._attribution(
                index,
                confidence="exact",
                evidence=f"package file is owned by layer {index}",
                path=path,
            )

        for hint in unique([*package.layer_hints, *hints]):
            index = self.owner_by_hint(hint)
            if index is not None:
                return self._attribution(
                    index,
                    confidence="tool",
                    evidence=f"layer reported by {tool or 'scanner'} ({hint})",
                    path=path_hint,
                )

        if exact_db:
            index, path = exact_db
            return self._attribution(
                index,
                confidence="db",
                evidence=f"package database file is owned by layer {index}: {path}",
                path=path,
            )

        if historical:
            index, path = historical
            return self._attribution(
                index,
                confidence="historical",
                evidence=f"file was present in layer {index} but removed later: {path}",
                path=path,
            )

        if package.name and package.name != "(secret)":
            heuristic = self._heuristic(package)
            if heuristic:
                return heuristic

        return self._attribution(
            None,
            confidence="unknown",
            evidence="no layer evidence available for this package",
            path=package.path,
        )

    def _ensure_name_indexes(self) -> None:
        if self._basename_index is not None:
            return
        basename_index: dict[str, list[tuple[int, str]]] = {}
        segment_index: dict[str, list[tuple[int, str]]] = {}
        for path, index in self.file_owner.items():
            basename = posixpath.basename(path).lower()
            if basename:
                basename_index.setdefault(basename, []).append((index, path))
            for segment in path.split("/")[:-1]:
                segment = segment.lower()
                if len(segment) >= 3:
                    segment_index.setdefault(segment, []).append((index, path))
        self._basename_index = basename_index
        self._segment_index = segment_index
        self._basename_sorted = sorted(basename_index)

    @staticmethod
    def _package_tokens(name: str) -> list[str]:
        name = name.strip().lower()
        if len(name) < 3:
            return []
        tokens = {name}
        if name.startswith("lib") and len(name) > 5:
            tokens.add(name[3:])
        without_digits = re.sub(r"\d+$", "", name)
        if len(without_digits) >= 3:
            tokens.add(without_digits)
        if "_" in name:
            tokens.add(name.replace("_", "-"))
        if "-" in name:
            tokens.add(name.replace("-", "_"))
        return [token for token in tokens if len(token) >= 3]

    def _heuristic(self, package: PackageRef) -> LayerAttribution | None:
        self._ensure_name_indexes()
        assert self._basename_index is not None and self._segment_index is not None
        matches: dict[str, tuple[int, int]] = {}  # path -> (priority, layer index)

        for token in self._package_tokens(package.name):
            for index, path in self._basename_index.get(token, [])[:500]:
                matches.setdefault(path, (0, index))
            for index, path in self._segment_index.get(token, [])[:500]:
                matches.setdefault(path, (1, index))
            # Basenames such as libssl.so.3 for the package libssl3.
            position = bisect_left(self._basename_sorted, token)
            while position < len(self._basename_sorted):
                basename = self._basename_sorted[position]
                if not basename.startswith(token):
                    break
                suffix = basename[len(token) : len(token) + 1]
                if basename != token and (suffix in (".", "-", "_") or suffix.isdigit()):
                    for index, path in self._basename_index[basename][:50]:
                        matches.setdefault(path, (0, index))
                position += 1

        if not matches:
            return None
        path, (priority, index) = max(
            matches.items(),
            key=lambda item: (item[1][1], -item[1][0], len(item[0])),
        )
        return self._attribution(
            index,
            confidence="inferred",
            evidence=(
                f"matched package name '{package.name}' against layer file path "
                f"(priority {priority})"
            ),
            path=path,
        )


def build_layer_index(
    layers: Iterable[Layer],
    *,
    dive_files: dict[int, Iterable[str]] | None = None,
    tar_files: dict[int, Iterable[str]] | None = None,
) -> LayerIndex:
    combined: dict[int, list[str]] = {}
    for source in (tar_files or {}, dive_files or {}):
        for index, paths in source.items():
            combined.setdefault(index, []).extend(paths)
    normalized = {index: unique(paths) for index, paths in combined.items()}
    return LayerIndex(layers, normalized)
