"""Docker/OCI image archive handling.

LayerSecOps never starts a container. Images are read from a local daemon with
``docker save`` or supplied directly as a docker-archive/OCI archive tarball.
"""

from __future__ import annotations

import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from layersecops.errors import ImageLoadError, ToolExecutionError
from layersecops.models import ImageInfo, Layer
from layersecops.tools.common import normalize_path
from layersecops.util import run_command


@dataclass
class ImageArchive:
    path: Path
    image_id: str | None = None
    repo_tags: list[str] = field(default_factory=list)
    repo_digests: list[str] = field(default_factory=list)
    architecture: str | None = None
    os: str | None = None
    created: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    manifest: dict[str, Any] = field(default_factory=dict)
    layers: list[Layer] = field(default_factory=list)
    layer_paths: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    format: str = "docker-archive"
    warnings: list[str] = field(default_factory=list)

    @property
    def size_bytes(self) -> int | None:
        sizes = [layer.size_bytes for layer in self.layers if layer.size_bytes]
        return sum(sizes) if sizes else None


def _json_member(tf: tarfile.TarFile, name: str) -> Any:
    member = tf.getmember(name)
    handle = tf.extractfile(member)
    if handle is None:
        raise ImageLoadError(f"{name} is not a regular file in {tf.name}")
    return json.load(handle)


def _history_entries(config: dict[str, Any]) -> list[dict[str, Any]]:
    history = config.get("history") or []
    return [entry for entry in history if not entry.get("empty_layer")]


def _layer_from_history(
    index: int,
    diff_id: str | None,
    history_entry: dict[str, Any] | None,
    size_bytes: int | None,
    digest: str | None = None,
) -> Layer:
    entry = history_entry or {}
    return Layer(
        index=index,
        digest=digest,
        diff_id=diff_id,
        size_bytes=size_bytes,
        command=entry.get("created_by"),
        created_at=entry.get("created"),
    )


def _digest_from_layer_path(layer_path: str) -> str | None:
    """Recover a compressed layer digest from containerd-style archive paths.

    Modern ``docker save`` (containerd image store) stores layers as
    ``blobs/sha256/<digest>``. Legacy archives use ``<layer-id>/layer.tar``,
    where the directory name is not a digest, so no digest is returned.
    """
    match = re.fullmatch(r"blobs/([a-z0-9]+)/([a-f0-9]{32,128})", layer_path.replace("\\", "/"))
    if not match:
        return None
    return f"{match.group(1)}:{match.group(2)}"


def _read_docker_archive(tf: tarfile.TarFile, path: Path) -> ImageArchive:
    try:
        manifest_data = _json_member(tf, "manifest.json")
    except (KeyError, ValueError) as exc:
        raise ImageLoadError(f"{path} does not contain a valid manifest.json") from exc

    if not isinstance(manifest_data, list) or not manifest_data:
        raise ImageLoadError(f"{path} has an empty or invalid manifest.json")
    if len(manifest_data) > 1:
        # Keep it simple and deterministic: scan the first image in the archive.
        pass
    manifest = manifest_data[0]
    config_name = manifest.get("Config")
    if not config_name:
        raise ImageLoadError(f"{path} manifest has no Config entry")
    try:
        config = _json_member(tf, config_name)
    except (KeyError, ValueError) as exc:
        raise ImageLoadError(f"Could not read image config {config_name}") from exc

    config_stem = Path(config_name).name
    if config_stem.endswith(".json"):
        config_stem = config_stem[:-5]
    image_id = f"sha256:{config_stem}" if re.fullmatch(r"[a-f0-9]{64}", config_stem) else config_stem

    layer_paths = [str(item) for item in manifest.get("Layers") or []]
    diff_ids = list((config.get("rootfs") or {}).get("diff_ids") or [])
    history = _history_entries(config)
    layers: list[Layer] = []
    for index, layer_path in enumerate(layer_paths):
        try:
            member = tf.getmember(layer_path)
            size_bytes = member.size
        except KeyError:
            size_bytes = None
        layers.append(
            _layer_from_history(
                index,
                diff_ids[index] if index < len(diff_ids) else None,
                history[index] if index < len(history) else None,
                size_bytes,
                digest=_digest_from_layer_path(layer_path),
            )
        )

    return ImageArchive(
        path=path,
        image_id=image_id,
        repo_tags=[str(tag) for tag in manifest.get("RepoTags") or []],
        repo_digests=[str(digest) for digest in manifest.get("RepoDigests") or []],
        architecture=config.get("architecture"),
        os=config.get("os"),
        created=config.get("created"),
        labels=((config.get("config") or {}).get("Labels") or {}),
        config=config,
        manifest=manifest,
        layers=layers,
        layer_paths=layer_paths,
        history=history,
        format="docker-archive",
    )


def _read_oci_archive(tf: tarfile.TarFile, path: Path) -> ImageArchive:
    try:
        index = _json_member(tf, "index.json")
    except (KeyError, ValueError) as exc:
        raise ImageLoadError(
            f"{path} is neither a docker-archive nor an OCI archive (no manifest.json or index.json)"
        ) from exc

    manifests = index.get("manifests") or []
    if not manifests:
        raise ImageLoadError(f"{path} OCI index has no manifests")
    descriptor = manifests[0]
    manifest_digest = descriptor.get("digest")
    if not manifest_digest:
        raise ImageLoadError(f"{path} OCI index entry has no digest")
    algorithm, _, hex_digest = manifest_digest.partition(":")
    manifest_path = f"blobs/{algorithm}/{hex_digest}"
    try:
        manifest = _json_member(tf, manifest_path)
    except (KeyError, ValueError) as exc:
        raise ImageLoadError(f"Could not read OCI manifest {manifest_digest}") from exc

    config_descriptor = manifest.get("config") or {}
    config_digest = config_descriptor.get("digest")
    if not config_digest:
        raise ImageLoadError("OCI manifest has no config descriptor")
    algorithm, _, hex_digest = config_digest.partition(":")
    config_path = f"blobs/{algorithm}/{hex_digest}"
    try:
        config = _json_member(tf, config_path)
    except (KeyError, ValueError) as exc:
        raise ImageLoadError(f"Could not read OCI config {config_digest}") from exc

    layer_descriptors = manifest.get("layers") or []
    layer_paths = []
    layer_sizes: list[int | None] = []
    layer_digests: list[str | None] = []
    for layer in layer_descriptors:
        digest = layer.get("digest")
        if not digest:
            continue
        algo, _, value = digest.partition(":")
        layer_paths.append(f"blobs/{algo}/{value}")
        layer_sizes.append(layer.get("size"))
        layer_digests.append(digest)

    diff_ids = list((config.get("rootfs") or {}).get("diff_ids") or [])
    history = _history_entries(config)
    layers = [
        _layer_from_history(
            index,
            diff_ids[index] if index < len(diff_ids) else None,
            history[index] if index < len(history) else None,
            layer_sizes[index] if index < len(layer_sizes) else None,
            digest=layer_digests[index] if index < len(layer_digests) else None,
        )
        for index in range(len(layer_paths))
    ]

    annotations = descriptor.get("annotations") or {}
    tag = annotations.get("org.opencontainers.image.ref.name")
    return ImageArchive(
        path=path,
        image_id=config_digest,
        repo_tags=[str(tag)] if tag else [],
        repo_digests=[manifest_digest],
        architecture=config.get("architecture"),
        os=config.get("os"),
        created=config.get("created"),
        labels=((config.get("config") or {}).get("Labels") or {}),
        config=config,
        manifest=manifest,
        layers=layers,
        layer_paths=layer_paths,
        history=history,
        format="oci-archive",
    )


def read_archive(path: Path) -> ImageArchive:
    path = path.expanduser().resolve()
    if path.is_dir():
        raise ImageLoadError(
            f"{path} is a directory; pass a docker-archive or OCI archive tarball, or use an image reference"
        )
    if not path.is_file():
        raise ImageLoadError(f"Image archive not found: {path}")
    try:
        with tarfile.open(path, "r:*") as tf:
            names = set(tf.getnames())
            if "manifest.json" in names:
                archive = _read_docker_archive(tf, path)
            elif "index.json" in names:
                archive = _read_oci_archive(tf, path)
            else:
                raise ImageLoadError(
                    f"{path} is not a docker-archive or OCI archive "
                    "(expected manifest.json or index.json)"
                )
    except tarfile.TarError as exc:
        raise ImageLoadError(f"Could not open image archive {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ImageLoadError(f"Invalid JSON inside image archive {path}: {exc}") from exc

    if not archive.layers:
        archive.warnings.append("Image archive contains no filesystem layers")
    return archive


def read_layer_files(archive: ImageArchive) -> tuple[dict[int, list[str]], list[str]]:
    """Read member paths directly from each layer tar.

    This is the fallback when Dive is unavailable. It is deliberately streamed
    from the archive and never extracts files to disk.
    """
    files_by_layer: dict[int, list[str]] = {}
    warnings: list[str] = []
    try:
        with tarfile.open(archive.path, "r:*") as outer:
            for index, layer_path in enumerate(archive.layer_paths):
                names: list[str] = []
                try:
                    member = outer.getmember(layer_path)
                    handle = outer.extractfile(member)
                    if handle is None:
                        warnings.append(f"Layer {index} is not a regular file; skipped")
                        continue
                    with tarfile.open(fileobj=handle, mode="r:*") as inner:
                        for item in inner:
                            if item.isdir():
                                continue
                            name = normalize_path(item.name)
                            if name:
                                names.append(name)
                except (KeyError, tarfile.TarError, OSError) as exc:
                    warnings.append(f"Could not read layer {index} ({layer_path}): {exc}")
                files_by_layer[index] = names
    except (OSError, tarfile.TarError) as exc:
        warnings.append(f"Could not reopen image archive for layer inspection: {exc}")
    return files_by_layer, warnings


def save_image(
    reference: str,
    destination: Path,
    *,
    docker: str = "docker",
    pull: bool = False,
    platform: str | None = None,
    timeout: float = 1800,
    log_path: Path | None = None,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if pull:
        args = [docker, "pull"]
        if platform:
            args.extend(["--platform", platform])
        args.append(reference)
        result = run_command(args, timeout=timeout, log_path=log_path)
        if not result.ok:
            raise ToolExecutionError(f"docker pull failed: {result.summary()}")

    args = [docker, "save", "-o", str(destination), reference]
    result = run_command(args, timeout=timeout, log_path=log_path)
    if not result.ok:
        raise ToolExecutionError(f"docker save failed: {result.summary()}")
    if not destination.is_file() or destination.stat().st_size == 0:
        raise ImageLoadError(f"docker save produced no output for {reference}")


def inspect_image(
    reference: str,
    *,
    docker: str = "docker",
    timeout: float = 120,
) -> dict[str, Any] | None:
    result = run_command(
        [docker, "image", "inspect", reference, "--format", "{{json .}}"],
        timeout=timeout,
    )
    if not result.ok:
        return None
    try:
        data = json.loads(result.stdout)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _bare_digest(value: str | None) -> str | None:
    if not value:
        return None
    return value.rsplit("@", 1)[-1] if "@" in value else value


def build_image_info(
    archive: ImageArchive,
    *,
    reference: str,
    dive_layers: list[Layer] | None = None,
    efficiency: dict[str, Any] | None = None,
    distro: dict[str, Any] | None = None,
    inspected: dict[str, Any] | None = None,
) -> ImageInfo:
    layers = [Layer(**layer.__dict__) for layer in archive.layers]
    by_index = {layer.index: layer for layer in layers}
    for dive_layer in dive_layers or []:
        target = by_index.get(dive_layer.index)
        if target is None:
            layers.append(dive_layer)
            continue
        target.digest = target.digest or dive_layer.digest
        target.diff_id = target.diff_id or dive_layer.diff_id
        target.size_bytes = dive_layer.size_bytes or target.size_bytes
        target.command = dive_layer.command or target.command
        target.created_at = dive_layer.created_at or target.created_at
    layers.sort(key=lambda layer: layer.index)

    tags = list(archive.repo_tags)
    digests = list(archive.repo_digests)
    size = archive.size_bytes
    image_id = archive.image_id
    if inspected:
        tags = list(inspected.get("RepoTags") or tags)
        digests = list(inspected.get("RepoDigests") or digests)
        size = inspected.get("Size") or size
        image_id = inspected.get("Id") or image_id

    return ImageInfo(
        reference=reference,
        id=image_id,
        digest=_bare_digest(digests[0]) if digests else None,
        tags=tags,
        architecture=archive.architecture or (inspected or {}).get("Architecture"),
        os=archive.os or (inspected or {}).get("Os"),
        distro=distro or {},
        size_bytes=size,
        layers=layers,
        efficiency=efficiency or {},
    )
