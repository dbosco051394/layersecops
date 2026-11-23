from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from layersecops.image import build_image_info, read_archive, read_layer_files
from layersecops.layer_map import LayerIndex


def _layer_tar(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _add_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def make_docker_archive(path: Path) -> Path:
    layer_files = [
        {"etc/os-release": b"ID=debian\n", "var/lib/dpkg/status": b"Package: libssl3\n"},
        {"usr/lib/x86_64-linux-gnu/libssl.so.3": b"old"},
        {"usr/lib/x86_64-linux-gnu/.wh.libssl.so.3": b""},
        {
            "usr/lib/x86_64-linux-gnu/libssl.so.3": b"new",
            "usr/lib/x86_64-linux-gnu/libz.so.1": b"zlib",
        },
        {"app/node_modules/lodash/package.json": b"{}"},
    ]
    layers = [_layer_tar(files) for files in layer_files]
    config = {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"diff_ids": [f"sha256:diff{i}" for i in range(len(layers))]},
        "history": [
            {"created_by": "ADD rootfs.tar.xz /"},
            {"created_by": "RUN apt-get update"},
            {"created_by": "RUN rm libssl"},
            {"created_by": "ENV FOO=bar", "empty_layer": True},
            {"created_by": "RUN apt-get install -y libssl3 zlib1g"},
            {"created_by": "COPY app /app"},
        ],
    }
    config_bytes = json.dumps(config).encode()
    manifest = [
        {
            "Config": "config.json",
            "RepoTags": ["demo:1.0"],
            "RepoDigests": ["demo@sha256:manifest"],
            "Layers": [f"l{i}/layer.tar" for i in range(len(layers))],
        }
    ]
    with tarfile.open(path, "w") as tf:
        for i, layer in enumerate(layers):
            _add_bytes(tf, f"l{i}/layer.tar", layer)
        _add_bytes(tf, "config.json", config_bytes)
        _add_bytes(tf, "manifest.json", json.dumps(manifest).encode())
    return path


def make_oci_archive(path: Path) -> Path:
    layer = _layer_tar({"usr/bin/hello": b"hello"})
    config = {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"diff_ids": ["sha256:diff0"]},
        "history": [{"created_by": "COPY hello /usr/bin/hello"}],
    }
    config_bytes = json.dumps(config).encode()
    manifest = {
        "schemaVersion": 2,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:c0", "size": len(config_bytes)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:l0", "size": len(layer)}],
    }
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:m0",
                "size": 1,
                "annotations": {"org.opencontainers.image.ref.name": "demo:oci"},
            }
        ],
    }
    with tarfile.open(path, "w") as tf:
        _add_bytes(tf, "index.json", json.dumps(index).encode())
        _add_bytes(tf, "blobs/sha256/m0", json.dumps(manifest).encode())
        _add_bytes(tf, "blobs/sha256/c0", config_bytes)
        _add_bytes(tf, "blobs/sha256/l0", layer)
    return path


class ArchiveTests(unittest.TestCase):
    def test_docker_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = make_docker_archive(Path(tmp) / "image.tar")
            archive = read_archive(path)
            self.assertEqual(archive.format, "docker-archive")
            self.assertEqual(archive.repo_tags, ["demo:1.0"])
            self.assertEqual(len(archive.layers), 5)
            self.assertEqual(archive.layers[4].command, "COPY app /app")
            self.assertEqual(archive.layers[0].diff_id, "sha256:diff0")
            self.assertEqual(archive.layers[3].command, "RUN apt-get install -y libssl3 zlib1g")

            files, warnings = read_layer_files(archive)
            self.assertEqual(warnings, [])
            index = LayerIndex(archive.layers, files)
            self.assertEqual(index.owner_of("usr/lib/x86_64-linux-gnu/libssl.so.3"), 3)
            self.assertEqual(index.owner_of("app/node_modules/lodash/package.json"), 4)

            info = build_image_info(archive, reference="demo:1.0")
            self.assertEqual(info.architecture, "amd64")
            self.assertEqual(info.digest, "sha256:manifest")
            self.assertEqual(len(info.layers), 5)

    def test_oci_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = make_oci_archive(Path(tmp) / "image.tar")
            archive = read_archive(path)
            self.assertEqual(archive.format, "oci-archive")
            self.assertEqual(archive.repo_tags, ["demo:oci"])
            self.assertEqual(len(archive.layers), 1)
            self.assertEqual(archive.layers[0].digest, "sha256:l0")
            files, _ = read_layer_files(archive)
            self.assertIn("usr/bin/hello", files[0])

    def test_docker_archive_blob_layers(self) -> None:
        layer = _layer_tar({"usr/bin/hello": b"hello"})
        digest = "a" * 64
        config = {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"diff_ids": ["sha256:" + "b" * 64]},
            "history": [{"created_by": "COPY hello /usr/bin/hello"}],
        }
        manifest = [
            {
                "Config": f"blobs/sha256/{'c' * 64}",
                "RepoTags": ["demo:blob"],
                "Layers": [f"blobs/sha256/{digest}"],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.tar"
            with tarfile.open(path, "w") as tf:
                _add_bytes(tf, f"blobs/sha256/{digest}", layer)
                _add_bytes(tf, f"blobs/sha256/{'c' * 64}", json.dumps(config).encode())
                _add_bytes(tf, "manifest.json", json.dumps(manifest).encode())
            archive = read_archive(path)
            self.assertEqual(archive.layers[0].digest, f"sha256:{digest}")
            self.assertEqual(archive.layers[0].diff_id, "sha256:" + "b" * 64)
            self.assertEqual(archive.layers[0].size_bytes, len(layer))


if __name__ == "__main__":
    unittest.main()
