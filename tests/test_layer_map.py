from __future__ import annotations

import unittest

from layersecops.layer_map import LayerIndex, build_layer_index
from layersecops.models import Layer, PackageRef


class LayerIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.layers = [
            Layer(index=0, digest="sha256:layer0", diff_id="sha256:diff0", command="ADD rootfs"),
            Layer(index=1, digest="sha256:layer1", command="RUN apt update"),
            Layer(index=2, digest="sha256:layer2", command="RUN rm libssl"),
            Layer(index=3, digest="sha256:layer3", command="RUN apt install libssl3 zlib1g"),
            Layer(index=4, digest="sha256:layer4", command="ENV X=1"),
            Layer(index=5, digest="sha256:layer5", command="COPY app /app"),
        ]
        self.files = {
            0: ["etc/os-release", "var/lib/dpkg/status"],
            1: ["usr/lib/x86_64-linux-gnu/libssl.so.3"],
            2: ["usr/lib/x86_64-linux-gnu/.wh.libssl.so.3"],
            3: ["usr/lib/x86_64-linux-gnu/libssl.so.3", "usr/lib/x86_64-linux-gnu/libz.so.1"],
            4: [],
            5: ["app/node_modules/lodash/package.json"],
        }
        self.index = LayerIndex(self.layers, self.files)

    def test_final_owner_after_whiteout(self) -> None:
        self.assertEqual(self.index.owner_of("usr/lib/x86_64-linux-gnu/libssl.so.3"), 3)
        self.assertEqual(self.index.file_introduced["usr/lib/x86_64-linux-gnu/libssl.so.3"], 1)
        self.assertEqual(self.index.owner_of("usr/lib/x86_64-linux-gnu/libz.so.1"), 3)
        self.assertEqual(self.index.owner_of("app/node_modules/lodash/package.json"), 5)

    def test_opaque_whiteout(self) -> None:
        index = LayerIndex(
            [Layer(index=0), Layer(index=1)],
            {0: ["a/b", "a/c", "a/d/e"], 1: ["a/.wh..wh..opq"]},
        )
        self.assertIsNone(index.owner_of("a/b"))
        self.assertIsNone(index.owner_of("a/d/e"))

    def test_exact_attribution(self) -> None:
        package = PackageRef(
            name="libssl3",
            version="3.0.11-1",
            type="deb",
            path="usr/lib/x86_64-linux-gnu/libssl.so.3",
            files=["usr/lib/x86_64-linux-gnu/libssl.so.3"],
        )
        layer = self.index.attribute(package)
        self.assertEqual(layer.index, 3)
        self.assertEqual(layer.confidence, "exact")
        self.assertEqual(layer.command, "RUN apt install libssl3 zlib1g")
        self.assertEqual(layer.introduced_index, 1)

    def test_tool_hint_attribution(self) -> None:
        package = PackageRef(name="libssl3", version="3.0.11-1", type="deb")
        layer = self.index.attribute(package, hints=["sha256:layer3"], tool="trivy")
        self.assertEqual(layer.index, 3)
        self.assertEqual(layer.confidence, "tool")
        self.assertIn("trivy", layer.evidence)

    def test_db_attribution(self) -> None:
        package = PackageRef(
            name="zlib1g",
            version="1:1.2.13",
            type="deb",
            path="var/lib/dpkg/status",
            files=["var/lib/dpkg/status"],
        )
        layer = self.index.attribute(package)
        self.assertEqual(layer.index, 0)
        self.assertEqual(layer.confidence, "db")

    def test_heuristic_attribution(self) -> None:
        package = PackageRef(name="lodash", version="4.17.20", type="npm")
        layer = self.index.attribute(package)
        self.assertEqual(layer.index, 5)
        self.assertEqual(layer.confidence, "inferred")

    def test_unknown_attribution(self) -> None:
        package = PackageRef(name="not-installed", version="1.0", type="deb")
        layer = self.index.attribute(package)
        self.assertIsNone(layer.index)
        self.assertEqual(layer.confidence, "unknown")

    def test_build_layer_index_combines_sources(self) -> None:
        index = build_layer_index(
            self.layers,
            dive_files={3: ["usr/lib/x86_64-linux-gnu/libssl.so.3"]},
            tar_files={0: ["etc/os-release"]},
        )
        self.assertEqual(index.owner_of("etc/os-release"), 0)
        self.assertEqual(index.owner_of("usr/lib/x86_64-linux-gnu/libssl.so.3"), 3)


if __name__ == "__main__":
    unittest.main()
