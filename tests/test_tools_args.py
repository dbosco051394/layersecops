from __future__ import annotations

import unittest
from pathlib import Path

from layersecops.tools import dive, grype, syft, trivy


class BuildArgsTests(unittest.TestCase):
    def test_trivy_args_include_input_and_output(self) -> None:
        args = trivy.build_args(
            Path("image.tar"),
            Path("out.json"),
            scanners=["vuln", "secret"],
            cache_dir=Path("cache"),
        )
        self.assertEqual(args[0], "image")
        self.assertIn("--input", args)
        self.assertEqual(args[args.index("--input") + 1], "image.tar")
        self.assertEqual(args[args.index("--output") + 1], "out.json")
        self.assertEqual(args[args.index("--scanners") + 1], "vuln,secret")
        self.assertIn("--cache-dir", args)
        self.assertNotIn("--skip-db-update", args)

    def test_trivy_offline_skips_db_update(self) -> None:
        args = trivy.build_args(Path("i.tar"), Path("o.json"), scanners=["vuln"], offline=True)
        self.assertIn("--skip-db-update", args)

    def test_syft_args_use_docker_archive_and_scope(self) -> None:
        args = syft.build_args(
            image_tar=Path("image.tar"), output=Path("sbom.json"), scope="all-layers"
        )
        self.assertTrue(args[0].startswith("docker-archive:"))
        self.assertIn("all-layers", args)
        self.assertEqual(args[args.index("--file") + 1], "sbom.json")
        self.assertIn("--quiet", args)

    def test_grype_prefers_sbom_and_supports_archive(self) -> None:
        from_sbom = grype.build_args(output=Path("g.json"), sbom=Path("sbom.json"))
        self.assertTrue(from_sbom[0].startswith("sbom:"))
        self.assertEqual(from_sbom[from_sbom.index("-o") + 1], "json")
        # Grype removed --db-auto-update; offline mode uses an environment variable.
        self.assertFalse(any(arg.startswith("--db-auto-update") for arg in from_sbom))

        from_archive = grype.build_args(
            output=Path("g.json"), image_tar=Path("image.tar"), scope="all-layers"
        )
        self.assertTrue(from_archive[0].startswith("docker-archive:"))
        self.assertEqual(from_archive[from_archive.index("--scope") + 1], "all-layers")

    def test_grype_requires_a_target(self) -> None:
        with self.assertRaises(ValueError):
            grype.build_args(output=Path("g.json"))

    def test_dive_args_are_docker_archive_json(self) -> None:
        args = dive.build_args(Path("image.tar"), Path("dive.json"))
        self.assertEqual(args[0], "image.tar")
        self.assertEqual(args[args.index("--source") + 1], "docker-archive")
        self.assertEqual(args[args.index("--json") + 1], "dive.json")


if __name__ == "__main__":
    unittest.main()
