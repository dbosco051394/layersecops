from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from layersecops.config import ConfigError, Policy, Settings, load_ignore_file, load_settings


class ConfigTests(unittest.TestCase):
    def test_load_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ignore.txt").write_text("# comment\nCVE-2023-*\nGHSA-1234\n", encoding="utf-8")
            (root / "layersecops.toml").write_text(
                """
[scan]
tools = ["trivy", "grype"]
require_tools = ["trivy"]
scanners = ["vuln", "secret"]
layer_scope = "all-layers"
timeout_seconds = 120
offline = true
output_dir = "out"
formats = ["json", "sarif"]
sbom = true

[policy]
fail_on = "critical"
ignore_unfixed = true
ignore = ["CVE-2022-1"]
ignore_packages = ["linux-*"]
ignore_file = "ignore.txt"
max_critical = 0
max_high = 2
""",
                encoding="utf-8",
            )
            settings = load_settings(root / "layersecops.toml")
            self.assertEqual(settings.tools, ["trivy", "grype"])
            self.assertEqual(settings.require_tools, ["trivy"])
            self.assertEqual(settings.scanners, ["vuln", "secret"])
            self.assertEqual(settings.layer_scope, "all-layers")
            self.assertEqual(settings.timeout, 120)
            self.assertTrue(settings.offline)
            self.assertEqual(settings.output_dir, root / "out")
            self.assertTrue(settings.output_dir_explicit)
            self.assertEqual(settings.formats, ["json", "sarif"])
            self.assertTrue(settings.sbom)
            self.assertEqual(settings.policy.fail_on, "critical")
            self.assertTrue(settings.policy.ignore_unfixed)
            self.assertIn("CVE-2022-1", settings.policy.ignore_ids)
            self.assertIn("CVE-2023-*", settings.policy.ignore_ids)
            self.assertIn("GHSA-1234", settings.policy.ignore_ids)
            self.assertEqual(settings.policy.max_critical, 0)
            self.assertEqual(settings.policy.max_high, 2)

    def test_invalid_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.toml"
            path.write_text('[scan]\nformats = ["xml"]\n', encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_settings(path)

    def test_invalid_layer_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.toml"
            path.write_text('[scan]\nlayer_scope = "everywhere"\n', encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_settings(path)

    def test_ignore_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ignore.txt"
            path.write_text("# x\nCVE-1\n\n CVE-2 \n", encoding="utf-8")
            self.assertEqual(load_ignore_file(path), ["CVE-1", "CVE-2"])

    def test_default_settings(self) -> None:
        settings = Settings()
        self.assertEqual(settings.layer_scope, "all-layers")
        self.assertEqual(settings.log_format, "text")
        self.assertEqual(settings.tools, ["trivy", "grype", "syft", "dive"])


if __name__ == "__main__":
    unittest.main()
