from __future__ import annotations

import unittest
from pathlib import Path

from layersecops.tools import dive, grype, syft, trivy

FIXTURES = Path(__file__).parent / "fixtures"


class ParserTests(unittest.TestCase):
    def test_trivy_fixture(self) -> None:
        parsed = trivy.parse(FIXTURES / "trivy.json")
        self.assertEqual(len(parsed.findings), 3)
        self.assertEqual(parsed.image_id, "sha256:imageid")
        self.assertEqual(parsed.distro["name"], "debian")
        self.assertEqual(parsed.distro["version"], "12.5")

        ssl = next(item for item in parsed.findings if item.vulnerability_id == "CVE-2024-1234")
        self.assertEqual(ssl.severity, "critical")
        self.assertEqual(ssl.package.name, "libssl3")
        self.assertEqual(ssl.package.type, "deb")
        self.assertEqual(ssl.package.fixed_versions, ["3.0.13-1"])
        self.assertEqual(ssl.package.layer_hints, ["sha256:diff3", "sha256:layer3"])
        self.assertEqual(ssl.sources[0].layer_hint, "sha256:diff3")
        self.assertEqual(ssl.sources[0].tool, "trivy")
        self.assertEqual(ssl.cvss[0].score, 9.8)
        self.assertEqual(ssl.cwe_ids, ["CWE-295"])

        secret = next(item for item in parsed.findings if item.kind == "secret")
        self.assertEqual(secret.vulnerability_id, "aws-access-key-id")
        self.assertEqual(secret.package.path, "etc/credentials")
        self.assertNotIn("Match", secret.to_dict())

    def test_grype_fixture(self) -> None:
        parsed = grype.parse(FIXTURES / "grype.json")
        self.assertEqual(len(parsed.findings), 2)
        self.assertEqual(parsed.image_id, "sha256:imageid")
        ssl = next(item for item in parsed.findings if item.vulnerability_id == "CVE-2024-1234")
        self.assertEqual(ssl.severity, "critical")
        self.assertEqual(ssl.epss, 0.91)
        self.assertTrue(ssl.known_exploited)
        self.assertEqual(ssl.package.path, "usr/lib/x86_64-linux-gnu/libssl.so.3")
        self.assertIn("sha256:layer3", ssl.package.layer_hints)

        lodash = next(item for item in parsed.findings if item.package.name == "lodash")
        self.assertEqual(lodash.vulnerability_id, "GHSA-wxyz-5678-abcd")
        self.assertIn("CVE-2024-9999", lodash.aliases)
        self.assertEqual(lodash.package.type, "npm")

    def test_syft_fixture(self) -> None:
        parsed = syft.parse(FIXTURES / "syft.json")
        self.assertEqual(len(parsed.packages), 3)
        self.assertEqual(parsed.distro["prettyName"], "Debian GNU/Linux 12 (bookworm)")
        ssl = next(item for item in parsed.packages if item.name == "libssl3")
        self.assertIn("usr/lib/x86_64-linux-gnu/libssl.so.3", ssl.files)
        self.assertIn("var/lib/dpkg/status", ssl.files)
        self.assertEqual(ssl.src_name, "openssl")
        self.assertEqual(ssl.path, "usr/lib/x86_64-linux-gnu/libssl.so.3")

    def test_dive_fixture(self) -> None:
        parsed = dive.parse(FIXTURES / "dive.json")
        self.assertEqual(len(parsed.layers), 6)
        self.assertEqual(parsed.layers[3].digest, "sha256:layer3")
        self.assertEqual(parsed.layers[3].command, "RUN apt-get install -y libssl3 zlib1g")
        self.assertIn(
            "usr/lib/x86_64-linux-gnu/libssl.so.3",
            parsed.files_by_layer[3],
        )
        self.assertEqual(parsed.efficiency["score"], 0.9)

    def test_dive_new_schema(self) -> None:
        parsed = dive.parse(FIXTURES / "dive-new.json")
        self.assertEqual(len(parsed.layers), 2)
        self.assertEqual(parsed.layers[0].diff_id, "sha256:diff0")
        self.assertIn("usr/bin/curl", parsed.files_by_layer[1])
        self.assertEqual(parsed.efficiency["score"], 0.93)
        self.assertEqual(parsed.efficiency["wastedBytes"], 10)
        self.assertEqual(parsed.efficiency["wastedPercent"], 6.67)


if __name__ == "__main__":
    unittest.main()
