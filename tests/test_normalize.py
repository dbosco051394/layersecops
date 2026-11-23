from __future__ import annotations

import unittest
from pathlib import Path

from layersecops.normalize import (
    canonical_vulnerability_id,
    deduplicate,
    normalize_package_type,
    normalize_severity,
)
from layersecops.models import Finding, PackageRef
from layersecops.tools import grype, trivy

FIXTURES = Path(__file__).parent / "fixtures"


class NormalizeTests(unittest.TestCase):
    def test_severity_mapping(self) -> None:
        self.assertEqual(normalize_severity("CRITICAL"), "critical")
        self.assertEqual(normalize_severity("Moderate"), "medium")
        self.assertEqual(normalize_severity("Negligible"), "negligible")
        self.assertEqual(normalize_severity(None), "unknown")
        self.assertEqual(normalize_severity("bogus"), "unknown")

    def test_package_type_mapping(self) -> None:
        self.assertEqual(normalize_package_type("debian"), "deb")
        self.assertEqual(normalize_package_type("ubuntu"), "deb")
        self.assertEqual(normalize_package_type("alpine"), "apk")
        self.assertEqual(normalize_package_type("redhat"), "rpm")
        self.assertEqual(normalize_package_type("gomod"), "go")
        self.assertEqual(normalize_package_type("java-archive"), "java")
        self.assertEqual(normalize_package_type("npm"), "npm")

    def test_canonical_id_prefers_cve(self) -> None:
        self.assertEqual(
            canonical_vulnerability_id("GHSA-abcd-1234-efgh", ["CVE-2024-1234"]),
            "CVE-2024-1234",
        )
        self.assertEqual(
            canonical_vulnerability_id("GHSA-abcd-1234-efgh"), "GHSA-ABCD-1234-EFGH"
        )

    def test_deduplicate_trivy_and_grype(self) -> None:
        trivy_scan = trivy.parse(FIXTURES / "trivy.json")
        grype_scan = grype.parse(FIXTURES / "grype.json")
        findings = deduplicate([*trivy_scan.findings, *grype_scan.findings])

        self.assertEqual(len(findings), 4)
        ssl = next(item for item in findings if item.vulnerability_id == "CVE-2024-1234")
        self.assertEqual(len(ssl.sources), 2)
        self.assertEqual({source.tool for source in ssl.sources}, {"trivy", "grype"})
        self.assertEqual(ssl.severity, "critical")
        self.assertTrue(ssl.known_exploited)
        self.assertEqual(ssl.epss, 0.91)
        self.assertEqual(ssl.package.fixed_versions, ["3.0.13-1"])
        self.assertEqual(ssl.risk_source, "cvss")
        self.assertAlmostEqual(ssl.risk_score, 9.8)
        self.assertIn("GHSA-ABCD-1234-EFGH", ssl.aliases)

        lodash = next(item for item in findings if item.package.name == "lodash")
        self.assertEqual(lodash.vulnerability_id, "CVE-2024-9999")
        self.assertIn("GHSA-WXYZ-5678-ABCD", lodash.aliases)

        secrets = [item for item in findings if item.kind == "secret"]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].id, "secret:aws-access-key-id:etc/credentials")

    def test_deduplicate_type_unknown_merges(self) -> None:
        trivy_scan = trivy.parse(FIXTURES / "trivy.json")
        grype_scan = grype.parse(FIXTURES / "grype.json")
        for finding in trivy_scan.findings:
            if finding.package.name == "libssl3":
                finding.package.type = "unknown"
        findings = deduplicate([*trivy_scan.findings, *grype_scan.findings])
        ssl = next(item for item in findings if item.vulnerability_id == "CVE-2024-1234")
        self.assertEqual(len(ssl.sources), 2)
        self.assertEqual(ssl.package.type, "deb")

    def test_deduplicate_unknown_not_duplicated_across_types(self) -> None:
        def make(pkg_type: str) -> Finding:
            return Finding(
                id="",
                kind="vulnerability",
                vulnerability_id="CVE-2024-0001",
                aliases=[],
                severity="high",
                status="affected",
                package=PackageRef(name="shared", version="1.0", type=pkg_type),
            )

        findings = deduplicate([make("deb"), make("rpm"), make("unknown")])
        self.assertEqual(len(findings), 2)
        self.assertEqual({item.package.type for item in findings}, {"deb", "rpm"})
        self.assertEqual(len({item.id for item in findings}), 2)


if __name__ == "__main__":
    unittest.main()
