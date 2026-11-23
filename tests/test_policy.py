from __future__ import annotations

import unittest

from layersecops.config import Policy, evaluate_policy
from layersecops.models import Finding, LayerAttribution, PackageRef


def finding(
    vuln_id: str,
    severity: str,
    *,
    package: str = "pkg",
    version: str = "1.0",
    fixed: list[str] | None = None,
    layer: int | None = 1,
    aliases: list[str] | None = None,
) -> Finding:
    return Finding(
        id=f"{vuln_id}:{package}",
        kind="vulnerability",
        vulnerability_id=vuln_id,
        aliases=aliases or [],
        severity=severity,
        status="fixed" if fixed else "affected",
        package=PackageRef(
            name=package,
            version=version,
            type="deb",
            fixed_versions=fixed or [],
        ),
        layer=LayerAttribution(index=layer),
    )


class PolicyTests(unittest.TestCase):
    def test_fail_on_high(self) -> None:
        findings = [
            finding("CVE-1", "critical"),
            finding("CVE-2", "high"),
            finding("CVE-3", "medium"),
        ]
        result = evaluate_policy(findings, Policy(fail_on="high"))
        self.assertFalse(result["passed"])
        self.assertEqual(len(result["violations"]), 2)
        self.assertEqual(result["counts"]["critical"], 1)

    def test_ignore_glob(self) -> None:
        findings = [finding("CVE-2024-1111", "critical"), finding("CVE-2024-2222", "high")]
        result = evaluate_policy(findings, Policy(fail_on="high", ignore_ids=["CVE-2024-1*"]))
        self.assertFalse(result["passed"])
        self.assertEqual(len(result["violations"]), 1)
        self.assertEqual(result["violations"][0]["vulnerabilityId"], "CVE-2024-2222")

    def test_ignore_unfixed(self) -> None:
        findings = [
            finding("CVE-1", "critical", fixed=["1.1"]),
            finding("CVE-2", "critical", fixed=[]),
        ]
        result = evaluate_policy(findings, Policy(fail_on="high", ignore_unfixed=True))
        self.assertFalse(result["passed"])
        self.assertEqual(len(result["violations"]), 1)
        self.assertEqual(result["ignored"], 1)

    def test_max_critical(self) -> None:
        findings = [finding("CVE-1", "critical"), finding("CVE-2", "critical")]
        result = evaluate_policy(findings, Policy(fail_on="none", max_critical=1))
        self.assertFalse(result["passed"])
        self.assertEqual(result["violations"][0]["type"], "count")

    def test_pass(self) -> None:
        result = evaluate_policy([finding("CVE-1", "low")], Policy(fail_on="high"))
        self.assertTrue(result["passed"])


if __name__ == "__main__":
    unittest.main()
