from __future__ import annotations

import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from layersecops.mask import (
    MaskRule,
    MaskSet,
    load_mask_file,
    load_masks,
    load_simple_ignore,
    load_toml_mask,
    merge_mask_sets,
)
from layersecops.models import Finding, LayerAttribution, PackageRef


def _finding(vuln_id="CVE-2024-1", package="pkg", severity="high", layer=1, aliases=None):
    return Finding(
        id=f"{vuln_id}:{package}",
        kind="vulnerability",
        vulnerability_id=vuln_id,
        aliases=aliases or [],
        severity=severity,
        status="affected",
        package=PackageRef(name=package, version="1.0", type="deb"),
        layer=LayerAttribution(index=layer),
    )


class MaskRuleTests(unittest.TestCase):
    def test_id_match(self):
        rule = MaskRule(id="CVE-2024-1", reason="test")
        self.assertTrue(rule.matches(_finding("CVE-2024-1")))
        self.assertFalse(rule.matches(_finding("CVE-2024-2")))

    def test_id_glob(self):
        rule = MaskRule(id="CVE-2024-*", reason="test")
        self.assertTrue(rule.matches(_finding("CVE-2024-1")))
        self.assertTrue(rule.matches(_finding("CVE-2024-999")))
        self.assertFalse(rule.matches(_finding("CVE-2023-1")))

    def test_alias_match(self):
        rule = MaskRule(id="CVE-2024-1", reason="test")
        self.assertTrue(rule.matches(_finding("GHSA-xxxx", aliases=["CVE-2024-1"])))

    def test_package_match(self):
        rule = MaskRule(package="openssl*", reason="test")
        self.assertTrue(rule.matches(_finding(package="openssl")))
        self.assertTrue(rule.matches(_finding(package="openssl-dev")))
        self.assertFalse(rule.matches(_finding(package="zlib")))

    def test_severity_match(self):
        rule = MaskRule(severity="high", reason="test")
        self.assertTrue(rule.matches(_finding(severity="high")))
        self.assertFalse(rule.matches(_finding(severity="critical")))

    def test_layer_match(self):
        rule = MaskRule(layer=2, reason="test")
        self.assertTrue(rule.matches(_finding(layer=2)))
        self.assertFalse(rule.matches(_finding(layer=1)))

    def test_path_match(self):
        rule = MaskRule(path="usr/lib/*", reason="test")
        f = _finding()
        f.package.path = "usr/lib/libssl.so.3"
        self.assertTrue(rule.matches(f))
        f2 = _finding()
        f2.package.path = "etc/passwd"
        self.assertFalse(rule.matches(f2))

    def test_combined_criteria(self):
        rule = MaskRule(id="CVE-2024-1", package="pkg", severity="high", reason="test")
        self.assertTrue(rule.matches(_finding("CVE-2024-1", "pkg", "high")))
        self.assertFalse(rule.matches(_finding("CVE-2024-1", "pkg", "low")))
        self.assertFalse(rule.matches(_finding("CVE-2024-2", "pkg", "high")))

    def test_expiry(self):
        rule = MaskRule(id="CVE-2024-1", reason="test", expires=date.today() - timedelta(days=1))
        self.assertFalse(rule.matches(_finding("CVE-2024-1")))
        rule2 = MaskRule(id="CVE-2024-1", reason="test", expires=date.today() + timedelta(days=1))
        self.assertTrue(rule2.matches(_finding("CVE-2024-1")))

    def test_no_criteria_returns_false(self):
        rule = MaskRule(reason="no criteria")
        self.assertFalse(rule.matches(_finding()))

    def test_to_dict(self):
        rule = MaskRule(id="CVE-1", reason="test", expires=date(2027, 1, 1))
        d = rule.to_dict()
        self.assertEqual(d["id"], "CVE-1")
        self.assertEqual(d["reason"], "test")
        self.assertEqual(d["expires"], "2027-01-01")


class MaskSetTests(unittest.TestCase):
    def test_is_masked(self):
        ms = MaskSet(rules=[MaskRule(id="CVE-2024-1", reason="test")])
        masked, rule = ms.is_masked(_finding("CVE-2024-1"))
        self.assertTrue(masked)
        self.assertIsNotNone(rule)
        masked2, _ = ms.is_masked(_finding("CVE-2024-2"))
        self.assertFalse(masked2)

    def test_empty_maskset(self):
        ms = MaskSet()
        masked, _ = ms.is_masked(_finding())
        self.assertFalse(masked)

    def test_to_dict(self):
        ms = MaskSet(rules=[MaskRule(id="CVE-1", reason="r")], source="test.toml")
        d = ms.to_dict()
        self.assertEqual(d["ruleCount"], 1)
        self.assertEqual(d["source"], "test.toml")


class SimpleIgnoreTests(unittest.TestCase):
    def test_load_simple(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".layersecopsignore"
            path.write_text("# comment\nCVE-2024-1\nCVE-2024-*\n\n  CVE-2023-1  \n", encoding="utf-8")
            ms = load_simple_ignore(path)
            self.assertEqual(len(ms.rules), 3)
            self.assertTrue(ms.is_masked(_finding("CVE-2024-1"))[0])
            self.assertTrue(ms.is_masked(_finding("CVE-2024-999"))[0])
            self.assertTrue(ms.is_masked(_finding("CVE-2023-1"))[0])

    def test_load_simple_missing_file(self):
        with self.assertRaises(Exception):
            load_simple_ignore(Path("/nonexistent/.layersecopsignore"))


class TomlMaskTests(unittest.TestCase):
    def test_load_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "layersecops-ignore.toml"
            path.write_text("""
expires = "2027-01-01"
ignore = ["CVE-2023-1"]
ignore_packages = ["zlib*"]

[[rules]]
id = "CVE-2024-1"
package = "pkg"
reason = "test reason"
expires = "2027-06-01"

[[rules]]
id = "CVE-2024-*"
severity = "high"
reason = "high CVEs in pkg"
""", encoding="utf-8")
            ms = load_toml_mask(path)
            # 2 rules + 1 ignore + 1 ignore_packages = 4
            self.assertEqual(len(ms.rules), 4)
            # Rule 1 matches
            self.assertTrue(ms.is_masked(_finding("CVE-2024-1", "pkg", "high"))[0])
            # Rule 2 matches by glob + severity
            self.assertTrue(ms.is_masked(_finding("CVE-2024-999", "other", "high"))[0])
            # ignore list
            self.assertTrue(ms.is_masked(_finding("CVE-2023-1"))[0])
            # ignore_packages
            self.assertTrue(ms.is_masked(_finding("CVE-2024-2", "zlib1g"))[0])

    def test_expired_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mask.toml"
            path.write_text("""
[[rules]]
id = "CVE-2024-1"
reason = "expired"
expires = "2020-01-01"
""", encoding="utf-8")
            ms = load_toml_mask(path)
            self.assertFalse(ms.is_masked(_finding("CVE-2024-1"))[0])

    def test_global_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mask.toml"
            path.write_text("""
expires = "2020-01-01"

[[rules]]
id = "CVE-2024-1"
reason = "globally expired"
""", encoding="utf-8")
            ms = load_toml_mask(path)
            self.assertFalse(ms.is_masked(_finding("CVE-2024-1"))[0])


class LoadMaskFileTests(unittest.TestCase):
    def test_auto_detect_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.toml"
            path.write_text('[[rules]]\nid = "CVE-1"\nreason = "r"\n', encoding="utf-8")
            ms = load_mask_file(path)
            self.assertEqual(len(ms.rules), 1)

    def test_auto_detect_simple(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.ignore"
            path.write_text("CVE-1\n", encoding="utf-8")
            ms = load_mask_file(path)
            self.assertEqual(len(ms.rules), 1)

    def test_missing_file(self):
        with self.assertRaises(Exception):
            load_mask_file(Path("/nonexistent.toml"))


class FindMaskFileTests(unittest.TestCase):
    def test_explicit_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mask.toml"
            path.write_text('[[rules]]\nid = "CVE-1"\nreason = "r"\n', encoding="utf-8")
            ms = load_masks(path)
            self.assertEqual(len(ms.rules), 1)

    def test_auto_discover_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                Path(tmp, "layersecops-ignore.toml").write_text(
                    '[[rules]]\nid = "CVE-1"\nreason = "r"\n', encoding="utf-8"
                )
                ms = load_masks()
                self.assertEqual(len(ms.rules), 1)
            finally:
                os.chdir(old_cwd)

    def test_no_mask_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                ms = load_masks()
                self.assertEqual(len(ms.rules), 0)
            finally:
                os.chdir(old_cwd)

    def test_merge(self):
        ms1 = MaskSet(rules=[MaskRule(id="CVE-1", reason="r1")])
        ms2 = MaskSet(rules=[MaskRule(id="CVE-2", reason="r2")])
        merged = merge_mask_sets(ms1, ms2)
        self.assertEqual(len(merged.rules), 2)


class EvaluatePolicyMaskTests(unittest.TestCase):
    def test_masked_findings_not_violations(self):
        from layersecops.config import Policy, evaluate_policy
        findings = [_finding("CVE-2024-1", "pkg", "high")]
        masks = MaskSet(rules=[MaskRule(id="CVE-2024-1", reason="accepted")])
        result = evaluate_policy(findings, Policy(fail_on="high"), masks)
        self.assertTrue(result["passed"])
        self.assertEqual(result["masked"], 1)
        self.assertEqual(len(result["maskedFindings"]), 1)
        self.assertEqual(result["maskedFindings"][0]["reason"], "accepted")

    def test_unmasked_findings_still_violate(self):
        from layersecops.config import Policy, evaluate_policy
        findings = [
            _finding("CVE-2024-1", "pkg", "high"),
            _finding("CVE-2024-2", "pkg", "high"),
        ]
        masks = MaskSet(rules=[MaskRule(id="CVE-2024-1", reason="accepted")])
        result = evaluate_policy(findings, Policy(fail_on="high"), masks)
        self.assertFalse(result["passed"])
        self.assertEqual(result["masked"], 1)
        self.assertEqual(len(result["violations"]), 1)


if __name__ == "__main__":
    unittest.main()
