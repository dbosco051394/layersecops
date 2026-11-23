from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from layersecops.config import Policy, Settings
from layersecops.layer_map import LayerIndex
from layersecops.models import ImageInfo, Layer, ToolStatus
from layersecops.normalize import deduplicate
from layersecops.report import write_reports
from layersecops.summary import build_document, build_summary
from layersecops.tools import dive, grype, syft, trivy

FIXTURES = Path(__file__).parent / "fixtures"


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        trivy_scan = trivy.parse(FIXTURES / "trivy.json")
        grype_scan = grype.parse(FIXTURES / "grype.json")
        syft_scan = syft.parse(FIXTURES / "syft.json")
        dive_scan = dive.parse(FIXTURES / "dive.json")
        self.findings = deduplicate([*trivy_scan.findings, *grype_scan.findings])
        self.layer_index = LayerIndex(dive_scan.layers, dive_scan.files_by_layer)
        for finding in self.findings:
            finding.layer = self.layer_index.attribute(
                finding.package,
                hints=[source.layer_hint for source in finding.sources if source.layer_hint],
            )
        self.image = ImageInfo(
            reference="demo:1.0",
            id="sha256:imageid",
            digest="sha256:manifest",
            tags=["demo:1.0"],
            architecture="amd64",
            os="linux",
            distro={"name": "debian", "version": "12.5", "prettyName": "Debian GNU/Linux 12 (bookworm)"},
            size_bytes=123456,
            layers=dive_scan.layers,
            efficiency=dive_scan.efficiency,
        )
        self.tools = [
            ToolStatus(name="trivy", status="ok", version="0.58.0"),
            ToolStatus(name="grype", status="ok", version="0.90.0"),
            ToolStatus(name="syft", status="ok", version="1.18.0"),
            ToolStatus(name="dive", status="ok", version="0.12.0"),
        ]
        self.settings = Settings(policy=Policy(fail_on="high"))
        self.started = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.finished = datetime(2026, 1, 1, 12, 1, tzinfo=timezone.utc)

    def _document(self) -> dict:
        summary = build_summary(self.findings, self.image, self.tools)
        return build_document(
            scan_id="scan-1",
            started_at=self.started,
            finished_at=self.finished,
            status="complete",
            image=self.image,
            settings=self.settings,
            findings=self.findings,
            validation={"passed": False, "policy": {"failOn": "high"}, "violations": []},
            tool_statuses=self.tools,
            warnings=[],
            errors=[],
            summary=summary,
        )

    def test_summary_and_document(self) -> None:
        document = self._document()
        self.assertEqual(document["schemaVersion"], "1.0")
        self.assertEqual(document["summary"]["total"], 4)
        self.assertEqual(document["summary"]["bySeverity"]["critical"], 2)
        self.assertEqual(document["scan"]["image"]["reference"], "demo:1.0")
        ssl = next(item for item in document["findings"] if item["vulnerabilityId"] == "CVE-2024-1234")
        self.assertEqual(ssl["layer"]["index"], 3)
        self.assertEqual(ssl["layer"]["confidence"], "exact")
        self.assertEqual(ssl["sources"][0]["tool"] in {"trivy", "grype"}, True)

    def test_write_reports(self) -> None:
        document = self._document()
        with tempfile.TemporaryDirectory() as tmp:
            outputs = write_reports(document, Path(tmp), ["json", "sarif", "html", "table"])
            self.assertEqual(set(outputs), {"json", "sarif", "html", "table"})
            saved = json.loads((Path(tmp) / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["scan"]["id"], "scan-1")

            sarif = json.loads((Path(tmp) / "report.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"]), 1)
            self.assertEqual(len(sarif["runs"][0]["results"]), 4)
            self.assertTrue(sarif["runs"][0]["tool"]["driver"]["rules"])

            html = (Path(tmp) / "report.html").read_text(encoding="utf-8")
            self.assertIn("CVE-2024-1234", html)
            self.assertIn("LayerSecOps report", html)
            self.assertIn("demo:1.0", html)

            table = (Path(tmp) / "report.txt").read_text(encoding="utf-8")
            self.assertIn("LayerSecOps", table)
            self.assertIn("CVE-2024-1234", table)


if __name__ == "__main__":
    unittest.main()
