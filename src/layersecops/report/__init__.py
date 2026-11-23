"""Report writers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from layersecops.report.html import build_html
from layersecops.report.metrics import build_metrics
from layersecops.report.sarif import build_sarif
from layersecops.report.table import render_text
from layersecops.util import atomic_write_json, atomic_write_text


def write_reports(
    document: dict[str, Any],
    output_dir: Path,
    formats: list[str],
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    formats = [fmt.lower() for fmt in formats]
    if "json" in formats:
        path = output_dir / "report.json"
        atomic_write_json(path, document)
        written["json"] = path
    if "sarif" in formats:
        path = output_dir / "report.sarif"
        atomic_write_json(path, build_sarif(document))
        written["sarif"] = path
    if "html" in formats:
        path = output_dir / "report.html"
        atomic_write_text(path, build_html(document))
        written["html"] = path
    if "table" in formats or "summary" in formats:
        path = output_dir / "report.txt"
        atomic_write_text(path, render_text(document, color=False))
        written["table"] = path
    if "metrics" in formats:
        path = output_dir / "report.prom"
        atomic_write_text(path, build_metrics(document))
        written["metrics"] = path
    return written