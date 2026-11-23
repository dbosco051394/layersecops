"""Scan orchestration: acquire image, run tools, normalize, attribute, report."""

from __future__ import annotations

import json
import os
import sys
import shutil
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from layersecops.config import Settings, evaluate_policy
from layersecops.errors import LayerSecOpsError, ImageLoadError, ToolExecutionError
from layersecops.image import (
    build_image_info,
    inspect_image,
    read_archive,
    read_layer_files,
    save_image,
)
from layersecops.layer_map import build_layer_index
from layersecops.models import Finding, PackageRef, ToolStatus
from layersecops.normalize import deduplicate
from layersecops.report import write_reports
from layersecops.summary import build_document, build_summary, filter_by_min_severity
from layersecops.tools import grype, dive, syft, trivy
from layersecops.tools.base import ParsedScan, ToolManager
from layersecops.util import ensure_dir, human_bytes, iso, slugify, utc_now

LogFn = Callable[[str, str], None]


@dataclass
class ScanResult:
    document: dict[str, Any]
    exit_code: int
    outputs: dict[str, Path] = field(default_factory=dict)
    workdir: Path | None = None
    status: str = "complete"


def _default_log(message: str, level: str = "info") -> None:
    import sys

    print(f"[layersecops] {message}", file=sys.stderr)


def _strip_epoch(version: str) -> str:
    if ":" in version:
        head, _, tail = version.partition(":")
        if head.isdigit() and tail:
            return tail
    return version


class PackageIndex:
    def __init__(self, packages: list[PackageRef]) -> None:
        self.by_key: dict[tuple, PackageRef] = {}
        self.by_name: dict[str, list[PackageRef]] = {}
        for package in packages:
            name = package.name.lower()
            self.by_name.setdefault(name, []).append(package)
            versions = {package.version, _strip_epoch(package.version)}
            for version in versions:
                if not version:
                    continue
                self._add((name, version, package.type), package)
                self._add((name, version), package)

    def _add(self, key: tuple, package: PackageRef) -> None:
        existing = self.by_key.get(key)
        if existing is None or (not existing.files and package.files):
            self.by_key[key] = package

    def match(self, package: PackageRef) -> PackageRef | None:
        name = package.name.lower()
        versions = [package.version, _strip_epoch(package.version)]
        for version in versions:
            if not version:
                continue
            found = self.by_key.get((name, version, package.type))
            if found:
                return found
            found = self.by_key.get((name, version))
            if found:
                return found
        # Last resort: exactly one package with this name, and the versions are
        # compatible after removing an epoch.
        candidates = self.by_name.get(name) or []
        if len(candidates) == 1:
            candidate = candidates[0]
            if _strip_epoch(candidate.version) == _strip_epoch(package.version):
                return candidate
        return None


def _enrich_from_syft(finding: Finding, index: PackageIndex) -> None:
    if finding.kind != "vulnerability":
        return
    match = index.match(finding.package)
    if not match:
        return
    package = finding.package
    package.purl = package.purl or match.purl
    package.ecosystem = package.ecosystem or match.ecosystem
    package.path = package.path or match.path
    package.src_name = package.src_name or match.src_name
    package.src_version = package.src_version or match.src_version
    if package.type == "unknown" and match.type != "unknown":
        package.type = match.type
    package.files = list(dict.fromkeys([*package.files, *match.files]))
    package.layer_hints = list(
        dict.fromkeys([*package.layer_hints, *match.layer_hints])
    )


def _merge_distro(*values: dict[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("name", "version", "prettyName", "idLike"):
        for value in values:
            if value and value.get(key):
                result[key] = value[key]
                break
    return result


def _output_dir(settings: Settings, reference: str, started: datetime) -> Path:
    if settings.output_dir_explicit:
        return settings.output_dir
    stamp = started.strftime("%Y%m%d-%H%M%S")
    return settings.output_dir / f"{slugify(reference)}-{stamp}"


def _cache_dir() -> Path:
    value = os.environ.get("LAYERSECOPS_CACHE_DIR")
    base = Path(value).expanduser() if value else Path.home() / ".cache" / "layersecops"
    return base


def _tool_log(logs_dir: Path, name: str) -> Path:
    return logs_dir / f"{name}.log"


def _has_output(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _read_json_quietly(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def run_scan(
    *,
    reference: str | None,
    image_tar: Path | None,
    settings: Settings,
    verbose: bool = False,
    quiet: bool = False,
    log: LogFn | None = None,
) -> ScanResult:
    if log is None:
        log = _default_log if settings.log_format != "json" else None
    # Build the effective logger based on format when the caller did not
    # supply one.
    if log is None:
        def _emit(message: str, level: str = "info") -> None:
            print(
                json.dumps(
                    {
                        "ts": iso(utc_now()),
                        "level": level,
                        "msg": message,
                        "tool": "layersecops",
                    }
                ),
                file=sys.stderr,
            )
        log = _emit if settings.log_format == "json" else _default_log

    def info(message: str) -> None:
        if not quiet:
            log(message, "info")

    def debug(message: str) -> None:
        if verbose and not quiet:
            log(message, "debug")

    started = utc_now()
    scan_id = str(uuid.uuid4())
    errors: list[str] = []
    warnings: list[str] = []
    required_failed = False
    if image_tar is not None and reference:
        warnings.append(
            "Both an image reference and --image-tar were provided; "
            "the archive is scanned and the reference is used as a label"
        )

    selected_tools = [tool for tool in settings.tools if tool in {"trivy", "grype", "syft", "dive"}]
    if not selected_tools:
        raise LayerSecOpsError("No scanners selected; choose at least one of trivy, grype, syft, dive")
    required_tools = [tool for tool in settings.require_tools if tool in selected_tools]
    unselected_required = [tool for tool in settings.require_tools if tool not in selected_tools]
    if unselected_required:
        warnings.append(
            "Ignoring require_tools entries that are not in tools: "
            + ", ".join(unselected_required)
        )

    manager = ToolManager(tool_dir=settings.tool_dir, timeout=settings.timeout, verbose=verbose)
    manager.discover([*selected_tools, "docker"])

    workdir = settings.workdir
    workdir_explicit = workdir is not None
    if workdir:
        workdir = workdir.expanduser().resolve()
        ensure_dir(workdir)
    else:
        workdir = Path(tempfile.mkdtemp(prefix="layersecops-")).resolve()
    tools_dir = ensure_dir(workdir / "tools")
    logs_dir = ensure_dir(workdir / "logs")

    archive_path: Path | None = None
    inspected: dict[str, Any] | None = None
    try:
        if image_tar is not None:
            archive_path = image_tar.expanduser().resolve()
            if not archive_path.is_file():
                raise ImageLoadError(f"Image archive not found: {archive_path}")
        else:
            if not reference:
                raise ImageLoadError("Provide an image reference or --image-tar")
            archive_path = workdir / "image.tar"
            info(f"saving image {reference} with docker save")
            save_image(
                reference,
                archive_path,
                docker=settings.docker,
                pull=settings.pull,
                platform=settings.platform,
                timeout=max(settings.timeout, 1800),
                log_path=_tool_log(logs_dir, "docker-save"),
            )
            inspected = inspect_image(
                reference, docker=settings.docker, timeout=min(settings.timeout, 120)
            )

        info(f"reading image archive {archive_path}")
        archive = read_archive(archive_path)
        if not reference:
            reference = archive.repo_tags[0] if archive.repo_tags else f"archive:{archive_path.name}"
        if archive.warnings:
            warnings.extend(archive.warnings)
        info(
            f"image {reference}: {len(archive.layers)} layers, "
            f"{human_bytes(archive.size_bytes)}"
        )

        # --- Tool execution -------------------------------------------------
        outputs = {
            "trivy": tools_dir / "trivy.json",
            "syft": tools_dir / "syft.json",
            "grype": tools_dir / "grype.json",
            "dive": tools_dir / "dive.json",
        }
        cache = ensure_dir(_cache_dir())

        def run_trivy() -> None:
            args = trivy.build_args(
                archive_path,
                outputs["trivy"],
                scanners=settings.scanners,
                cache_dir=cache / "trivy",
                offline=settings.offline,
                timeout=f"{int(settings.timeout)}s",
            )
            debug("trivy " + " ".join(args))
            result = manager.run("trivy", args, log_path=_tool_log(logs_dir, "trivy"))
            if not _has_output(outputs["trivy"]):
                raise ToolExecutionError(f"trivy produced no report: {result.summary()}")

        def run_syft() -> None:
            args = syft.build_args(
                image_tar=archive_path,
                output=outputs["syft"],
                scope=settings.layer_scope,
            )
            debug("syft " + " ".join(args))
            result = manager.run("syft", args, log_path=_tool_log(logs_dir, "syft"))
            if not _has_output(outputs["syft"]):
                raise ToolExecutionError(f"syft produced no SBOM: {result.summary()}")

        def run_dive() -> None:
            args = dive.build_args(archive_path, outputs["dive"])
            debug("dive " + " ".join(args))
            result = manager.run("dive", args, log_path=_tool_log(logs_dir, "dive"))
            if not _has_output(outputs["dive"]):
                raise ToolExecutionError(f"dive produced no report: {result.summary()}")

        def run_grype() -> None:
            sbom_path = outputs["syft"] if _has_output(outputs["syft"]) else None
            args = grype.build_args(
                output=outputs["grype"],
                image_tar=archive_path,
                sbom=sbom_path,
                scope=settings.layer_scope,
            )
            debug("grype " + " ".join(args))
            env = (
                {
                    "GRYPE_DB_AUTO_UPDATE": "false",
                    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                }
                if settings.offline
                else None
            )
            result = manager.run(
                "grype", args, log_path=_tool_log(logs_dir, "grype"), env=env
            )
            if not _has_output(outputs["grype"]):
                raise ToolExecutionError(f"grype produced no report: {result.summary()}")

        runnable: dict[str, Callable[[], None]] = {}
        for name, runner in (
            ("trivy", run_trivy),
            ("syft", run_syft),
            ("dive", run_dive),
        ):
            if name not in selected_tools:
                manager.statuses[name] = ToolStatus(name=name, status="skipped")
                continue
            if not manager.get(name):
                manager.statuses[name] = ToolStatus(
                    name=name,
                    status="missing",
                    error="not installed",
                )
                if name in required_tools:
                    required_failed = True
                    errors.append(f"Required tool is not installed: {name}")
                else:
                    warnings.append(f"Optional tool is not installed: {name}")
                continue
            runnable[name] = runner

        with ThreadPoolExecutor(max_workers=max(1, len(runnable))) as pool:
            futures = {
                pool.submit(runner): name for name, runner in runnable.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                    info(f"{name} finished")
                except Exception as exc:  # noqa: BLE001 - report tool failures
                    message = f"{name} failed: {exc}"
                    errors.append(message)
                    manager.statuses[name] = ToolStatus(
                        name=name,
                        path=manager.get(name),
                        status="failed",
                        error=str(exc),
                    )
                    if name in required_tools:
                        required_failed = True
                    else:
                        warnings.append(message)

        if "grype" in selected_tools:
            if not manager.get("grype"):
                manager.statuses["grype"] = ToolStatus(
                    name="grype", status="missing", error="not installed"
                )
                if "grype" in required_tools:
                    required_failed = True
                    errors.append("Required tool is not installed: grype")
                else:
                    warnings.append("Optional tool is not installed: grype")
            else:
                try:
                    run_grype()
                    info("grype finished")
                except Exception as exc:  # noqa: BLE001
                    message = f"grype failed: {exc}"
                    errors.append(message)
                    manager.statuses["grype"] = ToolStatus(
                        name="grype",
                        path=manager.get("grype"),
                        status="failed",
                        error=str(exc),
                    )
                    if "grype" in required_tools:
                        required_failed = True
                    else:
                        warnings.append(message)
        else:
            manager.statuses["grype"] = ToolStatus(name="grype", status="skipped")

        # --- Parsing --------------------------------------------------------
        parsed: dict[str, ParsedScan] = {}
        parsers = {
            "trivy": trivy.parse,
            "syft": syft.parse,
            "grype": grype.parse,
            "dive": dive.parse,
        }
        for name in ("trivy", "syft", "grype", "dive"):
            if name not in selected_tools:
                continue
            path = outputs[name]
            if not _has_output(path):
                status = manager.statuses.get(name)
                if name in required_tools and (status is None or status.status == "ok"):
                    required_failed = True
                    errors.append(f"{name} did not produce output")
                continue
            try:
                if name == "dive":
                    continue  # parsed separately below
                parsed[name] = parsers[name](path)  # type: ignore[operator]
                status = manager.statuses.get(name)
                if status and status.status == "failed":
                    warnings.append(
                        f"{name} exited nonzero but produced parseable output"
                    )
                    status.status = "ok"
                    status.error = None
            except Exception as exc:  # noqa: BLE001
                message = f"Could not parse {name} output: {exc}"
                errors.append(message)
                manager.statuses[name] = ToolStatus(
                    name=name,
                    path=manager.get(name),
                    status="failed",
                    error=str(exc),
                )
                if name in required_tools:
                    required_failed = True

        dive_result: dive.DiveResult | None = None
        if "dive" in selected_tools and _has_output(outputs["dive"]):
            try:
                dive_result = dive.parse(outputs["dive"])
                status = manager.statuses.get("dive")
                if status and status.status == "failed":
                    warnings.append("dive exited nonzero but produced parseable output")
                    status.status = "ok"
                    status.error = None
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Could not parse Dive output: {exc}")
                manager.statuses["dive"] = ToolStatus(
                    name="dive",
                    path=manager.get("dive"),
                    status="failed",
                    error=str(exc),
                )
        elif "dive" in selected_tools:
            warnings.append("Dive output unavailable; using layer tar member lists")

        # --- Layer ownership ------------------------------------------------
        if dive_result is not None:
            by_index = {layer.index: layer for layer in archive.layers}
            for dive_layer in dive_result.layers:
                target = by_index.get(dive_layer.index)
                if target is None:
                    archive.layers.append(dive_layer)
                    continue
                target.digest = target.digest or dive_layer.digest
                target.diff_id = target.diff_id or dive_layer.diff_id
                target.size_bytes = dive_layer.size_bytes or target.size_bytes
                target.command = dive_layer.command or target.command
                target.created_at = dive_layer.created_at or target.created_at
            archive.layers.sort(key=lambda layer: layer.index)

        layer_digests: dict[str, str] = {}
        for name in ("trivy", "grype", "syft"):
            scan = parsed.get(name)
            if scan:
                layer_digests.update(scan.metadata.get("layerDigests") or {})
        for layer in archive.layers:
            if not layer.digest and layer.diff_id in layer_digests:
                layer.digest = layer_digests[layer.diff_id]

        tar_files: dict[int, list[str]] = {}
        if dive_result is None or not any(dive_result.files_by_layer.values()):
            info("reading layer file lists from the image archive")
            tar_files, tar_warnings = read_layer_files(archive)
            warnings.extend(tar_warnings)
        layer_index = build_layer_index(
            archive.layers,
            dive_files=dive_result.files_by_layer if dive_result else None,
            tar_files=tar_files,
        )
        warnings.extend(layer_index.warnings)
        if not layer_index.file_owner:
            warnings.append("No layer file ownership data was available")

        # --- Normalize and attribute ---------------------------------------
        raw_findings: list[Finding] = []
        for name in ("trivy", "grype"):
            scan = parsed.get(name)
            if scan:
                raw_findings.extend(scan.findings)
        if not raw_findings and required_failed:
            warnings.append("No vulnerability findings were produced by the scanners")

        syft_scan = parsed.get("syft")
        package_index = PackageIndex(syft_scan.packages if syft_scan else [])
        for finding in raw_findings:
            _enrich_from_syft(finding, package_index)

        findings = deduplicate(raw_findings)
        for finding in findings:
            hints = [
                source.layer_hint
                for source in finding.sources
                if source.layer_hint
            ]
            finding.layer = layer_index.attribute(
                finding.package,
                hints=hints,
                path_hint=next(
                    (source.path for source in finding.sources if source.path), None
                ),
                tool=", ".join(sorted({source.tool for source in finding.sources})),
            )

        # --- Image metadata -------------------------------------------------
        trivy_scan = parsed.get("trivy")
        grype_scan = parsed.get("grype")
        distro = _merge_distro(
            trivy_scan.distro if trivy_scan else None,
            syft_scan.distro if syft_scan else None,
            grype_scan.distro if grype_scan else None,
        )
        image = build_image_info(
            archive,
            reference=reference or "unknown",
            dive_layers=dive_result.layers if dive_result else None,
            efficiency=dive_result.efficiency if dive_result else None,
            distro=distro,
            inspected=inspected,
        )
        for candidate in (syft_scan, grype_scan, trivy_scan):
            if not candidate:
                continue
            meta = candidate.metadata
            if not image.id and candidate.image_id:
                image.id = candidate.image_id
            if not image.digest and meta.get("manifestDigest"):
                image.digest = meta["manifestDigest"]
            if not image.tags and meta.get("tags"):
                image.tags = list(meta["tags"])
            if not image.size_bytes and meta.get("imageSize"):
                image.size_bytes = meta["imageSize"]

        # --- Policy and reports --------------------------------------------
        validation = evaluate_policy(findings, settings.policy)
        report_findings = filter_by_min_severity(findings, settings.min_severity)
        tool_statuses = [
            manager.tool_status(name) for name in ("trivy", "grype", "syft", "dive")
        ]

        finished = utc_now()
        if required_failed:
            status = "failed" if not findings else "partial"
        else:
            status = "complete"
        summary = build_summary(report_findings, image, tool_statuses)
        document = build_document(
            scan_id=scan_id,
            started_at=started,
            finished_at=finished,
            status=status,
            image=image,
            settings=settings,
            findings=report_findings,
            validation=validation,
            tool_statuses=tool_statuses,
            warnings=warnings,
            errors=errors,
            summary=summary,
        )

        output_dir = _output_dir(settings, reference or "image", started)
        outputs_written = write_reports(document, output_dir, settings.formats)
        if settings.sbom and _has_output(outputs["syft"]):
            sbom_path = output_dir / "sbom.syft.json"
            shutil.copy2(outputs["syft"], sbom_path)
            outputs_written["sbom"] = sbom_path
        if settings.keep_raw:
            raw_dir = ensure_dir(output_dir / "raw")
            for name, path in outputs.items():
                if _has_output(path):
                    shutil.copy2(path, raw_dir / f"{name}.json")
            if logs_dir.is_dir():
                shutil.copytree(logs_dir, raw_dir / "logs", dirs_exist_ok=True)

        exit_code = 2 if required_failed else (0 if validation["passed"] else 1)
        info(
            f"scan {status}: {len(report_findings)} findings, "
            f"validation {'passed' if validation['passed'] else 'failed'}"
        )
        for label, path in outputs_written.items():
            info(f"{label}: {path}")

        if settings.log_format == "json" and not quiet:
            print(
                json.dumps(
                    {
                        "ts": iso(utc_now()),
                        "level": "info",
                        "event": "scan.result",
                        "image": reference or "unknown",
                        "status": status,
                        "findings": len(report_findings),
                        "bySeverity": (document.get("summary") or {}).get("bySeverity", {}),
                        "policy": "pass" if validation["passed"] else "fail",
                        "exitCode": exit_code,
                        "durationMs": document.get("scan", {}).get("durationMs"),
                        "reports": {key: str(value) for key, value in outputs_written.items()},
                    }
                ),
                file=sys.stderr,
            )

        result = ScanResult(
            document=document,
            exit_code=exit_code,
            outputs=outputs_written,
            workdir=workdir,
            status=status,
        )
        if settings.keep_workdir or workdir_explicit:
            info(f"work directory kept at {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
        return result

    except Exception:
        if settings.keep_workdir or workdir_explicit:
            log(f"work directory kept at {workdir}", "info")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
        raise
