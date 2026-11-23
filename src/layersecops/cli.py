"""Command-line interface for LayerSecOps."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any, Sequence

from layersecops import __version__
from layersecops.config import (
    VALID_FORMATS,
    VALID_SCANNERS,
    VALID_TOOLS,
    Policy,
    Settings,
    evaluate_policy,
    load_ignore_file,
    load_settings,
)
from layersecops.errors import ConfigError, LayerSecOpsError
from layersecops.models import Finding, LayerAttribution, PackageRef
from layersecops.pipeline import run_scan
from layersecops.report.table import print_console
from layersecops.tools.base import ToolManager
from layersecops.util import read_json


def _list_arg(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


class _ArgumentParser(argparse.ArgumentParser):
    """Report usage errors with the config/usage exit code."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        raise ConfigError(message)


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", metavar="PATH", help="TOML config file (default: ./layersecops.toml)")
    parser.add_argument("--tool-dir", metavar="DIR", help="directory containing trivy/grype/syft/dive")
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    parser.add_argument("--verbose", action="store_true", help="show tool command lines and errors")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors on the console")


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on",
        choices=["none", "negligible", "low", "medium", "high", "critical", "unknown"],
        help="fail when a finding has at least this severity (default: high)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        metavar="ID",
        help="ignore a vulnerability ID or glob (repeatable)",
    )
    parser.add_argument("--ignore-file", metavar="PATH", help="file with vulnerability IDs/globs, one per line")
    parser.add_argument(
        "--ignore-package",
        action="append",
        metavar="NAME",
        help="ignore a package name or glob (repeatable)",
    )
    parser.add_argument("--ignore-unfixed", action="store_true", help="do not fail on findings without a fix")
    parser.add_argument("--max-critical", type=int, metavar="N", help="fail if critical findings exceed N")
    parser.add_argument("--max-high", type=int, metavar="N", help="fail if high findings exceed N")


def _apply_policy_args(policy: Policy, args: argparse.Namespace) -> None:
    if getattr(args, "fail_on", None):
        policy.fail_on = args.fail_on
    if getattr(args, "ignore", None):
        policy.ignore_ids.extend(args.ignore)
    if getattr(args, "ignore_file", None):
        policy.ignore_ids.extend(load_ignore_file(Path(args.ignore_file)))
    if getattr(args, "ignore_package", None):
        policy.ignore_packages.extend(args.ignore_package)
    if getattr(args, "ignore_unfixed", False):
        policy.ignore_unfixed = True
    if getattr(args, "max_critical", None) is not None:
        policy.max_critical = args.max_critical
    if getattr(args, "max_high", None) is not None:
        policy.max_high = args.max_high


def _apply_scan_args(settings: Settings, args: argparse.Namespace) -> None:
    if args.output_dir:
        settings.output_dir = Path(args.output_dir).expanduser()
        settings.output_dir_explicit = True
    if args.format:
        formats = _list_arg(args.format)
        invalid = set(formats) - VALID_FORMATS
        if invalid:
            raise ConfigError(f"Unknown format(s): {', '.join(sorted(invalid))}")
        settings.formats = formats
    if args.tools:
        tools = _list_arg(args.tools)
        invalid = set(tools) - VALID_TOOLS
        if invalid:
            raise ConfigError(f"Unknown tool(s): {', '.join(sorted(invalid))}")
        settings.tools = tools
    if args.require_tools is not None:
        required = _list_arg(args.require_tools)
        invalid = set(required) - VALID_TOOLS
        if invalid:
            raise ConfigError(f"Unknown required tool(s): {', '.join(sorted(invalid))}")
        settings.require_tools = required
    elif args.tools:
        # Selecting a subset of tools should not keep the default tools required.
        settings.require_tools = [
            tool for tool in settings.require_tools if tool in settings.tools
        ]
    if args.scanners:
        scanners = _list_arg(args.scanners)
        invalid = set(scanners) - VALID_SCANNERS
        if invalid:
            raise ConfigError(f"Unknown scanner(s): {', '.join(sorted(invalid))}")
        settings.scanners = scanners
    if getattr(args, "layer_scope", None):
        settings.layer_scope = args.layer_scope
    if args.timeout is not None:
        settings.timeout = args.timeout
    if args.offline:
        settings.offline = True
    if getattr(args, "log_format", None):
        settings.log_format = args.log_format
    if args.keep_workdir:
        settings.keep_workdir = True
    if args.keep_raw:
        settings.keep_raw = True
    if args.sbom:
        settings.sbom = True
    if args.pull:
        settings.pull = True
    if args.platform:
        settings.platform = args.platform
    if args.docker:
        settings.docker = args.docker
    if args.workdir:
        settings.workdir = Path(args.workdir).expanduser()
    if args.tool_dir:
        settings.tool_dir = Path(args.tool_dir).expanduser()
    if args.min_severity:
        settings.min_severity = args.min_severity


def _finding_from_dict(data: dict[str, Any]) -> Finding:
    package_data = data.get("package") or {}
    layer_data = data.get("layer") or {}
    package = PackageRef(
        name=package_data.get("name") or "",
        version=package_data.get("version") or "",
        type=package_data.get("type") or "unknown",
        purl=package_data.get("purl"),
        ecosystem=package_data.get("ecosystem"),
        path=package_data.get("path"),
        fixed_versions=list(package_data.get("fixedVersions") or []),
    )
    layer = None
    if layer_data:
        layer = LayerAttribution(
            index=layer_data.get("index"),
            digest=layer_data.get("digest"),
            diff_id=layer_data.get("diffId"),
            command=layer_data.get("command"),
            confidence=layer_data.get("confidence") or "unknown",
            evidence=layer_data.get("evidence"),
            path=layer_data.get("path"),
            introduced_index=layer_data.get("introducedIndex"),
        )
    return Finding(
        id=data.get("id") or "",
        kind=data.get("kind") or "vulnerability",
        vulnerability_id=data.get("vulnerabilityId") or "",
        aliases=list(data.get("aliases") or []),
        severity=data.get("severity") or "unknown",
        status=data.get("status") or "unknown",
        package=package,
        layer=layer,
    )


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.image and not args.image_tar:
        raise ConfigError("Provide an image reference or --image-tar")
    settings = load_settings(args.config)
    _apply_scan_args(settings, args)
    _apply_policy_args(settings.policy, args)

    result = run_scan(
        reference=args.image,
        image_tar=Path(args.image_tar) if args.image_tar else None,
        settings=settings,
        verbose=args.verbose,
        quiet=args.quiet,
    )
    if not args.quiet:
        print_console(result.document, color=False if args.no_color else None)
    return result.exit_code


def cmd_tools(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    tool_dir = Path(args.tool_dir).expanduser() if args.tool_dir else settings.tool_dir
    manager = ToolManager(tool_dir=tool_dir, timeout=60)
    statuses = manager.discover(["trivy", "grype", "syft", "dive", "docker"])
    if args.json:
        print(json.dumps({name: status.to_dict() for name, status in statuses.items()}, indent=2))
        return 0
    print(f"{'TOOL':<8} {'STATUS':<9} {'VERSION':<14} PATH")
    for name in ("trivy", "grype", "syft", "dive", "docker"):
        status = statuses[name]
        print(
            f"{name:<8} {status.status:<9} {(status.version or '-'):<14} "
            f"{status.path or '-'}"
        )
    missing = [name for name in ("trivy", "grype", "syft", "dive") if statuses[name].status != "ok"]
    if missing:
        print("")
        print("Missing tools: " + ", ".join(missing))
        print("Run scripts/bootstrap-tools.sh (Linux/WSL/macOS) or scripts/bootstrap-tools.ps1 (Windows).")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.report).expanduser()
    if not path.is_file():
        raise ConfigError(f"Report not found: {path}")
    document = read_json(path)
    settings = load_settings(args.config)
    _apply_policy_args(settings.policy, args)
    findings = [_finding_from_dict(item) for item in document.get("findings") or []]
    validation = evaluate_policy(findings, settings.policy)
    print(f"Report:     {path}")
    print(f"Image:      {(document.get('scan') or {}).get('image', {}).get('reference', 'unknown')}")
    print(f"Findings:   {len(findings)}")
    min_severity = ((document.get("scan") or {}).get("options") or {}).get("minSeverity")
    if min_severity:
        print(
            f"Warning:    report was filtered at '{min_severity}'; "
            "validation only sees the findings that remain in it"
        )
    print(f"Validation: {'PASS' if validation['passed'] else 'FAIL'}")
    if validation.get("ignored"):
        print(f"Ignored:    {validation['ignored']}")
    for violation in validation.get("violations") or []:
        print(f"  - {violation.get('message')}")
    return 0 if validation["passed"] else 1


def cmd_version(_: argparse.Namespace) -> int:
    print(f"layersecops {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="layersecops",
        description=(
            "Scan Docker image archives with Trivy, Grype, Syft and Dive; "
            "normalize findings and attribute them to layers."
        ),
    )
    parser.add_argument("--version", action="version", version=f"layersecops {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="scan an image reference or archive",
        description="Scan a Docker image and write normalized JSON/SARIF/HTML reports.",
    )
    scan.add_argument("image", nargs="?", help="image reference, e.g. nginx:1.25")
    scan.add_argument("--image-tar", metavar="PATH", help="docker-archive or OCI archive to scan")
    scan.add_argument("--pull", action="store_true", help="docker pull the image before saving it")
    scan.add_argument("--platform", metavar="OS/ARCH", help="platform passed to docker pull")
    scan.add_argument("--output-dir", metavar="DIR", help="report directory (default: reports/<image>-<time>)")
    scan.add_argument(
        "--format",
        metavar="LIST",
        help="comma-separated report formats: json,sarif,html,table,summary (default: json,html)",
    )
    scan.add_argument("--tools", metavar="LIST", help="tools to run: trivy,grype,syft,dive")
    scan.add_argument("--require-tools", metavar="LIST", help="tools that must succeed (default: trivy,grype,syft)")
    scan.add_argument("--scanners", metavar="LIST", help="Trivy scanners: vuln,secret (default: vuln)")
    scan.add_argument(
        "--layer-scope",
        choices=["squashed", "all-layers", "deep-squashed"],
        default="all-layers",
        help=(
            "what Syft/Grype catalog: 'all-layers' (default, every layer including "
            "files later deleted), 'squashed' (final filesystem only), or "
            "'deep-squashed' (squashed plus nested archives)"
        ),
    )
    scan.add_argument("--timeout", type=float, metavar="SECONDS", help="per-tool timeout (default: 900)")
    scan.add_argument("--offline", action="store_true", help="do not update vulnerability databases")
    scan.add_argument("--log-format", choices=["text", "json"], help="progress log format (default: text)")
    scan.add_argument("--keep-workdir", action="store_true", help="keep the temporary work directory")
    scan.add_argument("--workdir", metavar="DIR", help="use this work directory")
    scan.add_argument("--sbom", action="store_true", help="copy the Syft SBOM into the report directory")
    scan.add_argument("--keep-raw", action="store_true", help="copy raw tool JSON and logs into the report directory")
    scan.add_argument("--min-severity", choices=["negligible", "low", "medium", "high", "critical"], help="only report findings at or above this severity")
    scan.add_argument("--docker", metavar="PATH", help="docker executable (default: docker)")
    _add_policy_args(scan)
    _add_common(scan)
    scan.set_defaults(func=cmd_scan)

    tools = subparsers.add_parser("tools", help="show installed scanner versions")
    tools.add_argument("--json", action="store_true", help="emit JSON")
    _add_common(tools)
    tools.set_defaults(func=cmd_tools)

    validate = subparsers.add_parser("validate", help="re-apply policy to an existing report")
    validate.add_argument("report", help="report.json from a previous scan")
    _add_policy_args(validate)
    _add_common(validate)
    validate.set_defaults(func=cmd_validate)

    version = subparsers.add_parser("version", help="print the LayerSecOps version")
    version.set_defaults(func=cmd_version)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args: argparse.Namespace | None = None
    try:
        args = parser.parse_args(argv)
        return int(args.func(args))
    except LayerSecOpsError as exc:
        print(f"layersecops: error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("layersecops: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        if getattr(args, "verbose", False):
            traceback.print_exc()
        else:
            print(f"layersecops: unexpected error: {exc}", file=sys.stderr)
            print("Re-run with --verbose for a traceback.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
