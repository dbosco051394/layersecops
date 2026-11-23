"""Configuration and policy handling (TOML, no third-party dependencies)."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from layersecops.errors import ConfigError
from layersecops.models import Finding
from layersecops.normalize import SEVERITY_RANK, normalize_severity, severity_rank

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

VALID_FORMATS = {"json", "sarif", "html", "table", "summary", "metrics"}
VALID_TOOLS = {"trivy", "grype", "syft", "dive"}
VALID_SCANNERS = {"vuln", "secret"}
VALID_SCOPES = {"squashed", "all-layers", "deep-squashed"}


@dataclass
class Policy:
    fail_on: str = "high"
    ignore_unfixed: bool = False
    ignore_ids: list[str] = field(default_factory=list)
    ignore_packages: list[str] = field(default_factory=list)
    max_critical: int | None = None
    max_high: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "failOn": self.fail_on,
            "ignoreUnfixed": self.ignore_unfixed,
            "ignoreIds": self.ignore_ids,
            "ignorePackages": self.ignore_packages,
            "maxCritical": self.max_critical,
            "maxHigh": self.max_high,
        }


@dataclass
class Settings:
    tools: list[str] = field(default_factory=lambda: ["trivy", "grype", "syft", "dive"])
    require_tools: list[str] = field(default_factory=lambda: ["trivy", "grype", "syft"])
    scanners: list[str] = field(default_factory=lambda: ["vuln"])
    layer_scope: str = "squashed"
    log_format: str = "text"
    timeout: float = 900
    offline: bool = False
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    output_dir_explicit: bool = False
    formats: list[str] = field(default_factory=lambda: ["json", "html"])
    keep_workdir: bool = False
    keep_raw: bool = False
    sbom: bool = False
    tool_dir: Path | None = None
    docker: str = "docker"
    min_severity: str | None = None
    platform: str | None = None
    pull: bool = False
    workdir: Path | None = None
    policy: Policy = field(default_factory=Policy)
    config_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": self.tools,
            "requireTools": self.require_tools,
            "scanners": self.scanners,
            "layerScope": self.layer_scope,
            "logFormat": self.log_format,
            "timeoutSeconds": self.timeout,
            "offline": self.offline,
            "formats": self.formats,
            "minSeverity": self.min_severity,
            "platform": self.platform,
            "policy": self.policy.to_dict(),
        }


def _as_bool(value: Any, key: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    raise ConfigError(f"Expected a boolean for {key}, got {value!r}")


def _as_int(value: Any, key: str) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Expected an integer for {key}, got {value!r}") from exc


def _as_list(value: Any, key: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    raise ConfigError(f"Expected a list for {key}, got {value!r}")


def _resolve_path(value: Any, base: Path) -> Path | None:
    if value in (None, ""):
        return None
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = base / path
    return path


def load_ignore_file(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigError(f"Could not read ignore file {path}: {exc}") from exc
    result: list[str] = []
    for line in lines:
        value = line.split("#", 1)[0].strip()
        if value:
            result.append(value)
    return result


def find_config(explicit: str | Path | None = None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"Config file not found: {path}")
        return path
    env_path = os.environ.get("LAYERSECOPS_CONFIG")
    if env_path:
        path = Path(env_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"LAYERSECOPS_CONFIG points to a missing file: {path}")
        return path
    for candidate in (Path.cwd() / "layersecops.toml", Path.cwd() / ".layersecops.toml"):
        if candidate.is_file():
            return candidate
    return None


def load_settings(config_path: str | Path | None = None) -> Settings:
    settings = Settings()
    path = find_config(config_path)
    if path is None:
        return settings
    if tomllib is None:
        raise ConfigError(
            "Reading TOML config requires Python 3.11+ (or the 'tomli' package on 3.10)"
        )
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Could not parse config {path}: {exc}") from exc

    base = path.parent
    settings.config_path = path
    scan = data.get("scan") or {}
    policy = data.get("policy") or {}
    if not isinstance(scan, dict) or not isinstance(policy, dict):
        raise ConfigError("Config sections [scan] and [policy] must be tables")

    if "tools" in scan:
        tools = _as_list(scan["tools"], "scan.tools")
        invalid = set(tools) - VALID_TOOLS
        if invalid:
            raise ConfigError(f"Unknown tool(s) in scan.tools: {', '.join(sorted(invalid))}")
        settings.tools = tools
    if "require_tools" in scan:
        required = _as_list(scan["require_tools"], "scan.require_tools")
        invalid = set(required) - VALID_TOOLS
        if invalid:
            raise ConfigError(
                f"Unknown tool(s) in scan.require_tools: {', '.join(sorted(invalid))}"
            )
        settings.require_tools = required
    if "scanners" in scan:
        scanners = _as_list(scan["scanners"], "scan.scanners")
        invalid = set(scanners) - VALID_SCANNERS
        if invalid:
            raise ConfigError(
                f"Unknown scanner(s) in scan.scanners: {', '.join(sorted(invalid))}"
            )
        settings.scanners = scanners
    if "layer_scope" in scan:
        scope = str(scan["layer_scope"]).strip().lower()
        if scope not in VALID_SCOPES:
            raise ConfigError(
                "scan.layer_scope must be one of: " + ", ".join(sorted(VALID_SCOPES))
            )
        settings.layer_scope = scope
    if "log_format" in scan:
        value = str(scan["log_format"]).strip().lower()
        if value not in {"text", "json"}:
            raise ConfigError("scan.log_format must be 'text' or 'json'")
        settings.log_format = value
    if "timeout_seconds" in scan:
        try:
            settings.timeout = float(scan["timeout_seconds"])
        except (TypeError, ValueError) as exc:
            raise ConfigError("scan.timeout_seconds must be a number") from exc
    if "offline" in scan:
        settings.offline = _as_bool(scan["offline"], "scan.offline")
    if "output_dir" in scan:
        settings.output_dir = _resolve_path(scan["output_dir"], base) or settings.output_dir
        settings.output_dir_explicit = True
    if "formats" in scan:
        formats = _as_list(scan["formats"], "scan.formats")
        invalid = set(formats) - VALID_FORMATS
        if invalid:
            raise ConfigError(
                f"Unknown format(s) in scan.formats: {', '.join(sorted(invalid))}"
            )
        settings.formats = formats
    if "keep_workdir" in scan:
        settings.keep_workdir = _as_bool(scan["keep_workdir"], "scan.keep_workdir")
    if "keep_raw" in scan:
        settings.keep_raw = _as_bool(scan["keep_raw"], "scan.keep_raw")
    if "sbom" in scan:
        settings.sbom = _as_bool(scan["sbom"], "scan.sbom")
    if "tool_dir" in scan:
        settings.tool_dir = _resolve_path(scan["tool_dir"], base)
    if "docker" in scan:
        settings.docker = str(scan["docker"])
    if "min_severity" in scan:
        settings.min_severity = normalize_severity(scan["min_severity"])
    if "platform" in scan:
        settings.platform = str(scan["platform"])

    if "fail_on" in policy:
        fail_on = str(policy["fail_on"]).strip().lower()
        if fail_on not in {"none", *SEVERITY_RANK.keys()}:
            raise ConfigError(
                "policy.fail_on must be one of: none, negligible, low, medium, high, critical, unknown"
            )
        settings.policy.fail_on = fail_on
    if "ignore_unfixed" in policy:
        settings.policy.ignore_unfixed = _as_bool(
            policy["ignore_unfixed"], "policy.ignore_unfixed"
        )
    if "ignore" in policy:
        settings.policy.ignore_ids.extend(_as_list(policy["ignore"], "policy.ignore"))
    if "ignore_packages" in policy:
        settings.policy.ignore_packages.extend(
            _as_list(policy["ignore_packages"], "policy.ignore_packages")
        )
    if "ignore_file" in policy:
        ignore_path = _resolve_path(policy["ignore_file"], base)
        if ignore_path:
            settings.policy.ignore_ids.extend(load_ignore_file(ignore_path))
    if "max_critical" in policy:
        settings.policy.max_critical = _as_int(
            policy["max_critical"], "policy.max_critical"
        )
    if "max_high" in policy:
        settings.policy.max_high = _as_int(policy["max_high"], "policy.max_high")

    return settings


def _matches_any(value: str, patterns: list[str]) -> bool:
    lowered = value.lower()
    return any(fnmatch.fnmatch(lowered, pattern.lower()) for pattern in patterns)


def evaluate_policy(findings: list[Finding], policy: Policy) -> dict[str, Any]:
    fail_on = policy.fail_on.lower()
    threshold = SEVERITY_RANK.get(fail_on, 0)
    violations: list[dict[str, Any]] = []
    ignored = 0
    counts = {severity: 0 for severity in SEVERITY_RANK}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        identifiers = [finding.vulnerability_id, *finding.aliases]
        if any(_matches_any(identifier, policy.ignore_ids) for identifier in identifiers):
            ignored += 1
            continue
        if policy.ignore_packages and _matches_any(
            finding.package.name, policy.ignore_packages
        ):
            ignored += 1
            continue
        if (
            policy.ignore_unfixed
            and finding.kind == "vulnerability"
            and not finding.package.fixed_versions
        ):
            ignored += 1
            continue
        if fail_on != "none" and severity_rank(finding.severity) >= threshold:
            violations.append(
                {
                    "type": "severity",
                    "findingId": finding.id,
                    "vulnerabilityId": finding.vulnerability_id,
                    "package": finding.package.name,
                    "version": finding.package.version,
                    "severity": finding.severity,
                    "layer": finding.layer.index if finding.layer else None,
                    "message": (
                        f"{finding.vulnerability_id} in {finding.package.name} "
                        f"{finding.package.version} is {finding.severity} "
                        f"(threshold: {fail_on})"
                    ),
                }
            )

    for severity, limit in (("critical", policy.max_critical), ("high", policy.max_high)):
        if limit is None:
            continue
        count = counts.get(severity, 0)
        if count > limit:
            violations.append(
                {
                    "type": "count",
                    "severity": severity,
                    "count": count,
                    "limit": limit,
                    "message": f"{count} {severity} findings exceeds the limit of {limit}",
                }
            )

    return {
        "passed": not violations,
        "policy": policy.to_dict(),
        "violations": violations,
        "ignored": ignored,
        "counts": counts,
    }
