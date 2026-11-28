"""Masking rules for known, accepted vulnerabilities.

A mask file lets developers record vulnerabilities they have reviewed and
decided not to fail the pipeline on.  Each rule can match by vulnerability ID,
package name, severity, layer index, or file path, and may carry an expiry
date and a human-readable reason for auditability.

Two formats are supported:

1. **Simple** (``.layersecopsignore``): one vulnerability ID or glob per line,
   identical to the existing ``--ignore-file`` format.  Lines starting with
   ``#`` are comments.

2. **Rich** (``layersecops-ignore.toml``): a TOML file with structured rules
   that support package/severity/layer filters, expiry dates and reasons.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

from layersecops.errors import ConfigError
from layersecops.models import Finding


@dataclass
class MaskRule:
    """A single masking rule."""

    id: str | None = None
    package: str | None = None
    severity: str | None = None
    layer: int | None = None
    path: str | None = None
    reason: str = ""
    expires: date | None = None
    reviewed_by: str | None = None
    reviewed_date: date | None = None

    def matches(self, finding: Finding) -> bool:
        """Return True if this rule masks the given finding."""
        if self.expires is not None and date.today() > self.expires:
            return False
        if self.id is not None and not _glob_match(finding.vulnerability_id, self.id):
            # Also check aliases
            if not any(_glob_match(alias, self.id) for alias in finding.aliases):
                return False
        if self.package is not None and not _glob_match(finding.package.name, self.package):
            return False
        if self.severity is not None:
            if finding.severity.lower() != self.severity.lower():
                return False
        if self.layer is not None:
            layer_index = finding.layer.index if finding.layer else None
            if layer_index != self.layer:
                return False
        if self.path is not None:
            pkg_path = finding.package.path or ""
            if not _glob_match(pkg_path, self.path):
                return False
        # At least one criterion must be specified
        if all(v is None for v in (self.id, self.package, self.severity, self.layer, self.path)):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "package": self.package,
            "severity": self.severity,
            "layer": self.layer,
            "path": self.path,
            "reason": self.reason,
            "expires": self.expires.isoformat() if self.expires else None,
            "reviewedBy": self.reviewed_by,
            "reviewedDate": self.reviewed_date.isoformat() if self.reviewed_date else None,
        }


@dataclass
class MaskSet:
    """A collection of masking rules."""

    rules: list[MaskRule] = field(default_factory=list)
    source: str = ""

    def is_masked(self, finding: Finding) -> tuple[bool, MaskRule | None]:
        """Return (True, rule) if the finding is masked by any rule."""
        for rule in self.rules:
            if rule.matches(finding):
                return True, rule
        return False, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "ruleCount": len(self.rules),
            "rules": [r.to_dict() for r in self.rules],
        }


def _glob_match(value: str, pattern: str) -> bool:
    """Case-insensitive glob match."""
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def _parse_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date):
        return value
    if isinstance(value, datetime):
        return value.date()
    try:
        return date.fromisoformat(str(value).strip())
    except (ValueError, TypeError):
        return None


def load_simple_ignore(path: Path) -> MaskSet:
    """Load a simple line-based ignore file (one ID/glob per line)."""
    mask_set = MaskSet(source=str(path))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigError(f"Could not read ignore file {path}: {exc}") from exc
    for line in lines:
        value = line.split("#", 1)[0].strip()
        if value:
            mask_set.rules.append(MaskRule(id=value, reason="listed in ignore file"))
    return mask_set


def load_toml_mask(path: Path) -> MaskSet:
    """Load a rich TOML-based mask file."""
    if tomllib is None:
        raise ConfigError(
            "Reading TOML mask files requires Python 3.11+ (or the 'tomli' package)"
        )
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Could not parse mask file {path}: {exc}") from exc

    mask_set = MaskSet(source=str(path))

    # Global expiry
    global_expires = _parse_date(data.get("expires"))

    for entry in data.get("rules", []) or []:
        if not isinstance(entry, dict):
            continue
        rule = MaskRule(
            id=entry.get("id"),
            package=entry.get("package"),
            severity=entry.get("severity"),
            layer=entry.get("layer"),
            path=entry.get("path"),
            reason=str(entry.get("reason") or ""),
            expires=_parse_date(entry.get("expires")) or global_expires,
            reviewed_by=entry.get("reviewed_by") or entry.get("reviewedBy"),
            reviewed_date=_parse_date(entry.get("reviewed_date") or entry.get("reviewedDate")),
        )
        mask_set.rules.append(rule)

    # Also support simple list format: ignore = ["CVE-...", "GHSA-*"]
    for vid in data.get("ignore", []) or []:
        mask_set.rules.append(MaskRule(id=str(vid), reason="listed in ignore list"))

    for pkg in data.get("ignore_packages", []) or []:
        mask_set.rules.append(MaskRule(package=str(pkg), reason="listed in ignore_packages"))

    return mask_set


def load_mask_file(path: Path) -> MaskSet:
    """Load a mask file, auto-detecting format by extension."""
    path = path.expanduser()
    if not path.is_file():
        raise ConfigError(f"Mask file not found: {path}")
    if path.suffix == ".toml":
        return load_toml_mask(path)
    return load_simple_ignore(path)


def find_mask_files(explicit: str | Path | None = None) -> list[Path]:
    """Find mask files: explicit path, env var, or auto-discover (all found)."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"Mask file not found: {path}")
        return [path]

    env_path = os.environ.get("LAYERSECOPS_IGNORE_FILE") or os.environ.get("LAYERSECOPS_MASK_FILE")
    if env_path:
        path = Path(env_path).expanduser()
        if path.is_file():
            return [path]

    # Auto-discover all matching files in cwd
    found: list[Path] = []
    for candidate in (
        Path.cwd() / "layersecops-ignore.toml",
        Path.cwd() / ".layersecopsignore",
        Path.cwd() / "layersecops.ignore.toml",
    ):
        if candidate.is_file():
            found.append(candidate)
    return found


def load_masks(explicit: str | Path | None = None) -> MaskSet:
    """Load masks from explicit path or auto-discover. Merges all found files."""
    paths = find_mask_files(explicit)
    if not paths:
        return MaskSet(source="")
    sets = []
    for path in paths:
        if path.suffix == ".toml":
            sets.append(load_toml_mask(path))
        else:
            sets.append(load_simple_ignore(path))
    if len(sets) == 1:
        return sets[0]
    return merge_mask_sets(*sets)


def check_mask_expiry(masks: MaskSet, warn_days: int = 30) -> list[str]:
    """Return warning messages for expired or soon-to-expire mask rules."""
    warnings: list[str] = []
    today = date.today()
    for rule in masks.rules:
        if rule.expires is None:
            warnings.append(
                f"Mask rule has no expiry date: {rule.id or rule.package or rule.severity or '?'} "
                f"({rule.reason or 'no reason'})"
            )
        elif rule.expires < today:
            warnings.append(
                f"Mask rule expired on {rule.expires}: {rule.id or rule.package or rule.severity or '?'} "
                f"({rule.reason or 'no reason'})"
            )
        elif (rule.expires - today).days <= warn_days:
            warnings.append(
                f"Mask rule expires in {(rule.expires - today).days} days "
                f"({rule.expires}): {rule.id or rule.package or rule.severity or '?'} "
                f"({rule.reason or 'no reason'})"
            )
    return warnings
    """Merge multiple MaskSets into one."""
    merged = MaskSet(source=", ".join(s.source for s in sets if s.source))
    for s in sets:
        merged.rules.extend(s.rules)
    return merged


def merge_mask_sets(*sets: MaskSet) -> MaskSet:
    """Merge multiple MaskSets into one."""
    merged = MaskSet(source=", ".join(s.source for s in sets if s.source))
    for s in sets:
        merged.rules.extend(s.rules)
    return merged


def find_mask_file(explicit: str | Path | None = None) -> Path | None:
    """Find a single mask file (backward compat). Returns the first found."""
    paths = find_mask_files(explicit)
    return paths[0] if paths else None
    """Merge multiple MaskSets into one."""
    merged = MaskSet(source=", ".join(s.source for s in sets if s.source))
    for s in sets:
        merged.rules.extend(s.rules)
    return merged
