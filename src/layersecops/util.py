"""Small, dependency-free helpers shared by the scanner."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utc_now()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def slugify(value: str, max_length: int = 80) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-._")
    return (value or "image")[:max_length]


def human_bytes(size: int | float | None) -> str:
    if size is None:
        return "unknown"
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TiB"


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding=encoding, newline="\n")
    os.replace(tmp, path)


def atomic_write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def split_versions(value: Any) -> list[str]:
    """Turn Trivy/Grype fixed-version fields into a clean list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value]
    else:
        items = re.split(r"\s*,\s*|\s+", str(value))
    result: list[str] = []
    for item in items:
        item = item.strip().strip(",")
        if item and item not in result:
            result.append(item)
    return result


def unique(items: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for item in items:
        if item is None:
            continue
        marker = item if isinstance(item, (str, int, float, bool, tuple)) else repr(item)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def deep_get(data: Any, *keys: str, default: Any = None) -> Any:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def truncate(value: str | None, width: int, suffix: str = "...") -> str:
    if not value:
        return ""
    value = " ".join(str(value).split())
    if len(value) <= width:
        return value
    return value[: max(0, width - len(suffix))] + suffix


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None

    def summary(self, limit: int = 800) -> str:
        parts = [f"exit={self.returncode}"]
        if self.timed_out:
            parts.append("timed out")
        if self.error:
            parts.append(self.error)
        text = (self.stderr or self.stdout or "").strip()
        if text:
            parts.append(truncate(text, limit))
        return " | ".join(parts)


def run_command(
    argv: Sequence[str],
    *,
    timeout: float = 900,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    log_path: Path | None = None,
    stdin_text: str | None = None,
) -> CommandResult:
    """Run a command without a shell, capturing output and timing."""
    args = [str(item) for item in argv]
    started = time.monotonic()
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        completed = subprocess.run(
            args,
            input=stdin_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=full_env,
            **kwargs,
        )
        result = CommandResult(
            argv=args,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except FileNotFoundError as exc:
        result = CommandResult(
            argv=args,
            returncode=127,
            stdout="",
            stderr="",
            duration_ms=int((time.monotonic() - started) * 1000),
            error=f"executable not found: {exc}",
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        result = CommandResult(
            argv=args,
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=True,
            error=f"timed out after {timeout:g}s",
        )
    except OSError as exc:
        result = CommandResult(
            argv=args,
            returncode=126,
            stdout="",
            stderr="",
            duration_ms=int((time.monotonic() - started) * 1000),
            error=str(exc),
        )

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"$ {' '.join(args)}\n")
            handle.write(f"[exit {result.returncode} in {result.duration_ms}ms]\n")
            if result.error:
                handle.write(f"[error] {result.error}\n")
            if result.stdout:
                handle.write("--- stdout ---\n")
                handle.write(result.stdout)
                if not result.stdout.endswith("\n"):
                    handle.write("\n")
            if result.stderr:
                handle.write("--- stderr ---\n")
                handle.write(result.stderr)
                if not result.stderr.endswith("\n"):
                    handle.write("\n")
            handle.write("\n")
    return result


def find_executable(name: str, extra_dirs: Iterable[str | Path] = ()) -> str | None:
    """Locate a tool, honouring LAYERSECOPS_<TOOL>_PATH and tool directories."""
    env_key = "LAYERSECOPS_" + re.sub(r"[^A-Z0-9]+", "_", name.upper()) + "_PATH"
    explicit = os.environ.get(env_key)
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            return str(candidate)

    candidates: list[Path] = []
    for directory in extra_dirs:
        if not directory:
            continue
        base = Path(directory).expanduser()
        candidates.extend([base / name, base / f"{name}.exe"])
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    found = shutil.which(name)
    if found:
        return found
    if sys.platform == "win32":
        for ext in (".exe", ".cmd", ".bat"):
            found = shutil.which(name + ext)
            if found:
                return found
    return None


def parse_tool_version(text: str) -> str | None:
    """Extract a semver-ish version from `tool --version` output."""
    patterns = [
        r"(?:Version|version)\s*[:=]?\s*v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?)",
        r"\bv?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)
