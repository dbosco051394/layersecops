"""External tool discovery, execution and shared parser types."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from layersecops.errors import ToolNotFoundError
from layersecops.models import Finding, PackageRef, ToolStatus
from layersecops.util import (
    CommandResult,
    find_executable,
    parse_tool_version,
    run_command,
)

TOOL_NAMES = ("trivy", "grype", "syft", "dive", "docker")


@dataclass
class ParsedScan:
    findings: list[Finding] = field(default_factory=list)
    packages: list[PackageRef] = field(default_factory=list)
    distro: dict[str, Any] = field(default_factory=dict)
    image_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def _tool_dirs(explicit: str | Path | None = None) -> list[Path]:
    directories: list[Path] = []
    if explicit:
        directories.append(Path(explicit).expanduser())
    env_dir = os.environ.get("LAYERSECOPS_TOOL_DIR")
    if env_dir:
        directories.append(Path(env_dir).expanduser())
    project_root = Path(__file__).resolve().parents[3]
    directories.extend([project_root / ".tools" / "bin", project_root / "bin"])
    directories.extend([Path.cwd() / ".tools" / "bin", Path.cwd() / "bin"])
    return directories


class ToolManager:
    """Locates tools and runs them with consistent timeouts and logging."""

    def __init__(
        self,
        *,
        tool_dir: str | Path | None = None,
        timeout: float = 900,
        verbose: bool = False,
    ) -> None:
        self.tool_dir = tool_dir
        self.timeout = timeout
        self.verbose = verbose
        self.paths: dict[str, str] = {}
        self.statuses: dict[str, ToolStatus] = {}
        self._version_checked: set[str] = set()

    @property
    def directories(self) -> list[Path]:
        return _tool_dirs(self.tool_dir)

    def discover(self, names: Iterable[str] = TOOL_NAMES) -> dict[str, ToolStatus]:
        for name in names:
            if name in self.statuses:
                continue
            path = find_executable(name, self.directories)
            status = ToolStatus(name=name, path=path)
            if path:
                self.paths[name] = path
                status.status = "ok"
                self._read_version(name, status)
            else:
                status.status = "missing"
                status.error = "not found on PATH or in the configured tool directory"
            self.statuses[name] = status
        return self.statuses

    def _read_version(self, name: str, status: ToolStatus) -> None:
        if name in self._version_checked:
            return
        self._version_checked.add(name)
        result = run_command([self.paths[name], "--version"], timeout=30)
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        status.version = parse_tool_version(text)
        if result.returncode != 0 and not status.version:
            status.error = result.summary(300)

    def get(self, name: str) -> str | None:
        if name not in self.statuses:
            self.discover([name])
        return self.paths.get(name)

    def require(self, names: Iterable[str]) -> None:
        self.discover(names)
        missing = [name for name in names if not self.paths.get(name)]
        if missing:
            raise ToolNotFoundError(
                "Missing required tool(s): "
                + ", ".join(missing)
                + ". Run scripts/bootstrap-tools.sh (or scripts/bootstrap-tools.ps1 "
                "on Windows) or set LAYERSECOPS_TOOL_DIR."
            )

    def run(
        self,
        name: str,
        args: list[str],
        *,
        log_path: Path | None = None,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        path = self.get(name)
        if not path:
            raise ToolNotFoundError(f"Tool not found: {name}")
        started = time.monotonic()
        result = run_command(
            [path, *args],
            timeout=timeout or self.timeout,
            log_path=log_path,
            env=env,
        )
        status = self.statuses.setdefault(name, ToolStatus(name=name, path=path))
        status.duration_ms = int((time.monotonic() - started) * 1000)
        status.status = "ok" if result.ok else "failed"
        if not result.ok:
            status.error = result.summary()
        return result

    def tool_status(self, name: str) -> ToolStatus:
        return self.statuses.get(name, ToolStatus(name=name, status="not-run"))
