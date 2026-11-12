"""Common types for deterministic, no-model dependency fixers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol

from packaging.version import InvalidVersion, Version

from ananke.model import WorkItem
from ananke.worker.sandbox import Sandbox

FIX_TIMEOUT_S = 1800


@dataclass
class FixResult:
    changed: bool = False
    supported: bool = False
    changes: list[str] = field(default_factory=list)
    commands: list[dict[str, object]] = field(default_factory=list)
    error: str | None = None

    def add_error(self, message: str) -> None:
        self.error = message if not self.error else f"{self.error}; {message}"


class Fixer(Protocol):
    ecosystems: frozenset[str]

    def fix(self, item: WorkItem, workspace: Path, sandbox: Sandbox) -> FixResult: ...


def result_for(
    item: WorkItem, ecosystem: str | None, workspace: Path, sandbox: Sandbox
) -> FixResult:
    """Dispatch a WorkItem to the built-in ecosystem fixer."""
    if ecosystem == "pip":
        from ananke.worker.fixers.pip import PipFixer

        return PipFixer().fix(item, workspace, sandbox)
    if ecosystem == "npm":
        from ananke.worker.fixers.npm import NpmFixer

        return NpmFixer().fix(item, workspace, sandbox)
    if ecosystem == "go":
        from ananke.worker.fixers.go import GoFixer

        return GoFixer().fix(item, workspace, sandbox)
    return FixResult(supported=False, error=f"no deterministic fixer for ecosystem {ecosystem!r}")


def version_key(v: str) -> tuple[int, Version | str]:
    try:
        return (1, Version(v))
    except InvalidVersion:
        return (0, v)


def target_versions(item: WorkItem, ecosystem: str) -> dict[str, str]:
    """Package -> highest fixed version over the item's findings for `ecosystem`.

    Several advisories for one package usually have different fixed versions; bumping to the
    highest one is the minimal version that resolves all of them.
    """
    out: dict[str, str] = {}
    for f in item.findings:
        if f.ecosystem != ecosystem or not f.package or not f.fixed_version:
            continue
        current = out.get(f.package)
        if current is None or version_key(f.fixed_version) > version_key(current):
            out[f.package] = f.fixed_version
    return out


def manifest_dir(item: WorkItem, workspace: Path) -> Path:
    """Directory of the item's manifest inside the workspace (the workspace for None).

    Raises ValueError if the manifest path escapes the workspace.
    """
    rel = PurePosixPath(item.manifest_path).parent if item.manifest_path else PurePosixPath(".")
    path = (workspace / rel).resolve()
    path.relative_to(workspace.resolve())
    return path


def rel(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def run_command(
    sandbox: Sandbox, cmd: list[str], cwd: Path, result: FixResult | None = None
) -> tuple[int, str, str]:
    """Run a fixer command in the sandbox; record it on `result` when given."""
    res = sandbox.run(cmd, cwd=cwd, timeout_s=FIX_TIMEOUT_S)
    stdout, stderr = res.stdout[-12000:], res.stderr[-12000:]
    if result is not None:
        result.commands.append(
            {
                "cmd": " ".join(cmd),
                "cwd": str(cwd),
                "exit_code": res.exit_code,
                "stdout": stdout,
                "stderr": stderr,
            }
        )
    return res.exit_code, stdout, stderr


def read_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None
