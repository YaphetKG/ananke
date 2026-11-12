"""Deterministic Go module bump and tidy (no LLM)."""

from __future__ import annotations

from pathlib import Path

from ananke.model import WorkItem
from ananke.worker.fixers.base import (
    FixResult,
    manifest_dir,
    read_bytes,
    run_command,
    target_versions,
)
from ananke.worker.sandbox import Sandbox


def go_version(v: str) -> str:
    """Go module versions carry a `v` prefix; advisories usually omit it."""
    return v if v.startswith("v") else f"v{v}"


class GoFixer:
    ecosystems = frozenset({"go"})

    def fix(self, item: WorkItem, workspace: Path, sandbox: Sandbox) -> FixResult:
        result = FixResult(supported=True)
        targets = target_versions(item, "go")
        if not targets:
            result.add_error("no go findings with a fixed version")
            return result
        try:
            directory = manifest_dir(item, workspace)
        except ValueError:
            result.add_error(f"manifest path escapes the workspace: {item.manifest_path!r}")
            return result
        go_mod = directory / "go.mod"
        if not go_mod.is_file():
            result.add_error("go.mod not found")
            return result
        before = (read_bytes(go_mod), read_bytes(directory / "go.sum"))
        for package, fixed in targets.items():
            version = go_version(fixed)
            code, stdout, stderr = run_command(
                sandbox, ["go", "get", f"{package}@{version}"], directory, result
            )
            if code:
                result.add_error(f"go get failed for {package}: {(stderr or stdout)[-2000:]}")
                return result
            result.changes.append(f"go.mod: {package} -> {version}")
        code, stdout, stderr = run_command(sandbox, ["go", "mod", "tidy"], directory, result)
        if code:
            result.add_error(f"go mod tidy failed: {(stderr or stdout)[-2000:]}")
        if (read_bytes(go_mod), read_bytes(directory / "go.sum")) == before:
            result.changes = []
        result.changed = bool(result.changes)
        return result
