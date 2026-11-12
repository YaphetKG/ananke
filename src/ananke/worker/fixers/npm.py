"""Deterministic npm dependency bump and package-lock regeneration (no LLM).

Always edits `package.json` in the manifest's directory, even when the finding's manifest is
`package-lock.json` (Dependabot often reports the lockfile). A range prefix (`^`, `~`) is kept;
anything else becomes the exact fixed version. Packages that `package.json` does not declare
(transitive dependencies) are left to the agent rung.
"""

from __future__ import annotations

import json
from pathlib import Path

from ananke.model import WorkItem
from ananke.worker.fixers.base import FixResult, manifest_dir, rel, run_command, target_versions
from ananke.worker.sandbox import Sandbox

SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
LOCK_CMD = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]


def npm_spec(old: str, fixed: str) -> str:
    o = old.strip()
    for prefix in ("^", "~", ">="):
        if o.startswith(prefix):
            return f"{prefix}{fixed}"
    return fixed


class NpmFixer:
    ecosystems = frozenset({"npm"})

    def fix(self, item: WorkItem, workspace: Path, sandbox: Sandbox) -> FixResult:
        result = FixResult(supported=True)
        targets = target_versions(item, "npm")
        if not targets:
            result.add_error("no npm findings with a fixed version")
            return result
        try:
            directory = manifest_dir(item, workspace)
        except ValueError:
            result.add_error(f"manifest path escapes the workspace: {item.manifest_path!r}")
            return result
        manifest = directory / "package.json"
        if not manifest.is_file():
            result.add_error(f"package.json not found in {rel(directory, workspace) or '.'}")
            return result
        try:
            text = manifest.read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError) as exc:
            result.add_error(f"cannot read {rel(manifest, workspace)}: {exc}")
            return result
        if not isinstance(data, dict):
            result.add_error(f"{rel(manifest, workspace)} is not a JSON object")
            return result

        undeclared = []
        for package, fixed in targets.items():
            declared = False
            for section in SECTIONS:
                deps = data.get(section)
                if not isinstance(deps, dict) or not isinstance(deps.get(package), str):
                    continue
                declared = True
                old = deps[package]
                new = npm_spec(old, fixed)
                if old != new:
                    deps[package] = new
                    result.changes.append(f"{rel(manifest, workspace)}: {package} {old} -> {new}")
            if not declared:
                undeclared.append(package)
        if undeclared:
            result.add_error("not declared in package.json (transitive): " + ", ".join(undeclared))
        if result.changes:
            indent = 4 if '\n    "' in text and '\n  "' not in text else 2
            manifest.write_text(
                json.dumps(data, indent=indent, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            if (directory / "package-lock.json").is_file():
                code, stdout, stderr = run_command(sandbox, LOCK_CMD, directory, result)
                if code:
                    result.add_error(
                        f"npm lockfile regeneration failed: {(stderr or stdout)[-2000:]}"
                    )
                else:
                    result.changes.append(
                        f"{rel(directory / 'package-lock.json', workspace)}: regenerated"
                    )
        result.changed = bool(result.changes)
        return result
