"""Deterministic Python dependency bumps and lockfile regeneration (no LLM).

For each vulnerable package the fixer picks the highest fixed version among the item's findings,
then:

- edits every declaration of the package in the manifest directory's `pyproject.toml`
  (PEP 621 dependencies, optional dependencies, dependency groups, `[tool.uv]` lists, Poetry
  dependency tables) and `requirements*.txt` files. Exact pins become `==<fixed>`; ranges that
  already allow the fixed version are left alone; ranges that exclude it become `>=<fixed>`.
- regenerates `uv.lock` with `uv lock --upgrade-package <pkg>==<fixed>` for every target, which
  also covers transitive dependencies that no manifest declares. A conflict (a parent pins an
  older range) makes `uv lock` fail, and the item falls through to the agent rung.

Markers, extras and comments are preserved verbatim.
"""

from __future__ import annotations

import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from ananke.model import WorkItem
from ananke.worker.fixers.base import (
    FixResult,
    manifest_dir,
    read_bytes,
    rel,
    run_command,
    target_versions,
)
from ananke.worker.sandbox import Sandbox

_NAME_PREFIX = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?")
_REQ_LINE = re.compile(r"^(\s*)([^#\s-][^#]*?)(\s*(?:\s#.*)?)$")
_QUOTED = re.compile(r"(\"|')(.*?)\1")
_TABLE = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
_KEY = re.compile(r"^\s*([A-Za-z0-9_.\"'-]+)\s*=")
_POETRY_TABLE = re.compile(
    r"^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.]+\.dependencies)$"
)


def new_specifier(spec: SpecifierSet, fixed: str) -> str | None:
    """The specifier to write, or None when `spec` already admits `fixed` (lock-only bump)."""
    if any(s.operator in ("==", "===") for s in spec):
        return f"=={fixed}"
    if not str(spec) or spec.contains(fixed, prereleases=True):
        return None
    return f">={fixed}"


def rewrite_requirement(raw: str, package: str, fixed: str) -> tuple[bool, str]:
    """Rewrite one PEP 508 string. Returns (declares_package, new_text).

    Only the version-specifier span changes; the name, extras, marker and surrounding text are
    kept byte for byte (markers may contain quotes that must stay as written).
    """
    try:
        req = Requirement(raw.strip())
    except InvalidRequirement:
        return False, raw
    if canonicalize_name(req.name) != canonicalize_name(package) or req.url:
        return False, raw
    new = new_specifier(req.specifier, fixed)
    if new is None:
        return True, raw
    head = _NAME_PREFIX.match(raw)
    if head is None:  # pragma: no cover - Requirement() parsed it, so a name is present
        return True, raw
    rest = raw[head.end() :]
    semi = rest.find(";")
    marker = "" if semi < 0 else " " + rest[semi:].lstrip()
    return True, raw[: head.end()].rstrip() + new + marker


def edit_requirements(path: Path, package: str, fixed: str) -> tuple[bool, bool]:
    """Edit a requirements file in place. Returns (declares_package, changed)."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    declared = changed = False
    for i, line in enumerate(lines):
        body = line.rstrip("\r\n")
        ending = line[len(body) :]
        if body.rstrip().endswith("\\"):
            continue  # hashed / continued lines need pip-compile; leave them to the agent
        m = _REQ_LINE.match(body)
        if not m:
            continue
        hit, new = rewrite_requirement(m.group(2), package, fixed)
        declared |= hit
        if new != m.group(2):
            lines[i] = m.group(1) + new + m.group(3) + ending
            changed = True
    if changed:
        path.write_text("".join(lines), encoding="utf-8")
    return declared, changed


def _starts_dependency_array(table: str, line: str) -> bool:
    key = _KEY.match(line)
    if not key:
        return False
    name = key.group(1).strip("\"'")
    if table == "project":
        return name == "dependencies"
    if table in ("project.optional-dependencies", "dependency-groups"):
        return True
    if table == "tool.uv":
        return name in ("dev-dependencies", "constraint-dependencies", "override-dependencies")
    return False


def poetry_spec(old: str, fixed: str) -> str:
    o = old.strip()
    if o.startswith("^"):
        return f"^{fixed}"
    if o.startswith("~") and not o.startswith("~="):
        return f"~{fixed}"
    if o.startswith("==") or re.match(r"^\d", o):
        return fixed
    return f">={fixed}"


def edit_pyproject(path: Path, package: str, fixed: str) -> tuple[bool, bool]:
    """Edit dependency declarations in pyproject.toml. Returns (declares_package, changed)."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    table = ""
    depth = 0  # bracket depth inside a dependency array that spans lines
    declared = changed = False
    for i, line in enumerate(lines):
        if depth == 0:
            m = _TABLE.match(line)
            if m:
                table = m.group(1).strip()
                continue
        in_array = depth > 0 or _starts_dependency_array(table, line)
        if in_array:

            def repl(m: re.Match[str]) -> str:
                nonlocal declared
                hit, new = rewrite_requirement(m.group(2), package, fixed)
                declared |= hit
                return f"{m.group(1)}{new}{m.group(1)}"

            new_line = _QUOTED.sub(repl, line)
            bare = _QUOTED.sub("", line)
            bare = bare.split("#", 1)[0]
            depth = max(0, depth + bare.count("[") - bare.count("]"))
            if new_line != line:
                lines[i] = new_line
                changed = True
            continue
        if _POETRY_TABLE.match(table):
            key = _KEY.match(line)
            if not key or canonicalize_name(key.group(1).strip("\"'")) != canonicalize_name(
                package
            ):
                continue
            declared = True
            rest = line[key.end() :]
            inline = re.match(r"(\s*\{.*?\bversion\s*=\s*)([\"'])(.*?)\2", rest)
            plain = re.match(r"(\s*)([\"'])(.*?)\2", rest)
            m = inline or plain
            if m is None:
                continue
            new_value = poetry_spec(m.group(3), fixed)
            if new_value != m.group(3):
                start = key.end() + m.start(3)
                end = key.end() + m.end(3)
                lines[i] = line[:start] + new_value + line[end:]
                changed = True
    if changed:
        path.write_text("".join(lines), encoding="utf-8")
    return declared, changed


def _manifests(directory: Path, item: WorkItem, workspace: Path) -> list[Path]:
    found = [directory / "pyproject.toml", *sorted(directory.glob("requirements*.txt"))]
    if item.manifest_path and item.manifest_path.endswith((".txt", ".in")):
        found.append(workspace / item.manifest_path)
    out: list[Path] = []
    for p in found:
        if p.is_file() and p.resolve() not in {o.resolve() for o in out}:
            out.append(p)
    return out


class PipFixer:
    ecosystems = frozenset({"pip"})

    def fix(self, item: WorkItem, workspace: Path, sandbox: Sandbox) -> FixResult:
        result = FixResult(supported=True)
        targets = target_versions(item, "pip")
        if not targets:
            result.add_error("no pip findings with a fixed version")
            return result
        try:
            directory = manifest_dir(item, workspace)
        except ValueError:
            result.add_error(f"manifest path escapes the workspace: {item.manifest_path!r}")
            return result
        manifests = _manifests(directory, item, workspace)
        uv_lock = directory / "uv.lock"
        undeclared: list[str] = []
        edited = False
        for package, fixed in targets.items():
            declared = False
            for path in manifests:
                editor = edit_pyproject if path.name == "pyproject.toml" else edit_requirements
                hit, did_change = editor(path, package, fixed)
                declared |= hit
                if did_change:
                    edited = True
                    result.changes.append(f"{rel(path, workspace)}: {package} -> {fixed}")
            if not declared:
                undeclared.append(package)

        if uv_lock.is_file():
            before = read_bytes(uv_lock)
            cmd = ["uv", "lock"]
            for package, fixed in targets.items():
                cmd += ["--upgrade-package", f"{package}=={fixed}"]
            code, stdout, stderr = run_command(sandbox, cmd, directory, result)
            if code:
                result.add_error(f"uv lock failed: {(stderr or stdout)[-2000:]}")
            elif read_bytes(uv_lock) != before:
                result.changes.append(
                    f"{rel(uv_lock, workspace)}: regenerated ("
                    + ", ".join(f"{p} {v}" for p, v in targets.items())
                    + ")"
                )
        elif (directory / "Pipfile.lock").is_file() and edited:
            code, stdout, stderr = run_command(sandbox, ["pipenv", "lock"], directory, result)
            if code:
                result.add_error(f"pipenv lock failed: {(stderr or stdout)[-2000:]}")
        elif undeclared:
            result.add_error(
                "not declared in any manifest and no uv.lock to upgrade: " + ", ".join(undeclared)
            )
        result.changed = bool(result.changes)
        return result
