"""Deterministic verification gate for patches (PLAN.md §5).

Every check is plain code; the agent cannot talk its way past it. Git is read on the host (never
through the sandbox), and scanner coverage comes from each scanner's declared kinds/ecosystems.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.utils import canonicalize_name

from ananke.config import PolicyConfig, RepoWorkflowConfig
from ananke.model import Finding, WorkItem, severity_at_least
from ananke.scanners.base import ScanDelta, ScanReport
from ananke.worker.sandbox import Sandbox
from ananke.worker.workspace import (
    WorkspaceError,
    changed_paths,
    diff_numstat,
    diff_text,
    untracked_paths,
)

TEST_TIMEOUT_S = 1800
LOCK_TIMEOUT_S = 900
TAIL = 12000

LOCKFILES = frozenset(
    {
        "uv.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.sum",
        "Pipfile.lock",
        "poetry.lock",
    }
)
# manifest/lockfile basename -> (lockfile that must exist, consistency command)
_LOCK_CHECKS: dict[str, tuple[str, list[str]]] = {
    "pyproject.toml": ("uv.lock", ["uv", "lock", "--check"]),
    "uv.lock": ("uv.lock", ["uv", "lock", "--check"]),
    "package.json": (
        "package-lock.json",
        ["npm", "ci", "--dry-run", "--ignore-scripts", "--no-audit", "--no-fund"],
    ),
    "package-lock.json": (
        "package-lock.json",
        ["npm", "ci", "--dry-run", "--ignore-scripts", "--no-audit", "--no-fund"],
    ),
    "go.mod": ("go.mod", ["go", "mod", "verify"]),
    "go.sum": ("go.mod", ["go", "mod", "verify"]),
}

_SKIP_ADDED = re.compile(
    r"@pytest\.mark\.(?:skip|xfail)|pytest\.skip\(|@unittest\.skip|\.skip\(|\bxit\s*\(|"
    r"\bxdescribe\s*\(|\bt\.Skip(?:Now|f)?\("
)
_REMOVED_TEST = re.compile(
    r"\bdef\s+test_|\bclass\s+Test|\bassert\b|\bfunc\s+Test|\bexpect\(|\b(?:it|test)\s*\("
)
_TEST_DIRS = frozenset({"tests", "test", "__tests__", "spec", "testing"})
_TEST_SUFFIXES = (
    "_test.py", "_test.go", ".test.js", ".test.ts", ".test.jsx", ".test.tsx",
    ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx",
)  # fmt: skip


@dataclass
class Check:
    status: str  # passed | failed | warning | not run
    detail: str = ""


@dataclass
class VerifyResult:
    passed: bool
    checks: dict[str, Check] = field(default_factory=dict)
    paths: list[str] = field(default_factory=list)
    diff_lines: int = 0
    diff_files: int = 0
    tests_stdout: str = ""
    tests_stderr: str = ""
    db_warnings: list[str] = field(default_factory=list)

    def failures(self) -> list[str]:
        return [f"{k}: {v.detail}" for k, v in self.checks.items() if v.status == "failed"]

    def as_evidence(self) -> dict[str, Any]:
        """check name -> {status, detail}; `tests` adds `tail`, `diff_size` adds lines/files.

        This is the shape the PR body (evidence.verify.tests.status, .diff_size.lines) and the
        failure issue's verify table read.
        """
        ev: dict[str, dict[str, Any]] = {
            k: {"status": v.status, "detail": v.detail} for k, v in self.checks.items()
        }
        tests = ev.setdefault("tests", {"status": "not run", "detail": ""})
        tests["tail"] = (self.tests_stdout + "\n" + self.tests_stderr).strip()[-TAIL:]
        size = ev.setdefault("diff_size", {"status": "not run", "detail": ""})
        size.update(lines=self.diff_lines, files=self.diff_files)
        return ev


@dataclass(frozen=True)
class Coverage:
    """What a scanner can attest to: its kinds and ecosystems ({"*"} = all)."""

    kinds: frozenset[str]
    ecosystems: frozenset[str]

    def covers(self, target: Finding) -> bool:
        if "dependency" not in self.kinds:
            return False
        return (
            target.ecosystem is None
            or "*" in self.ecosystems
            or target.ecosystem in self.ecosystems
        )


def coverage_of(scanners: Iterable[Any]) -> dict[str, Coverage]:
    return {s.name: Coverage(frozenset(s.kinds), frozenset(s.ecosystems)) for s in scanners}


def matches(path: str, patterns: Iterable[str]) -> bool:
    """fnmatch-style match where `**/x` also matches `x` at the repository root."""
    return any(
        fnmatch.fnmatchcase(path, p) or (p.startswith("**/") and fnmatch.fnmatchcase(path, p[3:]))
        for p in patterns
    )


def is_dockerfile(path: str) -> bool:
    name = PurePosixPath(path).name
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def is_test_path(path: str) -> bool:
    p = PurePosixPath(path)
    if any(part in _TEST_DIRS for part in p.parts[:-1]):
        return True
    return p.name.startswith("test_") or p.name == "conftest.py" or p.name.endswith(_TEST_SUFFIXES)


def _pkg(name: str | None, ecosystem: str | None) -> str | None:
    if name is None:
        return None
    return canonicalize_name(name) if ecosystem in (None, "pip") else name.lower()


def target_present(target: Finding, report: ScanReport) -> bool:
    """True if `report` still contains `target` (shared advisory id/alias and same package)."""
    ids = {i.strip().upper() for i in target.advisory_ids if i and i.strip()}
    want = _pkg(target.package, target.ecosystem)
    for f in report.findings:
        if ids.isdisjoint(f.all_ids):
            continue
        if want and f.package and _pkg(f.package, target.ecosystem) != want:
            continue
        return True
    return False


def _mentions(text: str, target: Finding) -> bool:
    tokens = [target.package, *target.advisory_ids, target.source_id]
    return any(t and t.lower() in text for t in tokens)


def _added_file_lines(workspace: Path, path: str) -> int:
    try:
        return len((workspace / path).read_text(encoding="utf-8", errors="replace").splitlines())
    except (OSError, UnicodeError):
        return 0


def find_test_tampering(diff: str, paths: list[str], workspace: Path) -> dict[str, list[str]]:
    """Test file -> suspicious diff lines (skips added, tests/asserts removed, file deleted)."""
    found: dict[str, list[str]] = {}
    current: str | None = None
    old: str | None = None
    for line in diff.splitlines():
        if line.startswith("--- "):
            old = line[4:].removeprefix("a/") if line[4:] != "/dev/null" else None
            continue
        if line.startswith("+++ "):
            new = line[4:].removeprefix("b/") if line[4:] != "/dev/null" else None
            current = new or old
            continue
        if line.startswith("diff --git ") or current is None or not is_test_path(current):
            continue
        if line.startswith("+") and _SKIP_ADDED.search(line):
            found.setdefault(current, []).append(line[:240])
        elif line.startswith("-") and _REMOVED_TEST.search(line):
            found.setdefault(current, []).append(line[:240])
    for p in paths:
        if is_test_path(p) and not (workspace / p).exists():
            found.setdefault(p, []).append("(file deleted)")
    return found


def verify(
    *,
    item: WorkItem,
    workspace: Path,
    sandbox: Sandbox,
    base_ref: str,
    before: Mapping[str, ScanReport],
    after: Mapping[str, ScanReport],
    deltas: Mapping[str, ScanDelta],
    repo_config: RepoWorkflowConfig,
    policy: PolicyConfig,
    test_command: str | None,
    coverage: Mapping[str, Coverage],
    max_db_age_days: int = 7,
    result: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> VerifyResult:
    """Run every check of PLAN.md §5. Any failed (non-advisory) check blocks the PR.

    `result` is the agent's report_result arguments, or None on the deterministic rung.
    """
    out = VerifyResult(passed=True)

    def record(name: str, status: str, detail: str = "", *, advisory: bool = False) -> None:
        out.checks[name] = Check(status, detail)
        if status == "failed" and not advisory:
            out.passed = False

    # 1. diff_nonempty
    try:
        paths = changed_paths(workspace, base_ref)
        untracked = untracked_paths(workspace)
    except WorkspaceError as exc:
        paths, untracked = [], set()
        record("diff_nonempty", "failed", f"cannot diff against {base_ref}: {exc}")
    else:
        record("diff_nonempty", "passed" if paths else "failed", f"{len(paths)} changed paths")
    out.paths = paths

    # 2. paths_allowed
    protected = [p for p in paths if matches(p, repo_config.protected_paths)]
    disallowed = [p for p in paths if not matches(p, repo_config.allowed_paths)]
    dockerfiles = [p for p in paths if is_dockerfile(p)]
    if policy.allow_dockerfile:
        disallowed = [p for p in disallowed if p not in dockerfiles]
    else:
        protected += [p for p in dockerfiles if p not in protected]
    bad = bool(protected or disallowed)
    record(
        "paths_allowed",
        "failed" if bad else "passed",
        f"protected={protected}; outside_allowed={disallowed}"
        if bad
        else f"{len(paths)} paths allowed",
    )

    # 3. diff_size (lockfile churn exempt; new untracked files count in full)
    lines = 0
    try:
        for added, deleted, path in diff_numstat(workspace, base_ref):
            if PurePosixPath(path).name not in LOCKFILES:
                lines += (added or 0) + (deleted or 0)
    except WorkspaceError:
        pass
    for path in sorted(untracked):
        if PurePosixPath(path).name not in LOCKFILES:
            lines += _added_file_lines(workspace, path)
    out.diff_files, out.diff_lines = len(paths), lines
    record(
        "diff_size",
        "failed" if lines > repo_config.max_diff_lines else "passed",
        f"{lines} lines across {len(paths)} files; limit={repo_config.max_diff_lines}",
    )

    # 5. targets_resolved (4. scan_after happened before this call: `after` and `deltas`)
    unresolved: dict[str, list[str]] = {}
    unseen: list[str] = []
    for target in item.findings:
        covering = [n for n in after if n in coverage and coverage[n].covers(target)]
        if not covering:
            unresolved[target.key] = ["no covering scanner"]
            continue
        present = [n for n in covering if target_present(target, after[n])]
        if present:
            unresolved[target.key] = present
        if not any(n in before and target_present(target, before[n]) for n in covering):
            unseen.append(target.key)
    text = ""
    if result:
        text = " ".join(
            str(result.get(k, "")) for k in ("summary", "changes", "risk_notes")
        ).lower()
    partial_ok = (
        bool(unresolved)
        and result is not None
        and result.get("status") == "partial"
        and all(_mentions(text, f) for f in item.findings if f.key in unresolved)
    )
    if unresolved and not partial_ok:
        detail = f"unresolved={unresolved}"
    elif unresolved:
        detail = f"partial fix reported; still present: {sorted(unresolved)}"
    else:
        detail = "all targeted advisories absent from every covering scanner"
    if unseen:
        detail += f"; not reported before the change by any covering scanner: {unseen}"
    record("targets_resolved", "failed" if unresolved and not partial_ok else "passed", detail)

    # 6. no_regressions / 7. no_secrets
    regressions = [
        f"{name}:{f.id}"
        for name, d in deltas.items()
        for f in d.introduced
        if f.kind != "secret" and severity_at_least(f.severity, policy.regression_severity)
    ]
    record(
        "no_regressions",
        "failed" if regressions else "passed",
        f"introduced at/above {policy.regression_severity}: {regressions}"
        if regressions
        else f"no new findings at/above {policy.regression_severity}",
    )
    secrets = [
        f"{name}:{f.id}@{f.location}"
        for name, d in deltas.items()
        for f in d.introduced
        if f.kind == "secret"
    ]
    record(
        "no_secrets",
        "failed" if secrets else "passed",
        f"introduced secrets: {secrets}" if secrets else "none",
    )

    # 11. scanner_db_fresh (warning only)
    now = now or datetime.now(UTC)
    for name, report in after.items():
        updated = report.db_updated_at
        if updated is not None and now - updated > timedelta(days=max_db_age_days):
            out.db_warnings.append(
                f"{name} vulnerability database is older than {max_db_age_days} days "
                f"(updated {updated.date().isoformat()})."
            )
    record(
        "scanner_db_fresh", "warning" if out.db_warnings else "passed", "; ".join(out.db_warnings)
    )

    # 8. tests
    advisory_tests = repo_config.tests == "advisory"
    if not test_command:
        status = "not run" if advisory_tests else "failed"
        record("tests", status, "ANANKE.md has no test_command", advisory=advisory_tests)
    else:
        res = sandbox.run(test_command, cwd=workspace, timeout_s=TEST_TIMEOUT_S)
        out.tests_stdout, out.tests_stderr = res.stdout[-TAIL:], res.stderr[-TAIL:]
        record(
            "tests",
            "passed" if res.ok else "failed",
            f"exit {res.exit_code}",
            advisory=advisory_tests,
        )

    # 9. lockfile_consistent, per directory with a changed manifest or lockfile
    runs: dict[tuple[str, tuple[str, ...]], Path] = {}
    for p in paths:
        pp = PurePosixPath(p)
        spec = _LOCK_CHECKS.get(pp.name)
        if spec is None:
            continue
        lockfile, cmd = spec
        directory = workspace / pp.parent
        if (directory / lockfile).is_file():
            runs[(str(pp.parent), tuple(cmd))] = directory
    if not runs:
        record("lockfile_consistent", "passed", "no manifest with a supported lockfile changed")
    else:
        problems, ran = [], []
        for (rel_dir, cmd), directory in sorted(runs.items()):
            res = sandbox.run(list(cmd), cwd=directory, timeout_s=LOCK_TIMEOUT_S)
            ran.append(f"{' '.join(cmd)} in {rel_dir}")
            if not res.ok:
                tail = (res.stderr or res.stdout)[-1500:]
                problems.append(f"{' '.join(cmd)} in {rel_dir} exited {res.exit_code}: {tail}")
        record(
            "lockfile_consistent",
            "failed" if problems else "passed",
            "; ".join(problems) or "; ".join(ran),
        )

    # 10. no_test_tampering
    try:
        diff = diff_text(workspace, base_ref)
    except WorkspaceError:
        diff = ""
    tampering = find_test_tampering(diff, paths, workspace)
    notes = str((result or {}).get("risk_notes") or "").lower()
    unexplained = sorted(
        p for p in tampering if not (p.lower() in notes or PurePosixPath(p).name.lower() in notes)
    )
    if not tampering:
        record("no_test_tampering", "passed", "no skipped, removed or deleted tests")
    elif unexplained:
        record(
            "no_test_tampering",
            "failed",
            "test changes not explained in risk_notes: "
            + "; ".join(f"{p}: {tampering[p][:3]}" for p in unexplained),
        )
    else:
        record(
            "no_test_tampering",
            "warning",
            f"test changes explained in risk_notes: {sorted(tampering)}",
        )

    return out
