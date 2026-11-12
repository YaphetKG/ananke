"""Offline test doubles shared by the M1 worker tests (no Docker, no scanner binaries)."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from packaging.version import Version

from ananke.model import Finding, WorkItem
from ananke.scanners.base import ScanFinding, ScannerVersion, ScanReport
from ananke.worker.sandbox import CommandResult, LocalSandbox

REPO = "RENCI/example-repo"
# package -> [(CVE, GHSA, fixed_version, severity)]
ADVISORIES: dict[str, list[tuple[str, str, str, str]]] = {
    "requests": [
        ("CVE-2023-32681", "GHSA-j8r2-6x86-q33q", "2.31.0", "medium"),
        ("CVE-2024-35195", "GHSA-9wx4-h78v-vm56", "2.32.0", "medium"),
    ],
    "badlib": [("CVE-2030-0001", "GHSA-bad0-bad0-bad0", "9.9.9", "high")],
}
_PIN = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s;#]+)")


class PinScanner:
    """A dependency scanner that reads `pkg==version` pins from plain text files.

    Reports every advisory in `advisories` whose fixed version is above the pinned one.
    """

    name = "pinscan"
    kinds = frozenset({"dependency"})
    ecosystems = frozenset({"pip"})

    def __init__(
        self,
        advisories: dict[str, list[tuple[str, str, str, str]]] | None = None,
        files: tuple[str, ...] = ("requirements.txt", "deps.txt"),
        *,
        db_updated_at: datetime | None = None,
    ) -> None:
        self.advisories = ADVISORIES if advisories is None else advisories
        self.files = files
        self.db_updated_at = db_updated_at
        self.scans = 0

    def available(self, sandbox) -> bool:
        return True

    def version(self, sandbox) -> ScannerVersion:
        return ScannerVersion(tool_version="1.2.3", db_version="fake-db-1")

    def scan(self, sandbox, workspace: Path, targets=None) -> ScanReport:
        self.scans += 1
        findings: list[ScanFinding] = []
        for name in self.files:
            path = Path(workspace) / name
            if not path.is_file():
                continue
            for line in path.read_text().splitlines():
                m = _PIN.match(line)
                if not m:
                    continue
                pkg, installed = m.group(1).lower(), m.group(2)
                for cve, ghsa, fixed, severity in self.advisories.get(pkg, []):
                    if Version(installed) < Version(fixed):
                        findings.append(
                            ScanFinding(
                                id=cve,
                                aliases=[ghsa],
                                kind="dependency",
                                severity=severity,  # type: ignore[arg-type]
                                package=pkg,
                                installed_version=installed,
                                fixed_version=fixed,
                                location=name,
                                title=f"{pkg} advisory {cve}",
                            )
                        )
        return ScanReport(
            scanner=self.name,
            scanner_version="1.2.3",
            db_version="fake-db-1",
            db_updated_at=self.db_updated_at,
            targets=[str(workspace)],
            findings=findings,
        )

    def parse(self, raw: str) -> ScanReport:
        return ScanReport(scanner=self.name)


def finding(
    package: str = "requests",
    fixed: str = "2.32.0",
    *,
    ids: tuple[str, ...] = ("GHSA-9wx4-h78v-vm56", "CVE-2024-35195"),
    manifest: str = "requirements.txt",
    ecosystem: str = "pip",
    number: int = 1,
    severity: str = "high",
    repo: str = REPO,
) -> Finding:
    return Finding(
        key=Finding.make_key(repo, "github_dependabot", str(number)),
        repo=repo,
        source="github_dependabot",
        source_id=str(number),
        severity=severity,  # type: ignore[arg-type]
        advisory_ids=list(ids),
        summary=f"{package} advisory",
        url=f"https://github.com/advisories/{ids[0]}",
        ecosystem=ecosystem,
        package=package,
        manifest_path=manifest,
        vulnerable_range=f"< {fixed}",
        fixed_version=fixed,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def item_for(*findings: Finding, manifest: str | None = "requirements.txt") -> WorkItem:
    return WorkItem.from_findings(findings[0].repo, manifest, list(findings))


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def make_origin(tmp: Path, files: dict[str, str], name: str = "origin") -> Path:
    """A bare git repo (branch `main`) holding `files`, standing in for GitHub."""
    src = tmp / f"{name}-src"
    src.mkdir(parents=True)
    git(src, "init", "-q", "-b", "main")
    for rel, text in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    git(src, "add", "-A")
    git(src, "commit", "-q", "-m", "initial")
    bare = tmp / f"{name}.git"
    git(tmp, "clone", "-q", "--bare", str(src), str(bare))
    return bare


def checkout(tmp: Path, files: dict[str, str]) -> Path:
    """A clone of a fresh origin with `origin/main` available, for diff-based checks."""
    bare = make_origin(tmp, files)
    work = tmp / "work"
    git(tmp, "clone", "-q", str(bare), str(work))
    return work


class ScriptedSandbox(LocalSandbox):
    """LocalSandbox that answers commands matching a prefix with canned results and records
    every command it sees."""

    def __init__(
        self,
        root: Path,
        canned: dict[str, CommandResult | Callable[[list[str] | str], CommandResult]] | None = None,
    ) -> None:
        super().__init__(root)
        self.canned = canned or {}
        self.calls: list[list[str] | str] = []

    def run(self, cmd, *, cwd=None, timeout_s=600) -> CommandResult:
        self.calls.append(cmd)
        text = cmd if isinstance(cmd, str) else " ".join(cmd)
        for prefix, answer in self.canned.items():
            if text.startswith(prefix):
                return answer(cmd) if callable(answer) else answer
        return super().run(cmd, cwd=cwd, timeout_s=timeout_s)


OK = CommandResult(0, "", "")
