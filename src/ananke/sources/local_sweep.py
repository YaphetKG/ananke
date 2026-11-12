"""Local scanner sweep source for repositories without Dependabot (PLAN.md §3.5).

The source owns no credentials. It converts normalized dependency findings that have a known fix
into the same `Finding` shape Dependabot produces, so the same work-item pipeline applies. The
caller supplies the checkout and sandbox factories so the daemon can enforce its workspace and
isolation policy; the daemon also owns the sweep cadence (`scanners.sweep_interval_s`).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from ananke.logging import get_logger
from ananke.model import Finding
from ananke.scanners.base import ScanFinding, Scanner, ScanReport
from ananke.worker.sandbox import Sandbox

log = get_logger(__name__)

SOURCES = ("osv", "trivy")  # scanners that map onto a Finding.source value

_ECOSYSTEM_FILES = {
    "pip": (
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "setup.py",
        "setup.cfg",
    ),
    "npm": (
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
    ),
    "go": ("go.mod", "go.sum"),
}


def infer_ecosystem(location: str | None) -> str | None:
    """Ecosystem from a manifest/lockfile path (`requirements-dev.txt`, `sub/uv.lock`, ...)."""
    if not location:
        return None
    name = PurePosixPath(location.lower().split(":", 1)[0]).name
    for eco, names in _ECOSYSTEM_FILES.items():
        if name in names:
            return eco
    if name.startswith("requirements") and name.endswith((".txt", ".in")):
        return "pip"
    return None


def advisory_url(advisory_id: str) -> str:
    if advisory_id.upper().startswith("GHSA-"):
        return f"https://github.com/advisories/{advisory_id}"
    return f"https://osv.dev/vulnerability/{advisory_id}"


class LocalSweepSource:
    name = "local_sweep"

    def __init__(
        self,
        scanners: list[Scanner],
        *,
        workspace_for: Callable[[str], Path],
        sandbox_for: Callable[[Path], Sandbox],
        sync_repo: Callable[[str, Path], None],
    ) -> None:
        """`sync_repo(repo, path)` must clone `repo` into `path`, or reset an existing checkout
        to the latest default branch. It is called before every sweep."""
        self.scanners = scanners
        self.workspace_for = workspace_for
        self.sandbox_for = sandbox_for
        self.sync_repo = sync_repo
        self.last_reports: dict[str, list[ScanReport]] = {}

    async def fetch_open(self, repo: str) -> list[Finding]:
        return await asyncio.to_thread(self._scan, repo)

    async def fetch_by_keys(self, keys: list[str]) -> list[Finding]:
        repos = list(dict.fromkeys(k.split(":", 1)[0] for k in keys if ":" in k))
        findings: list[Finding] = []
        for repo in repos:
            findings.extend(await self.fetch_open(repo))
        wanted = set(keys)
        return [f for f in findings if f.key in wanted]

    def _scan(self, repo: str) -> list[Finding]:
        workspace = self.workspace_for(repo).expanduser().resolve()
        workspace.parent.mkdir(parents=True, exist_ok=True)
        self.sync_repo(repo, workspace)
        sandbox = self.sandbox_for(workspace)
        reports: list[ScanReport] = []
        try:
            for scanner in self.scanners:
                if "dependency" not in scanner.kinds or scanner.name not in SOURCES:
                    continue
                if not scanner.available(sandbox):
                    log.warning("sweep_scanner_unavailable", repo=repo, scanner=scanner.name)
                    continue
                reports.append(scanner.scan(sandbox, workspace))
        finally:
            close = getattr(sandbox, "close", None)
            if close is not None:
                close()
        self.last_reports[repo] = reports
        return findings_from_reports(repo, reports)


def findings_from_reports(repo: str, reports: list[ScanReport]) -> list[Finding]:
    """Fixable dependency findings, de-duplicated across scanners (first scanner wins)."""
    out: list[Finding] = []
    seen: list[ScanFinding] = []
    for report in reports:
        if report.scanner not in SOURCES:
            continue
        for sf in report.findings:
            if sf.kind != "dependency" or not sf.fixed_version or not sf.package:
                continue
            if any(sf.same_as(other) for other in seen):
                continue
            seen.append(sf)
            source_id = "|".join((sf.id, sf.package, sf.location or ""))
            out.append(
                Finding(
                    key=Finding.make_key(repo, report.scanner, source_id),
                    repo=repo,
                    source=report.scanner,  # type: ignore[arg-type]  # one of SOURCES
                    source_id=source_id,
                    severity=sf.severity,
                    advisory_ids=[sf.id, *sf.aliases],
                    summary=sf.title,
                    url=advisory_url(sf.id),
                    ecosystem=infer_ecosystem(sf.location),
                    package=sf.package,
                    manifest_path=sf.location,
                    vulnerable_range=None,
                    fixed_version=sf.fixed_version,
                    state="open",
                    created_at=report.ran_at,
                    raw={"scanner": report.scanner, "finding": sf.model_dump(mode="json")},
                )
            )
    return out
