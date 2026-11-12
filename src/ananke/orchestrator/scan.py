"""Fetch + triage for one pass over all configured repos (PLAN.md §3.4 steps 3-4).

Used by `ananke scan` and reused by the daemon tick. Two modes:

- network: Dependabot alerts via `DependabotSource` plus Ananke PRs (head branch `ananke/*`)
  via the read-only GitHub client; requires GitHub credentials.
- fixtures: `<fixtures>/dependabot_alerts/open.json` is parsed for every configured repo; no
  network, no credentials, no PRs.

Errors for one repo never abort the pass: they are collected in `ScanResult.errors`.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from rich.table import Table

from ananke.config import AnankeConfig
from ananke.github.auth import AuthError, GitHubAuth
from ananke.github.client import GitHubClient, GitHubError
from ananke.logging import get_logger
from ananke.model import BRANCH_PREFIX, Finding, WorkItem, severity_rank
from ananke.orchestrator.triage import PullRef, TriageResult, triage
from ananke.sources.base import SourceError
from ananke.sources.github_dependabot import SOURCE as DEPENDABOT
from ananke.sources.github_dependabot import DependabotSource, parse_alert

log = get_logger(__name__)

FIXTURE_ALERTS = Path("dependabot_alerts") / "open.json"


class ScanSetupError(Exception):
    """The scan cannot start at all (no credentials, unreadable App key, ...)."""


@dataclass
class ScanResult:
    triage: TriageResult
    errors: dict[str, str] = field(default_factory=dict)  # repo -> message

    @property
    def ok(self) -> bool:
        return not self.errors


# ---------------------------------------------------------------------------------------------
# Fetching


def pull_ref(payload: dict[str, Any]) -> PullRef | None:
    """A GitHub pull payload -> PullRef, or None if its head branch is not `ananke/*`."""
    ref = ((payload.get("head") or {}).get("ref")) or ""
    if not ref.startswith(BRANCH_PREFIX):
        return None
    closed_at = payload.get("closed_at")
    return PullRef(
        number=int(payload["number"]),
        head_branch=ref,
        state="open" if payload.get("state") == "open" else "closed",
        merged=payload.get("merged_at") is not None,
        closed_at=datetime.fromisoformat(closed_at.replace("Z", "+00:00")) if closed_at else None,
        labels=[lbl["name"] for lbl in payload.get("labels") or [] if lbl.get("name")],
    )


async def fetch_ananke_pulls(client: GitHubClient, repo: str) -> list[PullRef]:
    """Open and closed PRs of `repo` whose head branch starts with `ananke/`."""
    pulls = await client.get_paginated(f"/repos/{repo}/pulls", params={"state": "all"})
    return [p for p in (pull_ref(x) for x in pulls) if p is not None]


def load_fixture_findings(
    cfg: AnankeConfig, fixtures: Path
) -> tuple[list[Finding], dict[str, str]]:
    """Parse the recorded Dependabot alerts fixture once per configured repo."""
    findings: list[Finding] = []
    errors: dict[str, str] = {}
    if DEPENDABOT not in cfg.sources:
        return findings, errors
    path = Path(fixtures) / FIXTURE_ALERTS
    try:
        alerts = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return findings, {repo: f"cannot read fixture {path}: {e}" for repo in cfg.repos}
    for repo in cfg.repos:
        try:
            findings += [parse_alert(repo, a) for a in alerts]
        except (KeyError, TypeError, ValueError) as e:
            errors[repo] = f"bad fixture {path}: {e!r}"
    return findings, errors


async def fetch_network(
    cfg: AnankeConfig, *, http: httpx.AsyncClient | None = None
) -> tuple[list[Finding], dict[str, list[PullRef]], dict[str, str]]:
    """Fetch Dependabot alerts and Ananke PRs for every configured repo (read-only)."""
    if cfg.github.auth_mode == "none":
        raise ScanSetupError(
            "no GitHub credentials configured: set github.app_id, github.installation_id and "
            "github.private_key_path (GitHub App) or github.token (PAT), or use --fixtures DIR"
        )
    try:
        auth = GitHubAuth.from_config(cfg.github, client=http)
    except AuthError as e:
        raise ScanSetupError(str(e)) from e

    findings: list[Finding] = []
    pulls_by_repo: dict[str, list[PullRef]] = {}
    errors: dict[str, str] = {}
    async with GitHubClient(auth, api_url=cfg.github.api_url, client=http) as client:
        source = DependabotSource(client) if DEPENDABOT in cfg.sources else None
        for repo in cfg.repos:
            try:
                if source is not None:
                    findings += await source.fetch_open(repo)
                pulls_by_repo[repo] = await fetch_ananke_pulls(client, repo)
            except (SourceError, GitHubError, AuthError) as e:
                errors[repo] = str(e)
                log.warning("scan_repo_failed", repo=repo, error=str(e))
    return findings, pulls_by_repo, errors


def run_scan(
    cfg: AnankeConfig,
    *,
    fixtures: Path | None = None,
    now: datetime | None = None,
    http: httpx.AsyncClient | None = None,
) -> ScanResult:
    """Fetch findings (network or fixtures) and triage them. Raises ScanSetupError."""
    if fixtures is not None:
        findings, errors = load_fixture_findings(cfg, fixtures)
        pulls_by_repo: dict[str, list[PullRef]] = {}
    else:
        findings, pulls_by_repo, errors = asyncio.run(fetch_network(cfg, http=http))
    result = triage(findings, cfg, pulls_by_repo=pulls_by_repo, now=now or datetime.now(UTC))
    return ScanResult(triage=result, errors=errors)


# ---------------------------------------------------------------------------------------------
# Output


def to_json(result: ScanResult) -> dict[str, Any]:
    """Machine output: items (WorkItem dumps, ISO datetimes), dropped (key, reason), errors."""
    return {
        "items": [item.model_dump(mode="json") for item in result.triage.items],
        "dropped": [{"key": f.key, "reason": reason} for f, reason in result.triage.dropped],
        "errors": dict(result.errors),
    }


def _dedup(values: list[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _severities(item: WorkItem) -> str:
    sevs = sorted({f.severity for f in item.findings}, key=severity_rank, reverse=True)
    top = item.max_severity
    return ", ".join(f"[bold]{s}[/bold]" if s == top else s for s in sevs)


def _fixed_versions(item: WorkItem) -> str:
    by_pkg: dict[str, list[str]] = {}
    for f in item.findings:
        if f.fixed_version:
            by_pkg.setdefault(f.package or "?", []).append(f.fixed_version)
    return "; ".join(f"{pkg} {', '.join(_dedup(vs))}" for pkg, vs in by_pkg.items())


def items_table(items: list[WorkItem]) -> Table:
    table = Table(title=f"Work items ({len(items)})")
    for col in ("repo", "manifest", "packages", "severities", "fixed versions"):
        table.add_column(col)
    table.add_column("findings", justify="right")
    table.add_column("state")
    table.add_column("branch", overflow="fold")
    for item in items:
        table.add_row(
            item.repo,
            item.manifest_path or "(repo)",
            ", ".join(_dedup([f.package or "" for f in item.findings])),
            _severities(item),
            _fixed_versions(item),
            str(len(item.findings)),
            item.state + (f" (#{item.existing_pr})" if item.existing_pr else ""),
            item.branch,
        )
    return table


def dropped_table(dropped: list[tuple[Finding, str]]) -> Table:
    table = Table(title=f"Dropped findings ({len(dropped)})")
    for col in ("key", "manifest", "package", "severity", "reason"):
        table.add_column(col)
    for f, reason in dropped:
        table.add_row(f.key, f.manifest_path or "", f.package or "", f.severity, reason)
    return table


def render(result: ScanResult, print_: Callable[[Any], None], *, show_dropped: bool) -> None:
    """Print the work-item table and, if `show_dropped`, the dropped-findings table."""
    print_(items_table(result.triage.items))
    dropped = result.triage.dropped
    if show_dropped:
        print_(dropped_table(dropped))
    elif dropped:
        print_(f"{len(dropped)} finding(s) dropped by policy (use --all to list them)")
