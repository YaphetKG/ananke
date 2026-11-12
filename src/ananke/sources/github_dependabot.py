"""Dependabot alerts source (PLAN.md §2.2, §11): the primary remote signal.

`fetch_open(repo)` lists open alerts via GET /repos/{owner}/{repo}/dependabot/alerts?state=open;
`fetch_by_keys(keys)` re-reads individual alerts and silently omits ones that 404.
`parse_alert(repo, alert)` is the pure payload -> Finding mapping.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from ananke.github.client import GitHubClient, GitHubError, NotFound
from ananke.logging import get_logger
from ananke.model import Finding, FindingState, normalize_severity
from ananke.sources.base import SourceError

log = get_logger(__name__)

SOURCE = "github_dependabot"
FETCH_CONCURRENCY = 8

_STATE_MAP: dict[str, FindingState] = {
    "open": "open",
    "fixed": "fixed",
    "dismissed": "dismissed",
    "auto_dismissed": "dismissed",
}

_FORBIDDEN_HINT = (
    "enable Dependabot alerts on the repository (Settings > Code security) or grant the "
    'GitHub App / token the "Dependabot alerts: read" permission'
)


def _parse_dt(value: str | None) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def cvss_score(alert: dict[str, Any]) -> float | None:
    """CVSS v3 base score from `security_advisory.cvss_severities.cvss_v3.score`, if present."""
    adv = alert.get("security_advisory") or {}
    score = (((adv.get("cvss_severities") or {}).get("cvss_v3")) or {}).get("score")
    return float(score) if isinstance(score, int | float) and score > 0 else None


def parse_alert(repo: str, alert: dict[str, Any]) -> Finding:
    """Map one Dependabot alert payload onto a Finding (pure)."""
    number = str(alert["number"])
    adv = alert.get("security_advisory") or {}
    vuln = alert.get("security_vulnerability") or {}
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}
    patched = vuln.get("first_patched_version") or {}
    severity = adv.get("severity") or vuln.get("severity")
    return Finding(
        key=Finding.make_key(repo, SOURCE, number),
        repo=repo,
        source=SOURCE,
        source_id=number,
        severity=normalize_severity(severity),
        advisory_ids=[i for i in (adv.get("ghsa_id"), adv.get("cve_id")) if i],
        summary=adv.get("summary") or "",
        url=alert.get("html_url") or "",
        ecosystem=pkg.get("ecosystem"),
        package=pkg.get("name"),
        manifest_path=dep.get("manifest_path"),
        vulnerable_range=vuln.get("vulnerable_version_range"),
        fixed_version=patched.get("identifier") or None,
        state=_STATE_MAP.get(str(alert.get("state")), "unknown"),
        created_at=_parse_dt(alert.get("created_at")),
        raw=alert,
    )


def parse_key(key: str) -> tuple[str, str]:
    """'<owner>/<repo>:github_dependabot:<number>' -> (repo, number). Raises ValueError."""
    repo, sep, rest = key.partition(f":{SOURCE}:")
    if not sep or repo.count("/") != 1 or not rest.isdigit():
        raise ValueError(f"not a {SOURCE} key: {key!r}")
    return repo, rest


class DependabotSource:
    """Source adapter over the Dependabot alerts REST API."""

    def __init__(self, client: GitHubClient, *, name: str = SOURCE) -> None:
        self.client = client
        self.name = name

    async def fetch_open(self, repo: str) -> list[Finding]:
        path = f"/repos/{repo}/dependabot/alerts"
        try:
            alerts = await self.client.get_paginated(path, params={"state": "open"})
        except NotFound as e:
            raise SourceError(f"{repo}: repository not found or not visible to Ananke") from e
        except GitHubError as e:
            if e.status == 403:
                raise SourceError(
                    f"{repo}: Dependabot alerts are not readable ({e.message}); {_FORBIDDEN_HINT}"
                ) from e
            raise SourceError(f"{repo}: fetching Dependabot alerts failed: {e}") from e
        findings = [parse_alert(repo, a) for a in alerts]
        log.info("source_fetched", source=self.name, repo=repo, count=len(findings))
        return findings

    async def fetch_by_keys(self, keys: list[str]) -> list[Finding]:
        sem = asyncio.Semaphore(FETCH_CONCURRENCY)

        async def one(key: str) -> Finding | None:
            try:
                repo, number = parse_key(key)
            except ValueError:
                log.warning("source_bad_key", source=self.name, key=key)
                return None
            async with sem:
                try:
                    alert = await self.client.get(f"/repos/{repo}/dependabot/alerts/{number}")
                except NotFound:
                    return None
                except GitHubError as e:
                    if e.status == 403:
                        raise SourceError(f"{repo}: {e.message}; {_FORBIDDEN_HINT}") from e
                    raise SourceError(f"{key}: fetching Dependabot alert failed: {e}") from e
            return parse_alert(repo, alert)

        results = await asyncio.gather(*(one(k) for k in dict.fromkeys(keys)))
        return [f for f in results if f is not None]
