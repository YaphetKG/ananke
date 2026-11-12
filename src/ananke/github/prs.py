"""Host-side GitHub pull request and failure issue writes (only after verification)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ananke.github.client import GitHubClient, NotFound
from ananke.logging import get_logger
from ananke.model import WorkItem
from ananke.orchestrator.triage import PullRef

log = get_logger(__name__)

LABELS = ["ananke", "security"]
LABEL_COLORS = {"ananke": "5319e7", "security": "d93f0b", "ananke:retry": "fbca04"}


@dataclass(frozen=True)
class PullRequest:
    number: int
    url: str
    state: str
    head_branch: str


def split_reviewers(reviewers: list[str]) -> tuple[list[str], list[str]]:
    """ANANKE.md reviewers -> (users, team slugs). "org/team" entries are teams."""
    users = [r.lstrip("@") for r in reviewers if r and "/" not in r]
    teams = [r.split("/", 1)[1] for r in reviewers if r and "/" in r]
    return users, teams


class PullRequestManager:
    """PR writes are performed by the host process, after the verify gate succeeds."""

    def __init__(self, client: GitHubClient) -> None:
        self.client = client

    async def list_ananke(self, repo: str) -> list[PullRef]:
        from ananke.orchestrator.scan import fetch_ananke_pulls

        return await fetch_ananke_pulls(self.client, repo)

    async def upsert(
        self,
        item: WorkItem,
        *,
        base: str,
        title: str,
        body: str,
        reviewers: list[str] | None = None,
    ) -> PullRequest:
        """Create the item's PR, or update title/body of the open one on its branch."""
        repo = item.repo
        owner = repo.split("/")[0]
        pulls = await self.client.get_paginated(
            f"/repos/{repo}/pulls", {"state": "open", "head": f"{owner}:{item.branch}"}
        )
        existing = next((p for p in pulls if (p.get("head") or {}).get("ref") == item.branch), None)
        if existing:
            number = int(existing["number"])
            raw = await self.client.request(
                "PATCH", f"/repos/{repo}/pulls/{number}", json={"title": title, "body": body}
            )
        else:
            raw = await self.client.request(
                "POST",
                f"/repos/{repo}/pulls",
                json={"title": title, "head": item.branch, "base": base, "body": body},
            )
            number = int(raw["number"])
        await self._ensure_labels(repo, LABELS)
        await self.client.request(
            "POST", f"/repos/{repo}/issues/{number}/labels", json={"labels": LABELS}
        )
        users, teams = split_reviewers(reviewers or [])
        if users or teams:
            await self.client.request(
                "POST",
                f"/repos/{repo}/pulls/{number}/requested_reviewers",
                json={"reviewers": users, "team_reviewers": teams},
            )
        url = str((raw or {}).get("html_url", ""))
        log.info("pull_request_upserted", repo=repo, item_key=item.key, pr=number, url=url)
        return PullRequest(number=number, url=url, state="open", head_branch=item.branch)

    async def _ensure_labels(self, repo: str, labels: list[str]) -> None:
        for name in labels:
            try:
                await self.client.get(f"/repos/{repo}/labels/{name}")
            except NotFound:
                await self.client.request(
                    "POST",
                    f"/repos/{repo}/labels",
                    json={
                        "name": name,
                        "color": LABEL_COLORS.get(name, "ededed"),
                        "description": "Managed by Ananke",
                    },
                )

    async def open_failure_issue(
        self, item: WorkItem, *, title: str, body: str, labels: list[str] | None = None
    ) -> dict[str, Any]:
        selected = labels or ["ananke", "security", "ananke:retry"]
        await self._ensure_labels(item.repo, selected)
        return await self.client.request(
            "POST",
            f"/repos/{item.repo}/issues",
            json={"title": title, "body": body, "labels": selected},
        )
