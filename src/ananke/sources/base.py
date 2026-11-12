"""Source protocol for remote feeds (PLAN.md §2.2, §3.4).

A source discovers findings; it never writes. The daemon calls `fetch_open(repo)` every tick
for every configured repo and `fetch_by_keys(keys)` to refresh claimed items. Keys omitted from
the `fetch_by_keys` result mean "no longer visible" (Symphony rule): the caller releases them.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ananke.model import Finding


class SourceError(Exception):
    """A source could not fetch findings for a repo (misconfiguration, permissions, outage)."""


@runtime_checkable
class Source(Protocol):
    """A remote feed of findings (Dependabot alerts, code scanning alerts, ...)."""

    name: str

    async def fetch_open(self, repo: str) -> list[Finding]:
        """All currently open findings for `repo` ("owner/name")."""
        ...

    async def fetch_by_keys(self, keys: list[str]) -> list[Finding]:
        """Current state of the findings with these keys; missing keys are no longer visible."""
        ...
