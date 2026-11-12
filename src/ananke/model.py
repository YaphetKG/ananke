"""Core data model: Finding, WorkItem, RunRecord (PLAN.md §3.2) plus key/branch helpers."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field

Severity = Literal["critical", "high", "medium", "low", "unknown"]
SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low", "unknown")

# Higher rank = more severe. "unknown" ranks lowest so it never satisfies a min_severity filter
# other than "unknown" itself.
_SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
# Priority as in Symphony: lower number = dispatched first.
_SEVERITY_PRIORITY: dict[str, int] = {"critical": 1, "high": 2, "medium": 3, "low": 4, "unknown": 5}

FindingSource = Literal["github_dependabot", "github_code_scanning", "osv", "trivy"]
FindingState = Literal["open", "fixed", "dismissed", "unknown"]
WorkItemState = Literal["todo", "in_review", "declined", "done"]
Rung = Literal["deterministic", "agent"]
RunOutcome = Literal["pr_opened", "verify_failed", "agent_failed", "stalled", "no_change", "error"]

BRANCH_PREFIX = "ananke/"


def normalize_severity(value: str | None) -> Severity:
    """Map arbitrary severity strings (any case, 'moderate', 'warning', ...) onto Severity."""
    if not value:
        return "unknown"
    v = value.strip().lower()
    aliases = {"moderate": "medium", "warning": "medium", "error": "high", "note": "low"}
    v = aliases.get(v, v)
    return v if v in _SEVERITY_RANK else "unknown"  # type: ignore[return-value]


def severity_rank(sev: str) -> int:
    """Ordering helper: critical=4 > high=3 > medium=2 > low=1 > unknown=0."""
    return _SEVERITY_RANK.get(sev, 0)


def severity_at_least(sev: str, threshold: str) -> bool:
    """True if `sev` is as severe as or more severe than `threshold`."""
    return severity_rank(sev) >= severity_rank(threshold)


def max_severity(sevs: Iterable[str]) -> Severity:
    """Most severe value in `sevs`; 'unknown' for an empty iterable."""
    best: Severity = "unknown"
    for s in sevs:
        if severity_rank(s) > severity_rank(best):
            best = s  # type: ignore[assignment]
    return best


def severity_priority(sev: str) -> int:
    """critical=1, high=2, medium=3, low=4, unknown=5."""
    return _SEVERITY_PRIORITY.get(sev, 5)


_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_key(identifier: str) -> str:
    """Symphony workspace-key rule.

    Characters outside [A-Za-z0-9._-] become '_'. If that changed anything, append
    '-' + the first 16 hex chars of sha256(original) so distinct inputs stay distinct.
    """
    cleaned = _UNSAFE.sub("_", identifier)
    if cleaned != identifier:
        digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:16]
        cleaned = f"{cleaned}-{digest}"
    return cleaned


def branch_for(key: str) -> str:
    """Branch name for a work-item key: 'ananke/<key>'."""
    return f"{BRANCH_PREFIX}{key}"


def work_item_key(repo: str, manifest_path: str | None) -> str:
    """Sanitized key for a (repo, manifest_path) group; manifest None -> '<repo>/_repo'."""
    return sanitize_key(f"{repo}/{manifest_path}" if manifest_path else f"{repo}/_repo")


class Finding(BaseModel):
    """One security alert from a source or scanner."""

    key: str  # f"{repo}:{source}:{source_id}"
    repo: str
    source: FindingSource
    source_id: str
    severity: Severity = "unknown"
    advisory_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    url: str = ""
    ecosystem: str | None = None
    package: str | None = None
    manifest_path: str | None = None
    vulnerable_range: str | None = None
    fixed_version: str | None = None
    state: FindingState = "open"
    created_at: datetime
    raw: dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def make_key(repo: str, source: str, source_id: str) -> str:
        return f"{repo}:{source}:{source_id}"


class WorkItem(BaseModel):
    """A group of findings that share one branch / PR (default: one per manifest)."""

    key: str
    repo: str
    manifest_path: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    state: WorkItemState = "todo"
    existing_pr: int | None = None
    branch: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.branch:
            self.branch = branch_for(self.key)

    @property
    def max_severity(self) -> Severity:
        return max_severity(f.severity for f in self.findings)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def priority(self) -> int:
        """1=critical .. 4=low, 5=unknown/no findings; derived from the max severity."""
        return severity_priority(self.max_severity)

    @property
    def oldest_created_at(self) -> datetime | None:
        return min((f.created_at for f in self.findings), default=None)

    @classmethod
    def from_findings(
        cls, repo: str, manifest_path: str | None, findings: list[Finding], **kw: Any
    ) -> WorkItem:
        return cls(
            key=work_item_key(repo, manifest_path),
            repo=repo,
            manifest_path=manifest_path,
            findings=findings,
            **kw,
        )


class RunRecord(BaseModel):
    """One attempt of one WorkItem; persisted to sqlite for audit only."""

    run_id: str
    item_key: str
    attempt: int = 1
    started_at: datetime
    ended_at: datetime | None = None
    rung: Rung = "deterministic"
    outcome: RunOutcome | None = None
    pr_number: int | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
