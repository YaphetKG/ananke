"""Triage (PLAN.md §3.4 step 4): policy filters, grouping into WorkItems, state derivation from
Ananke PRs, Symphony priority sort, and dispatch eligibility. Pure functions, no I/O."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from typing import Literal

from ananke.config import AnankeConfig, PolicyConfig
from ananke.model import Finding, WorkItem, WorkItemState, severity_at_least, work_item_key

RETRY_LABEL = "ananke:retry"
Grouping = Literal["per_manifest", "per_package", "per_repo"]


@dataclass
class PullRef:
    """An Ananke pull request as seen on GitHub (head branch `ananke/<key>`)."""

    number: int
    head_branch: str
    state: Literal["open", "closed"]
    merged: bool
    closed_at: datetime | None
    labels: list[str] = field(default_factory=list)


@dataclass
class TriageResult:
    items: list[WorkItem]
    dropped: list[tuple[Finding, str]]  # (finding, reason)


# ---------------------------------------------------------------------------------------------
# Filters


def path_ignored(path: str | None, globs: Iterable[str]) -> bool:
    """fnmatch `path` against each glob; 'dir/**' also matches anything under 'dir/', and
    '**/x' also matches 'x' at the root."""
    if not path:
        return False
    while path.startswith("./"):
        path = path[2:]
    for g in globs:
        if fnmatchcase(path, g):
            return True
        if g.endswith("/**") and (path == g[:-3] or path.startswith(g[:-2])):
            return True
        if g.startswith("**/") and fnmatchcase(path, g[3:]):
            return True
    return False


def drop_reason(f: Finding, policy: PolicyConfig) -> str | None:
    """Why `f` is dropped by policy, or None if it is kept."""
    if f.state != "open":
        return "not_open"
    if not severity_at_least(f.severity, policy.min_severity):
        return "below_min_severity"
    if policy.require_fixed_version and not f.fixed_version:
        return "no_fixed_version"
    if path_ignored(f.manifest_path, policy.ignore_paths):
        return "ignored_path"
    return None


def filter_findings(
    findings: Iterable[Finding], policy: PolicyConfig
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    kept: list[Finding] = []
    dropped: list[tuple[Finding, str]] = []
    for f in findings:
        reason = drop_reason(f, policy)
        if reason is None:
            kept.append(f)
        else:
            dropped.append((f, reason))
    return kept, dropped


# ---------------------------------------------------------------------------------------------
# Grouping


def _group_ident(f: Finding, grouping: Grouping) -> tuple[str, str | None, str | None]:
    """(repo, manifest_path for the WorkItem, key component passed to work_item_key)."""
    if grouping == "per_repo":
        return f.repo, None, None
    if grouping == "per_package":
        comp = f"{f.manifest_path or '_repo'}#{f.package or '_'}"
        return f.repo, f.manifest_path, comp
    return f.repo, f.manifest_path, f.manifest_path


def group_findings(findings: Iterable[Finding], grouping: Grouping) -> list[WorkItem]:
    """Group findings into WorkItems.

    per_manifest -> key from (repo, manifest_path); per_package -> key from
    (repo, f"{manifest_path}#{package}") (manifest_path on the item stays the real path);
    per_repo -> key from (repo, None), item.manifest_path None.
    Findings inside an item are ordered by key; items in first-seen order (sort separately).
    """
    groups: dict[tuple[str, str | None], tuple[str | None, list[Finding]]] = {}
    for f in findings:
        repo, manifest, comp = _group_ident(f, grouping)
        groups.setdefault((repo, comp), (manifest, []))[1].append(f)
    items = []
    for (repo, comp), (manifest, fs) in groups.items():
        fs = sorted(fs, key=lambda x: x.key)
        if grouping == "per_package":
            items.append(
                WorkItem(
                    key=work_item_key(repo, comp), repo=repo, manifest_path=manifest, findings=fs
                )
            )
        else:
            items.append(WorkItem.from_findings(repo, manifest, fs))
    return items


# ---------------------------------------------------------------------------------------------
# State derivation


def _closed_sort_key(p: PullRef) -> tuple[float, int]:
    return (p.closed_at.timestamp() if p.closed_at else float("inf"), p.number)


def derive_state(
    item: WorkItem, pulls: Iterable[PullRef], *, now: datetime, cooldown_days: int
) -> WorkItemState:
    """State of `item` from Ananke PRs whose head branch equals `item.branch`.

    - an open PR -> "in_review" (item.existing_pr set to the newest open PR number);
    - else the newest closed PR: unmerged and closed within `cooldown_days` -> "declined",
      unless it carries the `ananke:retry` label -> "todo"; merged or older -> "todo"
      (findings reaching triage are still open, so a merged PR did not fix them).
    A closed PR with no closed_at counts as closed now.
    """
    mine = [p for p in pulls if p.head_branch == item.branch]
    open_prs = [p for p in mine if p.state == "open"]
    if open_prs:
        item.existing_pr = max(p.number for p in open_prs)
        return "in_review"
    closed = [p for p in mine if p.state == "closed"]
    if not closed:
        return "todo"
    newest = max(closed, key=_closed_sort_key)
    if newest.merged:
        return "todo"
    closed_at = newest.closed_at or now
    if now - closed_at < timedelta(days=cooldown_days):
        return "todo" if RETRY_LABEL in newest.labels else "declined"
    return "todo"


# ---------------------------------------------------------------------------------------------
# Ordering, composition, eligibility


def _item_sort_key(item: WorkItem) -> tuple[int, float, str]:
    oldest = item.oldest_created_at
    ts = float("inf")
    if oldest is not None:
        ts = (oldest if oldest.tzinfo else oldest.replace(tzinfo=UTC)).timestamp()
    return (item.priority, ts, item.key)


def sort_items(items: Iterable[WorkItem]) -> list[WorkItem]:
    """Symphony ordering: priority (1=critical first), oldest created_at, then key."""
    return sorted(items, key=_item_sort_key)


def triage(
    findings: Iterable[Finding],
    cfg: AnankeConfig,
    *,
    pulls_by_repo: dict[str, list[PullRef]],
    now: datetime | None = None,
) -> TriageResult:
    """Filter by policy, group, derive state from PRs, sort."""
    now = now or datetime.now(UTC)
    policy = cfg.policy
    kept, dropped = filter_findings(findings, policy)
    items = group_findings(kept, policy.grouping)
    for item in items:
        item.state = derive_state(
            item,
            pulls_by_repo.get(item.repo, []),
            now=now,
            cooldown_days=policy.declined_cooldown_days,
        )
    return TriageResult(items=sort_items(items), dropped=dropped)


def eligible(
    items: Iterable[WorkItem],
    *,
    claimed: set[str],
    running_by_repo: dict[str, int],
    max_concurrent: int,
    max_concurrent_per_repo: int,
    slots_free: int,
) -> list[WorkItem]:
    """Items to dispatch now, in the given order: state "todo", not claimed, within the
    per-repo cap (counting already-running runs), at most min(slots_free,
    max_concurrent - total running)."""
    limit = min(slots_free, max_concurrent - sum(running_by_repo.values()))
    per_repo = dict(running_by_repo)
    out: list[WorkItem] = []
    for item in items:
        if len(out) >= limit:
            break
        if item.state != "todo" or item.key in claimed:
            continue
        if per_repo.get(item.repo, 0) >= max_concurrent_per_repo:
            continue
        per_repo[item.repo] = per_repo.get(item.repo, 0) + 1
        out.append(item)
    return out
