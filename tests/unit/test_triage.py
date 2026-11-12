"""orchestrator/triage.py: filters, grouping, state derivation, ordering, eligibility."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ananke.config import AnankeConfig, PolicyConfig, config_from_dict
from ananke.model import Finding, WorkItem, branch_for, work_item_key
from ananke.orchestrator.triage import (
    PullRef,
    derive_state,
    eligible,
    filter_findings,
    group_findings,
    path_ignored,
    sort_items,
    triage,
)

REPO = "RENCI/example-repo"
NOW = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
_n = 0


def F(**kw) -> Finding:  # noqa: N802
    global _n
    _n += 1
    repo = kw.pop("repo", REPO)
    sid = kw.pop("source_id", str(_n))
    base = dict(
        key=Finding.make_key(repo, "github_dependabot", sid),
        repo=repo,
        source="github_dependabot",
        source_id=sid,
        severity="high",
        advisory_ids=[f"GHSA-{sid}"],
        package="requests",
        manifest_path="requirements.txt",
        fixed_version="2.32.0",
        state="open",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    base.update(kw)
    return Finding(**base)


# --- filters -------------------------------------------------------------------------------


def test_filter_reasons():
    policy = PolicyConfig(min_severity="medium", ignore_paths=["docs/**", "examples/**"])
    keep = F()
    cases = {
        "not_open": F(state="fixed"),
        "below_min_severity": F(severity="low"),
        "no_fixed_version": F(fixed_version=None),
        "ignored_path": F(manifest_path="docs/requirements.txt"),
    }
    unknown_sev = F(severity="unknown")
    kept, dropped = filter_findings([keep, *cases.values(), unknown_sev], policy)
    assert kept == [keep]
    reasons = {f.key: r for f, r in dropped}
    for reason, f in cases.items():
        assert reasons[f.key] == reason
    assert reasons[unknown_sev.key] == "below_min_severity"


def test_filter_fixed_version_not_required():
    policy = PolicyConfig(require_fixed_version=False)
    f = F(fixed_version=None)
    assert filter_findings([f], policy) == ([f], [])


def test_filter_dismissed_and_unknown_state_are_not_open():
    _, dropped = filter_findings([F(state="dismissed"), F(state="unknown")], PolicyConfig())
    assert [r for _, r in dropped] == ["not_open", "not_open"]


@pytest.mark.parametrize(
    ("path", "globs", "expected"),
    [
        ("docs/requirements.txt", ["docs/**"], True),
        ("docs/a/b/package.json", ["docs/**"], True),
        ("docs", ["docs/**"], True),
        ("documentation/requirements.txt", ["docs/**"], False),
        ("./examples/x/go.mod", ["examples/**"], True),
        ("package.json", ["**/package.json"], True),
        ("web/package.json", ["**/package.json"], True),
        ("requirements-dev.txt", ["requirements-*.txt"], True),
        ("requirements.txt", ["docs/**"], False),
        (None, ["**"], False),
    ],
)
def test_path_ignored(path, globs, expected):
    assert path_ignored(path, globs) is expected


# --- grouping ------------------------------------------------------------------------------


def _mixed() -> list[Finding]:
    return [
        F(manifest_path="requirements.txt", package="requests"),
        F(manifest_path="requirements.txt", package="requests"),
        F(manifest_path="requirements.txt", package="urllib3"),
        F(manifest_path="web/package.json", package="lodash", ecosystem="npm"),
        F(repo="RENCI/other", manifest_path="requirements.txt", package="requests"),
    ]


def test_group_per_manifest():
    items = group_findings(_mixed(), "per_manifest")
    keys = {i.key: i for i in items}
    assert set(keys) == {
        work_item_key(REPO, "requirements.txt"),
        work_item_key(REPO, "web/package.json"),
        work_item_key("RENCI/other", "requirements.txt"),
    }
    req = keys[work_item_key(REPO, "requirements.txt")]
    assert len(req.findings) == 3
    assert req.manifest_path == "requirements.txt"
    assert req.branch == branch_for(req.key)
    assert req.findings == sorted(req.findings, key=lambda f: f.key)


def test_group_per_package():
    items = group_findings(_mixed(), "per_package")
    by_key = {i.key: i for i in items}
    k_req = work_item_key(REPO, "requirements.txt#requests")
    k_url = work_item_key(REPO, "requirements.txt#urllib3")
    assert set(by_key) == {
        k_req,
        k_url,
        work_item_key(REPO, "web/package.json#lodash"),
        work_item_key("RENCI/other", "requirements.txt#requests"),
    }
    assert len(by_key[k_req].findings) == 2
    assert by_key[k_req].manifest_path == "requirements.txt"
    assert by_key[k_req].branch == f"ananke/{k_req}"
    # stable across calls
    assert {i.key for i in group_findings(_mixed(), "per_package")} == set(by_key)


def test_group_per_repo():
    items = group_findings(_mixed(), "per_repo")
    by_key = {i.key: i for i in items}
    assert set(by_key) == {work_item_key(REPO, None), work_item_key("RENCI/other", None)}
    mine = by_key[work_item_key(REPO, None)]
    assert mine.manifest_path is None
    assert len(mine.findings) == 4
    assert mine.branch == f"ananke/{work_item_key(REPO, None)}"


# --- state derivation ----------------------------------------------------------------------


def _item() -> WorkItem:
    return WorkItem.from_findings(REPO, "requirements.txt", [F()])


def _pr(item: WorkItem, number: int, state="closed", merged=False, days_ago=1.0, labels=()):
    closed_at = None if state == "open" else NOW - timedelta(days=days_ago)
    return PullRef(number, item.branch, state, merged, closed_at, list(labels))


def test_state_todo_without_prs_or_with_other_branches():
    item = _item()
    other = PullRef(5, "ananke/something-else", "open", False, None)
    assert derive_state(item, [other], now=NOW, cooldown_days=7) == "todo"
    assert item.existing_pr is None


def test_state_open_pr_is_in_review():
    item = _item()
    pulls = [_pr(item, 3, days_ago=2), _pr(item, 9, state="open")]
    assert derive_state(item, pulls, now=NOW, cooldown_days=7) == "in_review"
    assert item.existing_pr == 9


def test_state_closed_unmerged_within_cooldown_is_declined():
    item = _item()
    assert derive_state(item, [_pr(item, 4, days_ago=2)], now=NOW, cooldown_days=7) == "declined"


def test_state_closed_unmerged_outside_cooldown_is_todo():
    item = _item()
    assert derive_state(item, [_pr(item, 4, days_ago=8)], now=NOW, cooldown_days=7) == "todo"


def test_state_retry_label_on_newest_pr():
    item = _item()
    pulls = [_pr(item, 4, days_ago=1, labels=["ananke", "ananke:retry"])]
    assert derive_state(item, pulls, now=NOW, cooldown_days=7) == "todo"
    # label on an older PR does not count
    pulls = [_pr(item, 2, days_ago=3, labels=["ananke:retry"]), _pr(item, 4, days_ago=1)]
    assert derive_state(item, pulls, now=NOW, cooldown_days=7) == "declined"


def test_state_newest_closed_merged_is_todo():
    item = _item()
    pulls = [_pr(item, 2, days_ago=3), _pr(item, 4, merged=True, days_ago=1)]
    assert derive_state(item, pulls, now=NOW, cooldown_days=7) == "todo"


# --- ordering ------------------------------------------------------------------------------


def _wi(manifest: str, sev: str, created_day: int, repo: str = REPO) -> WorkItem:
    f = F(
        repo=repo,
        severity=sev,
        manifest_path=manifest,
        created_at=datetime(2026, 1, created_day, tzinfo=UTC),
    )
    return WorkItem.from_findings(repo, manifest, [f])


def test_sort_items():
    high_old = _wi("a/requirements.txt", "high", 1)
    crit_new = _wi("b/requirements.txt", "critical", 20)
    high_new = _wi("c/requirements.txt", "high", 10)
    tie_b = _wi("z/requirements.txt", "medium", 5)
    tie_a = _wi("y/requirements.txt", "medium", 5)
    ordered = sort_items([tie_b, high_new, tie_a, high_old, crit_new])
    assert ordered == [crit_new, high_old, high_new, tie_a, tie_b]


# --- triage composition --------------------------------------------------------------------


def test_triage_end_to_end():
    cfg: AnankeConfig = config_from_dict({"repos": [REPO], "policy": {"min_severity": "high"}})
    findings = [
        F(manifest_path="requirements.txt", severity="high"),
        F(manifest_path="web/package.json", severity="critical"),
        F(manifest_path="api/requirements.txt", severity="high"),
        F(manifest_path="docs/requirements.txt", severity="critical"),
        F(severity="medium"),
    ]
    branch_web = branch_for(work_item_key(REPO, "web/package.json"))
    branch_api = branch_for(work_item_key(REPO, "api/requirements.txt"))
    pulls = {
        REPO: [
            PullRef(11, branch_web, "open", False, None),
            PullRef(12, branch_api, "closed", False, NOW - timedelta(days=1)),
        ]
    }
    res = triage(findings, cfg, pulls_by_repo=pulls, now=NOW)
    assert sorted(r for _, r in res.dropped) == ["below_min_severity", "ignored_path"]
    states = {i.manifest_path: (i.state, i.existing_pr) for i in res.items}
    assert states == {
        "web/package.json": ("in_review", 11),
        "requirements.txt": ("todo", None),
        "api/requirements.txt": ("declined", None),
    }
    assert res.items[0].manifest_path == "web/package.json"  # critical first


# --- eligibility ---------------------------------------------------------------------------


def test_eligible_caps_and_claims():
    a1 = _wi("1/r.txt", "critical", 1, repo="o/a")
    a2 = _wi("2/r.txt", "critical", 2, repo="o/a")
    b1 = _wi("1/r.txt", "high", 1, repo="o/b")
    b2 = _wi("2/r.txt", "high", 2, repo="o/b")
    c1 = _wi("1/r.txt", "medium", 1, repo="o/c")
    review = _wi("3/r.txt", "critical", 1, repo="o/d")
    review.state = "in_review"
    items = [review, a1, a2, b1, b2, c1]

    kw = dict(max_concurrent=10, max_concurrent_per_repo=1)
    # per-repo cap 1: one per repo, in order; in_review skipped
    assert eligible(items, claimed=set(), running_by_repo={}, slots_free=10, **kw) == [a1, b1, c1]
    # slots_free bounds the result
    assert eligible(items, claimed=set(), running_by_repo={}, slots_free=2, **kw) == [a1, b1]
    # repo already running at cap is skipped; claimed items are skipped
    assert eligible(items, claimed={b1.key}, running_by_repo={"o/a": 1}, slots_free=10, **kw) == [
        b2,
        c1,
    ]
    # global cap counts running runs
    assert eligible(
        items,
        claimed=set(),
        running_by_repo={"o/x": 2},
        slots_free=10,
        max_concurrent=3,
        max_concurrent_per_repo=2,
    ) == [a1]
    # per-repo cap 2
    assert eligible(
        items,
        claimed=set(),
        running_by_repo={},
        slots_free=10,
        max_concurrent=10,
        max_concurrent_per_repo=2,
    ) == [a1, a2, b1, b2, c1]
    assert eligible(items, claimed=set(), running_by_repo={}, slots_free=0, **kw) == []
