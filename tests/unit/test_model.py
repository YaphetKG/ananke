from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from ananke.model import (
    Finding,
    RunRecord,
    WorkItem,
    branch_for,
    max_severity,
    normalize_severity,
    sanitize_key,
    severity_at_least,
    severity_priority,
    severity_rank,
    work_item_key,
)

NOW = datetime(2026, 11, 12, tzinfo=UTC)


def finding(sev: str = "high", sid: str = "1", **kw) -> Finding:
    return Finding(
        key=Finding.make_key("RENCI/x", "github_dependabot", sid),
        repo="RENCI/x",
        source="github_dependabot",
        source_id=sid,
        severity=sev,
        advisory_ids=["GHSA-aaaa-bbbb-cccc", "CVE-2024-0001"],
        created_at=NOW,
        **kw,
    )


def test_severity_ordering():
    assert severity_rank("critical") > severity_rank("high") > severity_rank("medium")
    assert severity_rank("medium") > severity_rank("low") > severity_rank("unknown")
    assert severity_at_least("high", "medium")
    assert not severity_at_least("low", "medium")
    assert severity_at_least("medium", "medium")
    assert max_severity(["low", "critical", "medium"]) == "critical"
    assert max_severity([]) == "unknown"


def test_normalize_severity():
    assert normalize_severity("MODERATE") == "medium"
    assert normalize_severity("Critical") == "critical"
    assert normalize_severity(None) == "unknown"
    assert normalize_severity("bogus") == "unknown"


def test_priority_from_max_severity():
    assert [severity_priority(s) for s in ("critical", "high", "medium", "low", "unknown")] == [
        1,
        2,
        3,
        4,
        5,
    ]
    item = WorkItem.from_findings("RENCI/x", "requirements.txt", [finding("low"), finding("high")])
    assert item.priority == 2
    assert WorkItem(key="k", repo="r").priority == 5
    assert item.model_dump()["priority"] == 2


def test_sanitize_key_unchanged_when_safe():
    assert sanitize_key("abc-1.2_X") == "abc-1.2_X"


def test_sanitize_key_hash_suffix():
    original = "RENCI/repo/requirements.txt"
    digest = hashlib.sha256(original.encode()).hexdigest()[:16]
    assert sanitize_key(original) == f"RENCI_repo_requirements.txt-{digest}"
    # distinct originals that sanitize identically stay distinct
    assert sanitize_key("a/b") != sanitize_key("a:b")


def test_branch_and_work_item_key():
    assert branch_for("abc") == "ananke/abc"
    item = WorkItem.from_findings("RENCI/x", "requirements.txt", [finding()])
    assert item.key == work_item_key("RENCI/x", "requirements.txt")
    assert item.branch == f"ananke/{item.key}"
    assert item.state == "todo"
    assert WorkItem(key="k", repo="r", branch="custom").branch == "custom"


def test_run_record_defaults():
    r = RunRecord(run_id="r1", item_key="k", started_at=NOW)
    assert r.rung == "deterministic" and r.outcome is None and r.tokens_in == 0
    assert RunRecord.model_validate(r.model_dump()) == r
