"""PR body and failure-issue templates (PLAN.md §6)."""

from __future__ import annotations

from datetime import UTC, datetime

from ananke.config import RepoWorkflowConfig
from ananke.model import Finding, RunRecord, WorkItem
from ananke.scanners.base import ScanDelta, ScanFinding, ScanReport
from ananke.workflow import render_failure_issue, render_pr_body

REPO = "RENCI/example-repo"


def _finding(n: int, sev: str = "high") -> Finding:
    return Finding(
        key=Finding.make_key(REPO, "github_dependabot", str(n)),
        repo=REPO,
        source="github_dependabot",
        source_id=str(n),
        severity=sev,
        advisory_ids=[f"GHSA-aaaa-bbbb-000{n}"],
        url=f"https://github.com/advisories/GHSA-aaaa-bbbb-000{n}",
        ecosystem="pip",
        package=f"pkg{n}",
        manifest_path="requirements.txt",
        vulnerable_range="< 2.0",
        fixed_version="2.0",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


ITEM = WorkItem.from_findings(REPO, "requirements.txt", [_finding(1), _finding(2, "critical")])
RUN = RunRecord(
    run_id="run-123",
    item_key=ITEM.key,
    attempt=2,
    started_at=datetime(2026, 11, 12, tzinfo=UTC),
    rung="agent",
    tokens_in=1200,
    tokens_out=340,
)
CFG = RepoWorkflowConfig(test_command="uv run pytest -q")

SF_OLD = ScanFinding(id="CVE-2026-0001", kind="dependency", severity="high", package="pkg1")
SF_OLD2 = ScanFinding(id="CVE-2026-0002", kind="dependency", severity="critical", package="pkg2")
SF_NEW = ScanFinding(id="CVE-2026-9999", kind="dependency", severity="high", package="pkg3")


def _evidence() -> dict:
    """Mix of pydantic models (trivy) and plain dicts (osv) on purpose."""
    return {
        "before": {
            "trivy": ScanReport(
                scanner="trivy",
                scanner_version="0.58.0",
                db_version="2026-11-11",
                findings=[SF_OLD, SF_OLD2],
            ),
            "osv": {
                "scanner": "osv",
                "scanner_version": "2.0.1",
                "db_version": None,
                "findings": [SF_OLD.model_dump()],
            },
        },
        "after": {
            "trivy": ScanReport(
                scanner="trivy", scanner_version="0.58.0", db_version="2026-11-11", findings=[]
            ),
            "osv": {
                "scanner": "osv",
                "scanner_version": "2.0.1",
                "db_version": None,
                "findings": [SF_NEW.model_dump()],
            },
        },
        "delta": {
            "trivy": ScanDelta(resolved=[SF_OLD, SF_OLD2]),
            "osv": {
                "resolved": [SF_OLD.model_dump()],
                "remaining": [],
                "introduced": [SF_NEW.model_dump()],
            },
        },
        "verify": {
            "diff_nonempty": {"status": "pass"},
            "tests": {"status": "pass", "tail": "12 passed in 0.3s"},
            "diff_size": {"status": "pass", "lines": 14, "files": 2},
            "targets_resolved": {"status": "fail", "detail": "CVE-2026-0002 still present"},
        },
        "deterministic": {
            "summary": "Bumped pkg1 and pkg2 to 2.0 in requirements.txt.",
            "changes": ["pkg1 1.0 -> 2.0", "pkg2 1.5 -> 2.0"],
        },
        "release_notes": ["pkg1 2.0: https://example.org/pkg1/releases/2.0"],
    }


RESULT = {
    "status": "patched",
    "summary": "Upgraded pkg1 and pkg2; migrated one call site.",
    "changes": ["requirements.txt: pkg1 2.0", "src/app.py: use new API"],
    "risk_notes": "pkg1 2.0 drops Python 3.9.",
    "tests": "12 passed",
}


def test_pr_body_full_evidence():
    body = render_pr_body(
        item=ITEM,
        result=RESULT,
        evidence=_evidence(),
        run=RUN,
        repo_cfg=CFG,
        db_warnings=["osv DB is 9 days old"],
    )
    assert body.startswith(f"## Ananke security patch — {REPO} / requirements.txt")
    assert (
        "| [GHSA-aaaa-bbbb-0001](https://github.com/advisories/GHSA-aaaa-bbbb-0001) | pkg1 |"
        " < 2.0 | 2.0 | high |" in body
    )
    assert "Upgraded pkg1 and pkg2" in body
    assert "- src/app.py: use new API" in body
    assert "| Scanner | Version / DB | Before | After | Resolved | Introduced |" in body
    assert "| trivy | 0.58.0 / 2026-11-11 | 2 | 0 | 2 | 0 |" in body
    assert "| osv | 2.0.1 / n/a | 1 | 1 | 1 | 1 |" in body
    # trivy row precedes osv row (delta order)
    assert body.index("| trivy |") < body.index("| osv |")
    assert "> ⚠ `osv` reports 1 new finding(s) (CVE-2026-9999); see risk notes." in body
    assert "`trivy` reports" not in body
    assert "> ⚠ osv DB is 9 days old" in body
    assert "- Tests: `uv run pytest -q` → pass (log tail below)" in body
    assert "- Diff: 14 lines across 2 files" in body
    assert "- Rung: agent (attempt 2), tokens 1200/340" in body
    assert "pkg1 2.0 drops Python 3.9." in body
    assert "- pkg1 2.0: https://example.org/pkg1/releases/2.0" in body
    assert "<details><summary>Test output</summary>" in body
    assert "12 passed in 0.3s" in body
    assert body.rstrip().endswith("patch-level bumps._")
    assert "_Opened by Ananke run `run-123`." in body
    assert "Deterministic rung" not in body


def test_pr_body_deterministic_rung():
    run = RUN.model_copy(
        update={"rung": "deterministic", "attempt": 1, "tokens_in": 0, "tokens_out": 0}
    )
    ev = _evidence()
    del ev["release_notes"]
    body = render_pr_body(item=ITEM, result=None, evidence=ev, run=run, repo_cfg=CFG)
    assert "Deterministic rung: no agent was involved." in body
    assert "Bumped pkg1 and pkg2 to 2.0 in requirements.txt." in body
    assert "- pkg1 1.0 -> 2.0" in body
    assert "- Rung: deterministic (attempt 1), tokens 0/0" in body
    assert "Version bump only" in body
    assert "- None." in body  # no release notes


def test_pr_body_minimal_evidence_does_not_crash():
    body = render_pr_body(
        item=ITEM, result=None, evidence={}, run=RUN, repo_cfg=RepoWorkflowConfig()
    )
    assert "- Tests: `n/a` → not run" in body
    assert "- Diff: 0 lines across 0 files" in body
    assert "Deterministic dependency bump" in body


def test_failure_issue():
    run = RUN.model_copy(update={"outcome": "verify_failed"})
    first = RUN.model_copy(
        update={
            "run_id": "run-100",
            "attempt": 1,
            "rung": "deterministic",
            "outcome": "verify_failed",
        }
    )
    body = render_failure_issue(
        item=ITEM,
        run=run,
        evidence=_evidence(),
        attempts=3,
        error="targets_resolved: CVE-2026-0002 still present",
        runs=[first, run],
    )
    assert "gave up after 3 attempt(s)" in body
    assert "| GHSA-aaaa-bbbb-0001 | pkg1 | < 2.0 | 2.0 | **HIGH** |" in body
    assert "| 1 | deterministic | verify_failed | `run-100` |" in body
    assert "| 2 | agent | verify_failed | `run-123` |" in body
    assert "targets_resolved: CVE-2026-0002 still present" in body
    assert "| targets_resolved | fail | CVE-2026-0002 still present |" in body
    assert "| diff_size | pass | 14 lines / 2 files |" in body
    assert "Bumped pkg1 and pkg2" in body
    assert "`ananke:retry`" in body
    assert "12 passed in 0.3s" in body


def test_failure_issue_minimal():
    body = render_failure_issue(item=ITEM, run=RUN, evidence={}, attempts=1, error="boom")
    assert "| 2 | agent | n/a | `run-123` |" in body
    assert "boom" in body
    assert "Verify did not run." in body
