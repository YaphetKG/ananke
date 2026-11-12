"""The verify gate (PLAN.md §5): one test or more per check. Real git, fake scanners/sandbox."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fakes import OK, PinScanner, ScriptedSandbox, checkout, finding, item_for

from ananke.config import PolicyConfig, RepoWorkflowConfig
from ananke.model import RunRecord
from ananke.scanners.base import ScanDelta, ScanFinding, ScanReport, delta
from ananke.worker.sandbox import CommandResult
from ananke.worker.verify import (
    Coverage,
    coverage_of,
    find_test_tampering,
    is_test_path,
    matches,
    target_present,
    verify,
)
from ananke.workflow import render_failure_issue, render_pr_body

BASE = {
    "requirements.txt": "requests==2.25.1\n",
    "src/app.py": "import requests\n",
    "tests/test_app.py": "def test_one():\n    assert True\n\n\ndef test_two():\n    assert 1\n",
}
SCANNER = PinScanner()
COVERAGE = coverage_of([SCANNER])


@pytest.fixture
def work(tmp_path):
    return checkout(tmp_path, BASE)


def run(work, *, item=None, sandbox=None, repo_cfg=None, policy=None, test_command="true",
        result=None, coverage=None, before=None, after=None, deltas=None, now=None):  # fmt: skip
    item = item or item_for(finding("requests", "2.32.0"))
    before = before if before is not None else {"pinscan": SCANNER.parse("")}
    after = after if after is not None else {"pinscan": SCANNER.scan(None, work)}
    if deltas is None:
        deltas = {n: delta(before[n], after[n]) for n in after if n in before}
    return verify(
        item=item,
        workspace=work,
        sandbox=sandbox or ScriptedSandbox(work),
        base_ref="origin/main",
        before=before,
        after=after,
        deltas=deltas,
        repo_config=repo_cfg or RepoWorkflowConfig(),
        policy=policy or PolicyConfig(),
        test_command=test_command,
        coverage=COVERAGE if coverage is None else coverage,
        result=result,
        now=now,
    )


def bump(work, version="2.32.0"):
    (work / "requirements.txt").write_text(f"requests=={version}\n")


def status(res, name):
    return res.checks[name].status


# --- the happy path --------------------------------------------------------------------------


def test_clean_bump_passes_every_check(work):
    before = {"pinscan": SCANNER.scan(None, work)}
    bump(work)
    res = run(work, before=before)
    assert res.passed, res.failures()
    assert {k: v.status for k, v in res.checks.items()} == {
        "diff_nonempty": "passed",
        "paths_allowed": "passed",
        "diff_size": "passed",
        "targets_resolved": "passed",
        "no_regressions": "passed",
        "no_secrets": "passed",
        "scanner_db_fresh": "passed",
        "tests": "passed",
        "lockfile_consistent": "passed",
        "no_test_tampering": "passed",
    }
    assert res.diff_files == 1 and res.diff_lines == 2


# --- 1. diff_nonempty ------------------------------------------------------------------------


def test_diff_nonempty_fails_without_changes(work):
    res = run(work)
    assert not res.passed and status(res, "diff_nonempty") == "failed"


def test_diff_nonempty_reports_bad_base_ref(work):
    res = verify(
        item=item_for(finding()), workspace=work, sandbox=ScriptedSandbox(work),
        base_ref="origin/nope", before={}, after={}, deltas={},
        repo_config=RepoWorkflowConfig(), policy=PolicyConfig(), test_command="true",
        coverage=COVERAGE,
    )  # fmt: skip
    assert "cannot diff against origin/nope" in res.checks["diff_nonempty"].detail


# --- 2. paths_allowed ------------------------------------------------------------------------


def test_protected_path_fails(work):
    bump(work)
    (work / ".github" / "workflows").mkdir(parents=True)
    (work / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    res = run(work)
    assert status(res, "paths_allowed") == "failed"
    assert ".github/workflows/ci.yml" in res.checks["paths_allowed"].detail


def test_path_outside_allowed_fails(work):
    bump(work)
    (work / "README.md").write_text("x\n")
    res = run(work)
    assert (
        status(res, "paths_allowed") == "failed"
        and "README.md" in res.checks["paths_allowed"].detail
    )


def test_dockerfile_needs_policy(work):
    bump(work)
    (work / "Dockerfile").write_text("FROM python:3.12\n")
    assert status(run(work), "paths_allowed") == "failed"
    assert (
        status(run(work, policy=PolicyConfig(allow_dockerfile=True)), "paths_allowed") == "passed"
    )


def test_glob_matching():
    assert matches("package.json", ["**/package.json"])
    assert matches("web/package.json", ["**/package.json"])
    assert matches("src/a/b.py", ["src/**"])
    assert not matches("tests/x.py", ["src/**"])
    assert matches("config/db_secret.yaml", ["**/*secret*"])


# --- 3. diff_size ----------------------------------------------------------------------------


def test_diff_size_limit_and_lockfile_exemption(work):
    bump(work)
    (work / "uv.lock").write_text("x\n" * 5000)  # untracked lockfile: churn is exempt
    (work / "src" / "big.py").write_text("x = 1\n" * 30)
    cfg = RepoWorkflowConfig(max_diff_lines=20, allowed_paths=["**"])
    sandbox = ScriptedSandbox(work, {"uv lock": OK})
    res = run(work, repo_cfg=cfg, sandbox=sandbox)
    assert res.diff_lines == 32
    assert status(res, "diff_size") == "failed"
    cfg = RepoWorkflowConfig(max_diff_lines=40, allowed_paths=["**"])
    assert status(run(work, repo_cfg=cfg, sandbox=sandbox), "diff_size") == "passed"


# --- 5. targets_resolved ---------------------------------------------------------------------


def test_target_still_present_fails(work):
    bump(work, "2.31.0")  # fixes CVE-2023-32681 but not CVE-2024-35195
    res = run(work)
    assert status(res, "targets_resolved") == "failed"
    assert "pinscan" in res.checks["targets_resolved"].detail


def test_clean_covering_scanner_counts_as_covering(work):
    """Regression: a scanner with zero findings after the fix still covers the ecosystem."""
    bump(work)
    res = run(work, after={"pinscan": ScanReport(scanner="pinscan")})
    assert status(res, "targets_resolved") == "passed"


def test_no_covering_scanner_fails(work):
    bump(work)
    gitleaks_only = {"gitleaks": Coverage(frozenset({"secret"}), frozenset({"*"}))}
    res = run(work, after={"gitleaks": ScanReport(scanner="gitleaks")}, coverage=gitleaks_only)
    assert status(res, "targets_resolved") == "failed"
    assert "no covering scanner" in res.checks["targets_resolved"].detail


def test_wildcard_scanner_covers_any_ecosystem(work):
    bump(work)
    wild = {"trivy": Coverage(frozenset({"dependency", "secret"}), frozenset({"*"}))}
    res = run(work, after={"trivy": ScanReport(scanner="trivy")}, coverage=wild)
    assert status(res, "targets_resolved") == "passed"


def test_partial_fix_must_name_what_remains(work):
    bump(work, "2.31.0")
    vague = {"status": "partial", "summary": "bumped", "changes": [], "risk_notes": ""}
    named = {**vague, "risk_notes": "CVE-2024-35195 remains: needs requests 2.32"}
    assert status(run(work, result=vague), "targets_resolved") == "failed"
    assert status(run(work, result=named), "targets_resolved") == "passed"
    patched = {**named, "status": "patched"}
    assert status(run(work, result=patched), "targets_resolved") == "failed"


def test_target_matching_uses_aliases_and_canonical_names():
    target = finding("Requests", "2.32.0", ids=("GHSA-9wx4-h78v-vm56",))
    report = ScanReport(
        scanner="osv",
        findings=[
            ScanFinding(
                id="CVE-2024-35195",
                aliases=["GHSA-9WX4-H78V-VM56"],
                kind="dependency",
                package="requests",
            )
        ],  # fmt: skip
    )
    assert target_present(target, report)
    other_pkg = report.model_copy(
        update={"findings": [report.findings[0].model_copy(update={"package": "urllib3"})]}
    )
    assert not target_present(target, other_pkg)


# --- 6. no_regressions / 7. no_secrets -------------------------------------------------------


def _introduced(*findings: ScanFinding) -> dict[str, ScanDelta]:
    return {"pinscan": ScanDelta(introduced=list(findings))}


def test_introduced_high_finding_is_a_regression(work):
    bump(work)
    high = ScanFinding(id="CVE-2031-1", kind="dependency", severity="high", package="idna")
    low = ScanFinding(id="CVE-2031-2", kind="dependency", severity="low", package="idna")
    assert status(run(work, deltas=_introduced(high)), "no_regressions") == "failed"
    assert status(run(work, deltas=_introduced(low)), "no_regressions") == "passed"
    strict = PolicyConfig(regression_severity="low")
    assert status(run(work, deltas=_introduced(low), policy=strict), "no_regressions") == "failed"


def test_introduced_secret_fails(work):
    bump(work)
    leak = ScanFinding(
        id="aws-access-token", kind="secret", severity="high", location="src/app.py:3"
    )
    res = run(work, deltas=_introduced(leak))
    assert status(res, "no_secrets") == "failed"
    assert status(res, "no_regressions") == "passed"  # secrets are reported once, here


# --- 8. tests --------------------------------------------------------------------------------


def test_failing_tests_block_unless_advisory(work):
    bump(work)
    res = run(work, test_command="echo boom >&2; exit 4")
    assert not res.passed and res.checks["tests"].detail == "exit 4"
    assert "boom" in res.as_evidence()["tests"]["tail"]
    advisory = run(work, test_command="exit 4", repo_cfg=RepoWorkflowConfig(tests="advisory"))
    assert advisory.passed and status(advisory, "tests") == "failed"


def test_missing_test_command(work):
    bump(work)
    assert status(run(work, test_command=None), "tests") == "failed"
    res = run(work, test_command=None, repo_cfg=RepoWorkflowConfig(tests="advisory"))
    assert res.passed and status(res, "tests") == "not run"


# --- 9. lockfile_consistent ------------------------------------------------------------------


def test_lockfile_check_runs_in_changed_manifest_directory(work):
    web = work / "web"
    web.mkdir()
    (web / "package.json").write_text('{"dependencies": {"lodash": "^4.17.21"}}\n')
    (web / "package-lock.json").write_text("{}\n")
    sandbox = ScriptedSandbox(work, {"npm ci": CommandResult(1, "", "out of sync")})
    item = item_for(finding("lodash", "4.17.21", ecosystem="npm", manifest="web/package.json"))
    res = run(work, item=item, sandbox=sandbox, after={})
    assert status(res, "lockfile_consistent") == "failed"
    assert "out of sync" in res.checks["lockfile_consistent"].detail
    assert [
        "npm",
        "ci",
        "--dry-run",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    ] in sandbox.calls


def test_no_lockfile_check_when_no_manifest_changed(work):
    (work / "src" / "app.py").write_text("import requests  # noqa\n")
    res = run(work, after={})
    assert status(res, "lockfile_consistent") == "passed"


# --- 10. no_test_tampering -------------------------------------------------------------------


def test_skip_added_to_test_fails_unless_explained(work):
    bump(work)
    (work / "tests" / "test_app.py").write_text(
        "import pytest\n\n\n@pytest.mark.skip\ndef test_one():\n    assert True\n\n\n"
        "def test_two():\n    assert 1\n"
    )
    res = run(work, repo_cfg=RepoWorkflowConfig(allowed_paths=["**"]))
    assert status(res, "no_test_tampering") == "failed"
    assert "tests/test_app.py" in res.checks["no_test_tampering"].detail
    notes = "Skipped test_one in tests/test_app.py: upstream API removed."
    explained = {"status": "patched", "summary": "", "changes": [], "risk_notes": notes}
    res = run(work, repo_cfg=RepoWorkflowConfig(allowed_paths=["**"]), result=explained)
    assert status(res, "no_test_tampering") == "warning" and res.passed


def test_deleted_test_file_fails(work):
    bump(work)
    (work / "tests" / "test_app.py").unlink()
    res = run(work, repo_cfg=RepoWorkflowConfig(allowed_paths=["**"]))
    assert status(res, "no_test_tampering") == "failed"


def test_tampering_parser():
    diff = (
        "diff --git a/src/x.py b/src/x.py\n--- a/src/x.py\n+++ b/src/x.py\n"
        "-    assert x\n"
        "diff --git a/pkg/thing_test.go b/pkg/thing_test.go\n--- a/pkg/thing_test.go\n"
        '+++ b/pkg/thing_test.go\n+\tt.Skip("flaky")\n'
        "diff --git a/web/a.test.js b/web/a.test.js\n--- a/web/a.test.js\n+++ b/web/a.test.js\n"
        "-  expect(x).toBe(1)\n+  xit('works', () => {})\n"
    )
    found = find_test_tampering(diff, [], __import__("pathlib").Path("/nonexistent"))
    assert set(found) == {"pkg/thing_test.go", "web/a.test.js"}
    assert len(found["web/a.test.js"]) == 2


@pytest.mark.parametrize(
    ("path", "expected"),
    [("tests/test_a.py", True), ("src/test_a.py", True), ("pkg/a_test.go", True),
     ("web/__tests__/a.js", True), ("src/app.py", False), ("src/testing_utils/x.py", False)],
)  # fmt: skip
def test_is_test_path(path, expected):
    assert is_test_path(path) is expected


# --- 11. scanner_db_fresh --------------------------------------------------------------------


def test_stale_scanner_db_warns_but_passes(work):
    bump(work)
    now = datetime(2026, 11, 12, tzinfo=UTC)
    stale = ScanReport(scanner="pinscan", db_updated_at=now - timedelta(days=30))
    res = run(work, after={"pinscan": stale}, now=now)
    assert res.passed and status(res, "scanner_db_fresh") == "warning"
    assert res.db_warnings and "older than 7 days" in res.db_warnings[0]


# --- evidence shape --------------------------------------------------------------------------


def test_evidence_renders_in_pr_body_and_failure_issue(work):
    bump(work)
    res = run(work, test_command="echo ran-tests")
    ev = res.as_evidence()
    assert ev["tests"] == {"status": "passed", "detail": "exit 0", "tail": "ran-tests"}
    assert ev["diff_size"]["lines"] == 2 and ev["diff_size"]["files"] == 1
    item = item_for(finding())
    run_rec = RunRecord(run_id="r1", item_key=item.key, started_at=datetime.now(UTC))
    body = render_pr_body(
        item=item, result=None, evidence={"verify": ev}, run=run_rec,
        repo_cfg=RepoWorkflowConfig(test_command="echo ran-tests"),
    )  # fmt: skip
    assert "→ passed" in body and "2 lines across 1 files" in body
    issue = render_failure_issue(
        item=item, run=run_rec, evidence={"verify": ev}, attempts=3, error="x"
    )
    assert "| targets_resolved | passed |" in issue
    assert "| tests | passed | exit 0 |" in issue
