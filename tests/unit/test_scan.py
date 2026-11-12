"""`ananke scan`, `ananke scanners`, `ananke validate` end to end through the CLI. Offline."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from ananke.cli import app
from ananke.orchestrator.scan import pull_ref

runner = CliRunner()

API = "https://api.github.com"
REPOS = ["RENCI/example-repo", "RENCI/another-repo"]

CONFIG = """\
repos:
  - RENCI/example-repo
  - RENCI/another-repo
sources: [github_dependabot]
workspace:
  root: workspaces
sandbox:
  allow_local: true
  scanner_db_volume: scanner-db
"""


def _config(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "ananke.yaml"
    path.write_text(CONFIG + extra, encoding="utf-8")
    return path


@pytest.fixture
def two_repo_config(tmp_path: Path) -> Path:
    return _config(tmp_path)


def _scan(*args: str):
    return runner.invoke(app, ["scan", *args])


# ---------------------------------------------------------------------------------------------
# fixtures mode


def test_scan_fixtures_table(two_repo_config: Path, fixtures_dir: Path):
    result = _scan("--fixtures", str(fixtures_dir), "--config", str(two_repo_config), "--all")
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "Work items (4)" in out
    for repo in REPOS:
        for manifest in ("requirements.txt", "package.json"):
            assert any(repo in line and manifest in line for line in out.splitlines())
    assert "requests, urllib3" in out
    assert "lodash 4.17.19, 4.17.21" in out
    assert "Dropped findings (2)" in out
    for repo in REPOS:
        line = next(ln for ln in out.splitlines() if f"{repo}:github_dependabot:6" in ln)
        assert "no_fixed_version" in line


def test_scan_fixtures_hides_dropped_without_all(two_repo_config: Path, fixtures_dir: Path):
    result = _scan("--fixtures", str(fixtures_dir), "--config", str(two_repo_config))
    assert result.exit_code == 0, result.output
    assert "Dropped findings" not in result.stdout
    assert "2 finding(s) dropped by policy" in result.stdout


def test_scan_fixtures_json(two_repo_config: Path, fixtures_dir: Path):
    result = _scan("--fixtures", str(fixtures_dir), "--config", str(two_repo_config), "--json")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert {"items", "dropped"} <= set(data)
    items = data["items"]
    assert len(items) == 4
    for repo in REPOS:
        manifests = sorted(i["manifest_path"] for i in items if i["repo"] == repo)
        assert manifests == ["package.json", "requirements.txt"]
    item = items[0]
    assert {"key", "repo", "manifest_path", "findings", "state", "branch", "priority"} <= set(item)
    assert item["state"] == "todo"
    assert isinstance(item["findings"][0]["created_at"], str)  # ISO string, not datetime
    assert item["findings"][0]["created_at"].startswith("20")
    assert sorted(data["dropped"], key=lambda d: d["key"]) == [
        {"key": f"{r}:github_dependabot:6", "reason": "no_fixed_version"} for r in sorted(REPOS)
    ]


def test_scan_fixtures_needs_no_credentials(tmp_path: Path, fixtures_dir: Path):
    # $VARs that are unset expand to null; fixtures mode must not care.
    cfg = _config(tmp_path, "github:\n  app_id: $ANANKE_TEST_UNSET_APP_ID\n")
    with respx.mock(assert_all_called=False) as mock:
        result = _scan("--fixtures", str(fixtures_dir), "--config", str(cfg))
    assert result.exit_code == 0, result.output
    assert not mock.calls


def test_scan_missing_fixture_dir_reports_error(two_repo_config: Path, tmp_path: Path):
    (tmp_path / "empty").mkdir()
    result = _scan("--fixtures", str(tmp_path / "empty"), "--config", str(two_repo_config))
    assert result.exit_code == 1
    assert "cannot read fixture" in result.output


# ---------------------------------------------------------------------------------------------
# network mode (respx)


def _pull(number: int, ref: str, state: str, merged_at=None, closed_at=None, labels=()):
    return {
        "number": number,
        "state": state,
        "head": {"ref": ref},
        "merged_at": merged_at,
        "closed_at": closed_at,
        "labels": [{"name": n} for n in labels],
    }


def test_scan_network_one_repo_fails(tmp_path: Path, fixtures_dir: Path):
    cfg = _config(tmp_path, "github:\n  token: ghp_test\n")
    alerts = json.loads((fixtures_dir / "dependabot_alerts" / "open.json").read_text())
    ok_repo, bad_repo = REPOS
    ok_branch = "ananke/RENCI_example-repo_requirements.txt-c510357048002a"
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{API}/repos/{ok_repo}/dependabot/alerts").mock(
            return_value=httpx.Response(200, json=alerts)
        )
        # The open PR's branch is whatever triage computes; read it back from fixtures mode.
        fx = json.loads(
            _scan("--fixtures", str(fixtures_dir), "--config", str(cfg), "--json").stdout
        )
        ok_branch = next(
            i["branch"]
            for i in fx["items"]
            if i["repo"] == ok_repo and i["manifest_path"] == "requirements.txt"
        )
        pulls = mock.get(f"{API}/repos/{ok_repo}/pulls").mock(
            return_value=httpx.Response(
                200,
                json=[
                    _pull(41, ok_branch, "open"),
                    _pull(7, "dependabot/pip/urllib3-1.26.19", "open"),
                ],
            )
        )
        mock.get(f"{API}/repos/{bad_repo}/dependabot/alerts").mock(
            return_value=httpx.Response(403, json={"message": "Resource not accessible"})
        )
        result = _scan("--config", str(cfg), "--json")
    assert result.exit_code == 1
    assert f"error: {bad_repo}" in result.output
    assert "Dependabot alerts" in result.output
    data = json.loads(result.stdout)
    assert {i["repo"] for i in data["items"]} == {ok_repo}
    assert len(data["items"]) == 2
    by_manifest = {i["manifest_path"]: i for i in data["items"]}
    assert by_manifest["requirements.txt"]["state"] == "in_review"
    assert by_manifest["requirements.txt"]["existing_pr"] == 41
    assert by_manifest["package.json"]["state"] == "todo"
    assert data["errors"].keys() == {bad_repo}
    assert pulls.calls[0].request.url.params["state"] == "all"
    assert pulls.calls[0].request.url.params["per_page"] == "100"


def test_scan_network_table_still_printed(tmp_path: Path, fixtures_dir: Path):
    cfg = _config(tmp_path, "github:\n  token: ghp_test\n")
    alerts = json.loads((fixtures_dir / "dependabot_alerts" / "open.json").read_text())
    ok_repo, bad_repo = REPOS
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{API}/repos/{ok_repo}/dependabot/alerts").mock(
            return_value=httpx.Response(200, json=alerts)
        )
        mock.get(f"{API}/repos/{ok_repo}/pulls").mock(return_value=httpx.Response(200, json=[]))
        mock.get(f"{API}/repos/{bad_repo}/dependabot/alerts").mock(
            return_value=httpx.Response(403, json={"message": "Resource not accessible"})
        )
        result = _scan("--config", str(cfg))
    assert result.exit_code == 1
    assert "Work items (2)" in result.stdout
    assert ok_repo in result.stdout
    assert bad_repo not in result.stdout  # only on stderr
    assert f"error: {bad_repo}" in result.output


def test_scan_network_without_credentials(two_repo_config: Path):
    with respx.mock(assert_all_called=False) as mock:
        result = _scan("--config", str(two_repo_config))
    assert result.exit_code == 1
    assert "no GitHub credentials" in result.output
    assert not mock.calls


def test_pull_ref_mapping():
    assert pull_ref(_pull(1, "feature/x", "open")) is None
    p = pull_ref(
        _pull(
            3,
            "ananke/k",
            "closed",
            merged_at=None,
            closed_at="2026-11-01T00:00:00Z",
            labels=["ananke", "ananke:retry"],
        )
    )
    assert p is not None
    assert (p.number, p.head_branch, p.state, p.merged) == (3, "ananke/k", "closed", False)
    assert p.closed_at is not None and p.closed_at.tzinfo is not None
    assert p.labels == ["ananke", "ananke:retry"]
    merged = pull_ref(_pull(4, "ananke/k", "closed", merged_at="2026-11-01T00:00:00Z"))
    assert merged is not None and merged.merged


# ---------------------------------------------------------------------------------------------
# scanners / validate


def test_scanners_lists_builtins_unavailable(two_repo_config: Path):
    result = runner.invoke(app, ["scanners", "--config", str(two_repo_config)])
    assert result.exit_code == 0, result.output
    rows = {}
    for line in result.stdout.splitlines():
        cells = [c.strip() for c in line.split("│")[1:-1]]
        if len(cells) == 6:
            rows[cells[0]] = cells
    for name in ("trivy", "osv", "gitleaks"):
        assert name in rows, result.stdout
        assert rows[name][3] == "True"  # enabled
        assert rows[name][4] == "False"  # available: no binaries on this host


def test_validate_reports_counts(two_repo_config: Path):
    result = runner.invoke(app, ["validate", "--config", str(two_repo_config)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.stdout
    assert "workflow template OK" in result.stdout
    assert "repos: 2" in result.stdout
    assert "enabled scanners: 3 (trivy, osv, gitleaks)" in result.stdout
