from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ananke.cli import app

runner = CliRunner()


def test_validate_ok(tmp_config: Path):
    result = runner.invoke(app, ["validate", "--config", str(tmp_config)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_validate_failure_names_key(tmp_path: Path):
    p = tmp_path / "ananke.yaml"
    p.write_text("agent:\n  max_concurrent: 0\n")
    result = runner.invoke(app, ["validate", "--config", str(p)])
    assert result.exit_code == 1
    assert "agent.max_concurrent" in result.output


def test_validate_missing_file(tmp_path: Path):
    result = runner.invoke(app, ["validate", "--config", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 1


@pytest.mark.parametrize("cmd", ["daemon", "status"])
def test_placeholders(cmd):
    result = runner.invoke(app, [cmd])
    assert result.exit_code == 2
    assert "not implemented in this milestone" in result.output


def test_run_requires_yes_or_dry_run(tmp_config: Path):
    result = runner.invoke(app, ["run", "some-key", "--config", str(tmp_config)])
    assert result.exit_code == 2
    assert "--yes" in result.output


def test_run_fixtures_needs_clone_url(tmp_config: Path, fixtures_dir: Path):
    result = runner.invoke(
        app,
        ["run", "k", "--dry-run", "--config", str(tmp_config), "--fixtures", str(fixtures_dir)],
    )
    assert result.exit_code == 2
    assert "--clone-url" in result.output


def test_run_dry_run_offline_from_fixtures(tmp_path: Path, monkeypatch):
    """`ananke run KEY --dry-run --fixtures DIR --clone-url PATH` works with no GitHub at all."""
    import json

    from fakes import ADVISORIES, PinScanner, make_origin

    import ananke.scanners as scanners_mod

    alerts = json.loads(
        (Path(__file__).parents[1] / "fixtures/dependabot_alerts/open.json").read_text()
    )
    fixtures = tmp_path / "fx"
    (fixtures / "dependabot_alerts").mkdir(parents=True)
    pip_alerts = [a for a in alerts if a["dependency"]["package"]["ecosystem"] == "pip"]
    (fixtures / "dependabot_alerts" / "open.json").write_text(json.dumps(pip_alerts))
    origin = make_origin(
        tmp_path,
        {
            "requirements.txt": "requests==2.25.1\nurllib3==1.26.5\n",
            "ANANKE.md": '---\ntest_command: "true"\n---\nPatch {{ repo }}.\n',
        },
    )
    advisories = {
        "requests": ADVISORIES["requests"][:1],
        "urllib3": [
            ("CVE-2023-43804", "GHSA-v845-jxx5-vc9f", "1.26.17", "high"),
            ("CVE-2024-37891", "GHSA-34jh-p97f-mpxf", "1.26.19", "medium"),
        ],
    }
    monkeypatch.setattr(scanners_mod, "build_scanners", lambda *a, **k: [PinScanner(advisories)])
    cfg = tmp_path / "ananke.yaml"
    cfg.write_text(
        "repos: [RENCI/example-repo]\nworkspace:\n  root: ws\nsandbox:\n  allow_local: true\n"
        "policy:\n  min_severity: low\n"
    )
    scan = runner.invoke(app, ["scan", "--config", str(cfg), "--fixtures", str(fixtures), "--json"])
    key = json.loads(scan.output)["items"][0]["key"]
    result = runner.invoke(
        app,
        ["run", key, "--dry-run", "--config", str(cfg), "--fixtures", str(fixtures),
         "--clone-url", str(origin)],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "## Ananke security patch" in result.output
    assert "requirements.txt: requests -> 2.31.0" in result.output
    assert "requirements.txt: urllib3 -> 1.26.19" in result.output
    assert "outcome=dry_run" in result.output
