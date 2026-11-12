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


@pytest.mark.parametrize("cmd", ["scan", "scanners", "run", "daemon", "status"])
def test_placeholders(cmd):
    result = runner.invoke(app, [cmd])
    assert result.exit_code == 2
    assert "not implemented in this milestone" in result.output
