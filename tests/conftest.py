"""Shared fixtures. Everything here is offline: no network, no Docker, no live model."""

from __future__ import annotations

from pathlib import Path

import pytest

from ananke.worker.sandbox import LocalSandbox

FIXTURES = Path(__file__).parent / "fixtures"

MINIMAL_CONFIG = """\
repos:
  - RENCI/example-repo
workspace:
  root: workspaces
sandbox:
  allow_local: true
  scanner_db_volume: scanner-db
"""


@pytest.fixture(autouse=True)
def _no_live_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Belt and braces: tests never see the live-model env var or real API keys."""
    monkeypatch.delenv("ANANKE_LIVE_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def tmp_config(tmp_path: Path) -> Path:
    """A minimal valid ananke.yaml in tmp_path; returns its path."""
    path = tmp_path / "ananke.yaml"
    path.write_text(MINIMAL_CONFIG, encoding="utf-8")
    return path


@pytest.fixture
def fake_sandbox(tmp_path: Path) -> LocalSandbox:
    """A LocalSandbox (not isolated; dev/test only) rooted at tmp_path."""
    return LocalSandbox(tmp_path)
