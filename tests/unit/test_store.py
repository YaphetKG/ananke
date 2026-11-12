"""RunStore: sqlite audit log of RunRecords."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ananke.config import load_config
from ananke.model import RunRecord
from ananke.orchestrator.store import RunStore, default_store_path

T0 = datetime(2026, 11, 12, 8, tzinfo=UTC)


def rec(run_id: str, item: str = "item-a", *, at: datetime = T0, **kw) -> RunRecord:
    return RunRecord(run_id=run_id, item_key=item, started_at=at, **kw)


def test_record_get_and_replace(tmp_path):
    store = RunStore(tmp_path / "s" / "runs.sqlite3")
    assert store.get("r1") is None
    store.record(rec("r1", evidence={"verify": {"tests": {"status": "passed"}}}))
    store.record(rec("r1", outcome="pr_opened", pr_number=7, ended_at=T0 + timedelta(minutes=3)))
    got = store.get("r1")
    assert got is not None and got.outcome == "pr_opened" and got.pr_number == 7
    assert len(store.recent()) == 1


def test_runs_for_recent_and_token_totals(tmp_path):
    store = RunStore(tmp_path / "runs.sqlite3")
    store.record(rec("r1", at=T0, tokens_in=100, tokens_out=10))
    store.record(rec("r2", at=T0 + timedelta(hours=1), tokens_in=5, tokens_out=1, attempt=2))
    store.record(rec("r3", "item-b", at=T0 + timedelta(days=1), tokens_in=1, tokens_out=1))
    assert [r.run_id for r in store.runs_for("item-a")] == ["r1", "r2"]
    assert [r.run_id for r in store.recent(2)] == ["r3", "r2"]
    assert store.token_totals() == (106, 12)
    assert store.token_totals(since=T0 + timedelta(minutes=30)) == (6, 2)
    # a second handle on the same file sees the same data
    assert RunStore(tmp_path / "runs.sqlite3").get("r3").item_key == "item-b"


def test_default_path_is_under_workspace_root(tmp_config):
    cfg = load_config(tmp_config)
    assert default_store_path(cfg) == tmp_config.parent / "workspaces" / ".ananke" / "runs.sqlite3"
