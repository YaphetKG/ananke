"""sqlite audit store for RunRecords and token totals (PLAN.md §3.2, §3.3 `report`).

Never authoritative: GitHub alerts and PRs are the source of truth for what still needs doing.
The store exists for audit, cost accounting and post-mortems. Each call opens its own
connection, so a store can be shared across threads.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from ananke.config import AnankeConfig
from ananke.model import RunRecord

STORE_DIRNAME = ".ananke"
STORE_FILENAME = "runs.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    item_key    TEXT NOT NULL,
    attempt     INTEGER NOT NULL,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    rung        TEXT NOT NULL,
    outcome     TEXT,
    pr_number   INTEGER,
    tokens_in   INTEGER NOT NULL DEFAULT 0,
    tokens_out  INTEGER NOT NULL DEFAULT 0,
    cost_usd    REAL,
    record      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_item ON runs (item_key, started_at);
CREATE INDEX IF NOT EXISTS runs_started ON runs (started_at);
"""


def default_store_path(cfg: AnankeConfig) -> Path:
    """`<workspace.root>/.ananke/runs.sqlite3` (work-item keys never start with a dot)."""
    return Path(cfg.workspace.root).expanduser() / STORE_DIRNAME / STORE_FILENAME


class RunStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(_SCHEMA)

    @classmethod
    def for_config(cls, cfg: AnankeConfig) -> RunStore:
        return cls(default_store_path(cfg))

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:  # commits on success, rolls back on error
                yield db
        finally:
            db.close()

    def record(self, run: RunRecord) -> None:
        """Insert or replace one run (a run is recorded again when it ends)."""
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO runs (run_id, item_key, attempt, started_at, ended_at,"
                " rung, outcome, pr_number, tokens_in, tokens_out, cost_usd, record)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run.run_id,
                    run.item_key,
                    run.attempt,
                    run.started_at.isoformat(),
                    run.ended_at.isoformat() if run.ended_at else None,
                    run.rung,
                    run.outcome,
                    run.pr_number,
                    run.tokens_in,
                    run.tokens_out,
                    run.cost_usd,
                    run.model_dump_json(),
                ),
            )

    def get(self, run_id: str) -> RunRecord | None:
        with self._connect() as db:
            row = db.execute("SELECT record FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return RunRecord.model_validate_json(row[0]) if row else None

    def runs_for(self, item_key: str) -> list[RunRecord]:
        """Every run of one work item, oldest first."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT record FROM runs WHERE item_key = ? ORDER BY started_at, run_id",
                (item_key,),
            ).fetchall()
        return [RunRecord.model_validate_json(r[0]) for r in rows]

    def recent(self, limit: int = 50) -> list[RunRecord]:
        """Most recent runs first."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT record FROM runs ORDER BY started_at DESC, run_id LIMIT ?", (limit,)
            ).fetchall()
        return [RunRecord.model_validate_json(r[0]) for r in rows]

    def token_totals(self, since: datetime | None = None) -> tuple[int, int]:
        """(tokens_in, tokens_out) summed over runs started at or after `since` (all if None)."""
        sql = "SELECT COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0) FROM runs"
        args: tuple[str, ...] = ()
        if since is not None:
            sql += " WHERE started_at >= ?"
            args = (since.isoformat(),)
        with self._connect() as db:
            tin, tout = db.execute(sql, args).fetchone()
        return int(tin), int(tout)
