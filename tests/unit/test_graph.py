"""The per-item run graph end to end, offline: LocalSandbox, a fake scanner, a local bare git
remote standing in for GitHub, and the scripted fake model for the agent rung."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes import PinScanner, finding, git, item_for, make_origin

from ananke.config import load_config
from ananke.orchestrator.store import RunStore
from ananke.worker.graph import RunContext, run_item
from ananke.worker.sandbox import LocalSandbox

FIXTURES = Path(__file__).parents[1] / "fixtures"
AGENT_SCRIPT = FIXTURES / "fake_model_scripts" / "offline_pins_bump.json"

WORKFLOW = """\
---
test_command: "python -c \\"print('tests ok')\\""
allowed_paths: ["requirements*.txt", "pins.cfg"]
---
Patch {{ repo }}.
{{ findings | findings_table }}
{% if prior_failure %}Previous attempt:
{{ prior_failure }}{% endif %}
"""


class ClosingSandbox(LocalSandbox):
    closed = 0

    def close(self) -> None:
        ClosingSandbox.closed += 1


@pytest.fixture
def cfg(tmp_config):
    return load_config(tmp_config)


@pytest.fixture
def store(tmp_path):
    return RunStore(tmp_path / "runs.sqlite3")


def context(cfg, origin, scanner, store, **kw) -> RunContext:
    ClosingSandbox.closed = 0
    return RunContext(
        cfg=cfg,
        clone_url=str(origin),
        scanners=[scanner],
        store=store,
        sandbox_factory=ClosingSandbox,
        **kw,
    )


def requests_item():
    return item_for(
        finding("requests", "2.31.0", number=1), finding("requests", "2.32.0", number=2)
    )


def test_deterministic_rung_dry_run(cfg, tmp_path, store):
    origin = make_origin(
        tmp_path, {"requirements.txt": "requests==2.25.1\n", "ANANKE.md": WORKFLOW}
    )
    scanner = PinScanner()
    ctx = context(cfg, origin, scanner, store, dry_run=True)
    state = run_item(ctx, requests_item())

    assert state["outcome"] == "dry_run" and state["rung"] == "deterministic"
    assert state["verify"].passed, state["verify"].failures()
    body = state["body"]
    assert "| pinscan | 1.2.3 / fake-db-1 | 2 | 0 | 2 | 0 |" in body
    assert "_Deterministic rung: no agent was involved._" in body
    assert "requirements.txt: requests -> 2.32.0" in body
    ws = state["workspace"]
    assert git(ws.path, "log", "-1", "--format=%s").startswith("fix(security): patch 2 finding(s)")
    assert git(origin, "branch", "--list", ws.branch) == ""  # dry run pushes nothing
    assert ClosingSandbox.closed == 1
    (rec,) = store.runs_for(ctx.run_id and state["item"].key)
    assert rec.outcome == "dry_run" and rec.ended_at is not None
    assert set(rec.evidence) >= {"before", "after", "delta", "verify", "deterministic"}


def test_deterministic_rung_pushes_and_opens_pr(cfg, tmp_path, store):
    origin = make_origin(
        tmp_path, {"requirements.txt": "requests==2.25.1\n", "ANANKE.md": WORKFLOW}
    )
    opened = []

    def opener(item, base, title, body, reviewers):
        opened.append((item.key, base, title))
        return 42, "https://github.invalid/pr/42"

    ctx = context(cfg, origin, PinScanner(), store, dry_run=False, pr_opener=opener)
    state = run_item(ctx, requests_item())
    assert state["outcome"] == "pr_opened" and state["pr_number"] == 42
    assert opened == [
        (state["item"].key, "main", "fix(security): patch 2 finding(s) in requirements.txt")
    ]
    branch = state["workspace"].branch
    assert git(origin, "show", f"{branch}:requirements.txt") == "requests==2.32.0"
    assert store.get(ctx.run_id).pr_number == 42


def test_agent_rung_disabled_ends_as_verify_failed(cfg, tmp_path, store):
    origin = make_origin(tmp_path, {"pins.cfg": "badlib==1.0.0\n", "ANANKE.md": WORKFLOW})
    item = item_for(
        finding("badlib", "9.9.9", ids=("GHSA-bad0-bad0-bad0",), manifest="pins.cfg"),
        manifest="pins.cfg",
    )
    ctx = context(cfg, origin, PinScanner(files=("pins.cfg",)), store, dry_run=False)
    state = run_item(ctx, item)
    assert state["outcome"] == "no_change"  # the fixer cannot edit pins.cfg; nothing changed
    assert "agent rung not run" in state["error"]
    assert "body" not in state
    assert git(origin, "branch", "--list", item.branch) == ""
    assert store.get(ctx.run_id).outcome == "no_change"


def test_agent_rung_with_fake_model(cfg, tmp_path, store):
    origin = make_origin(tmp_path, {"pins.cfg": "badlib==1.0.0\n", "ANANKE.md": WORKFLOW})
    item = item_for(
        finding("badlib", "9.9.9", ids=("GHSA-bad0-bad0-bad0",), manifest="pins.cfg"),
        manifest="pins.cfg",
    )
    scanner = PinScanner(files=("pins.cfg",))
    ctx = context(cfg, origin, scanner, store, dry_run=True, fake_model=AGENT_SCRIPT)
    state = run_item(ctx, item)

    assert state["rung"] == "agent"
    assert state["outcome"] == "dry_run", state["verify"].failures()
    assert (state["workspace"].path / "pins.cfg").read_text() == "badlib==9.9.9\n"
    report = state["agent_result"]["result"]
    assert report["status"] == "patched"
    assert "pinscan" in state["agent_result"]["deltas"]  # the agent called scan_workspace
    assert "Bumped badlib 1.0.0 -> 9.9.9" in state["body"]
    assert "Rung: agent" in state["body"]
    assert store.get(ctx.run_id).rung == "agent"


def test_agent_without_report_result_is_agent_failed(cfg, tmp_path, store):
    origin = make_origin(tmp_path, {"pins.cfg": "badlib==1.0.0\n", "ANANKE.md": WORKFLOW})
    script = tmp_path / "silent.json"
    script.write_text('[{"content": "I give up."}]')
    item = item_for(
        finding("badlib", "9.9.9", ids=("GHSA-bad0-bad0-bad0",), manifest="pins.cfg"),
        manifest="pins.cfg",
    )
    ctx = context(cfg, origin, PinScanner(files=("pins.cfg",)), store, fake_model=script)
    state = run_item(ctx, item)
    assert state["outcome"] == "agent_failed"
    assert "report_result" in state["error"]


def test_setup_failure_raises_and_records_error(cfg, tmp_path, store):
    workflow = WORKFLOW.replace(
        "---\ntest_command", '---\nsetup_command: "exit 5"\ntest_command', 1
    )
    origin = make_origin(
        tmp_path, {"requirements.txt": "requests==2.25.1\n", "ANANKE.md": workflow}
    )
    ctx = context(cfg, origin, PinScanner(), store)
    with pytest.raises(RuntimeError, match="setup_command failed \\(exit 5\\)"):
        run_item(ctx, requests_item())
    assert ClosingSandbox.closed == 1
    rec = store.get(ctx.run_id)
    assert rec.outcome == "error" and "setup_command failed" in rec.evidence["error"]


def test_unavailable_scanner_is_an_error(cfg, tmp_path, store):
    origin = make_origin(
        tmp_path, {"requirements.txt": "requests==2.25.1\n", "ANANKE.md": WORKFLOW}
    )

    class Missing(PinScanner):
        name = "missing"

        def available(self, sandbox):
            return False

    with pytest.raises(RuntimeError, match="'missing' is not available"):
        run_item(context(cfg, origin, Missing(), store), requests_item())


def test_repository_workflow_cannot_read_host_environment(cfg, tmp_path, store, monkeypatch):
    """`$VAR` in a target repo's ANANKE.md must not expand host environment values."""
    monkeypatch.setenv("ANANKE_PROBE", "leak")
    workflow = WORKFLOW.replace(
        'test_command: "', 'setup_command: "$ANANKE_PROBE"\ntest_command: "', 1
    )
    origin = make_origin(
        tmp_path, {"requirements.txt": "requests==2.25.1\n", "ANANKE.md": workflow}
    )
    ctx = context(cfg, origin, PinScanner(), store)
    run_item(ctx, requests_item())
    assert ctx.workflow is not None and ctx.workflow.config.setup_command is None


def test_push_without_credentials_fails_before_pushing(cfg, tmp_path, store):
    origin = make_origin(
        tmp_path, {"requirements.txt": "requests==2.25.1\n", "ANANKE.md": WORKFLOW}
    )
    ctx = context(cfg, origin, PinScanner(), store, dry_run=False)  # no auth, no pr_opener
    item = requests_item()
    with pytest.raises(RuntimeError, match="needs GitHub credentials"):
        run_item(ctx, item)
    assert git(origin, "branch", "--list", item.branch) == ""
    assert store.get(ctx.run_id).outcome == "error"
