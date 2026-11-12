"""WorkspaceManager against a local bare remote: clone, reset, excludes, commit, push, hooks."""

from __future__ import annotations

import pytest
from fakes import ScriptedSandbox, finding, git, item_for, make_origin

from ananke.config import HooksConfig
from ananke.worker.sandbox import CommandResult, LocalSandbox
from ananke.worker.workspace import (
    Workspace,
    WorkspaceError,
    WorkspaceManager,
    changed_paths,
    diff_numstat,
)

FILES = {"requirements.txt": "requests==2.25.1\n", "src/app.py": "print('hi')\n"}


@pytest.fixture
def origin(tmp_path):
    return make_origin(tmp_path, FILES)


@pytest.fixture
def manager(tmp_path):
    return WorkspaceManager(tmp_path / "workspaces", LocalSandbox(tmp_path))


def test_prepare_clones_and_creates_branch(manager, origin):
    item = item_for(finding())
    ws = manager.prepare(item, clone_url=str(origin))
    assert ws.created and ws.default_branch == "main" and ws.branch == item.branch
    assert ws.path.parent == manager.root
    assert git(ws.path, "rev-parse", "--abbrev-ref", "HEAD") == item.branch
    assert (ws.path / "requirements.txt").read_text() == FILES["requirements.txt"]


def test_prepare_again_resets_local_changes(manager, origin):
    item = item_for(finding())
    ws = manager.prepare(item, clone_url=str(origin))
    (ws.path / "requirements.txt").write_text("tampered\n")
    (ws.path / "stray.txt").write_text("x")
    ws2 = manager.prepare(item, clone_url=str(origin), default_branch="main")
    assert not ws2.created
    assert (ws2.path / "requirements.txt").read_text() == FILES["requirements.txt"]
    assert not (ws2.path / "stray.txt").exists()


def test_build_artifacts_are_not_changes(manager, origin):
    ws = manager.prepare(item_for(finding()), clone_url=str(origin))
    (ws.path / "src" / "__pycache__").mkdir()
    (ws.path / "src" / "__pycache__" / "app.cpython-312.pyc").write_bytes(b"\0")
    (ws.path / "node_modules" / "x").mkdir(parents=True)
    (ws.path / ".pytest_cache").mkdir()
    assert changed_paths(ws.path, "origin/main") == []
    (ws.path / "requirements.txt").write_text("requests==2.32.0\n")
    (ws.path / "src" / "new.py").write_text("x = 1\n")
    assert changed_paths(ws.path, "origin/main") == ["requirements.txt", "src/new.py"]
    assert diff_numstat(ws.path, "origin/main") == [(1, 1, "requirements.txt")]


def test_commit_and_push_to_bare_remote(manager, origin):
    item = item_for(finding())
    ws = manager.prepare(item, clone_url=str(origin))
    assert manager.commit_changes(ws, message="nothing") is False
    (ws.path / "requirements.txt").write_text("requests==2.32.0\n")
    assert manager.commit_changes(ws, message="fix(security): bump requests") is True
    manager.push(ws)
    assert (
        git(origin, "log", "-1", "--format=%an %s", item.branch)
        == "Ananke fix(security): bump requests"
    )


def test_host_git_never_runs_repository_hooks(manager, origin, tmp_path):
    ws = manager.prepare(item_for(finding()), clone_url=str(origin))
    marker = tmp_path / "hook-ran"
    hook = ws.path / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    (ws.path / "requirements.txt").write_text("requests==2.32.0\n")
    manager.commit_changes(ws, message="x")
    assert not marker.exists()


def test_hooks_run_in_sandbox_and_failures_raise(tmp_path, origin):
    sandbox = ScriptedSandbox(tmp_path, {"false-hook": CommandResult(3, "", "boom")})
    manager = WorkspaceManager(tmp_path / "workspaces", sandbox)
    hooks = HooksConfig(after_create="echo created > created.txt", before_run="false-hook")
    with pytest.raises(WorkspaceError, match="before_run hook failed \\(exit 3\\): boom"):
        manager.prepare(item_for(finding()), clone_url=str(origin), hooks=hooks)
    ws_path = manager.path_for(item_for(finding()))
    assert (ws_path / "created.txt").read_text().strip() == "created"


def test_remove_refuses_paths_outside_root(manager, tmp_path):
    outside = Workspace(
        path=tmp_path / "elsewhere", branch="b", default_branch="main", created=True
    )
    outside.path.mkdir()
    with pytest.raises(WorkspaceError, match="outside root"):
        manager.remove(outside)
    assert outside.path.exists()


def test_clone_failure_raises(manager, tmp_path):
    with pytest.raises(WorkspaceError, match="git clone"):
        manager.prepare(item_for(finding()), clone_url=str(tmp_path / "missing.git"))
