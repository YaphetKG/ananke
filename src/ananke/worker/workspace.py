"""Per-item Git workspace management (PLAN.md §3.3).

Git operations happen on the host. Repository commands and hooks are delegated to the configured
sandbox, whose bind mount contains the checkout. Credentials are never added to the workspace or
passed to agent tools.

Host git runs with hooks and fsmonitor disabled. Together with the read-only `.git` mount in
`DockerSandbox`, this keeps code running in the container from getting the host to execute
anything through git.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ananke.config import HooksConfig
from ananke.logging import get_logger
from ananke.model import WorkItem, sanitize_key
from ananke.worker.sandbox import Sandbox

log = get_logger(__name__)

# Applied to every host git invocation: never run repository hooks or an fsmonitor command.
_SAFE_GIT_CONFIG = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]

# Written to .git/info/exclude (local to the clone, never committed). Build and test artifacts
# created by setup/test commands must not show up as changed paths or get committed.
ARTIFACT_EXCLUDES = [
    "__pycache__/",
    "*.py[cod]",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".tox/",
    ".nox/",
    ".venv/",
    ".eggs/",
    "*.egg-info/",
    ".coverage",
    "htmlcov/",
    "node_modules/",
]
_EXCLUDE_MARKER = "# ananke: build artifacts"

ANANKE_AUTHOR = ["-c", "user.name=Ananke", "-c", "user.email=ananke[bot]@users.noreply.github.com"]


class WorkspaceError(RuntimeError):
    """Workspace setup, git, or hook operation failed."""


@dataclass(frozen=True)
class Workspace:
    path: Path
    branch: str
    default_branch: str
    created: bool


def _git_env(token: str | None = None) -> dict[str, str]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if token:
        credential = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        try:
            existing = int(env.get("GIT_CONFIG_COUNT", "0"))
        except ValueError:
            existing = 0
        env.update(
            {
                "GIT_CONFIG_COUNT": str(existing + 1),
                f"GIT_CONFIG_KEY_{existing}": "http.https://github.com/.extraheader",
                f"GIT_CONFIG_VALUE_{existing}": f"AUTHORIZATION: basic {credential}",
            }
        )
    return env


def git(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout_s: float = 300,
    token: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run host git with hooks/fsmonitor disabled. Raises WorkspaceError on failure if `check`."""
    try:
        proc = subprocess.run(
            ["git", *_SAFE_GIT_CONFIG, *args],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_s,
            env=_git_env(token),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorkspaceError(f"git {' '.join(args[:2])} failed: {exc}") from exc
    if check and proc.returncode:
        detail = (proc.stderr or proc.stdout).strip()[-3000:]
        raise WorkspaceError(f"git {' '.join(args[:2])} exited {proc.returncode}: {detail}")
    return proc


class WorkspaceManager:
    """Create and reset one working tree per WorkItem under a fixed root."""

    def __init__(
        self,
        root: Path | str,
        sandbox: Sandbox | None = None,
        *,
        git_timeout_s: int = 300,
        token: str | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.sandbox = sandbox
        self.git_timeout_s = git_timeout_s
        self.token = token

    def path_for(self, item: WorkItem) -> Path:
        path = (self.root / sanitize_key(item.key)).resolve()
        try:
            path.relative_to(self.root)
        except ValueError:
            raise WorkspaceError(f"unsafe work item key: {item.key!r}") from None
        if path == self.root:
            raise WorkspaceError(f"unsafe work item key: {item.key!r}")
        return path

    def _git(self, args: list[str], *, cwd: Path | None = None) -> str:
        proc = git(args, cwd=cwd, timeout_s=self.git_timeout_s, token=self.token)
        return proc.stdout.strip()

    def prepare(
        self,
        item: WorkItem,
        *,
        clone_url: str,
        default_branch: str | None = None,
        hooks: HooksConfig | None = None,
    ) -> Workspace:
        """Clone or refresh the checkout, then reset the deterministic Ananke branch.

        `hooks` run in `self.sandbox`; pass None when the caller runs them itself (the run graph
        does, because the repo's ANANKE.md is only known after the checkout).
        """
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(item)
        created = not path.exists()
        if created:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._git(["clone", "--no-checkout", clone_url, str(path)])
        elif not (path / ".git").is_dir():
            raise WorkspaceError(f"workspace path exists but is not a git checkout: {path}")

        self._git(["fetch", "--prune", "origin"], cwd=path)
        if default_branch is None:
            remote_head = self._git(
                ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=path
            )
            default_branch = remote_head.removeprefix("origin/")
        if not default_branch or any(ch.isspace() for ch in default_branch):
            raise WorkspaceError(f"invalid default branch: {default_branch!r}")
        self._git(["checkout", "--force", "-B", item.branch, f"origin/{default_branch}"], cwd=path)
        self._git(["reset", "--hard", f"origin/{default_branch}"], cwd=path)
        self._git(["clean", "-ffdx"], cwd=path)
        self._write_excludes(path)
        workspace = Workspace(
            path=path, branch=item.branch, default_branch=default_branch, created=created
        )
        if hooks is not None:
            if created and hooks.after_create:
                self.run_hook("after_create", hooks, path)
            if hooks.before_run:
                self.run_hook("before_run", hooks, path)
        return workspace

    @staticmethod
    def _write_excludes(path: Path) -> None:
        exclude = path / ".git" / "info" / "exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        current = exclude.read_text(encoding="utf-8") if exclude.is_file() else ""
        if _EXCLUDE_MARKER in current:
            return
        block = "\n".join([_EXCLUDE_MARKER, *ARTIFACT_EXCLUDES]) + "\n"
        exclude.write_text(
            current.rstrip("\n") + ("\n" if current else "") + block, encoding="utf-8"
        )

    def commit_changes(self, workspace: Workspace, *, message: str) -> bool:
        """Commit the workspace diff. Return False when there are no changes."""
        status = self._git(["status", "--porcelain"], cwd=workspace.path)
        if not status:
            return False
        self._git(["add", "--all"], cwd=workspace.path)
        self._git([*ANANKE_AUTHOR, "commit", "--no-verify", "-m", message], cwd=workspace.path)
        return True

    def push(self, workspace: Workspace) -> None:
        """Push the verified branch with force-with-lease using host-only credentials."""
        self._git(
            ["push", "--force-with-lease", "origin", f"{workspace.branch}:{workspace.branch}"],
            cwd=workspace.path,
        )

    def finish(self, workspace: Workspace, hooks: HooksConfig | None = None) -> None:
        """Run the after_run hook (if any)."""
        if hooks is not None and hooks.after_run:
            self.run_hook("after_run", hooks, workspace.path)

    def remove(self, workspace: Workspace, hooks: HooksConfig | None = None) -> None:
        if hooks is not None and hooks.before_remove:
            self.run_hook("before_remove", hooks, workspace.path)
        path = workspace.path.resolve()
        try:
            path.relative_to(self.root)
        except ValueError:
            raise WorkspaceError(f"refusing to remove workspace outside root: {path}") from None
        if path == self.root:
            raise WorkspaceError(f"refusing to remove the workspace root: {path}")
        if path.exists():
            shutil.rmtree(path)

    def run_hook(self, name: str, hooks: HooksConfig, path: Path) -> None:
        """Run hook `name` (after_create, before_run, after_run, before_remove) in the sandbox."""
        command = getattr(hooks, name)
        if not command:
            return
        if self.sandbox is None:
            raise WorkspaceError(f"{name} hook needs a sandbox")
        result = self.sandbox.run(command, cwd=path, timeout_s=hooks.timeout_s)
        if result.exit_code:
            detail = (result.stderr or result.stdout).strip()[-3000:]
            raise WorkspaceError(f"{name} hook failed (exit {result.exit_code}): {detail}")
        log.info("workspace_hook_done", hook=name, path=path)


# ---------------------------------------------------------------------------------------------
# Read-only diff helpers for the verify gate (host git, never the sandbox)


def changed_paths(workspace: Path, base_ref: str) -> list[str]:
    """Tracked changes against `base_ref` plus untracked, non-ignored paths."""
    res = git(["diff", "--no-ext-diff", "--name-only", base_ref], cwd=workspace)
    paths = {line for line in res.stdout.splitlines() if line}
    untracked = git(["ls-files", "--others", "--exclude-standard"], cwd=workspace)
    paths.update(line for line in untracked.stdout.splitlines() if line)
    return sorted(paths)


def untracked_paths(workspace: Path) -> set[str]:
    res = git(["ls-files", "--others", "--exclude-standard"], cwd=workspace)
    return {line for line in res.stdout.splitlines() if line}


def diff_numstat(workspace: Path, base_ref: str) -> list[tuple[int | None, int | None, str]]:
    """(added, deleted, path) per tracked changed file; None counts for binary files."""
    res = git(["diff", "--no-ext-diff", "--numstat", base_ref], cwd=workspace)
    rows: list[tuple[int | None, int | None, str]] = []
    for row in res.stdout.splitlines():
        parts = row.split("\t", 2)
        if len(parts) != 3:
            continue
        added = int(parts[0]) if parts[0].isdigit() else None
        deleted = int(parts[1]) if parts[1].isdigit() else None
        rows.append((added, deleted, parts[2]))
    return rows


def diff_text(workspace: Path, base_ref: str) -> str:
    """Unified diff (no context) of tracked changes against `base_ref`."""
    return git(["diff", "--no-ext-diff", "--unified=0", base_ref], cwd=workspace).stdout
