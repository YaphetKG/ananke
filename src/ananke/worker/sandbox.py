"""Sandbox protocol and implementations (PLAN.md §3.3, §15).

`DockerSandbox` is the production sandbox (M1). `LocalSandbox` runs subprocesses directly on
the host: dev and test only, NOT isolated. The daemon refuses it unless
`sandbox.allow_local: true` is configured.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

DEFAULT_TIMEOUT_S = 600


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@runtime_checkable
class Sandbox(Protocol):
    """Where scanners, fixers, tests and agent commands execute."""

    is_isolated: bool

    def run(
        self,
        cmd: list[str] | str,
        *,
        cwd: Path | str | None = None,
        timeout_s: float | None = DEFAULT_TIMEOUT_S,
    ) -> CommandResult: ...


class LocalSandbox:
    """Runs commands as host subprocesses. Dev/test only; provides no isolation.

    `root` is the default cwd; a relative `cwd` passed to `run` resolves against it.
    A string `cmd` runs through the shell; a list runs without one.
    Timeouts return exit_code 124 (like coreutils `timeout`); a missing executable returns 127.
    """

    is_isolated: bool = False

    def __init__(self, root: Path | str, env: dict[str, str] | None = None) -> None:
        self.root = Path(root)
        self.env = env

    def _resolve_cwd(self, cwd: Path | str | None) -> Path:
        if cwd is None:
            return self.root
        p = Path(cwd)
        return p if p.is_absolute() else self.root / p

    def run(
        self,
        cmd: list[str] | str,
        *,
        cwd: Path | str | None = None,
        timeout_s: float | None = DEFAULT_TIMEOUT_S,
    ) -> CommandResult:
        env = None if self.env is None else {**os.environ, **self.env}
        try:
            proc = subprocess.run(
                cmd,
                shell=isinstance(cmd, str),
                cwd=self._resolve_cwd(cwd),
                env=env,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else ""
            err = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else ""
            return CommandResult(124, out or "", (err or "") + f"\ntimed out after {timeout_s}s")
        except FileNotFoundError as exc:
            shown = cmd if isinstance(cmd, str) else shlex.join(cmd)
            return CommandResult(127, "", f"command not found: {shown}: {exc}")
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def which(self, binary: str) -> bool:
        """True if `binary` is on PATH inside this sandbox."""
        return self.run(["sh", "-c", f"command -v {shlex.quote(binary)}"], timeout_s=10).ok


class DockerSandbox:
    """Docker container per run with the workspace bind-mounted and an egress allowlist."""

    is_isolated: bool = True

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError("DockerSandbox is implemented in milestone M1")

    def run(
        self,
        cmd: list[str] | str,
        *,
        cwd: Path | str | None = None,
        timeout_s: float | None = DEFAULT_TIMEOUT_S,
    ) -> CommandResult:
        raise NotImplementedError("DockerSandbox is implemented in milestone M1")
