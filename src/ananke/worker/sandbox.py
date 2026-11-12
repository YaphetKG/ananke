"""Sandbox protocol and implementations (PLAN.md §3.3, §15).

`DockerSandbox` is the production sandbox (M1). `LocalSandbox` runs subprocesses directly on
the host: dev and test only, NOT isolated. The daemon refuses it unless
`sandbox.allow_local: true` is configured.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import uuid
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


_SECRET_ENV_MARKERS = ("token", "secret", "password", "private_key", "api_key", "credential")


def _scrub_env(env: dict[str, str]) -> dict[str, str]:
    """Drop environment variables whose names suggest they carry credentials."""
    return {k: v for k, v in env.items() if not any(m in k.lower() for m in _SECRET_ENV_MARKERS)}


class LocalSandbox:
    """Runs commands as host subprocesses. Dev/test only; provides no isolation.

    `root` is the default cwd; a relative `cwd` passed to `run` resolves against it.
    A string `cmd` runs through the shell; a list runs without one.
    Timeouts return exit_code 124 (like coreutils `timeout`); a missing executable returns 127.
    Environment variables whose names look secret-bearing are stripped from the child process.
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
        env = {**_scrub_env(dict(os.environ)), **_scrub_env(dict(self.env or {}))}
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
            out = _decode(exc.stdout)
            err = _decode(exc.stderr)
            return CommandResult(124, out, err + f"\ntimed out after {timeout_s}s")
        except FileNotFoundError as exc:
            shown = cmd if isinstance(cmd, str) else shlex.join(cmd)
            return CommandResult(127, "", f"command not found: {shown}: {exc}")
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def which(self, binary: str) -> bool:
        """True if `binary` is on PATH inside this sandbox."""
        return self.run(["sh", "-c", f"command -v {shlex.quote(binary)}"], timeout_s=10).ok


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


# Writable locations inside the container. HOME and tool caches live on the tmpfs because the
# container runs with the host user's uid, which usually has no home directory in the image.
_CONTAINER_ENV = {
    "HOME": "/tmp/home",
    "XDG_CACHE_HOME": "/tmp/cache",
    "UV_CACHE_DIR": "/tmp/cache/uv",
    "npm_config_cache": "/tmp/cache/npm",
    "GOPATH": "/tmp/go",
    "GOCACHE": "/tmp/cache/go-build",
    "PYTHONDONTWRITEBYTECODE": "1",
}
_UNRESTRICTED_NETWORKS = {"bridge", "host", "default"}
# Trivy's vulnerability DB directory inside the worker image (TRIVY_CACHE_DIR + "/db"). A
# non-empty `sandbox.scanner_db_volume` (holding trivy.db + metadata.json) replaces it read-only.
TRIVY_DB_DIR = "/opt/ananke/cache/trivy/db"


class DockerSandbox:
    """A hardened per-run container with one writable workspace mount.

    The container joins Docker's ``none`` network by default. Deployments that need package
    registry access should use a host-managed restricted egress network/proxy and pass its Docker
    network name as ``network``. Unrestricted modes (``bridge``, ``host``, ``container:*``) are
    refused unless ``allow_unrestricted_network`` is set, which is meant for integration tests.

    The container runs as the host user's uid/gid so files it writes in the bind-mounted
    workspace stay owned by the host user. The workspace's ``.git`` directory is mounted
    read-only on top of the workspace mount, so code running in the container cannot plant git
    hooks or config that the host's ``git commit`` / ``git push`` would later execute.
    """

    is_isolated: bool = True

    def __init__(
        self,
        workspace: Path | str,
        *,
        image: str = "ghcr.io/renci/ananke-worker:latest",
        network: str = "none",
        cpu: float = 2,
        memory: str = "4g",
        scanner_db_volume: Path | str | None = None,
        extra_mounts: list[Path | str] | None = None,
        docker: str = "docker",
        container_name: str | None = None,
        user: str | None = None,
        tmpfs_size: str = "1g",
        allow_unrestricted_network: bool = False,
        start: bool = True,
    ) -> None:
        self.workspace = Path(workspace).expanduser().resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.image = image
        self.network = network or "none"
        unrestricted = self.network in _UNRESTRICTED_NETWORKS or self.network.startswith(
            "container:"
        )
        if unrestricted and not allow_unrestricted_network:
            raise ValueError(
                f"unrestricted Docker network {self.network!r} is not allowed; use `none` or a "
                "host-managed restricted network"
            )
        self.docker = docker
        self.container_name = container_name or f"ananke-{uuid.uuid4().hex[:12]}"
        self.container_id: str | None = None
        self.user = user or f"{os.getuid()}:{os.getgid()}"
        self.tmpfs_size = tmpfs_size
        self._closed = False
        self._db_volume = (
            Path(scanner_db_volume).expanduser().resolve() if scanner_db_volume else None
        )
        self._extra_mounts = [Path(p).expanduser().resolve() for p in (extra_mounts or [])]
        if start:
            self.start(cpu=cpu, memory=memory)

    def _docker(
        self, args: list[str], *, timeout_s: float = 120
    ) -> subprocess.CompletedProcess[str]:
        """Run the docker CLI. Raises subprocess.TimeoutExpired; wraps OSError in RuntimeError."""
        try:
            return subprocess.run(
                [self.docker, *args],
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout_s,
            )
        except OSError as exc:
            raise RuntimeError(f"Docker command failed: {exc}") from exc

    def start_args(self, *, cpu: float = 2, memory: str = "4g") -> list[str]:
        """The `docker run` arguments (without the docker binary). Pure; used by tests."""
        args = [
            "run", "--detach", "--rm", "--name", self.container_name,
            "--network", self.network, "--cpus", str(cpu), "--memory", memory,
            "--pids-limit", "1024", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--user", self.user,
            "--tmpfs", f"/tmp:rw,nosuid,nodev,size={self.tmpfs_size},mode=1777",
            "--mount", f"type=bind,src={self.workspace},dst={self.workspace}",
        ]  # fmt: skip
        git_dir = self.workspace / ".git"
        if git_dir.is_dir():
            args += ["--mount", f"type=bind,src={git_dir},dst={git_dir},readonly"]
        if (
            self._db_volume is not None
            and self._db_volume.is_dir()
            and any(self._db_volume.iterdir())
        ):
            args += [
                "--mount",
                f"type=bind,src={self._db_volume},dst={TRIVY_DB_DIR},readonly",
            ]
        for mount in self._extra_mounts:
            args += ["--mount", f"type=bind,src={mount},dst={mount}"]
        for key, value in _CONTAINER_ENV.items():
            args += ["--env", f"{key}={value}"]
        args += ["--workdir", str(self.workspace), self.image, "sleep", "infinity"]
        return args

    def start(self, *, cpu: float = 2, memory: str = "4g") -> None:
        """Start the container. It runs unprivileged with no Linux capabilities."""
        for mount in self._extra_mounts:
            mount.mkdir(parents=True, exist_ok=True)
        try:
            result = self._docker(self.start_args(cpu=cpu, memory=memory), timeout_s=300)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"docker run timed out: {exc}") from exc
        if result.returncode:
            detail = (result.stderr or result.stdout)[-3000:]
            raise RuntimeError(f"docker run failed ({result.returncode}): {detail}")
        self.container_id = result.stdout.strip().splitlines()[-1]
        self.run(
            ["mkdir", "-p", _CONTAINER_ENV["HOME"], _CONTAINER_ENV["XDG_CACHE_HOME"]], timeout_s=30
        )

    def run(
        self,
        cmd: list[str] | str,
        *,
        cwd: Path | str | None = None,
        timeout_s: float | None = DEFAULT_TIMEOUT_S,
    ) -> CommandResult:
        if self._closed or self.container_id is None:
            return CommandResult(125, "", "sandbox container is not running")
        workdir = self.workspace if cwd is None else Path(cwd)
        if not workdir.is_absolute():
            workdir = self.workspace / workdir
        try:
            workdir.resolve().relative_to(self.workspace)
        except ValueError:
            return CommandResult(126, "", f"working directory is outside workspace: {workdir}")
        command = ["sh", "-lc", cmd] if isinstance(cmd, str) else list(cmd)
        if timeout_s:
            command = ["timeout", "--signal=TERM", "--kill-after=10s", f"{timeout_s}s", *command]
        try:
            result = self._docker(
                ["exec", "--workdir", str(workdir), self.container_id, *command],
                timeout_s=(timeout_s + 30) if timeout_s else 3600,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", f"timed out after {timeout_s}s")
        return CommandResult(
            result.returncode, result.stdout[-2_000_000:], result.stderr[-2_000_000:]
        )

    def copy_file_from(self, container_path: Path | str, host_path: Path | str) -> None:
        """Copy a transient scanner report out of the container without mounting its directory."""
        if self.container_id is None:
            raise RuntimeError("sandbox container is not running")
        target = Path(host_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = self._docker(
                ["cp", f"{self.container_id}:{container_path}", str(target)], timeout_s=60
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"docker cp timed out: {exc}") from exc
        if result.returncode:
            raise RuntimeError(f"docker cp failed: {(result.stderr or result.stdout)[-2000:]}")

    def close(self) -> None:
        """Remove the container. Idempotent; safe to call when start() failed."""
        if self._closed:
            return
        self._closed = True
        if self.container_id is None:
            return
        try:
            result = self._docker(["rm", "--force", self.container_id], timeout_s=60)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"docker rm timed out: {exc}") from exc
        if result.returncode and "No such container" not in result.stderr:
            raise RuntimeError(f"docker rm failed: {(result.stderr or result.stdout)[-2000:]}")

    def __enter__(self) -> DockerSandbox:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
