from __future__ import annotations

import os
import subprocess

import pytest

from ananke.worker.sandbox import CommandResult, DockerSandbox, LocalSandbox, Sandbox


def test_local_sandbox_is_a_sandbox(fake_sandbox):
    assert isinstance(fake_sandbox, Sandbox)
    assert fake_sandbox.is_isolated is False


def test_run_list_and_string(fake_sandbox, tmp_path):
    (tmp_path / "f.txt").write_text("hello")
    r = fake_sandbox.run(["cat", "f.txt"])
    assert r == CommandResult(0, "hello", "")
    r = fake_sandbox.run("echo out; echo err >&2; exit 3")
    assert r.exit_code == 3 and r.stdout.strip() == "out" and r.stderr.strip() == "err"
    assert not r.ok


def test_relative_cwd(fake_sandbox, tmp_path):
    (tmp_path / "sub").mkdir()
    assert fake_sandbox.run("pwd", cwd="sub").stdout.strip().endswith("/sub")


def test_timeout_and_missing_binary(fake_sandbox):
    assert fake_sandbox.run(["sleep", "5"], timeout_s=0.2).exit_code == 124
    assert fake_sandbox.run(["definitely-not-a-binary-xyz"]).exit_code == 127
    assert fake_sandbox.which("sh")
    assert not fake_sandbox.which("definitely-not-a-binary-xyz")


def test_env_override(tmp_path):
    sb = LocalSandbox(tmp_path, env={"ANANKE_TEST_VAR": "v1"})
    assert sb.run("echo $ANANKE_TEST_VAR").stdout.strip() == "v1"


def test_local_sandbox_strips_secret_env(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("PLAIN_VALUE", "ok")
    out = LocalSandbox(tmp_path).run("echo ${GITHUB_TOKEN:-none} $PLAIN_VALUE").stdout.strip()
    assert out == "none ok"


# --- DockerSandbox, driven through a fake `docker` executable (no daemon needed) -------------


@pytest.fixture
def fake_docker(tmp_path):
    log = tmp_path / "docker.log"
    script = tmp_path / "docker"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> {log}\n'
        'case "$1" in\n'
        "  run) echo cid123 ;;\n"
        '  exec) shift 3; echo "exec:$*" ;;\n'
        "  rm) exit 0 ;;\n"
        "esac\n"
    )
    script.chmod(0o755)
    return script, log


def test_docker_start_args(tmp_path, fake_docker):
    ws = tmp_path / "ws"
    (ws / ".git").mkdir(parents=True)
    sb = DockerSandbox(ws, docker=str(fake_docker[0]), start=False, container_name="ananke-t")
    args = sb.start_args(cpu=1, memory="2g")
    joined = " ".join(args)
    assert args[:2] == ["run", "--detach"]
    assert f"--user {os.getuid()}:{os.getgid()}" in joined
    assert "--network none" in joined and "--cap-drop ALL" in joined
    assert f"type=bind,src={ws.resolve()},dst={ws.resolve()}" in joined
    assert f"type=bind,src={ws.resolve()}/.git,dst={ws.resolve()}/.git,readonly" in joined
    assert "--env HOME=/tmp/home" in joined
    assert args[-3:] == ["ghcr.io/renci/ananke-worker:latest", "sleep", "infinity"]


def test_docker_run_and_close(tmp_path, fake_docker):
    script, log = fake_docker
    ws = tmp_path / "ws"
    sb = DockerSandbox(ws, docker=str(script))
    assert sb.container_id == "cid123"
    res = sb.run(["echo", "hi"], timeout_s=5)
    assert (
        res.ok
        and res.stdout.strip() == "exec:cid123 timeout --signal=TERM --kill-after=10s 5s echo hi"
    )
    assert sb.run("ls", cwd=tmp_path).exit_code == 126  # outside the workspace
    sb.close()
    sb.close()
    assert sb.run("ls").exit_code == 125
    assert log.read_text().count("rm --force cid123") == 1


def test_docker_refuses_unrestricted_networks(tmp_path):
    for net in ("bridge", "host", "container:abc"):
        with pytest.raises(ValueError, match="unrestricted"):
            DockerSandbox(tmp_path, network=net, start=False)
    sb = DockerSandbox(tmp_path, network="bridge", allow_unrestricted_network=True, start=False)
    assert sb.network == "bridge"


def test_docker_exec_timeout_returns_124(tmp_path, monkeypatch):
    sb = DockerSandbox(tmp_path, start=False)
    sb.container_id = "cid"

    def boom(args, *, timeout_s=120):
        raise subprocess.TimeoutExpired(args, timeout_s)

    monkeypatch.setattr(sb, "_docker", boom)
    assert sb.run(["sleep", "99"], timeout_s=1).exit_code == 124


def test_docker_close_without_start_is_safe(tmp_path):
    sb = DockerSandbox(tmp_path, start=False)
    sb.close()
    assert sb.run("ls").exit_code == 125
