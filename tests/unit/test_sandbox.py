from __future__ import annotations

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


def test_docker_sandbox_is_stub():
    with pytest.raises(NotImplementedError, match="M1"):
        DockerSandbox()
