"""gitleaks plugin: fixture parsing, redaction, command construction, version parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ananke.scanners import ScannerError
from ananke.scanners.base import Scanner, ScanReport, delta
from ananke.scanners.gitleaks import GitleaksScanner, parse_version_output
from ananke.worker.sandbox import CommandResult

SECRET = "AKIAIOSFODNN7EXAMPLE"


class RecordingSandbox:
    """Records calls; on a gitleaks scan, writes `report` to the --report-path like the tool."""

    is_isolated = False

    def __init__(self, report: str = "[]", exit_code: int = 0, version_out: str = "8.30.1"):
        self.calls: list[tuple[list[str], object]] = []
        self.report, self.exit_code, self.version_out = report, exit_code, version_out

    def run(self, cmd, *, cwd=None, timeout_s=600):
        cmd = list(cmd)
        self.calls.append((cmd, cwd))
        if "--version" in cmd:
            return CommandResult(0, self.version_out, "")
        if self.exit_code in (0, 1):
            Path(cmd[cmd.index("--report-path") + 1]).write_text(self.report)
        return CommandResult(self.exit_code, "", "")


def _raw(fixtures_dir: Path, name: str) -> str:
    return (fixtures_dir / "scanner_output" / "gitleaks" / name).read_text()


def test_satisfies_protocol():
    assert isinstance(GitleaksScanner(), Scanner)


def test_parse_one_secret(fixtures_dir):
    report = GitleaksScanner().parse(_raw(fixtures_dir, "one_secret.json"))
    (f,) = report.findings
    assert f.id == "aws-access-token"
    assert f.kind == "secret"
    assert f.severity == "high"
    assert f.package is None
    assert f.location == "settings.env:2"
    assert f.title.startswith("Identified a pattern that may indicate AWS credentials")
    assert f.aliases == ["settings.env:aws-access-token:2"]


def test_parse_never_leaks_secret(fixtures_dir):
    report = GitleaksScanner().parse(_raw(fixtures_dir, "one_secret.json"))
    assert SECRET not in report.model_dump_json()
    assert SECRET not in repr(report)


def test_secret_in_fingerprint_is_dropped():
    raw = json.dumps(
        [{"RuleID": "r", "File": "a", "StartLine": 1, "Secret": "s3cr3tvalue",
          "Match": "k=s3cr3tvalue", "Fingerprint": "a:r:s3cr3tvalue"}]
    )  # fmt: skip
    report = GitleaksScanner().parse(raw)
    assert "s3cr3tvalue" not in report.model_dump_json()


@pytest.mark.parametrize("raw", ["", "[]", "{}", "null"])
def test_parse_empty(raw, fixtures_dir):
    assert GitleaksScanner().parse(raw).findings == []
    assert GitleaksScanner().parse(_raw(fixtures_dir, "clean.json")).findings == []


def test_delta_resolved(fixtures_dir):
    g = GitleaksScanner()
    before = g.parse(_raw(fixtures_dir, "one_secret.json"))
    after = g.parse(_raw(fixtures_dir, "clean.json"))
    d = delta(before, after)
    assert [f.id for f in d.resolved] == ["aws-access-token"]
    assert d.introduced == [] and d.remaining == []
    d2 = delta(after, before)
    assert [f.id for f in d2.introduced] == ["aws-access-token"]


def test_parse_relativizes_absolute_file(fixtures_dir):
    raw = _raw(fixtures_dir, "one_secret.json").replace('"settings.env', '"/ws/settings.env')
    (f,) = GitleaksScanner().parse(raw, workspace=Path("/ws")).findings
    assert f.location == "settings.env:2"
    assert f.aliases == ["settings.env:aws-access-token:2"]


@pytest.mark.parametrize(
    ("out", "ver"),
    [("8.30.1\n", "8.30.1"), ("v8.30.1", "8.30.1"), ("gitleaks version 8.30.1", "8.30.1")],
)
def test_version_parsing(out, ver):
    assert parse_version_output(out).tool_version == ver


def test_available(fake_sandbox):
    assert GitleaksScanner().available(fake_sandbox) is False
    sb = RecordingSandbox()
    assert GitleaksScanner().available(sb) is True
    assert sb.calls[0][0] == ["gitleaks", "--version"]


def test_command(tmp_path):
    ws, rp = tmp_path / "ws", tmp_path / "raw" / "gitleaks.json"
    base = [
        "gitleaks",
        "dir",
        str(ws),
        "--report-format",
        "json",
        "--report-path",
        str(rp),
        "--no-banner",
        "--exit-code",
        "1",
    ]
    assert GitleaksScanner().command(ws, rp) == base
    assert GitleaksScanner({"config": "/etc/gl.toml"}).command(ws, rp) == [
        *base,
        "--config",
        "/etc/gl.toml",
    ]


@pytest.mark.parametrize("code", [0, 1])
def test_scan(tmp_path, fixtures_dir, code):
    ws = tmp_path / "ws"
    ws.mkdir()
    raw_dir = tmp_path / "raw"
    sb = RecordingSandbox(report=_raw(fixtures_dir, "one_secret.json"), exit_code=code)
    report = GitleaksScanner(raw_dir=raw_dir).scan(sb, ws)
    cmd, cwd = sb.calls[0]
    assert cmd[:3] == ["gitleaks", "dir", str(ws)] and cwd == ws
    assert Path(cmd[cmd.index("--report-path") + 1]).parent == raw_dir
    assert isinstance(report, ScanReport)
    assert report.scanner_version == "8.30.1"
    assert [f.id for f in report.findings] == ["aws-access-token"]
    assert SECRET not in report.model_dump_json()
    assert list(ws.iterdir()) == []


def test_scan_failure(tmp_path):
    with pytest.raises(ScannerError, match="exit 2"):
        GitleaksScanner(raw_dir=tmp_path / "raw").scan(
            RecordingSandbox(exit_code=2), tmp_path / "ws"
        )
