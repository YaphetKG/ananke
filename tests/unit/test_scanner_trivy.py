"""Trivy plugin: fixture parsing, delta, command construction, version parsing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ananke.scanners import ScannerError
from ananke.scanners.base import Scanner, delta
from ananke.scanners.trivy import TrivyScanner, parse_version_output
from ananke.worker.sandbox import CommandResult

PY_IDS = {
    "CVE-2023-32681": ("GHSA-j8r2-6x86-q33q", "requests"),
    "CVE-2024-35195": ("GHSA-9wx4-h78v-vm56", "requests"),
    "CVE-2023-43804": ("GHSA-v845-jxx5-vc9f", "urllib3"),
    "CVE-2023-45803": ("GHSA-g4mx-q9vg-27p4", "urllib3"),
    "CVE-2024-37891": ("GHSA-34jh-p97f-mpxf", "urllib3"),
}
JS_IDS = {
    "CVE-2020-8203": "GHSA-p6mc-m468-83gw",
    "CVE-2021-23337": "GHSA-35jh-r3h4-6jhm",
    "CVE-2020-28500": "GHSA-29mw-wpgm-hmr9",
}

TRIVY_VERSION_OUT = """\
Version: 0.76.2
Vulnerability DB:
  Version: 2
  UpdatedAt: 2026-11-12 06:13:54.123456789 +0000 UTC
  NextUpdate: 2026-11-13 06:13:54.123456789 +0000 UTC
  DownloadedAt: 2026-11-12 07:00:01.5 +0000 UTC
Java DB:
  Version: 1
  UpdatedAt: 2026-11-10 01:02:03 +0000 UTC
"""


class RecordingSandbox:
    is_isolated = False

    def __init__(self, results: dict[str, CommandResult] | None = None):
        self.calls: list[tuple[list[str], object]] = []
        self.results = results or {}

    def run(self, cmd, *, cwd=None, timeout_s=600):
        self.calls.append((list(cmd), cwd))
        key = "version" if "--version" in cmd else "scan"
        return self.results.get(key, CommandResult(0, "", ""))


def _load(fixtures_dir: Path, name: str):
    return TrivyScanner().parse((fixtures_dir / "scanner_output" / "trivy" / name).read_text())


def test_satisfies_protocol():
    assert isinstance(TrivyScanner(), Scanner)


def test_parse_before_py(fixtures_dir):
    report = _load(fixtures_dir, "before_py.json")
    assert report.scanner == "trivy"
    assert report.scanner_version == "0.76.2"
    by_id = {f.id: f for f in report.findings}
    assert set(PY_IDS) <= set(by_id)
    for cve, (ghsa, pkg) in PY_IDS.items():
        f = by_id[cve]
        assert ghsa in f.aliases
        assert f.package == pkg
        assert f.kind == "dependency"
        assert f.location == "uv.lock"
        assert f.installed_version == ("2.25.1" if pkg == "requests" else "1.26.5")
    assert by_id["CVE-2023-32681"].fixed_version == "2.31.0"
    assert by_id["CVE-2023-43804"].fixed_version == "2.0.6, 1.26.17"  # kept verbatim
    assert by_id["CVE-2023-43804"].severity == "high"
    assert by_id["CVE-2023-32681"].severity == "medium"
    assert by_id["CVE-2023-32681"].title.startswith("Unintended leak of Proxy-Authorization")


def test_parse_before_js(fixtures_dir):
    by_id = {f.id: f for f in _load(fixtures_dir, "before_js.json").findings}
    assert set(JS_IDS) <= set(by_id)
    for cve, ghsa in JS_IDS.items():
        f = by_id[cve]
        assert f.aliases == [ghsa] or ghsa in f.aliases
        assert (f.package, f.installed_version, f.location) == (
            "lodash",
            "4.17.15",
            "package-lock.json",
        )
    assert by_id["CVE-2021-23337"].fixed_version == "4.17.21"


@pytest.mark.parametrize(("eco", "ids"), [("py", set(PY_IDS)), ("js", set(JS_IDS))])
def test_delta_resolves_known_ids(fixtures_dir, eco, ids):
    before = _load(fixtures_dir, f"before_{eco}.json")
    after = _load(fixtures_dir, f"after_{eco}.json")
    d = delta(before, after)
    assert ids <= {f.id for f in d.resolved}
    assert not ids & {f.id for f in d.remaining}
    assert not ids & {f.id for f in d.introduced}
    assert d.introduced == [] or all(f.id not in ids for f in d.introduced)


def test_delta_matches_via_alias(fixtures_dir):
    before = _load(fixtures_dir, "before_js.json")
    after = before.model_copy(deep=True)
    for f in after.findings:  # same advisory, reported under the GHSA instead
        f.id, f.aliases = f.aliases[0], [f.id]
    d = delta(before, after)
    assert d.resolved == [] and d.introduced == []
    assert len(d.remaining) == len(before.findings)


@pytest.mark.parametrize("raw", ["", "  ", "{}", '{"Results": null}', '{"Results": []}', "[]"])
def test_parse_empty(raw):
    assert TrivyScanner().parse(raw).findings == []


def test_parse_misconfig_and_secret_redacted():
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    raw = json.dumps(
        {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Class": "config",
                    "Type": "dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS-0002",
                            "AVDID": "AVD-DS-0002",
                            "Title": "Image user should not be 'root'",
                            "Severity": "HIGH",
                            "Status": "FAIL",
                            "CauseMetadata": {"StartLine": 3, "EndLine": 3},
                        },
                        {"ID": "DS-0001", "Title": "ok", "Severity": "LOW", "Status": "PASS"},
                    ],
                },
                {
                    "Target": "app/config.py",
                    "Class": "secret",
                    "Secrets": [
                        {
                            "RuleID": "github-pat",
                            "Category": "GitHub",
                            "Severity": "CRITICAL",
                            "Title": "GitHub Personal Access Token",
                            "StartLine": 7,
                            "EndLine": 7,
                            "Match": f"TOKEN = '{secret}'",
                            "Code": {"Lines": [{"Number": 7, "Content": secret}]},
                        }
                    ],
                },
            ]
        }
    )
    report = TrivyScanner().parse(raw)
    by_id = {f.id: f for f in report.findings}
    assert set(by_id) == {"DS-0002", "github-pat"}
    assert by_id["DS-0002"].kind == "iac"
    assert by_id["DS-0002"].location == "Dockerfile:3"
    assert by_id["DS-0002"].aliases == ["AVD-DS-0002"]
    assert by_id["github-pat"].kind == "secret"
    assert by_id["github-pat"].location == "app/config.py:7"
    assert by_id["github-pat"].severity == "critical"
    assert secret not in report.model_dump_json()


def test_version_parsing():
    v = parse_version_output(TRIVY_VERSION_OUT)
    assert v.tool_version == "0.76.2"
    assert v.db_version == "2"
    assert v.db_updated_at == datetime(2026, 11, 12, 6, 13, 54, 123456, tzinfo=UTC)


def test_version_parsing_without_db():
    v = parse_version_output("Version: 0.76.2\n")
    assert (v.tool_version, v.db_version, v.db_updated_at) == ("0.76.2", None, None)


def test_available_false_without_binary(fake_sandbox):
    s = TrivyScanner()
    assert s.available(fake_sandbox) is False
    assert s.version(fake_sandbox).tool_version == "unknown"


def test_available_true_with_stub():
    sb = RecordingSandbox()
    assert TrivyScanner().available(sb) is True
    assert sb.calls[0][0] == ["trivy", "--version"]


def test_command_default_options(tmp_path):
    ws = tmp_path / "ws"
    assert TrivyScanner(
        {"scanners": ["vuln", "misconfig", "secret"], "ignore_unfixed": True}
    ).command(ws) == [
        "trivy",
        "fs",
        "--scanners",
        "vuln,misconfig,secret",
        "--format",
        "json",
        "--ignore-unfixed",
        "--skip-db-update",
        str(ws),
    ]


def test_command_options(tmp_path):
    ws = tmp_path / "ws"
    s = TrivyScanner({"scanners": ["vuln"], "ignore_unfixed": False, "cache_dir": "/db/trivy"})
    assert s.command(ws) == [
        "trivy",
        "fs",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--skip-db-update",
        "--cache-dir",
        "/db/trivy",
        str(ws),
    ]


def test_scan_runs_in_workspace_and_saves_raw(tmp_path, fixtures_dir):
    ws = tmp_path / "ws"
    ws.mkdir()
    raw_dir = tmp_path / "raw"
    raw = (fixtures_dir / "scanner_output" / "trivy" / "before_py.json").read_text()
    sb = RecordingSandbox(
        {"scan": CommandResult(0, raw, ""), "version": CommandResult(0, TRIVY_VERSION_OUT, "")}
    )
    report = TrivyScanner({"scanners": ["vuln"]}, raw_dir=raw_dir).scan(sb, ws)
    scan_cmd, cwd = sb.calls[0]
    assert scan_cmd[:2] == ["trivy", "fs"] and scan_cmd[-1] == str(ws)
    assert cwd == ws
    assert report.scanner_version == "0.76.2" and report.db_version == "2"
    assert report.targets == [str(ws)]
    assert Path(report.raw_path).parent == raw_dir
    assert Path(report.raw_path).read_text() == raw
    assert "CVE-2023-32681" in {f.id for f in report.findings}
    assert list(ws.iterdir()) == []  # nothing written into the workspace


def test_scan_target_filter(tmp_path, fixtures_dir):
    ws = tmp_path / "ws"
    ws.mkdir()
    raw = (fixtures_dir / "scanner_output" / "trivy" / "before_py.json").read_text()
    sb = RecordingSandbox({"scan": CommandResult(0, raw, "")})
    s = TrivyScanner(raw_dir=tmp_path / "raw")
    assert s.scan(sb, ws, targets=[Path("other/uv.lock")]).findings == []
    assert len(s.scan(sb, ws, targets=[ws / "uv.lock"]).findings) == 5


def test_scan_failure_raises(tmp_path):
    sb = RecordingSandbox({"scan": CommandResult(2, "", "FATAL db missing")})
    with pytest.raises(ScannerError, match="exit 2"):
        TrivyScanner(raw_dir=tmp_path / "raw").scan(sb, tmp_path / "ws")


def test_raw_dir_inside_workspace_refused(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    with pytest.raises(ScannerError, match="inside the workspace"):
        TrivyScanner(raw_dir=ws / ".raw").scan(RecordingSandbox(), ws)
