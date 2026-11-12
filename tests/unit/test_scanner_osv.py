"""OSV-Scanner plugin: fixture parsing, delta, command construction, version parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ananke.scanners import ScannerError
from ananke.scanners.base import Scanner, delta
from ananke.scanners.osv import OsvScanner, cvss_score_severity, parse_version_output
from ananke.worker.sandbox import CommandResult

PY = {
    "CVE-2023-32681": ("GHSA-j8r2-6x86-q33q", "PYSEC-2023-74", "requests", "2.31.0"),
    "CVE-2024-35195": ("GHSA-9wx4-h78v-vm56", "PYSEC-2026-1873", "requests", "2.32.0"),
    "CVE-2023-43804": ("GHSA-v845-jxx5-vc9f", "PYSEC-2023-192", "urllib3", "1.26.17"),
    "CVE-2023-45803": ("GHSA-g4mx-q9vg-27p4", "PYSEC-2023-212", "urllib3", "1.26.18"),
    "CVE-2024-37891": ("GHSA-34jh-p97f-mpxf", "PYSEC-2026-1995", "urllib3", "1.26.19"),
}
JS = {
    "CVE-2020-8203": ("GHSA-p6mc-m468-83gw", "4.17.19", "high"),
    "CVE-2021-23337": ("GHSA-35jh-r3h4-6jhm", "4.17.21", "high"),
    "CVE-2020-28500": ("GHSA-29mw-wpgm-hmr9", "4.17.21", "medium"),
}
WS = {"py": Path("/scan/py-vulnerable"), "js": Path("/scan/js-vulnerable")}


class RecordingSandbox:
    is_isolated = False

    def __init__(self, results: dict[str, CommandResult] | None = None):
        self.calls: list[tuple[list[str], object]] = []
        self.results = results or {}

    def run(self, cmd, *, cwd=None, timeout_s=600):
        self.calls.append((list(cmd), cwd))
        key = "version" if "--version" in cmd else "scan"
        return self.results.get(key, CommandResult(0, "", ""))


def _raw(fixtures_dir: Path, name: str) -> str:
    return (fixtures_dir / "scanner_output" / "osv" / name).read_text()


def _load(fixtures_dir: Path, eco: str, when: str):
    return OsvScanner().parse(_raw(fixtures_dir, f"{when}_{eco}.json"), workspace=WS[eco])


def test_satisfies_protocol():
    assert isinstance(OsvScanner(), Scanner)


def test_parse_before_py(fixtures_dir):
    report = _load(fixtures_dir, "py", "before")
    by_id = {f.id: f for f in report.findings}
    assert set(PY) <= set(by_id)
    for cve, (ghsa, pysec, pkg, fixed) in PY.items():
        f = by_id[cve]
        assert {ghsa, pysec} <= set(f.aliases)
        assert f.package == pkg
        assert f.installed_version == ("2.25.1" if pkg == "requests" else "1.26.5")
        assert f.fixed_version == fixed
        assert f.kind == "dependency"
        assert f.location == "uv.lock"
    # GHSA and PYSEC records for the same CVE collapse into one finding
    assert len([f for f in report.findings if f.id == "CVE-2023-32681"]) == 1
    assert by_id["CVE-2023-32681"].severity == "medium"  # max_severity 6.1
    assert by_id["CVE-2024-35195"].title.startswith("Requests `Session` object")
    assert report.targets == ["uv.lock"]


def test_parse_before_js(fixtures_dir):
    by_id = {f.id: f for f in _load(fixtures_dir, "js", "before").findings}
    assert set(JS) <= set(by_id)
    for cve, (ghsa, fixed, sev) in JS.items():
        f = by_id[cve]
        assert ghsa in f.aliases
        assert (f.package, f.installed_version, f.location) == (
            "lodash",
            "4.17.15",
            "package-lock.json",
        )
        assert f.fixed_version == fixed  # lodash-es / lodash-rails ranges are ignored
        assert f.severity == sev


def test_parse_without_workspace_keeps_absolute_path(fixtures_dir):
    report = OsvScanner().parse(_raw(fixtures_dir, "before_js.json"))
    assert {f.location for f in report.findings} == {"/scan/js-vulnerable/package-lock.json"}


@pytest.mark.parametrize(("eco", "ids"), [("py", set(PY)), ("js", set(JS))])
def test_delta_resolves_known_ids(fixtures_dir, eco, ids):
    d = delta(_load(fixtures_dir, eco, "before"), _load(fixtures_dir, eco, "after"))
    assert ids <= {f.id for f in d.resolved}
    assert not ids & {f.id for f in d.remaining}
    assert not ids & {f.id for f in d.introduced}


def test_osv_matches_trivy_identity(fixtures_dir):
    """A Trivy-shaped finding (CVE id, GHSA alias, same package/location) is the same finding."""
    from ananke.scanners.trivy import TrivyScanner

    trivy = TrivyScanner().parse(
        (fixtures_dir / "scanner_output" / "trivy" / "before_py.json").read_text()
    )
    osv = _load(fixtures_dir, "py", "before")
    for t in trivy.findings:
        assert any(t.same_as(o) for o in osv.findings), t.id


@pytest.mark.parametrize("raw", ["", "{}", "[]", '{"results": []}', '{"results": null}'])
def test_parse_empty(raw):
    assert OsvScanner().parse(raw).findings == []


def test_severity_fallback_and_record_id():
    raw = json.dumps(
        {
            "results": [
                {
                    "source": {"path": "/w/go.mod", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "x", "version": "1.0.0", "ecosystem": "Go"},
                            "vulnerabilities": [
                                {
                                    "id": "GO-2024-0001",
                                    "summary": "s",
                                    "database_specific": {"severity": "CRITICAL"},
                                    "affected": [
                                        {
                                            "package": {"name": "x", "ecosystem": "Go"},
                                            "ranges": [
                                                {
                                                    "type": "SEMVER",
                                                    "events": [
                                                        {"introduced": "0"},
                                                        {"fixed": "1.2.0"},
                                                        {"introduced": "2.0.0"},
                                                        {"fixed": "2.0.1"},
                                                    ],
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    (f,) = OsvScanner().parse(raw, workspace=Path("/w")).findings
    assert (f.id, f.aliases, f.severity, f.fixed_version, f.location) == (
        "GO-2024-0001",
        [],
        "critical",
        "1.2.0",
        "go.mod",
    )


@pytest.mark.parametrize(
    ("score", "sev"),
    [("9.8", "critical"), ("9.0", "critical"), ("7.4", "high"), ("4.0", "medium"),
     ("3.9", "low"), ("0", "unknown"), ("", "unknown"), (None, "unknown")],
)  # fmt: skip
def test_cvss_buckets(score, sev):
    assert cvss_score_severity(score) == sev


def test_version_parsing():
    out = "osv-scanner version: 2.7.1\ncommit: 1a2b3c4\nbuilt at: 2026-10-01T00:00:00Z\n"
    v = parse_version_output(out)
    assert v.tool_version == "2.7.1" and v.db_version is None


def test_available(fake_sandbox):
    assert OsvScanner().available(fake_sandbox) is False
    sb = RecordingSandbox()
    assert OsvScanner().available(sb) is True
    assert sb.calls[0][0] == ["osv-scanner", "--version"]


def test_command_recursive(tmp_path):
    ws = tmp_path / "ws"
    assert OsvScanner({"offline": True}).command(ws) == [
        "osv-scanner",
        "scan",
        "--format",
        "json",
        "--offline",
        "-r",
        str(ws),
    ]
    assert OsvScanner({"offline": False}).command(ws) == [
        "osv-scanner",
        "scan",
        "--format",
        "json",
        "-r",
        str(ws),
    ]


def test_command_lockfiles(tmp_path):
    cmd = OsvScanner({"offline": True}).command(
        tmp_path, [Path("uv.lock"), Path("web/package-lock.json")]
    )
    assert cmd == [
        "osv-scanner",
        "scan",
        "--format",
        "json",
        "--offline",
        "--lockfile",
        "uv.lock",
        "--lockfile",
        "web/package-lock.json",
    ]


@pytest.mark.parametrize("code", [0, 1])
def test_scan_exit_0_and_1_are_success(tmp_path, fixtures_dir, code):
    ws = tmp_path / "ws"
    ws.mkdir()
    raw = _raw(fixtures_dir, "before_js.json").replace("/scan/js-vulnerable", str(ws))
    sb = RecordingSandbox(
        {
            "scan": CommandResult(code, raw, ""),
            "version": CommandResult(0, "osv-scanner version: 2.7.1\n", ""),
        }
    )
    report = OsvScanner(raw_dir=tmp_path / "raw").scan(sb, ws)
    assert sb.calls[0][1] == ws
    assert report.scanner_version == "2.7.1"
    assert {f.location for f in report.findings} == {"package-lock.json"}
    assert set(JS) <= {f.id for f in report.findings}
    assert Path(report.raw_path).read_text() == raw


@pytest.mark.parametrize("code", [2, 127])
def test_scan_other_exit_codes_fail(tmp_path, code):
    sb = RecordingSandbox({"scan": CommandResult(code, "", "boom")})
    with pytest.raises(ScannerError):
        OsvScanner(raw_dir=tmp_path / "raw").scan(sb, tmp_path / "ws")
