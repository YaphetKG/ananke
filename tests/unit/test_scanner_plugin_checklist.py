"""docs/SCANNERS.md checklist, followed literally with a toy scanner defined in-test."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ananke.config import ScannersConfig
from ananke.scanners import ScannerError, build_scanners, registry
from ananke.scanners.base import ScanFinding, Scanner, ScannerVersion, ScanReport, delta
from ananke.worker.sandbox import CommandResult

DOCS = Path(__file__).resolve().parents[2] / "docs" / "SCANNERS.md"

# Step 2 of the checklist: a fixture of the tool's JSON output (inline here; a real plugin
# puts it under tests/fixtures/scanner_output/<name>/).
BEFORE = json.dumps(
    {"vulns": [{"cve": "CVE-2023-32681", "ghsa": "GHSA-j8r2-6x86-q33q", "pkg": "requests",
                "have": "2.25.1", "fix": "2.31.0", "file": "uv.lock", "sev": "MODERATE"}]}
)  # fmt: skip
AFTER = json.dumps({"vulns": []})


class ToyScanner:
    """Step 1: one module implementing the Scanner protocol."""

    name = "toyscan"
    kinds = frozenset({"dependency"})
    ecosystems = frozenset({"pip"})

    def __init__(self, options: dict[str, Any] | None = None, *, raw_dir: Path | None = None):
        self.options = dict(options or {})
        self.raw_dir = raw_dir

    def available(self, sandbox) -> bool:
        return sandbox.run(["toyscan", "--version"]).exit_code == 0

    def version(self, sandbox) -> ScannerVersion:
        res = sandbox.run(["toyscan", "--version"])
        return ScannerVersion(tool_version=res.stdout.strip() or "unknown")

    def scan(self, sandbox, workspace: Path, targets: list[Path] | None = None) -> ScanReport:
        res = sandbox.run(["toyscan", "--json", str(workspace)], cwd=workspace)
        if res.exit_code != 0:
            raise ScannerError(self.name, f"exit {res.exit_code}")
        raw_path = Path(self.raw_dir) / "toyscan.json"
        raw_path.write_text(res.stdout)
        report = self.parse(res.stdout)
        report.scanner_version = self.version(sandbox).tool_version
        report.targets, report.raw_path = [str(workspace)], str(raw_path)
        return report

    def parse(self, raw: str) -> ScanReport:
        data = json.loads(raw) if raw.strip() else {}
        return ScanReport(
            scanner=self.name,
            findings=[
                ScanFinding(
                    id=v["cve"],
                    aliases=[v["ghsa"]],
                    kind="dependency",
                    severity="medium" if v["sev"] == "MODERATE" else "unknown",
                    package=v["pkg"],
                    installed_version=v["have"],
                    fixed_version=v["fix"],
                    location=v["file"],
                    title=f"{v['pkg']} advisory",
                )
                for v in data.get("vulns") or []
            ],
        )


class StubSandbox:
    is_isolated = False

    def __init__(self, scan_out: str):
        self.scan_out = scan_out

    def run(self, cmd, *, cwd=None, timeout_s=600):
        if "--version" in cmd:
            return CommandResult(0, "toyscan 1.0.0", "")
        return CommandResult(0, self.scan_out, "")


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    monkeypatch.setattr(registry, "_REGISTRY", {})


def test_docs_checklist_exists():
    text = DOCS.read_text()
    for needle in ("one module", "tests/fixtures/scanner_output/", "registry", "worker.Dockerfile",
                   "scanners.<name>", "ananke scanners", "Secret"):  # fmt: skip
        assert needle in text, needle


def test_toy_scanner_registers_and_flows_through_delta(tmp_path):
    toy = ToyScanner({}, raw_dir=tmp_path / "raw")
    (tmp_path / "raw").mkdir()
    assert isinstance(toy, Scanner)
    registry.register(toy)  # step 3: one registry line
    assert toy in registry.all_scanners()

    # step 5: enabled via config, options under scanners.toyscan, ordered as configured
    cfg = ScannersConfig.model_validate({"enabled": ["toyscan", "osv"], "toyscan": {"x": 1}})
    assert cfg.options_for("toyscan") == {"x": 1}
    assert [s.name for s in build_scanners(cfg)] == ["toyscan", "osv"]
    assert "toyscan" in {s.name for s in registry.all_scanners()}

    ws = tmp_path / "ws"
    ws.mkdir()
    assert toy.available(StubSandbox(BEFORE)) is True
    before = toy.scan(StubSandbox(BEFORE), ws)
    after = toy.scan(StubSandbox(AFTER), ws)
    assert before.scanner_version == "toyscan 1.0.0"
    d = delta(before, after)
    assert [(f.id, f.aliases) for f in d.resolved] == [("CVE-2023-32681", ["GHSA-j8r2-6x86-q33q"])]
    assert d.introduced == [] and d.remaining == []

    # the toy finding is the same identity as Trivy's finding for that advisory
    from ananke.scanners.trivy import TrivyScanner

    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "scanner_output" / "trivy"
    trivy = TrivyScanner().parse((fixtures / "before_py.json").read_text())
    assert any(before.findings[0].same_as(t) for t in trivy.findings)


def test_toy_scanner_shows_in_cli_listing_and_pr_table(tmp_path):
    """M1 acceptance: following SCANNERS.md alone, a new scanner appears in `ananke scanners`
    and gets its own row in the PR body's proof-of-work table."""
    from datetime import UTC, datetime

    from typer.testing import CliRunner

    from ananke.cli import app
    from ananke.config import RepoWorkflowConfig
    from ananke.model import RunRecord
    from ananke.workflow import render_pr_body, synthetic_item

    toy = ToyScanner({}, raw_dir=tmp_path)
    registry.register(toy)
    cfg = tmp_path / "ananke.yaml"
    cfg.write_text("repos: [RENCI/x]\nscanners:\n  enabled: [toyscan, trivy]\n")
    out = CliRunner().invoke(app, ["scanners", "--config", str(cfg)])
    assert out.exit_code == 0, out.output
    toy_row = next(line for line in out.output.splitlines() if "toyscan" in line)
    assert "dependency" in toy_row and "True" in toy_row  # registered and enabled

    ws = tmp_path / "ws"
    ws.mkdir()
    before, after = toy.scan(StubSandbox(BEFORE), ws), toy.scan(StubSandbox(AFTER), ws)
    item = synthetic_item()
    body = render_pr_body(
        item=item,
        result=None,
        evidence={
            "before": {"toyscan": before},
            "after": {"toyscan": after},
            "delta": {"toyscan": delta(before, after)},
        },  # fmt: skip
        run=RunRecord(run_id="r", item_key=item.key, started_at=datetime.now(UTC)),
        repo_cfg=RepoWorkflowConfig(),
    )
    assert "| toyscan | toyscan 1.0.0 / n/a | 1 | 0 | 1 | 0 |" in body
