"""M1 acceptance (PLAN.md §10): the full run graph in a real DockerSandbox with the real scanners
against tests/fixtures/repos/py-vulnerable, with a local bare git remote standing in for GitHub.

Needs a Docker daemon and the worker image (build it with
`docker build -f docker/worker.Dockerfile -t ghcr.io/renci/ananke-worker:latest .`, or point
ANANKE_WORKER_IMAGE at another tag). The container uses Docker's unrestricted bridge network so
`uv sync` / `uv lock` can reach PyPI; production configs must use a restricted network.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ananke.config import load_config
from ananke.model import Finding, WorkItem
from ananke.orchestrator.store import RunStore
from ananke.scanners import build_scanners
from ananke.worker.graph import RunContext, run_item

pytestmark = pytest.mark.docker

IMAGE = os.environ.get("ANANKE_WORKER_IMAGE", "ghcr.io/renci/ananke-worker:latest")
FIXTURE_REPO = Path(__file__).parents[1] / "fixtures" / "repos" / "py-vulnerable"
REPO = "RENCI/py-vulnerable"
# (package, GHSA, CVE, fixed_version): the advisories in tests/fixtures/scanner_output/README.md
ADVISORIES = [
    ("requests", "GHSA-j8r2-6x86-q33q", "CVE-2023-32681", "2.31.0"),
    ("requests", "GHSA-9wx4-h78v-vm56", "CVE-2024-35195", "2.32.0"),
    ("urllib3", "GHSA-v845-jxx5-vc9f", "CVE-2023-43804", "1.26.17"),
    ("urllib3", "GHSA-g4mx-q9vg-27p4", "CVE-2023-45803", "1.26.18"),
    ("urllib3", "GHSA-34jh-p97f-mpxf", "CVE-2024-37891", "1.26.19"),
]


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip


@pytest.fixture(scope="module", autouse=True)
def _image_present():
    probe = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True)
    if probe.returncode != 0:
        pytest.skip(f"worker image {IMAGE} not built")


@pytest.fixture
def origin(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO, src)
    _git(src, "init", "-q", "-b", "main")
    _git(src, "add", "-A")
    _git(src, "commit", "-q", "-m", "fixture")
    bare = tmp_path / "origin.git"
    _git(tmp_path, "clone", "-q", "--bare", str(src), str(bare))
    return bare


def _item() -> WorkItem:
    findings = [
        Finding(
            key=Finding.make_key(REPO, "github_dependabot", str(n)),
            repo=REPO,
            source="github_dependabot",
            source_id=str(n),
            severity="high",
            advisory_ids=[ghsa, cve],
            url=f"https://github.com/advisories/{ghsa}",
            ecosystem="pip",
            package=pkg,
            manifest_path="uv.lock",
            fixed_version=fixed,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        for n, (pkg, ghsa, cve, fixed) in enumerate(ADVISORIES, 1)
    ]
    return WorkItem.from_findings(REPO, "uv.lock", findings)


def test_full_graph_in_docker(tmp_path: Path, origin: Path):
    cfg_path = tmp_path / "ananke.yaml"
    cfg_path.write_text(
        f"repos: [{REPO}]\n"
        "workspace:\n  root: ws\n"
        f"sandbox:\n  image: {IMAGE}\n  network: bridge\n  allow_unrestricted_network: true\n"
        "  scanner_db_volume: no-such-volume\n"
        "scanners:\n  enabled: [trivy, osv, gitleaks]\n"
    )
    cfg = load_config(cfg_path)
    raw = tmp_path / "raw"
    raw.mkdir()
    opened: list[tuple[str, str]] = []

    def opener(item, base, title, body, reviewers):
        opened.append((base, body))
        return 1, "https://github.invalid/pull/1"

    ctx = RunContext(
        cfg=cfg,
        clone_url=str(origin),
        scanners=build_scanners(cfg.scanners, raw_dir=raw),
        dry_run=False,
        pr_opener=opener,
        store=RunStore(tmp_path / "runs.sqlite3"),
    )
    item = _item()
    state = run_item(ctx, item)

    assert state["verify"].passed, state["verify"].failures()
    assert state["outcome"] == "pr_opened" and state["rung"] == "deterministic"
    pyproject = _git(origin, "show", f"{item.branch}:pyproject.toml")
    assert '"requests==2.32.0"' in pyproject and '"urllib3==1.26.19"' in pyproject

    for name in ("trivy", "osv"):
        before = {i for f in state["before"][name].findings for i in f.all_ids}
        after = {i for f in state["after"][name].findings for i in f.all_ids}
        assert "CVE-2024-35195" in before, f"{name} did not report the fixture CVE before"
        assert "CVE-2024-35195" not in after, f"{name} still reports the fixture CVE after"

    (base, body) = opened[0]
    assert base == "main"
    for name in ("trivy", "osv", "gitleaks"):
        row = next(line for line in body.splitlines() if line.startswith(f"| {name} |"))
        assert "unknown /" not in row, row  # tool version recorded
    trivy_row = next(line for line in body.splitlines() if line.startswith("| trivy |"))
    assert "/ n/a |" not in trivy_row  # Trivy DB version recorded

    leftover = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=ananke-"], capture_output=True, text=True
    ).stdout.split()
    assert leftover == [], "run left a container behind"
