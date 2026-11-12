"""Local sweep source: scanner findings -> Findings, de-duplicated, refreshed every sweep."""

from __future__ import annotations

import pytest

from ananke.scanners.base import ScanFinding, ScanReport
from ananke.sources.local_sweep import LocalSweepSource, findings_from_reports, infer_ecosystem

REPO = "RENCI/no-dependabot"


def sf(id_, pkg="requests", loc="uv.lock", fixed="2.32.0", aliases=(), kind="dependency"):
    return ScanFinding(id=id_, aliases=list(aliases), kind=kind, severity="high", package=pkg,
                       installed_version="2.25.1", fixed_version=fixed, location=loc)  # fmt: skip


@pytest.mark.parametrize(
    ("loc", "eco"),
    [("uv.lock", "pip"), ("svc/requirements-dev.txt", "pip"), ("requirements.in", "pip"),
     ("web/package-lock.json", "npm"), ("go.sum", "go"), ("Dockerfile", None), (None, None)],
)  # fmt: skip
def test_infer_ecosystem(loc, eco):
    assert infer_ecosystem(loc) == eco


def test_findings_are_fixable_dependency_findings_deduplicated_across_scanners():
    trivy = ScanReport(scanner="trivy", findings=[
        sf("CVE-2024-35195", aliases=["GHSA-9wx4-h78v-vm56"]),
        sf("CVE-2099-0001", fixed=None),                       # no fix: not dispatchable
        sf("aws-access-token", pkg=None, kind="secret"),       # not a dependency
    ])  # fmt: skip
    osv = ScanReport(scanner="osv", findings=[
        sf("CVE-2024-35195", aliases=["GHSA-9wx4-h78v-vm56", "PYSEC-2024-1"]),  # same as trivy's
        sf("GHSA-34jh-p97f-mpxf", pkg="urllib3", fixed="1.26.19"),
    ])  # fmt: skip
    gitleaks = ScanReport(scanner="gitleaks", findings=[sf("x")])
    out = findings_from_reports(REPO, [trivy, osv, gitleaks])
    assert [(f.source, f.package, f.advisory_ids[0]) for f in out] == [
        ("trivy", "requests", "CVE-2024-35195"),
        ("osv", "urllib3", "GHSA-34jh-p97f-mpxf"),
    ]
    assert out[0].ecosystem == "pip" and out[0].manifest_path == "uv.lock"
    assert out[1].url == "https://github.com/advisories/GHSA-34jh-p97f-mpxf"
    assert out[0].url == "https://osv.dev/vulnerability/CVE-2024-35195"
    assert len({f.key for f in out}) == 2


async def test_fetch_open_syncs_scans_and_closes(tmp_path):
    synced, closed = [], []

    class Sandbox:
        is_isolated = True

        def close(self):
            closed.append(True)

    class Scanner:
        name, kinds, ecosystems = "osv", frozenset({"dependency"}), frozenset({"pip"})

        def available(self, sandbox):
            return True

        def scan(self, sandbox, workspace, targets=None):
            return ScanReport(scanner="osv", findings=[sf("CVE-2024-35195")])

    source = LocalSweepSource(
        [Scanner()],
        workspace_for=lambda repo: tmp_path / repo.replace("/", "_"),
        sandbox_for=lambda path: Sandbox(),
        sync_repo=lambda repo, path: synced.append((repo, path.name)),
    )
    first = await source.fetch_open(REPO)
    await source.fetch_open(REPO)
    assert synced == [(REPO, "RENCI_no-dependabot")] * 2 and closed == [True, True]
    assert [f.package for f in first] == ["requests"]
    again = await source.fetch_by_keys([first[0].key, "other:osv:x"])
    assert [f.key for f in again] == [first[0].key]
