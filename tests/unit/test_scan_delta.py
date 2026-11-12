from __future__ import annotations

from ananke.scanners.base import ScanFinding, Scanner, ScannerVersion, ScanReport, delta


def sf(id_: str, aliases=(), package="requests", location="requirements.txt", **kw) -> ScanFinding:
    return ScanFinding(
        id=id_, aliases=list(aliases), kind="dependency", package=package, location=location, **kw
    )


def report(*findings: ScanFinding) -> ScanReport:
    return ScanReport(scanner="t", scanner_version="1", findings=list(findings))


def test_resolved_remaining_introduced():
    a, b, c = sf("CVE-1"), sf("CVE-2"), sf("CVE-3")
    d = delta(report(a, b), report(b, c))
    assert [f.id for f in d.resolved] == ["CVE-1"]
    assert [f.id for f in d.remaining] == ["CVE-2"]
    assert [f.id for f in d.introduced] == ["CVE-3"]


def test_ghsa_cve_alias_matching_both_directions():
    before = sf("CVE-2024-1", aliases=["GHSA-xxxx-yyyy-zzzz"])
    after = sf("GHSA-xxxx-yyyy-zzzz")
    d = delta(report(before), report(after))
    assert d.resolved == [] and d.introduced == [] and len(d.remaining) == 1
    d2 = delta(report(after), report(before))
    assert d2.resolved == [] and d2.introduced == []


def test_alias_match_is_case_insensitive():
    d = delta(report(sf("ghsa-abcd")), report(sf("GHSA-ABCD")))
    assert d.introduced == [] and d.resolved == []


def test_package_or_location_mismatch_is_different_finding():
    d = delta(report(sf("CVE-1")), report(sf("CVE-1", package="urllib3")))
    assert len(d.resolved) == 1 and len(d.introduced) == 1
    d = delta(report(sf("CVE-1")), report(sf("CVE-1", location="sub/requirements.txt")))
    assert len(d.resolved) == 1 and len(d.introduced) == 1


def test_none_package_and_location_match_each_other():
    s = ScanFinding(id="aws-key", kind="secret", location=None)
    d = delta(report(s), report(s))
    assert len(d.remaining) == 1


def test_empty_reports():
    d = delta(report(), report())
    assert d.resolved == d.remaining == d.introduced == []
    d = delta(report(sf("CVE-1")), report())
    assert len(d.resolved) == 1


def test_scanner_protocol_runtime_check():
    class Toy:
        name = "toy"
        kinds = frozenset({"dependency"})
        ecosystems = frozenset({"*"})

        def available(self, sandbox):
            return True

        def version(self, sandbox):
            return ScannerVersion(tool_version="0")

        def scan(self, sandbox, workspace, targets=None):
            return report()

        def parse(self, raw):
            return report()

    assert isinstance(Toy(), Scanner)
