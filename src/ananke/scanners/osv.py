"""OSV-Scanner plugin (PLAN.md §3.5): `osv-scanner scan --format json`; parse() is pure.

Command (exit 0 = clean, exit 1 = vulnerabilities found; both are success):

    osv-scanner scan --format json [--offline] -r <workspace>
    osv-scanner scan --format json [--offline] --lockfile <t1> [--lockfile <t2> ...]

Mapping: one finding per (source, package, advisory group). OSV lists the same advisory once per
database (GHSA-..., PYSEC-...); records whose ids/aliases overlap are merged into one finding
whose id is the CVE alias when there is one, and whose aliases hold every other id.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from ananke.model import Severity, max_severity, normalize_severity
from ananke.scanners import (
    ScannerError,
    _binary_available,
    _check_raw_dir,
    _first_version,
    _raw_path,
    _relativize,
    _run,
    _tail,
)
from ananke.scanners.base import ScanFinding, ScanKind, ScannerVersion, ScanReport
from ananke.worker.sandbox import Sandbox

BINARY = "osv-scanner"
DEFAULT_TIMEOUT_S = 1800
SUCCESS_EXIT_CODES = frozenset({0, 1})  # 1 = vulnerabilities found

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_TOOL_VERSION_RE = re.compile(r"osv-scanner version:\s*v?(\S+)", re.IGNORECASE)


def cvss_score_severity(score: str | float | None) -> Severity:
    """CVSS base score -> severity bucket (critical>=9, high>=7, medium>=4, low>0)."""
    try:
        s = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "unknown"


def parse_version_output(text: str) -> ScannerVersion:
    """Parse `osv-scanner --version` ('osv-scanner version: 2.7.1\\ncommit: ...')."""
    m = _TOOL_VERSION_RE.search(text or "")
    tool = m.group(1) if m else (_first_version(text) or "unknown")
    return ScannerVersion(tool_version=tool)


def _vkey(v: str) -> tuple[int, Any]:
    try:
        return (1, Version(v))
    except InvalidVersion:
        return (0, v)


def _version_lt(a: str, b: str) -> bool:
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        return a < b


def _fixed_version(records: list[dict[str, Any]], pkg: dict[str, Any]) -> str | None:
    """Smallest `fixed` event (above the installed version when comparable) among affected[]
    entries for this package and ecosystem. GIT ranges (commit hashes) are ignored."""
    name, eco, installed = pkg.get("name"), pkg.get("ecosystem"), pkg.get("version")
    fixes: set[str] = set()
    for rec in records:
        for aff in rec.get("affected") or []:
            ap = aff.get("package") or {}
            if ap.get("name") != name or (eco and ap.get("ecosystem") != eco):
                continue
            for rng in aff.get("ranges") or []:
                if (rng.get("type") or "").upper() == "GIT":
                    continue
                fixes.update(e["fixed"] for e in rng.get("events") or [] if e.get("fixed"))
    if not fixes:
        return None
    if installed:
        above = [f for f in fixes if _version_lt(installed, f)]
        if above:
            fixes = set(above)
    return min(fixes, key=_vkey)


def _group_records(vulns: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Merge OSV records whose id/alias sets overlap (GHSA + PYSEC for the same CVE)."""
    groups: list[tuple[set[str], list[dict[str, Any]]]] = []
    for rec in vulns:
        ids = {rec["id"], *(rec.get("aliases") or [])}
        hits = [g for g in groups if g[0] & ids]
        merged_ids, merged_recs = set(ids), [rec]
        for g in hits:
            merged_ids |= g[0]
            merged_recs = g[1] + merged_recs
            groups.remove(g)
        groups.append((merged_ids, merged_recs))
    return [recs for _, recs in groups]


def _primary_id(ids: set[str], records: list[dict[str, Any]]) -> str:
    cves = sorted(i for i in ids if _CVE_RE.match(i))
    if cves:
        return cves[0]
    ghsa = sorted(r["id"] for r in records if r["id"].upper().startswith("GHSA-"))
    return ghsa[0] if ghsa else records[0]["id"]


class OsvScanner:
    name = "osv"
    kinds: frozenset[ScanKind] = frozenset({"dependency"})
    ecosystems = frozenset(
        {"pip", "npm", "go", "cargo", "maven", "gradle", "nuget", "rubygems", "composer", "pub"}
    )

    def __init__(self, options: dict[str, Any] | None = None, *, raw_dir: Path | None = None):
        self.options: dict[str, Any] = dict(options or {})
        self.raw_dir = Path(raw_dir) if raw_dir is not None else None

    def available(self, sandbox: Sandbox) -> bool:
        return _binary_available(sandbox, BINARY)

    def version(self, sandbox: Sandbox) -> ScannerVersion:
        res = _run(sandbox, [BINARY, "--version"], timeout_s=60)
        if res is None or not res.ok:
            return ScannerVersion(tool_version="unknown")
        return parse_version_output(res.stdout or res.stderr)

    def command(self, workspace: Path, targets: list[Path] | None = None) -> list[str]:
        cmd = [BINARY, "scan", "--format", "json"]
        if self.options.get("offline", True):
            cmd.append("--offline")
        if targets:
            for t in targets:
                cmd += ["--lockfile", str(t)]
        else:
            cmd += ["-r", str(workspace)]
        return cmd

    def scan(
        self, sandbox: Sandbox, workspace: Path, targets: list[Path] | None = None
    ) -> ScanReport:
        raw_path = _raw_path(self.raw_dir, self.name)
        _check_raw_dir(raw_path.parent, workspace, self.name)
        timeout = self.options.get("timeout_s", DEFAULT_TIMEOUT_S)
        res = sandbox.run(self.command(workspace, targets), cwd=workspace, timeout_s=timeout)
        raw_path.write_text(res.stdout or "", encoding="utf-8")
        if res.exit_code not in SUCCESS_EXIT_CODES:
            raise ScannerError(
                self.name, f"exit {res.exit_code}: {_tail(res.stderr)}", exit_code=res.exit_code
            )
        try:
            report = self.parse(res.stdout, workspace=workspace)
        except json.JSONDecodeError as exc:
            raise ScannerError(self.name, f"unparseable JSON output: {exc}") from exc
        ver = self.version(sandbox)
        report.scanner_version = ver.tool_version
        report.db_version = ver.db_version
        report.raw_path = str(raw_path)
        report.targets = [str(t) for t in targets] if targets else [str(workspace)]
        return report

    def parse(self, raw: str, *, workspace: Path | None = None) -> ScanReport:
        """Pure. `workspace` (optional) makes absolute `source.path`s workspace-relative."""
        data = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(data, dict):
            data = {}
        findings: list[ScanFinding] = []
        sources: list[str] = []
        for result in data.get("results") or []:
            src = result.get("source") or {}
            location = _relativize(src.get("path"), workspace)
            if location:
                sources.append(location)
            for pkg_entry in result.get("packages") or []:
                findings += _package_findings(pkg_entry, location)
        return ScanReport(scanner=self.name, targets=sources, findings=findings)


def _package_findings(entry: dict[str, Any], location: str | None) -> list[ScanFinding]:
    pkg = entry.get("package") or {}
    vulns = [v for v in entry.get("vulnerabilities") or [] if v.get("id")]
    osv_groups = entry.get("groups") or []
    out: list[ScanFinding] = []
    for records in _group_records(vulns):
        ids: set[str] = set()
        for r in records:
            ids |= {r["id"], *(r.get("aliases") or [])}
        severity: Severity = "unknown"
        for g in osv_groups:
            if ids & {*(g.get("ids") or []), *(g.get("aliases") or [])}:
                severity = max_severity([severity, cvss_score_severity(g.get("max_severity"))])
        if severity == "unknown":
            severity = max_severity(
                normalize_severity((r.get("database_specific") or {}).get("severity"))
                for r in records
            )
        primary = _primary_id(ids, records)
        title = next((r["summary"] for r in records if r.get("summary")), "") or primary
        out.append(
            ScanFinding(
                id=primary,
                aliases=sorted(ids - {primary}),
                kind="dependency",
                severity=severity,
                package=pkg.get("name"),
                installed_version=pkg.get("version"),
                fixed_version=_fixed_version(records, pkg),
                location=location,
                title=title,
            )
        )
    return out
