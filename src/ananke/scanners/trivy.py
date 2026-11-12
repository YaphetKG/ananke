"""Trivy scanner plugin (PLAN.md §3.5): `trivy fs --format json`; parse() is pure.

Command (exit 0 = success; Trivy exits 0 even when it finds vulnerabilities):

    trivy fs --scanners vuln,misconfig,secret --format json [--ignore-unfixed]
        --skip-db-update [--cache-dir <cache_dir>] <workspace>

Mapping: `Results[].Vulnerabilities` -> kind "dependency" (id = VulnerabilityID, usually the
CVE; aliases = VendorIDs, usually the GHSA); `Results[].Misconfigurations` -> kind "iac";
`Results[].Secrets` -> kind "secret" (the matched text is never copied).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ananke.model import normalize_severity
from ananke.scanners import (
    ScannerError,
    _binary_available,
    _check_raw_dir,
    _raw_path,
    _run,
    _tail,
)
from ananke.scanners.base import ScanFinding, ScanKind, ScannerVersion, ScanReport
from ananke.worker.sandbox import Sandbox

BINARY = "trivy"
DEFAULT_TIMEOUT_S = 1800

_DEPENDENCY_CLASSES = {"lang-pkgs", "os-pkgs"}
_TOOL_VERSION_RE = re.compile(r"^Version:\s*v?(\S+)", re.MULTILINE)
_DB_BLOCK_RE = re.compile(r"^Vulnerability DB:\s*\n((?:[ \t]+.*\n?)*)", re.MULTILINE)


def _parse_trivy_time(value: str) -> datetime | None:
    """Parse Go's time.String() form, e.g. '2026-11-12 06:13:54.123456789 +0000 UTC'."""
    v = value.strip()
    v = re.sub(r"\s+[A-Z]{2,5}$", "", v)  # trailing zone abbreviation ("UTC")
    v = re.sub(r"(\.\d{6})\d+", r"\1", v)  # Go nanoseconds -> microseconds
    for fmt in ("%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def parse_version_output(text: str) -> ScannerVersion:
    """Parse `trivy --version` output (tool version, vulnerability DB version + UpdatedAt)."""
    m = _TOOL_VERSION_RE.search(text or "")
    tool = m.group(1) if m else "unknown"
    db_version: str | None = None
    db_updated: datetime | None = None
    block = _DB_BLOCK_RE.search(text or "")
    if block:
        for line in block.group(1).splitlines():
            key, _, val = line.strip().partition(":")
            if key == "Version" and val.strip():
                db_version = val.strip()
            elif key == "UpdatedAt" and val.strip():
                db_updated = _parse_trivy_time(val)
    return ScannerVersion(tool_version=tool, db_version=db_version, db_updated_at=db_updated)


class TrivyScanner:
    name = "trivy"
    kinds: frozenset[ScanKind] = frozenset({"dependency", "container", "iac", "secret"})
    ecosystems = frozenset({"*"})

    def __init__(self, options: dict[str, Any] | None = None, *, raw_dir: Path | None = None):
        self.options: dict[str, Any] = dict(options or {})
        self.raw_dir = Path(raw_dir) if raw_dir is not None else None

    # -- binary probes -----------------------------------------------------------------------

    def available(self, sandbox: Sandbox) -> bool:
        return _binary_available(sandbox, BINARY)

    def version(self, sandbox: Sandbox) -> ScannerVersion:
        res = _run(sandbox, [BINARY, "--version"], timeout_s=60)
        if res is None or not res.ok:
            return ScannerVersion(tool_version="unknown")
        return parse_version_output(res.stdout or res.stderr)

    # -- scanning ----------------------------------------------------------------------------

    def command(self, workspace: Path) -> list[str]:
        scanners = self.options.get("scanners") or ["vuln", "misconfig", "secret"]
        cmd = [BINARY, "fs", "--scanners", ",".join(scanners), "--format", "json"]
        if self.options.get("ignore_unfixed", True):
            cmd.append("--ignore-unfixed")
        cmd.append("--skip-db-update")
        if self.options.get("cache_dir"):
            cmd += ["--cache-dir", str(self.options["cache_dir"])]
        cmd.append(str(workspace))
        return cmd

    def scan(
        self, sandbox: Sandbox, workspace: Path, targets: list[Path] | None = None
    ) -> ScanReport:
        """Scan the whole workspace; with `targets`, keep only findings located in them."""
        raw_path = _raw_path(self.raw_dir, self.name)
        _check_raw_dir(raw_path.parent, workspace, self.name)
        timeout = self.options.get("timeout_s", DEFAULT_TIMEOUT_S)
        res = sandbox.run(self.command(workspace), cwd=workspace, timeout_s=timeout)
        raw_path.write_text(res.stdout or "", encoding="utf-8")
        if res.exit_code != 0:
            raise ScannerError(
                self.name, f"exit {res.exit_code}: {_tail(res.stderr)}", exit_code=res.exit_code
            )
        report = self.parse(res.stdout)
        ver = self.version(sandbox)
        report.scanner_version = ver.tool_version
        report.db_version = ver.db_version
        report.raw_path = str(raw_path)
        if targets:
            wanted = [_rel_target(t, workspace) for t in targets]
            report.findings = [f for f in report.findings if _in_targets(f.location, wanted)]
            report.targets = wanted
        else:
            report.targets = [str(workspace)]
        return report

    # -- parsing (pure) ----------------------------------------------------------------------

    def parse(self, raw: str) -> ScanReport:
        data = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(data, dict):
            data = {}
        findings: list[ScanFinding] = []
        for result in data.get("Results") or []:
            findings += _result_findings(result)
        tool = (data.get("Trivy") or {}).get("Version") or "unknown"
        artifact = data.get("ArtifactName")
        return ScanReport(
            scanner=self.name,
            scanner_version=tool,
            targets=[artifact] if artifact else [],
            findings=findings,
        )


def _result_findings(result: dict[str, Any]) -> list[ScanFinding]:
    target = result.get("Target") or None
    cls = result.get("Class") or ""
    out: list[ScanFinding] = []
    for v in result.get("Vulnerabilities") or []:
        vid = v.get("VulnerabilityID")
        if not vid:
            continue
        out.append(
            ScanFinding(
                id=vid,
                aliases=[a for a in v.get("VendorIDs") or [] if a and a != vid],
                kind="dependency" if cls in _DEPENDENCY_CLASSES or not cls else "container",
                severity=normalize_severity((v.get("Severity") or "").lower()),
                package=v.get("PkgName"),
                installed_version=v.get("InstalledVersion") or None,
                fixed_version=v.get("FixedVersion") or None,
                location=target,
                title=v.get("Title") or (v.get("Description") or "")[:200] or vid,
            )
        )
    for m in result.get("Misconfigurations") or []:
        if (m.get("Status") or "FAIL").upper() != "FAIL":
            continue
        mid = m.get("ID") or m.get("AVDID")
        if not mid:
            continue
        line = (m.get("CauseMetadata") or {}).get("StartLine")
        aliases = [a for a in [m.get("AVDID")] if a and a != mid]
        out.append(
            ScanFinding(
                id=mid,
                aliases=aliases,
                kind="iac",
                severity=normalize_severity((m.get("Severity") or "").lower()),
                location=f"{target}:{line}" if target and line else target,
                title=m.get("Title") or mid,
            )
        )
    for s in result.get("Secrets") or []:
        rid = s.get("RuleID")
        if not rid:
            continue
        line = s.get("StartLine")
        out.append(  # never copy Match / Code: they contain the secret
            ScanFinding(
                id=rid,
                kind="secret",
                severity=normalize_severity((s.get("Severity") or "").lower()),
                location=f"{target}:{line}" if target and line else target,
                title=s.get("Title") or rid,
            )
        )
    return out


def _rel_target(target: Path, workspace: Path) -> str:
    t = Path(target)
    if t.is_absolute():
        try:
            return t.relative_to(workspace).as_posix()
        except ValueError:
            return t.as_posix()
    return t.as_posix()


def _in_targets(location: str | None, wanted: list[str]) -> bool:
    if not location:
        return False
    path = location.rsplit(":", 1)[0] if re.search(r":\d+$", location) else location
    return any(path == w or path.startswith(w.rstrip("/") + "/") for w in wanted)
