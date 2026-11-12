"""gitleaks scanner plugin (PLAN.md §3.5): `gitleaks dir --report-format json`; parse() is pure.

Command (exit 0 = clean, exit 1 = leaks found; both are success):

    gitleaks dir <path> --report-format json --report-path <raw_dir>/<file>.json
        --no-banner --exit-code 1 [--config <config>]

Redaction rule: the `Secret` and `Match` fields of a gitleaks finding are NEVER copied into a
ScanFinding (nor logged). Only the rule id, description, file:line and the fingerprint are kept.
The raw report on disk does contain the secret; it lives in raw_dir, outside the workspace.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

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

BINARY = "gitleaks"
DEFAULT_TIMEOUT_S = 900
SUCCESS_EXIT_CODES = frozenset({0, 1})  # 1 = leaks found (we pass --exit-code 1)


def parse_version_output(text: str) -> ScannerVersion:
    """Parse `gitleaks --version` ('8.30.1', 'v8.30.1' or 'gitleaks version 8.30.1')."""
    return ScannerVersion(tool_version=_first_version(text) or "unknown")


class GitleaksScanner:
    name = "gitleaks"
    kinds: frozenset[ScanKind] = frozenset({"secret"})
    ecosystems = frozenset({"*"})

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

    def command(self, path: Path, report_path: Path) -> list[str]:
        cmd = [
            BINARY,
            "dir",
            str(path),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--no-banner",
            "--exit-code",
            "1",
        ]
        if self.options.get("config"):
            cmd += ["--config", str(self.options["config"])]
        return cmd

    def _run_one(self, sandbox: Sandbox, workspace: Path, path: Path) -> tuple[Path, str]:
        raw_path = _raw_path(self.raw_dir, self.name)
        _check_raw_dir(raw_path.parent, workspace, self.name)
        timeout = self.options.get("timeout_s", DEFAULT_TIMEOUT_S)
        isolated = bool(getattr(sandbox, "is_isolated", False))
        report_path = (
            Path("/tmp") / f"ananke-gitleaks-{uuid.uuid4().hex}.json" if isolated else raw_path
        )
        res = sandbox.run(self.command(path, report_path), cwd=workspace, timeout_s=timeout)
        if res.exit_code not in SUCCESS_EXIT_CODES:
            raise ScannerError(
                self.name, f"exit {res.exit_code}: {_tail(res.stderr)}", exit_code=res.exit_code
            )
        if isolated:
            copy_file = getattr(sandbox, "copy_file_from", None)
            if copy_file is None:
                raise ScannerError(self.name, "isolated sandbox cannot retrieve the raw report")
            try:
                copy_file(report_path, raw_path)
            finally:
                sandbox.run(["rm", "-f", str(report_path)], cwd=workspace, timeout_s=30)
        if not raw_path.is_file():
            raise ScannerError(self.name, f"no report written to {raw_path}")
        return raw_path, raw_path.read_text(encoding="utf-8")

    def scan(
        self, sandbox: Sandbox, workspace: Path, targets: list[Path] | None = None
    ) -> ScanReport:
        paths = [Path(t) for t in targets] if targets else [Path(workspace)]
        findings: list[ScanFinding] = []
        raw_paths: list[Path] = []
        for p in paths:
            rp, raw = self._run_one(sandbox, workspace, p)
            raw_paths.append(rp)
            try:
                findings += self.parse(raw, workspace=workspace).findings
            except json.JSONDecodeError as exc:
                raise ScannerError(self.name, f"unparseable report {rp}: {exc}") from exc
        ver = self.version(sandbox)
        return ScanReport(
            scanner=self.name,
            scanner_version=ver.tool_version,
            db_version=ver.db_version,
            targets=[str(p) for p in paths],
            findings=findings,
            raw_path=",".join(str(p) for p in raw_paths),
        )

    def parse(self, raw: str, *, workspace: Path | None = None) -> ScanReport:
        """Pure. Never copies `Secret` or `Match`. `workspace` relativizes absolute paths."""
        data = json.loads(raw) if raw and raw.strip() else []
        if not isinstance(data, list):
            data = []
        findings: list[ScanFinding] = []
        for leak in data:
            if not isinstance(leak, dict) or not leak.get("RuleID"):
                continue
            file = _relativize(leak.get("File"), workspace)
            line = leak.get("StartLine")
            fingerprint = _relativize_fingerprint(leak.get("Fingerprint"), leak.get("File"), file)
            if any(s and s in fingerprint for s in (leak.get("Secret"), leak.get("Match"))):
                fingerprint = ""  # defensive: never let the secret ride along in an alias
            findings.append(
                ScanFinding(
                    id=leak["RuleID"],
                    aliases=[fingerprint] if fingerprint else [],
                    kind="secret",
                    severity="high",
                    package=None,
                    location=f"{file}:{line}" if file and line else file,
                    title=leak.get("Description") or leak["RuleID"],
                )
            )
        return ScanReport(scanner=self.name, findings=findings)


def _relativize_fingerprint(fp: str | None, raw_file: str | None, rel_file: str | None) -> str:
    """Fingerprint is '[commit:]file:rule:line'; rewrite the file part like the location."""
    if not fp:
        return ""
    if raw_file and rel_file and raw_file != rel_file and raw_file in fp:
        return fp.replace(raw_file, rel_file, 1)
    return fp
