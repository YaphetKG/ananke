"""Workspace-scoped tools exposed to the Deep Agent. They never receive GitHub credentials."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from langchain_core.tools import tool

from ananke.scanners.base import ScanReport, delta
from ananke.worker.sandbox import Sandbox

_DENIED = re.compile(
    r"\b(?:sudo|git\s+push|git\s+remote)\b"
    r"|\b(?:curl|wget)\b[^\n]*(?:\|\s*(?:sh|bash)\b|&&\s*(?:sh|bash)\b)",
    re.IGNORECASE,
)
_OUTPUT_LIMIT = 32_000
_ADVISORY_ID = re.compile(r"^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9][A-Za-z0-9._:-]{1,80}$")
_PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]{0,213}$")
MAX_COMMAND_TIMEOUT_S = 1800


@dataclass
class ToolContext:
    workspace: Path
    sandbox: Sandbox
    scanners: list[Any] = field(default_factory=list)
    before: dict[str, ScanReport] = field(default_factory=dict)
    report: dict[str, Any] | None = None
    deltas: dict[str, Any] = field(default_factory=dict)


def _tail(text: str) -> str:
    return text if len(text) <= _OUTPUT_LIMIT else "[truncated]\n" + text[-_OUTPUT_LIMIT:]


def build_tools(context: ToolContext) -> list[Any]:
    """Build tool closures for one isolated run."""

    @tool
    def run_command(cmd: str, timeout_s: int = 600) -> str:
        """Run a shell command inside the run container, in the checked-out repository."""
        if _DENIED.search(cmd):
            return (
                "Command denied by Ananke: this tool cannot use sudo, git push, git remote, "
                "or pipe a download into a shell."
            )
        timeout = min(max(int(timeout_s), 1), MAX_COMMAND_TIMEOUT_S)
        result = context.sandbox.run(cmd, cwd=context.workspace, timeout_s=timeout)
        return json.dumps(
            {
                "exit_code": result.exit_code,
                "stdout_tail": _tail(result.stdout),
                "stderr_tail": _tail(result.stderr),
            }
        )

    @tool
    def advisory_details(advisory_id: str) -> str:
        """Fetch public advisory details from OSV by CVE, GHSA, or OSV id."""
        if not _ADVISORY_ID.match(advisory_id):
            return f"Invalid advisory id {advisory_id!r}; expected e.g. CVE-2024-1234 or GHSA-..."
        try:
            response = httpx.get(
                f"https://api.osv.dev/v1/vulns/{advisory_id}", timeout=20, follow_redirects=False
            )
            if response.status_code != 200:
                return f"No OSV record for {advisory_id} (HTTP {response.status_code})."
            return _tail(json.dumps(response.json(), indent=2))
        except httpx.HTTPError as exc:
            return f"Advisory lookup failed ({type(exc).__name__})."

    @tool
    def package_release_notes(ecosystem: str, name: str, from_version: str, to_version: str) -> str:
        """Fetch package metadata from the ecosystem registry; returns safe public metadata."""
        del from_version, to_version
        if not _PACKAGE_NAME.match(name):
            return f"Invalid package name {name!r}."
        try:
            if ecosystem == "pip":
                url = f"https://pypi.org/pypi/{name}/json"
            elif ecosystem == "npm":
                url = f"https://registry.npmjs.org/{name.replace('/', '%2f')}"
            else:
                return f"Release-note lookup is not configured for ecosystem {ecosystem!r}."
            response = httpx.get(url, timeout=20, follow_redirects=False)
            if response.status_code != 200:
                return f"Package metadata unavailable for {name} (HTTP {response.status_code})."
            data = response.json()
            if ecosystem == "pip":
                info = data.get("info") or {}
                summary = {
                    "name": name,
                    "version": info.get("version"),
                    "project_urls": info.get("project_urls"),
                    "description": (info.get("description") or "")[:12000],
                }
            else:
                summary = {
                    "name": data.get("name"),
                    "version": (data.get("dist-tags") or {}).get("latest"),
                    "repository": data.get("repository"),
                    "homepage": data.get("homepage"),
                }
            return _tail(json.dumps(summary, indent=2))
        except (httpx.HTTPError, ValueError) as exc:
            return f"Package metadata lookup failed ({type(exc).__name__})."

    @tool
    def scan_workspace() -> str:
        """Run enabled scanners against this workspace and report before/after deltas."""
        deltas: dict[str, Any] = {}
        after: dict[str, ScanReport] = {}
        for scanner in context.scanners:
            if not scanner.available(context.sandbox):
                continue
            try:
                report = scanner.scan(context.sandbox, context.workspace)
            except Exception as exc:  # report the failure to the agent instead of aborting
                deltas[scanner.name] = {"error": f"{type(exc).__name__}: {exc}"[:2000]}
                continue
            after[scanner.name] = report
            if scanner.name in context.before:
                deltas[scanner.name] = delta(context.before[scanner.name], report)
        context.deltas = deltas
        return json.dumps(
            {n: d if isinstance(d, dict) else d.model_dump(mode="json") for n, d in deltas.items()},
            indent=2,
        )

    @tool
    def report_result(
        status: str, summary: str, changes: list[str], risk_notes: str, tests: str
    ) -> str:
        """Report the patch result once after editing, testing, and scanning."""
        if status not in {"patched", "partial", "blocked"}:
            return "Invalid status. Use patched, partial, or blocked."
        if context.report is not None:
            return "A result was already recorded for this run."
        context.report = {
            "status": status,
            "summary": summary,
            "changes": list(changes),
            "risk_notes": risk_notes,
            "tests": tests,
        }
        return (
            "Result recorded. The independent verification gate will decide whether a PR can open."
        )

    return [run_command, advisory_details, package_release_notes, scan_workspace, report_result]
