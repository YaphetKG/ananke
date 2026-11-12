"""Scanner protocol and normalized scan types (PLAN.md §3.5).

`ScanFinding`, `ScanReport`, `ScanDelta` are the only types the verify node and PR template
consume, so no scanner-specific logic leaks past a scanner's own module.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from ananke.model import Severity

if TYPE_CHECKING:
    from ananke.worker.sandbox import Sandbox

ScanKind = Literal["dependency", "container", "iac", "secret", "sast"]


class ScanFinding(BaseModel):
    id: str  # CVE preferred, else GHSA / rule id; other ids go in `aliases`
    aliases: list[str] = Field(default_factory=list)
    kind: ScanKind
    severity: Severity = "unknown"
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    location: str | None = None  # manifest path, Dockerfile line, file:line
    title: str = ""

    @property
    def all_ids(self) -> frozenset[str]:
        """id plus aliases, case-normalized (upper) for matching."""
        return frozenset(i.strip().upper() for i in [self.id, *self.aliases] if i and i.strip())

    def same_as(self, other: ScanFinding) -> bool:
        """Identity: any id/alias in common AND same package AND same location."""
        return (
            self.package == other.package
            and self.location == other.location
            and not self.all_ids.isdisjoint(other.all_ids)
        )


class ScanReport(BaseModel):
    scanner: str
    scanner_version: str = "unknown"
    db_version: str | None = None
    ran_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    targets: list[str] = Field(default_factory=list)
    findings: list[ScanFinding] = Field(default_factory=list)
    raw_path: str = ""  # raw JSON kept on disk under the run directory for audit


class ScanDelta(BaseModel):
    """Before vs after for one scanner.

    resolved: before-findings with no match after. remaining: after-findings that match a
    before-finding. introduced: after-findings with no match before.
    """

    resolved: list[ScanFinding] = Field(default_factory=list)
    remaining: list[ScanFinding] = Field(default_factory=list)
    introduced: list[ScanFinding] = Field(default_factory=list)


class ScannerVersion(BaseModel):
    tool_version: str
    db_version: str | None = None
    db_updated_at: datetime | None = None


@runtime_checkable
class Scanner(Protocol):
    name: str
    kinds: frozenset[ScanKind]
    ecosystems: frozenset[str]  # {"pip", "npm", ...} or {"*"}

    def available(self, sandbox: Sandbox) -> bool: ...

    def version(self, sandbox: Sandbox) -> ScannerVersion: ...

    def scan(
        self, sandbox: Sandbox, workspace: Path, targets: list[Path] | None = None
    ) -> ScanReport: ...

    def parse(self, raw: str) -> ScanReport: ...


def _matches_any(f: ScanFinding, pool: list[ScanFinding]) -> bool:
    return any(f.same_as(o) for o in pool)


def delta(before: ScanReport, after: ScanReport) -> ScanDelta:
    """Pure before/after comparison; identity = (id or any alias, package, location)."""
    return ScanDelta(
        resolved=[f for f in before.findings if not _matches_any(f, after.findings)],
        remaining=[f for f in after.findings if _matches_any(f, before.findings)],
        introduced=[f for f in after.findings if not _matches_any(f, before.findings)],
    )
