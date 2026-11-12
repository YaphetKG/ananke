"""Load a repo's ANANKE.md and strict-render its Jinja2 prompt body (PLAN.md §2.2, §4, §6, §7.2).

- `load_workflow(text)` parses front matter via `config.parse_repo_workflow` (unknown keys are
  ignored there) and compiles the body; `None`/empty text falls back to
  `templates/ANANKE.default.md`.
- Rendering uses `StrictUndefined`: an unknown variable or filter raises `WorkflowRenderError`
  (Symphony: strict rendering fails the run before dispatch). `validate_workflow` renders
  against a synthetic WorkItem so dispatch preflight can reject a bad template.
- `WorkflowCache` re-parses a repo's ANANKE.md when its text changes and keeps the last known
  good Workflow when the new text is broken (Symphony: dynamic reload, keep last good).
- `render_pr_body` / `render_failure_issue` render `templates/pr_body.md.j2` and
  `templates/failure_issue.md.j2` with the same strict environment.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import jinja2
from pydantic import BaseModel

from ananke.config import ConfigError, RepoWorkflowConfig, parse_repo_workflow
from ananke.logging import get_logger
from ananke.model import Finding, RunRecord, WorkItem

log = get_logger(__name__)

# src/ananke/workflow.py -> repo root / templates
TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"
DEFAULT_WORKFLOW_PATH = TEMPLATES_DIR / "ANANKE.default.md"
PR_BODY_TEMPLATE = "pr_body.md.j2"
FAILURE_ISSUE_TEMPLATE = "failure_issue.md.j2"
RETRY_LABEL = "ananke:retry"


class WorkflowError(Exception):
    """ANANKE.md could not be loaded (bad front matter, bad template syntax)."""


class WorkflowRenderError(WorkflowError):
    """A template failed strict rendering (unknown variable or filter, syntax error)."""


@dataclass
class Workflow:
    config: RepoWorkflowConfig
    body: str
    source: str
    loaded_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------------------------
# Jinja environment and filters


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def md_cell(value: Any) -> str:
    """Make a value safe for one markdown table cell: None -> 'n/a', escape pipes/newlines."""
    if value is None or value == "":
        return "n/a"
    if isinstance(value, list | tuple):
        value = ", ".join(str(v) for v in value) or "n/a"
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def severity_badge(severity: Any) -> str:
    """critical/high in bold caps so they stand out; others as plain lower-case text."""
    sev = str(severity or "unknown").lower()
    return f"**{sev.upper()}**" if sev in ("critical", "high") else sev


def findings_table(findings: Iterable[Finding | Mapping[str, Any]]) -> str:
    """Markdown table: Advisory | Package | Installed/Vulnerable range | Fixed in | Severity | Link.

    Accepts Finding models or plain dicts with the same keys.
    """
    lines = [
        "| Advisory | Package | Installed/Vulnerable range | Fixed in | Severity | Link |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        ids = _get(f, "advisory_ids") or [_get(f, "source_id")]
        url = _get(f, "url")
        link = f"[{md_cell(_get(f, 'source'))}]({url})" if url else "n/a"
        raw = _get(f, "raw") or {}
        installed = raw.get("installed_version") if isinstance(raw, Mapping) else None
        rng = _get(f, "vulnerable_range")
        cell = f"{installed} ({rng})" if installed and rng else (installed or rng)
        lines.append(
            "| "
            + " | ".join(
                [
                    md_cell(ids),
                    md_cell(_get(f, "package")),
                    md_cell(cell),
                    md_cell(_get(f, "fixed_version")),
                    severity_badge(_get(f, "severity")),
                    link,
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def make_environment() -> jinja2.Environment:
    """Strict environment shared by prompt, PR body and failure-issue rendering."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        undefined=jinja2.StrictUndefined,
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["findings_table"] = findings_table
    env.filters["severity_badge"] = severity_badge
    env.filters["md_cell"] = md_cell
    return env


@lru_cache(maxsize=1)
def _env() -> jinja2.Environment:
    return make_environment()


def _compile(body: str, source: str) -> jinja2.Template:
    try:
        return _env().from_string(body)
    except jinja2.TemplateError as exc:
        raise WorkflowRenderError(f"{source}: {type(exc).__name__}: {exc}") from exc


def _render(template: jinja2.Template, context: dict[str, Any], source: str) -> str:
    try:
        return template.render(**context)
    except jinja2.TemplateError as exc:  # UndefinedError, TemplateRuntimeError (filters), ...
        raise WorkflowRenderError(f"{source}: {type(exc).__name__}: {exc}") from exc


def _render_file(name: str, context: dict[str, Any]) -> str:
    try:
        template = _env().get_template(name)
    except jinja2.TemplateError as exc:
        raise WorkflowRenderError(f"{name}: {type(exc).__name__}: {exc}") from exc
    return _render(template, context, name)


# ---------------------------------------------------------------------------------------------
# Loading


def default_workflow_text() -> str:
    """Contents of `templates/ANANKE.default.md`."""
    return DEFAULT_WORKFLOW_PATH.read_text(encoding="utf-8")


def load_workflow(
    text: str | None, *, source: str = "ANANKE.md", env: dict[str, str] | None = None
) -> Workflow:
    """Parse ANANKE.md text (None/blank -> the default template) and compile its body.

    Raises WorkflowError for bad front matter, WorkflowRenderError for bad template syntax.
    """
    if text is None or not text.strip():
        text, source = default_workflow_text(), str(DEFAULT_WORKFLOW_PATH)
    try:
        cfg, body = parse_repo_workflow(text, source=source, env=env)
    except ConfigError as exc:
        raise WorkflowError(str(exc)) from exc
    _compile(body, source)  # syntax / unknown-filter errors surface at load time
    return Workflow(config=cfg, body=body, source=source, loaded_at=datetime.now(UTC))


def render_prompt(
    workflow: Workflow,
    *,
    item: WorkItem,
    repo: str,
    attempt: int | None = None,
    prior_failure: str | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Render the ANANKE.md body. Context: item, repo, attempt, prior_failure, workflow
    (the RepoWorkflowConfig), findings (= item.findings), plus any `extra` keys."""
    context: dict[str, Any] = {
        **(extra or {}),
        "item": item,
        "repo": repo,
        "attempt": attempt,
        "prior_failure": prior_failure,
        "workflow": workflow.config,
        "findings": item.findings,
    }
    return _render(_compile(workflow.body, workflow.source), context, workflow.source)


def synthetic_item(repo: str = "example/repo") -> WorkItem:
    """A one-finding WorkItem used to dry-render templates."""
    finding = Finding(
        key=Finding.make_key(repo, "github_dependabot", "1"),
        repo=repo,
        source="github_dependabot",
        source_id="1",
        severity="high",
        advisory_ids=["GHSA-xxxx-xxxx-xxxx", "CVE-2000-0001"],
        summary="Synthetic finding for template validation",
        url="https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
        ecosystem="pip",
        package="example-package",
        manifest_path="requirements.txt",
        vulnerable_range="< 1.2.3",
        fixed_version="1.2.3",
        state="open",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return WorkItem.from_findings(repo, "requirements.txt", [finding])


def validate_workflow(workflow: Workflow) -> None:
    """Render the body against a synthetic item, both without and with attempt/prior_failure,
    so both branches of `{% if prior_failure %}` are checked. Raises WorkflowRenderError."""
    item = synthetic_item()
    render_prompt(workflow, item=item, repo=item.repo)
    render_prompt(
        workflow, item=item, repo=item.repo, attempt=2, prior_failure="synthetic failure output"
    )


# ---------------------------------------------------------------------------------------------
# Reload cache


@dataclass
class _CacheEntry:
    text: str | None
    workflow: Workflow
    failed_text: str | None = None
    has_failed: bool = False


class WorkflowCache:
    """Per-repo ANANKE.md cache: re-parse on change, keep the last good Workflow on error."""

    def __init__(self, *, env: dict[str, str] | None = None) -> None:
        self._env = env
        self._entries: dict[str, _CacheEntry] = {}

    def get(self, repo: str, fetch_text: Callable[[], str | None]) -> Workflow:
        """Return the current Workflow for `repo`.

        `fetch_text()` returns the ANANKE.md text (None if the repo has none -> default). If the
        text is unchanged the cached Workflow is returned. If the new text fails to fetch, parse
        or validate, the last good Workflow is returned and `workflow_reload_failed` is logged
        (once per distinct broken text); with no last good Workflow the error propagates.
        """
        entry = self._entries.get(repo)
        try:
            text = fetch_text()
        except Exception as exc:
            if entry is None:
                raise
            log.warning("workflow_reload_failed", repo=repo, error=f"fetch: {exc}")
            return entry.workflow
        if entry is not None:
            if text == entry.text:
                return entry.workflow
            if entry.has_failed and text == entry.failed_text:
                return entry.workflow
        try:
            wf = load_workflow(text, source=f"{repo}:ANANKE.md", env=self._env)
            validate_workflow(wf)
        except WorkflowError as exc:
            if entry is None:
                raise
            log.warning("workflow_reload_failed", repo=repo, error=str(exc))
            entry.failed_text, entry.has_failed = text, True
            return entry.workflow
        if entry is not None:
            log.info("workflow_reloaded", repo=repo, source=wf.source)
        self._entries[repo] = _CacheEntry(text=text, workflow=wf)
        return wf

    def invalidate(self, repo: str) -> None:
        self._entries.pop(repo, None)


# ---------------------------------------------------------------------------------------------
# PR body and failure issue


def _plain(value: Any) -> Any:
    """Recursively turn pydantic models into plain dicts/lists (JSON-mode not needed)."""
    if isinstance(value, BaseModel):
        return _plain(value.model_dump())
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


_EMPTY_REPORT = {"scanner_version": "unknown", "db_version": None, "findings": []}
_EMPTY_DELTA = {"resolved": [], "remaining": [], "introduced": []}


def normalize_evidence(evidence: Mapping[str, Any] | None) -> dict[str, Any]:
    """Fill defaults so the strict templates never hit a missing key.

    Every scanner named in before/after/delta gets a before, after and delta entry (empty
    report / delta when absent, ordered as delta, then after, then before). verify.tests gets
    {status: "not run", tail: ""}; verify.diff_size gets {lines: 0, files: 0}.
    """
    ev = _plain(dict(evidence or {}))
    before = dict(ev.get("before") or {})
    after = dict(ev.get("after") or {})
    delta = dict(ev.get("delta") or {})
    names = list(dict.fromkeys([*delta, *after, *before]))
    ev["before"] = {n: {**_EMPTY_REPORT, "scanner": n, **(before.get(n) or {})} for n in names}
    ev["after"] = {n: {**_EMPTY_REPORT, "scanner": n, **(after.get(n) or {})} for n in names}
    ev["delta"] = {n: {**_EMPTY_DELTA, **(delta.get(n) or {})} for n in names}
    verify = dict(ev.get("verify") or {})
    verify["tests"] = {"status": "not run", "tail": "", **(verify.get("tests") or {})}
    verify["diff_size"] = {"lines": 0, "files": 0, **(verify.get("diff_size") or {})}
    ev["verify"] = verify
    ev["deterministic"] = dict(ev.get("deterministic") or {})
    ev["release_notes"] = list(ev.get("release_notes") or [])
    return ev


def _deterministic_result(det: Mapping[str, Any]) -> dict[str, Any]:
    changes = list(det.get("changes") or [])
    summary = det.get("summary") or (
        "Deterministic dependency bump (no agent): pinned each vulnerable package to its "
        "advisory's fixed version and regenerated the lockfile."
    )
    return {
        "status": det.get("status", "patched"),
        "summary": summary,
        "changes": changes,
        "risk_notes": det.get("risk_notes")
        or "Version bump only; no application code was changed. Review the release notes below "
        "for breaking changes.",
        "tests": det.get("tests", ""),
    }


def _normalize_result(result: Mapping[str, Any] | None, ev: Mapping[str, Any]) -> dict[str, Any]:
    if result is None:
        return _deterministic_result(ev["deterministic"])
    r = _plain(dict(result))
    return {
        "status": r.get("status", "patched"),
        "summary": r.get("summary") or "",
        "changes": list(r.get("changes") or []),
        "risk_notes": r.get("risk_notes") or "None reported.",
        "tests": r.get("tests") or "",
    }


def _verify_rows(verify: Mapping[str, Any]) -> list[dict[str, str]]:
    rows = []
    for name, v in verify.items():
        if not isinstance(v, Mapping):
            rows.append({"name": name, "status": md_cell(v), "detail": ""})
            continue
        detail = v.get("detail") or v.get("reason") or v.get("message") or ""
        if not detail and name == "diff_size":
            detail = f"{v.get('lines', 0)} lines / {v.get('files', 0)} files"
        rows.append(
            {
                "name": name,
                "status": md_cell(v.get("status", "n/a")),
                "detail": md_cell(detail) if detail else "",
            }
        )
    return rows


def render_pr_body(
    *,
    item: WorkItem,
    result: Mapping[str, Any] | None,
    evidence: Mapping[str, Any],
    run: RunRecord,
    repo_cfg: RepoWorkflowConfig,
    db_warnings: list[str] | None = None,
) -> str:
    """Render templates/pr_body.md.j2 (PLAN.md §6).

    `result` is the agent's report_result args (status, summary, changes, risk_notes, tests),
    or None for the deterministic rung, in which case the summary comes from
    evidence["deterministic"]. ScanReport/ScanDelta values may be models or dicts.
    """
    ev = normalize_evidence(evidence)
    context = {
        "item": item,
        "result": _normalize_result(result, ev),
        "deterministic": result is None,
        "evidence": ev,
        "run": run,
        "repo_cfg": repo_cfg,
        "db_warnings": list(db_warnings or []),
    }
    return _render_file(PR_BODY_TEMPLATE, context)


def render_failure_issue(
    *,
    item: WorkItem,
    run: RunRecord,
    evidence: Mapping[str, Any],
    attempts: int,
    error: str,
    runs: list[RunRecord] | None = None,
) -> str:
    """Render templates/failure_issue.md.j2: the body of the issue opened after max_attempts.

    `runs` (optional) lists every attempt so the issue can show the rung history; when omitted
    only `run` (the last attempt) is shown.
    """
    ev = normalize_evidence(evidence)
    context = {
        "item": item,
        "run": run,
        "runs": list(runs or [run]),
        "evidence": ev,
        "attempts": attempts,
        "error": error,
        "verify_rows": _verify_rows(_plain(dict((evidence or {}).get("verify") or {}))),
        "retry_label": RETRY_LABEL,
    }
    return _render_file(FAILURE_ISSUE_TEMPLATE, context)
