"""Per-item LangGraph pipeline (PLAN.md §3.3).

    prepare_workspace -> deterministic_fix -> verify --pass--> open_pr -> report
                                                 \\--fail--> agent --pass--> open_pr
                                                                  \\--fail--> report

All nodes except `agent` are deterministic. In M1 the agent node runs only with a scripted fake
model; without one it raises `LiveModelDisabled`, which ends the run as `verify_failed` with the
deterministic rung's evidence. Nothing is pushed and no PR is opened unless verify passed.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from ananke.config import AnankeConfig
from ananke.github.auth import GitHubAuth
from ananke.llm import LiveModelDisabled
from ananke.logging import get_logger
from ananke.model import Rung, RunOutcome, RunRecord, WorkItem
from ananke.orchestrator.store import RunStore
from ananke.scanners.base import ScanDelta, ScanReport, delta
from ananke.worker.agent import run_agent
from ananke.worker.fixers.base import result_for
from ananke.worker.sandbox import DockerSandbox, LocalSandbox, Sandbox
from ananke.worker.verify import VerifyResult, coverage_of, verify
from ananke.worker.workspace import Workspace, WorkspaceManager
from ananke.workflow import Workflow, load_workflow, render_pr_body, validate_workflow

log = get_logger(__name__)

SETUP_TIMEOUT_S = 1800
TEST_TIMEOUT_S = 1800
TAIL = 12000

# (item, base_branch, title, body, reviewers) -> (pr_number, pr_url)
PrOpener = Callable[[WorkItem, str, str, str, list[str]], tuple[int, str]]
SandboxFactory = Callable[[Path], Sandbox]


class RunState(TypedDict, total=False):
    item: WorkItem
    started_at: datetime
    workspace: Workspace
    workflow: Workflow
    before: dict[str, ScanReport]
    after: dict[str, ScanReport]
    deltas: dict[str, ScanDelta]
    fix: dict[str, Any]
    verify: VerifyResult
    rung: Rung
    agent_result: dict[str, Any] | None
    body: str
    run: RunRecord
    outcome: RunOutcome
    error: str
    pr_number: int
    pr_url: str


@dataclass
class RunContext:
    """Run-scoped dependencies. Nodes close over this; it also tracks resources for cleanup."""

    cfg: AnankeConfig
    clone_url: str
    scanners: list[Any]
    default_branch: str | None = None
    dry_run: bool = True
    fake_model: Path | str | None = None
    attempt: int = 1
    github_auth: GitHubAuth | None = None
    github_token: str | None = None
    pr_opener: PrOpener | None = None
    store: RunStore | None = None
    sandbox_factory: SandboxFactory | None = None
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    # filled in while the run executes
    workspace_manager: WorkspaceManager | None = None
    workspace: Workspace | None = None
    workflow: Workflow | None = None
    sandbox: Sandbox | None = None
    finished: bool = False


def make_sandbox(cfg: AnankeConfig, workspace: Path) -> Sandbox:
    """DockerSandbox, or the non-isolated LocalSandbox when `sandbox.allow_local` is set."""
    sc = cfg.sandbox
    if sc.allow_local:
        log.warning(
            "local_sandbox_enabled",
            path=workspace,
            warning="commands run on the host without isolation",
        )
        return LocalSandbox(workspace)
    return DockerSandbox(
        workspace,
        image=sc.image,
        network=sc.network,
        cpu=sc.cpu,
        memory=sc.memory,
        scanner_db_volume=sc.scanner_db_volume,
        allow_unrestricted_network=sc.allow_unrestricted_network,
    )


def scan_all(scanners: list[Any], sandbox: Sandbox, workspace: Path) -> dict[str, ScanReport]:
    """Run every enabled scanner over the whole workspace. A missing scanner is an error:
    proof of work must come from every enabled scanner."""
    reports: dict[str, ScanReport] = {}
    for scanner in scanners:
        if not scanner.available(sandbox):
            raise RuntimeError(f"enabled scanner {scanner.name!r} is not available in the sandbox")
        reports[scanner.name] = scanner.scan(sandbox, workspace)
    return reports


def _tail(text: str, n: int = TAIL) -> str:
    return text[-n:]


def evidence_of(state: RunState) -> dict[str, Any]:
    """RunRecord.evidence (PLAN.md §3.2) from whatever the run produced so far."""
    ev: dict[str, Any] = {
        "before": {n: r.model_dump(mode="json") for n, r in (state.get("before") or {}).items()},
        "after": {n: r.model_dump(mode="json") for n, r in (state.get("after") or {}).items()},
        "delta": {n: d.model_dump(mode="json") for n, d in (state.get("deltas") or {}).items()},
        "deterministic": state.get("fix") or {},
    }
    if state.get("verify") is not None:
        ev["verify"] = state["verify"].as_evidence()
    if state.get("agent_result"):
        ev["agent"] = state["agent_result"]
    if state.get("error"):
        ev["error"] = state["error"]
    return ev


def prior_failure_text(state: RunState) -> str:
    """What the deterministic rung tried and why verify failed, for the agent prompt."""
    fix = state.get("fix") or {}
    parts = [f"Deterministic rung: {fix.get('summary') or 'no change'}"]
    for err in fix.get("errors") or []:
        parts.append(f"Fixer error: {err}")
    result = state.get("verify")
    if result is not None:
        parts.append("Verify failures:")
        parts += [f"- {line}" for line in result.failures()]
        tail = (result.tests_stdout + "\n" + result.tests_stderr).strip()
        if tail:
            parts.append("Test output (tail):\n" + tail[-4000:])
    return "\n".join(parts)


def _default_pr_opener(ctx: RunContext) -> PrOpener:
    from ananke.github.client import GitHubClient
    from ananke.github.prs import PullRequestManager

    auth = ctx.github_auth
    if auth is None:
        raise RuntimeError("opening a pull request needs GitHub credentials")

    def open_pr(
        item: WorkItem, base: str, title: str, body: str, reviewers: list[str]
    ) -> tuple[int, str]:
        async def upsert() -> tuple[int, str]:
            async with GitHubClient(auth, api_url=ctx.cfg.github.api_url) as api:
                pr = await PullRequestManager(api).upsert(
                    item, base=base, title=title, body=body, reviewers=reviewers
                )
                return pr.number, pr.url

        return asyncio.run(upsert())

    return open_pr


def build_run_graph(ctx: RunContext):
    """Build and compile one item's graph. Nodes close over `ctx`."""
    coverage = coverage_of(ctx.scanners)

    def prepare(state: RunState) -> dict[str, Any]:
        item = state["item"]
        manager = WorkspaceManager(ctx.cfg.workspace.root, token=ctx.github_token)
        ctx.workspace_manager = manager
        workspace = manager.prepare(
            item, clone_url=ctx.clone_url, default_branch=ctx.default_branch
        )
        ctx.workspace = workspace
        factory = ctx.sandbox_factory or (lambda path: make_sandbox(ctx.cfg, path))
        sandbox = factory(workspace.path)
        ctx.sandbox = manager.sandbox = sandbox
        wf_path = workspace.path / "ANANKE.md"
        workflow = load_workflow(
            wf_path.read_text(encoding="utf-8") if wf_path.is_file() else None,
            source=f"{item.repo}:ANANKE.md",
            env={},  # repository-controlled text must never expand host environment values
        )
        validate_workflow(workflow)
        ctx.workflow = workflow
        hooks = workflow.config.hooks
        if workspace.created:
            manager.run_hook("after_create", hooks, workspace.path)
        manager.run_hook("before_run", hooks, workspace.path)
        setup_command = workflow.config.setup_command
        if setup_command:
            setup = sandbox.run(setup_command, cwd=workspace.path, timeout_s=SETUP_TIMEOUT_S)
            if not setup.ok:
                detail = (setup.stderr or setup.stdout)[-3000:]
                raise RuntimeError(f"setup_command failed (exit {setup.exit_code}): {detail}")
        before = scan_all(ctx.scanners, sandbox, workspace.path)
        log.info("run_prepared", item_key=item.key, run_id=ctx.run_id, path=workspace.path)
        return {
            "workspace": workspace,
            "workflow": workflow,
            "before": before,
            "rung": "deterministic",
        }

    def deterministic_fix(state: RunState) -> dict[str, Any]:
        item, workspace = state["item"], state["workspace"]
        sandbox = ctx.sandbox
        assert sandbox is not None
        ecosystems = sorted({f.ecosystem for f in item.findings if f.ecosystem})
        results = [result_for(item, eco, workspace.path, sandbox) for eco in ecosystems]
        changes = [c for r in results for c in r.changes]
        errors = [r.error for r in results if r.error]
        tests: dict[str, Any] = {"status": "not run", "tail": ""}
        command = state["workflow"].config.test_command
        if changes and command:
            res = sandbox.run(command, cwd=workspace.path, timeout_s=TEST_TIMEOUT_S)
            tests = {
                "status": "passed" if res.ok else "failed",
                "tail": _tail((res.stdout + "\n" + res.stderr).strip()),
            }
        fix = {
            "changed": bool(changes),
            "supported": bool(results) and all(r.supported for r in results),
            "changes": changes,
            "commands": [c for r in results for c in r.commands],
            "errors": errors,
            "summary": "; ".join(changes) if changes else "no deterministic change applied",
            "tests": tests,
        }
        log.info(
            "deterministic_fix_done", item_key=item.key, run_id=ctx.run_id, changed=bool(changes)
        )
        return {"fix": fix}

    def check(state: RunState, agent_result: dict[str, Any] | None) -> dict[str, Any]:
        item, workspace = state["item"], state["workspace"]
        sandbox = ctx.sandbox
        assert sandbox is not None
        after = scan_all(ctx.scanners, sandbox, workspace.path)
        before = state["before"]
        deltas = {
            name: delta(before[name], report) for name, report in after.items() if name in before
        }
        outcome = verify(
            item=item,
            workspace=workspace.path,
            sandbox=sandbox,
            base_ref=f"origin/{workspace.default_branch}",
            before=before,
            after=after,
            deltas=deltas,
            repo_config=state["workflow"].config,
            policy=ctx.cfg.policy,
            test_command=state["workflow"].config.test_command,
            coverage=coverage,
            max_db_age_days=ctx.cfg.scanners.max_db_age_days,
            result=(agent_result or {}).get("result"),
        )
        log.info(
            "verify_done",
            item_key=item.key,
            run_id=ctx.run_id,
            passed=outcome.passed,
            failed=[k for k, v in outcome.checks.items() if v.status == "failed"],
        )
        return {"after": after, "deltas": deltas, "verify": outcome}

    def verify_node(state: RunState) -> dict[str, Any]:
        return check(state, None)

    def agent(state: RunState) -> dict[str, Any]:
        item, workspace = state["item"], state["workspace"]
        try:
            result = run_agent(
                cfg=ctx.cfg,
                workflow=state["workflow"],
                item=item,
                workspace=workspace.path,
                sandbox=ctx.sandbox,  # type: ignore[arg-type]
                scanners=ctx.scanners,
                before=state["before"],
                fake_script=ctx.fake_model,
                attempt=ctx.attempt,
                prior_failure=prior_failure_text(state),
            )
        except LiveModelDisabled as exc:
            log.info("agent_rung_disabled", item_key=item.key, run_id=ctx.run_id)
            # The run ends with the deterministic rung's verdict (verify_failed or no_change).
            return {"error": f"agent rung not run: {exc}"}
        except Exception as exc:
            log.exception("agent_failed", item_key=item.key, run_id=ctx.run_id)
            return {
                "rung": "agent",
                "outcome": "agent_failed",
                "error": f"{type(exc).__name__}: {exc}",
            }
        if result.get("result") is None:
            return {
                "rung": "agent",
                "agent_result": result,
                "outcome": "agent_failed",
                "error": "the agent ended without calling report_result",
            }
        return {"rung": "agent", "agent_result": result, **check(state, result)}

    def route_after_verify(state: RunState) -> Literal["open_pr", "agent"]:
        return "open_pr" if state["verify"].passed else "agent"

    def route_after_agent(state: RunState) -> Literal["open_pr", "report"]:
        if state.get("outcome") or state.get("rung") != "agent":
            return "report"
        return "open_pr" if state["verify"].passed else "report"

    def open_pr(state: RunState) -> dict[str, Any]:
        item, workspace = state["item"], state["workspace"]
        manager = ctx.workspace_manager
        assert manager is not None
        run = RunRecord(
            run_id=ctx.run_id,
            item_key=item.key,
            attempt=ctx.attempt,
            started_at=state["started_at"],
            rung=state.get("rung", "deterministic"),
            evidence=evidence_of(state),
        )
        agent_report = (state.get("agent_result") or {}).get("result")
        body = render_pr_body(
            item=item,
            result=agent_report,
            evidence=run.evidence,
            run=run,
            repo_cfg=state["workflow"].config,
            db_warnings=state["verify"].db_warnings,
        )
        where = item.manifest_path or item.repo
        title = f"fix(security): patch {len(item.findings)} finding(s) in {where}"
        manager.commit_changes(workspace, message=f"{title}\n\nAnanke run {ctx.run_id}")
        if ctx.dry_run:
            return {"body": body, "run": run, "outcome": "dry_run"}
        opener = ctx.pr_opener or _default_pr_opener(ctx)  # fail before pushing, not after
        if ctx.github_auth is not None:
            manager.token = asyncio.run(ctx.github_auth.token())
        manager.push(workspace)
        number, url = opener(
            item, workspace.default_branch, title, body, state["workflow"].config.reviewers
        )
        run.pr_number = number
        log.info("pr_opened", item_key=item.key, run_id=ctx.run_id, pr=number, url=url)
        return {
            "body": body,
            "run": run,
            "outcome": "pr_opened",
            "pr_number": number,
            "pr_url": url,
        }

    def report(state: RunState) -> dict[str, Any]:
        error = state.get("error", "")
        problems = _finish(ctx)
        if problems:
            error = "; ".join([e for e in (error, *problems) if e])
        result = state.get("verify")
        diff_check = result.checks.get("diff_nonempty") if result is not None else None
        outcome: RunOutcome
        if state.get("outcome"):
            outcome = state["outcome"]
        elif diff_check is not None and diff_check.status == "failed":
            outcome = "no_change"
        else:
            outcome = "verify_failed"
        run = state.get("run") or RunRecord(
            run_id=ctx.run_id,
            item_key=state["item"].key,
            attempt=ctx.attempt,
            started_at=state["started_at"],
            rung=state.get("rung", "deterministic"),
            evidence=evidence_of({**state, "error": error}),
        )
        if error and "error" not in run.evidence:
            run.evidence["error"] = error
        run.outcome = outcome
        run.ended_at = datetime.now(UTC)
        if ctx.store is not None:
            ctx.store.record(run)
        log.info("run_finished", item_key=run.item_key, run_id=ctx.run_id, outcome=outcome)
        update: dict[str, Any] = {"run": run, "outcome": outcome}
        if error:
            update["error"] = error
        return update

    graph = StateGraph(RunState)
    graph.add_node("prepare_workspace", prepare)
    graph.add_node("deterministic_fix", deterministic_fix)
    graph.add_node("verify", verify_node)
    graph.add_node("agent", agent)
    graph.add_node("open_pr", open_pr)
    graph.add_node("report", report)
    graph.add_edge(START, "prepare_workspace")
    graph.add_edge("prepare_workspace", "deterministic_fix")
    graph.add_edge("deterministic_fix", "verify")
    graph.add_conditional_edges(
        "verify", route_after_verify, {"open_pr": "open_pr", "agent": "agent"}
    )
    graph.add_conditional_edges(
        "agent", route_after_agent, {"open_pr": "open_pr", "report": "report"}
    )
    graph.add_edge("open_pr", "report")
    graph.add_edge("report", END)
    return graph.compile()


def _finish(ctx: RunContext) -> list[str]:
    """Run the after_run hook and stop the sandbox, once. Returns problems instead of raising."""
    if ctx.finished:
        return []
    ctx.finished = True
    problems: list[str] = []
    if ctx.workspace_manager and ctx.workspace and ctx.workflow:
        try:
            ctx.workspace_manager.finish(ctx.workspace, ctx.workflow.config.hooks)
        except Exception as exc:
            log.warning("after_run_hook_failed", error=str(exc))
            problems.append(f"after_run hook: {exc}")
    close = getattr(ctx.sandbox, "close", None)
    if close is not None:
        try:
            close()
        except Exception as exc:
            log.warning("sandbox_cleanup_failed", error=str(exc))
            problems.append(f"sandbox cleanup: {exc}")
    return problems


def run_item(ctx: RunContext, item: WorkItem) -> RunState:
    """Execute one item's graph synchronously.

    Exceptions (clone failure, setup failure, scanner failure, push failure) are re-raised after
    cleanup and an `error` RunRecord is written to the store. They never open a PR.
    """
    started = datetime.now(UTC)
    graph = build_run_graph(ctx)
    try:
        return graph.invoke({"item": item, "started_at": started})
    except Exception as exc:
        problems = _finish(ctx)
        if ctx.store is not None:
            run = RunRecord(
                run_id=ctx.run_id,
                item_key=item.key,
                attempt=ctx.attempt,
                started_at=started,
                ended_at=datetime.now(UTC),
                outcome="error",
                evidence={"error": "; ".join([f"{type(exc).__name__}: {exc}", *problems])},
            )
            ctx.store.record(run)
        log.warning("run_error", item_key=item.key, run_id=ctx.run_id, error=str(exc))
        raise
