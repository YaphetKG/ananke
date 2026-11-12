"""Ananke command-line interface (typer): validate | scan | scanners | run | daemon | status."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ananke.config import AnankeConfig, ConfigError, load_config

app = typer.Typer(
    name="ananke",
    help="Ananke: turn security findings into mergeable PRs with proof of work.",
    no_args_is_help=True,
    add_completion=False,
)

NOT_IMPLEMENTED_EXIT = 2

ConfigOption = typer.Option(
    Path("ananke.yaml"), "--config", "-c", help="Path to ananke.yaml.", dir_okay=False
)

FixturesOption = typer.Option(
    None,
    "--fixtures",
    help="Read recorded Dependabot alerts from DIR/dependabot_alerts/open.json for every "
    "configured repo instead of calling GitHub (no credentials needed).",
    file_okay=False,
)


FakeModelOption = typer.Option(
    None, "--fake-model", help="Drive the agent rung with a scripted fake model (offline)."
)

RunFixturesOption = typer.Option(
    None,
    "--fixtures",
    help="Read Dependabot alerts from DIR/dependabot_alerts/open.json instead of GitHub.",
    file_okay=False,
)


def _not_implemented(command: str) -> None:
    typer.echo(f"ananke {command}: not implemented in this milestone", err=True)
    raise typer.Exit(NOT_IMPLEMENTED_EXIT)


def _console() -> Console:
    # Wide tables when piped / captured so rows don't wrap mid-word.
    return Console(width=None if sys.stdout.isatty() else 200)


def _load(config: Path) -> AnankeConfig:
    """load_config with CLI error reporting (exit 1); prints unknown-key warnings."""
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        typer.echo(f"config not found: {config}", err=True)
        raise typer.Exit(1) from None
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from None
    for key in cfg.unknown_keys:
        typer.echo(f"warning: unknown key ignored: {key}", err=True)
    return cfg


@app.command()
def validate(config: Path = ConfigOption) -> None:
    """Load and validate ananke.yaml and the default ANANKE.md template."""
    from ananke.workflow import WorkflowError, load_workflow, validate_workflow

    cfg = _load(config)
    try:
        wf = load_workflow(None)
        validate_workflow(wf)
    except WorkflowError as exc:
        typer.echo(f"default workflow template invalid: {exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"OK {cfg.path}")
    typer.echo(f"workflow template OK: {wf.source}")
    typer.echo(f"repos: {len(cfg.repos)}")
    enabled = cfg.scanners.enabled
    typer.echo(f"enabled scanners: {len(enabled)} ({', '.join(enabled) or 'none'})")


@app.command()
def scan(
    config: Path = ConfigOption,
    fixtures: Path | None = FixturesOption,
    as_json: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
    show_all: bool = typer.Option(False, "--all", help="Also list findings dropped by policy."),
) -> None:
    """List open findings grouped into work items and triaged (read-only)."""
    from ananke.orchestrator.scan import ScanSetupError, render, run_scan, to_json

    cfg = _load(config)
    try:
        result = run_scan(cfg, fixtures=fixtures)
    except ScanSetupError as exc:
        typer.echo(f"ananke scan: {exc}", err=True)
        raise typer.Exit(1) from None
    for repo, message in result.errors.items():
        typer.echo(f"error: {repo}: {message}", err=True)
    if as_json:
        typer.echo(json.dumps(to_json(result), indent=2))
    else:
        render(result, _console().print, show_dropped=show_all)
    raise typer.Exit(0 if result.ok else 1)


@app.command()
def scanners(config: Path = ConfigOption) -> None:
    """List registered scanners (built-in and entry points) and whether each binary is present."""
    from ananke.scanners import register_builtin, registry
    from ananke.worker.sandbox import LocalSandbox

    cfg = _load(config)
    register_builtin(cfg.scanners)
    registry.load_entry_points()
    sandbox = LocalSandbox(Path.cwd())  # probe only: runs `<binary> --version` on this host
    enabled = cfg.scanners.enabled
    table = Table(title="Scanners")
    for col in ("name", "kinds", "ecosystems", "enabled", "available", "version"):
        table.add_column(col)
    for s in registry.all_scanners():
        available = bool(s.available(sandbox))
        version = ""
        if available:
            v = s.version(sandbox)
            version = v.tool_version + (f" (db {v.db_version})" if v.db_version else "")
        table.add_row(
            s.name,
            ", ".join(sorted(s.kinds)),
            ", ".join(sorted(s.ecosystems)),
            str(s.name in enabled),
            str(available),
            version,
        )
    _console().print(table)
    known = {s.name for s in registry.all_scanners()}
    missing = [n for n in enabled if n not in known]
    if missing:
        typer.echo(f"error: scanners.enabled names unregistered scanner(s): {missing}", err=True)
        raise typer.Exit(1)


def _find_item(items: list, item_key: str):
    return next(
        (i for i in items if i.key == item_key or i.branch.removeprefix("ananke/") == item_key),
        None,
    )


@app.command()
def run(
    item_key: str,
    config: Path = ConfigOption,
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Patch and verify locally, print the PR body, push nothing."
    ),
    yes: bool = typer.Option(False, "--yes", help="Confirm pushing the branch and opening the PR."),
    fake_model: Path | None = FakeModelOption,
    fixtures: Path | None = RunFixturesOption,
    clone_url: str | None = typer.Option(
        None, "--clone-url", help="Clone from this URL or path instead of the GitHub repo."
    ),
    default_branch: str | None = typer.Option(
        None, "--default-branch", help="Base branch (default: the repo's default branch)."
    ),
) -> None:
    """Run one work item: deterministic fix, verify, then (if it passes) branch + PR."""
    if not dry_run and not yes:
        typer.echo("writing a branch and pull request requires --yes (or use --dry-run)", err=True)
        raise typer.Exit(2)
    if fixtures is not None and clone_url is None:
        typer.echo("--fixtures needs --clone-url (there is no GitHub repo to clone)", err=True)
        raise typer.Exit(2)
    from ananke.orchestrator.store import RunStore
    from ananke.scanners import build_scanners, default_raw_dir
    from ananke.worker.graph import RunContext, run_item

    cfg = _load(config)
    try:
        if fixtures is not None:
            item, url, branch, auth, token = _item_from_fixtures(cfg, fixtures, item_key)
        else:
            item, url, branch, auth, token = asyncio.run(_item_from_github(cfg, item_key))
        ctx = RunContext(
            cfg=cfg,
            clone_url=clone_url or url,
            default_branch=default_branch or branch,
            scanners=build_scanners(cfg.scanners, raw_dir=default_raw_dir()),
            dry_run=dry_run,
            fake_model=fake_model,
            github_auth=auth,
            github_token=token,
            store=RunStore.for_config(cfg),
        )
        result = run_item(ctx, item)
    except Exception as exc:
        typer.echo(f"ananke run: {exc}", err=True)
        raise typer.Exit(1) from None
    outcome = result.get("outcome", "error")
    if result.get("body"):
        typer.echo(result["body"])
    verify = result.get("verify")
    if verify is not None and not verify.passed:
        typer.echo("verify failed:", err=True)
        for line in verify.failures():
            typer.echo(f"  {line}", err=True)
    if result.get("error"):
        typer.echo(f"error: {result['error']}", err=True)
    typer.echo(
        f"outcome={outcome} item={item.key} run={ctx.run_id} pr={result.get('pr_number', '-')}"
    )
    raise typer.Exit(0 if outcome in ("pr_opened", "dry_run") else 1)


def _item_from_fixtures(cfg: AnankeConfig, fixtures: Path, item_key: str):
    from ananke.orchestrator.scan import load_fixture_findings
    from ananke.orchestrator.triage import triage

    findings, errors = load_fixture_findings(cfg, fixtures)
    if errors:
        raise ValueError("; ".join(f"{repo}: {msg}" for repo, msg in errors.items()))
    item = _find_item(triage(findings, cfg, pulls_by_repo={}).items, item_key)
    if item is None:
        raise ValueError(f"work item not found or not eligible: {item_key}")
    return item, "", None, None, None


async def _item_from_github(cfg: AnankeConfig, item_key: str):
    from ananke.github.auth import GitHubAuth
    from ananke.github.client import GitHubClient
    from ananke.orchestrator.scan import fetch_ananke_pulls
    from ananke.orchestrator.triage import triage
    from ananke.sources.github_dependabot import DependabotSource

    if "github_dependabot" not in cfg.sources:
        raise ValueError("ananke run needs github_dependabot in sources (or use --fixtures)")
    auth = GitHubAuth.from_config(cfg.github)
    async with GitHubClient(auth, api_url=cfg.github.api_url) as client:
        source = DependabotSource(client)
        findings, pulls_by_repo, repo_info = [], {}, {}
        for repo in cfg.repos:
            findings.extend(await source.fetch_open(repo))
            pulls_by_repo[repo] = await fetch_ananke_pulls(client, repo)
            repo_info[repo] = await client.get(f"/repos/{repo}")
        item = _find_item(triage(findings, cfg, pulls_by_repo=pulls_by_repo).items, item_key)
        if item is None:
            raise ValueError(f"work item not found or not eligible: {item_key}")
        info = repo_info[item.repo]
        url = str(info.get("clone_url") or f"https://github.com/{item.repo}.git")
        branch = str(info.get("default_branch") or "") or None
        return item, url, branch, auth, await auth.token()


@app.command()
def daemon() -> None:
    """Run the polling daemon (M3)."""
    _not_implemented("daemon")


@app.command()
def status() -> None:
    """Show daemon / run status (M3)."""
    _not_implemented("status")


if __name__ == "__main__":  # pragma: no cover
    app()
