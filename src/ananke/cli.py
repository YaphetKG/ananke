"""Ananke command-line interface (typer): validate | scan | scanners | run | daemon | status."""

from __future__ import annotations

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


@app.command()
def run() -> None:
    """Run one work item end to end (M1)."""
    _not_implemented("run")


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
