"""Ananke command-line interface (typer): validate | scan | scanners | run | daemon | status."""

from __future__ import annotations

from pathlib import Path

import typer

from ananke.config import ConfigError, load_config

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


def _not_implemented(command: str) -> None:
    typer.echo(f"ananke {command}: not implemented in this milestone", err=True)
    raise typer.Exit(NOT_IMPLEMENTED_EXIT)


@app.command()
def validate(config: Path = ConfigOption) -> None:
    """Load and validate ananke.yaml; print OK or the validation errors."""
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
    typer.echo(f"OK {cfg.path}")


@app.command()
def scan() -> None:
    """List open findings, grouped and triaged (M0)."""
    _not_implemented("scan")


@app.command()
def scanners() -> None:
    """List registered scanners and whether each binary is present (M0)."""
    _not_implemented("scanners")


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
