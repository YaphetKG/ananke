"""Local scanner plugins (discover + attest), PLAN.md §3.5.

Built-in scanners: `trivy`, `osv`, `gitleaks`. Each is a class taking `options` (from
`ScannersConfig.options_for(name)`) and an optional `raw_dir` where raw tool output is kept for
audit. `build_scanners(cfg)` returns the enabled scanners in config order. See docs/SCANNERS.md.

Built-in modules are imported lazily inside the functions below so that they can import the
shared helpers defined here without a circular import.
"""

from __future__ import annotations

import re
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ananke.config import ScannersConfig
    from ananke.scanners.base import Scanner
    from ananke.worker.sandbox import CommandResult, Sandbox

__all__ = [
    "BUILTIN",
    "ScannerError",
    "build_scanners",
    "default_raw_dir",
    "register_builtin",
]

BUILTIN: tuple[str, ...] = ("trivy", "osv", "gitleaks")

_DEFAULT_RAW_DIR: Path | None = None
_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z.\-]+)?)")


class ScannerError(RuntimeError):
    """A scanner binary ran but did not produce a usable report (bad exit code / bad JSON)."""

    def __init__(self, scanner: str, message: str, *, exit_code: int | None = None) -> None:
        self.scanner = scanner
        self.exit_code = exit_code
        super().__init__(f"{scanner}: {message}")


def default_raw_dir() -> Path:
    """Per-process temp directory for raw scanner output (never inside a workspace)."""
    global _DEFAULT_RAW_DIR
    if _DEFAULT_RAW_DIR is None or not _DEFAULT_RAW_DIR.is_dir():
        _DEFAULT_RAW_DIR = Path(tempfile.mkdtemp(prefix="ananke-scans-"))
    return _DEFAULT_RAW_DIR


# ---------------------------------------------------------------------------------------------
# helpers shared by the built-in scanner modules (not part of the plugin contract)


def _raw_path(raw_dir: Path | None, scanner: str, suffix: str = "json") -> Path:
    """A fresh, unique file path under raw_dir for one scan's raw output."""
    base = Path(raw_dir) if raw_dir is not None else default_raw_dir()
    base.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    return base / f"{scanner}-{stamp}-{uuid.uuid4().hex[:8]}.{suffix}"


def _check_raw_dir(raw_dir: Path, workspace: Path, scanner: str) -> None:
    """Refuse a raw_dir inside the workspace: raw reports would pollute the diff."""
    try:
        Path(raw_dir).resolve().relative_to(Path(workspace).resolve())
    except ValueError:
        return
    raise ScannerError(scanner, f"raw_dir {raw_dir} is inside the workspace {workspace}")


def _run(sandbox: Sandbox, cmd: list[str], **kwargs: Any) -> CommandResult | None:
    """sandbox.run that never raises (returns None on an exception from the sandbox)."""
    try:
        return sandbox.run(cmd, **kwargs)
    except Exception:  # a broken sandbox means "not available", never a crash
        return None


def _binary_available(sandbox: Sandbox, binary: str) -> bool:
    res = _run(sandbox, [binary, "--version"], timeout_s=30)
    return res is not None and res.exit_code == 0


def _first_version(text: str) -> str | None:
    m = _VERSION_RE.search(text or "")
    return m.group(1) if m else None


def _relativize(path: str | None, workspace: Path | None) -> str | None:
    """`path` relative to `workspace` when it lies under it; unchanged otherwise."""
    if not path or workspace is None:
        return path
    p = Path(path)
    if not p.is_absolute():
        return path
    for root in {Path(workspace), Path(workspace).resolve()}:
        try:
            return p.relative_to(root).as_posix()
        except ValueError:
            continue
    return path


def _tail(text: str, n: int = 2000) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else "..." + text[-n:]


# ---------------------------------------------------------------------------------------------
# registration / factory


def _builtin_classes() -> dict[str, type]:
    from ananke.scanners.gitleaks import GitleaksScanner
    from ananke.scanners.osv import OsvScanner
    from ananke.scanners.trivy import TrivyScanner

    return {"trivy": TrivyScanner, "osv": OsvScanner, "gitleaks": GitleaksScanner}


def register_builtin(cfg: ScannersConfig | None = None, *, raw_dir: Path | None = None) -> None:
    """(Re-)register the built-in scanners with options from `cfg`. Idempotent."""
    from ananke.config import ScannersConfig
    from ananke.scanners import registry

    cfg = cfg if cfg is not None else ScannersConfig()
    for name, cls in _builtin_classes().items():
        registry.register(cls(cfg.options_for(name), raw_dir=raw_dir), replace=True)


def build_scanners(cfg: ScannersConfig, *, raw_dir: Path | None = None) -> list[Scanner]:
    """The scanners in `cfg.enabled`, in that order (duplicates dropped).

    Registers the built-ins (configured from `cfg`) and loads `ananke.scanners` entry points.
    Raises ValueError for an enabled name that is not registered.
    """
    from ananke.scanners import registry

    register_builtin(cfg, raw_dir=raw_dir)
    registry.load_entry_points()
    known = sorted(s.name for s in registry.all_scanners())
    out: list[Scanner] = []
    seen: set[str] = set()
    for name in cfg.enabled:
        if name in seen:
            continue
        seen.add(name)
        try:
            out.append(registry.get(name))
        except KeyError:
            raise ValueError(
                f"unknown scanner {name!r} in scanners.enabled (registered: {', '.join(known)})"
            ) from None
    return out
