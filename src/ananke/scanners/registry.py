"""Scanner registry: name -> Scanner, plus the `ananke.scanners` entry-point group."""

from __future__ import annotations

from importlib.metadata import entry_points

from ananke.logging import get_logger
from ananke.scanners.base import Scanner

ENTRY_POINT_GROUP = "ananke.scanners"

_REGISTRY: dict[str, Scanner] = {}
log = get_logger(__name__)


def register(scanner: Scanner, *, replace: bool = False) -> Scanner:
    """Register a scanner instance under `scanner.name`. Returns it (usable as a decorator
    on instances). Raises ValueError on a duplicate name unless replace=True."""
    name = scanner.name
    if name in _REGISTRY and _REGISTRY[name] is not scanner and not replace:
        raise ValueError(f"scanner {name!r} is already registered")
    _REGISTRY[name] = scanner
    return scanner


def unregister(name: str) -> None:
    _REGISTRY.pop(name, None)


def get(name: str) -> Scanner:
    """Return the scanner registered as `name`; KeyError naming known scanners otherwise."""
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "none"
        raise KeyError(f"unknown scanner {name!r} (registered: {known})") from None


def all_scanners() -> list[Scanner]:
    """All registered scanners, sorted by name."""
    return [_REGISTRY[n] for n in sorted(_REGISTRY)]


def load_entry_points() -> list[str]:
    """Load scanners exposed via the `ananke.scanners` entry-point group.

    Each entry point may resolve to a Scanner instance, a zero-arg class/factory returning one,
    or a module that registers itself on import. Returns names newly registered. Broken entry
    points are logged and skipped.
    """
    loaded: list[str] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            obj = ep.load()
            if isinstance(obj, type) or (callable(obj) and not hasattr(obj, "name")):
                obj = obj()
            if hasattr(obj, "name") and hasattr(obj, "parse"):
                if obj.name not in _REGISTRY:
                    register(obj)
                    loaded.append(obj.name)
        except Exception as exc:  # plugin isolation: never let one plugin break the rest
            log.warning("scanner_entry_point_failed", entry_point=ep.name, error=str(exc))
    return loaded
