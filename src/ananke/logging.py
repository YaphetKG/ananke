"""Structured key=value logging on top of stdlib logging (Symphony-style).

    log = get_logger(__name__)
    log.info("run_started", item_key="RENCI/x/requirements.txt", run_id="r1", attempt=1)
    # -> event=run_started attempt=1 item_key=RENCI/x/requirements.txt run_id=r1

One line per event; `event` first, remaining keys sorted; values quoted (JSON-style) when they
contain whitespace, quotes, '=' or are empty. `item_key` and `run_id` are ordinary fields and
are also attached to the LogRecord (record.item_key / record.run_id) when present.
"""

from __future__ import annotations

import json
import logging as _stdlib_logging
from collections.abc import Mapping
from typing import Any

_PASSTHROUGH = ("item_key", "run_id")


def format_value(value: Any) -> str:
    if value is None:
        s = "null"
    elif isinstance(value, bool):
        s = "true" if value else "false"
    elif isinstance(value, str):
        s = value
    elif isinstance(value, int | float):
        s = str(value)
    else:
        try:
            s = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            s = str(value)
    if s == "" or any(c.isspace() or c in '"=\\' for c in s):
        return json.dumps(s)
    return s


def format_event(event: str, fields: Mapping[str, Any]) -> str:
    parts = [f"event={format_value(event)}"]
    parts += [f"{k}={format_value(fields[k])}" for k in sorted(fields)]
    return " ".join(parts)


class StructLogger:
    """Thin wrapper over a stdlib Logger that takes an event name plus keyword fields."""

    def __init__(self, logger: _stdlib_logging.Logger, context: Mapping[str, Any] | None = None):
        self._logger = logger
        self._context = dict(context or {})

    @property
    def stdlib(self) -> _stdlib_logging.Logger:
        return self._logger

    def bind(self, **fields: Any) -> StructLogger:
        """Return a child logger that adds `fields` to every event."""
        return StructLogger(self._logger, {**self._context, **fields})

    def log(self, level: int, event: str, /, exc_info: Any = None, **fields: Any) -> None:
        if not self._logger.isEnabledFor(level):
            return
        merged = {**self._context, **fields}
        extra: dict[str, Any] = {"ananke_event": event, "ananke_fields": merged}
        for k in _PASSTHROUGH:
            if k in merged:
                extra[k] = merged[k]
        self._logger.log(
            level, format_event(event, merged), exc_info=exc_info, extra=extra, stacklevel=3
        )

    def debug(self, event: str, /, **fields: Any) -> None:
        self.log(_stdlib_logging.DEBUG, event, **fields)

    def info(self, event: str, /, **fields: Any) -> None:
        self.log(_stdlib_logging.INFO, event, **fields)

    def warning(self, event: str, /, **fields: Any) -> None:
        self.log(_stdlib_logging.WARNING, event, **fields)

    def error(self, event: str, /, **fields: Any) -> None:
        self.log(_stdlib_logging.ERROR, event, **fields)

    def exception(self, event: str, /, **fields: Any) -> None:
        self.log(_stdlib_logging.ERROR, event, exc_info=True, **fields)


def get_logger(name: str) -> StructLogger:
    return StructLogger(_stdlib_logging.getLogger(name))


def configure_logging(level: int | str = "INFO") -> None:
    """Install a plain stderr handler on the `ananke` logger: '<time> <level> <logger> <kv>'."""
    root = _stdlib_logging.getLogger("ananke")
    root.setLevel(level if isinstance(level, int) else level.upper())
    if not any(getattr(h, "_ananke", False) for h in root.handlers):
        h = _stdlib_logging.StreamHandler()
        h.setFormatter(
            _stdlib_logging.Formatter("%(asctime)s level=%(levelname)s logger=%(name)s %(message)s")
        )
        h._ananke = True  # type: ignore[attr-defined]
        root.addHandler(h)
