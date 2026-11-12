"""The ONLY place a chat model is constructed in Ananke (PLAN.md §4, §0).

Three-way live-model gate. A real `ChatAnthropic` is built only when ALL of these hold:
  1. config `live_model: true`
  2. environment `ANANKE_LIVE_MODEL=1`
  3. the caller passes `live=True` (wired to the CLI `--live` flag)
Otherwise `get_model` returns an offline fake model; `require_live_model` raises
`LiveModelDisabled` for callers (e.g. the daemon) that must not silently fall back.

A test greps src/ for the construction call and asserts it appears only in this file.
"""

from __future__ import annotations

import itertools
import json
import os
import uuid
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from langchain_core.language_models import BaseChatModel
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

if TYPE_CHECKING:
    from ananke.config import AnankeConfig

LIVE_ENV_VAR = "ANANKE_LIVE_MODEL"


class LiveModelDisabled(RuntimeError):
    """Raised when a live model is required but the three-way gate is not satisfied."""


class ScriptedFakeChatModel(GenericFakeChatModel):
    """GenericFakeChatModel that tolerates `bind_tools` (Deep Agents / create_agent call it).

    Tools are ignored; the scripted messages drive the conversation.
    """

    def bind_tools(  # type: ignore[override]
        self,
        tools: Sequence[Any],
        *,
        tool_choice: Any = None,
        **kwargs: Any,
    ) -> ScriptedFakeChatModel:
        return self


def gate_status(cfg: AnankeConfig, *, live: bool) -> dict[str, bool]:
    """Each leg of the gate, for diagnostics."""
    return {
        "config_live_model": bool(cfg.live_model),
        "env_ANANKE_LIVE_MODEL": os.environ.get(LIVE_ENV_VAR) == "1",
        "live_flag": bool(live),
    }


def live_model_allowed(cfg: AnankeConfig, *, live: bool) -> bool:
    return all(gate_status(cfg, live=live).values())


def _script_message(turn: dict[str, Any], index: int) -> AIMessage:
    if not isinstance(turn, dict):
        raise ValueError(f"fake script turn {index} must be an object, got {type(turn).__name__}")
    calls = []
    for j, call in enumerate(turn.get("tool_calls") or []):
        if "name" not in call:
            raise ValueError(f"fake script turn {index} tool_calls[{j}] is missing 'name'")
        calls.append(
            {
                "name": call["name"],
                "args": call.get("args") or {},
                "id": call.get("id") or f"call_{index}_{j}_{uuid.uuid4().hex[:8]}",
                "type": "tool_call",
            }
        )
    return AIMessage(content=turn.get("content", ""), tool_calls=calls)


def load_fake_script(path: Path | str) -> list[AIMessage]:
    """Load a fake-model script: a JSON list of assistant turns, each either
    {"content": "..."} or {"tool_calls": [{"name": ..., "args": {...}}]} (or both)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "turns" in data:  # tolerate {"turns": [...]}
        data = data["turns"]
    if not isinstance(data, list):
        raise ValueError(f"fake script {path} must be a JSON list of turns")
    return [_script_message(t, i) for i, t in enumerate(data)]


def fake_model(
    messages: Sequence[AIMessage] | None = None, *, repeat_empty: bool = True
) -> ScriptedFakeChatModel:
    """Offline fake model. Yields `messages` in order, then (if repeat_empty) empty replies
    forever so an over-long loop ends quietly instead of raising StopIteration."""
    it: Iterator[AIMessage] = iter(list(messages or []))
    if repeat_empty:
        it = itertools.chain(it, (AIMessage(content="") for _ in itertools.count()))
    return ScriptedFakeChatModel(messages=it)


def _construct_live(cfg: AnankeConfig, **kwargs: Any) -> BaseChatModel:
    # Imported lazily so offline code paths never touch the Anthropic client.
    from langchain_anthropic import ChatAnthropic

    params: dict[str, Any] = {"model": cfg.agent.model, "reasoning_effort": cfg.agent.effort}
    params.update(kwargs)
    return ChatAnthropic(**params)


def get_model(
    cfg: AnankeConfig,
    *,
    live: bool = False,
    fake_script: Path | str | None = None,
    **live_kwargs: Any,
) -> BaseChatModel:
    """Return the chat model for a run.

    Live (ChatAnthropic) only when the three-way gate is satisfied; otherwise a fake model
    seeded from `fake_script` (JSON list of turns) or an empty-content fake model.
    """
    if live_model_allowed(cfg, live=live):
        return _construct_live(cfg, **live_kwargs)
    messages = load_fake_script(fake_script) if fake_script is not None else []
    return fake_model(messages)


def require_live_model(cfg: AnankeConfig, *, live: bool, **live_kwargs: Any) -> BaseChatModel:
    """Like get_model but raises LiveModelDisabled instead of falling back to a fake."""
    status = gate_status(cfg, live=live)
    if not all(status.values()):
        missing = ", ".join(k for k, ok in status.items() if not ok)
        raise LiveModelDisabled(f"live model disabled; gate legs not satisfied: {missing}")
    return _construct_live(cfg, **live_kwargs)


ModelFactory = Callable[..., BaseChatModel]
