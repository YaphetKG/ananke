from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import HumanMessage

from ananke import llm
from ananke.config import config_from_dict
from ananke.llm import LiveModelDisabled, get_model, live_model_allowed, require_live_model

SRC = Path(__file__).resolve().parents[2] / "src"


@pytest.fixture
def no_construct(monkeypatch):
    """Fail loudly if anything tries to build a live model during these tests."""

    def boom(*a, **k):
        raise AssertionError("live model construction attempted in a test")

    monkeypatch.setattr(llm, "_construct_live", boom)


@pytest.mark.parametrize(
    "cfg_live,env,flag",
    [
        (False, "1", True),
        (True, None, True),
        (True, "0", True),
        (True, "1", False),
        (False, None, False),
    ],
)
def test_gate_refuses_when_any_leg_missing(monkeypatch, no_construct, cfg_live, env, flag):
    if env is None:
        monkeypatch.delenv("ANANKE_LIVE_MODEL", raising=False)
    else:
        monkeypatch.setenv("ANANKE_LIVE_MODEL", env)
    cfg = config_from_dict({"live_model": cfg_live})
    assert not live_model_allowed(cfg, live=flag)
    model = get_model(cfg, live=flag)
    assert isinstance(model, GenericFakeChatModel)
    with pytest.raises(LiveModelDisabled):
        require_live_model(cfg, live=flag)


def test_gate_allows_only_when_all_legs_set(monkeypatch):
    # Do NOT construct the live model: substitute the construction site with a sentinel.
    sentinel = object()
    monkeypatch.setattr(llm, "_construct_live", lambda cfg, **kw: sentinel)
    monkeypatch.setenv("ANANKE_LIVE_MODEL", "1")
    cfg = config_from_dict({"live_model": True})
    assert live_model_allowed(cfg, live=True)
    assert get_model(cfg, live=True) is sentinel
    assert require_live_model(cfg, live=True) is sentinel


def test_empty_fake_model(no_construct):
    model = get_model(config_from_dict({}))
    out = model.invoke([HumanMessage("hi")])
    assert out.content == ""
    assert model.invoke([HumanMessage("again")]).content == ""  # does not run dry


def test_fake_script(tmp_path: Path, no_construct):
    script = tmp_path / "s.json"
    script.write_text(
        json.dumps(
            [
                {"tool_calls": [{"name": "run_command", "args": {"cmd": "pytest"}}]},
                {"content": "done"},
            ]
        )
    )
    model = get_model(config_from_dict({}), fake_script=script)
    assert model.bind_tools([]) is model
    first = model.invoke([HumanMessage("go")])
    assert first.tool_calls[0]["name"] == "run_command"
    assert first.tool_calls[0]["args"] == {"cmd": "pytest"}
    assert first.tool_calls[0]["id"]
    assert model.invoke([HumanMessage("next")]).content == "done"


def test_bad_fake_script(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps([{"tool_calls": [{"args": {}}]}]))
    with pytest.raises(ValueError, match="missing 'name'"):
        llm.load_fake_script(p)


def test_chat_anthropic_constructed_only_in_llm_py():
    hits = []
    for path in SRC.rglob("*.py"):
        if re.search(r"ChatAnthropic\(", path.read_text(encoding="utf-8")):
            hits.append(path.relative_to(SRC).as_posix())
    assert hits == ["ananke/llm.py"]
