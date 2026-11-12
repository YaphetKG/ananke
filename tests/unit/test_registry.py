from __future__ import annotations

from types import SimpleNamespace

import pytest

from ananke.scanners import registry
from ananke.scanners.base import ScanReport


class Toy:
    def __init__(self, name: str = "toy"):
        self.name = name
        self.kinds = frozenset({"dependency"})
        self.ecosystems = frozenset({"*"})

    def available(self, sandbox):
        return False

    def version(self, sandbox):
        raise NotImplementedError

    def scan(self, sandbox, workspace, targets=None):
        raise NotImplementedError

    def parse(self, raw):
        return ScanReport(scanner=self.name)


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    monkeypatch.setattr(registry, "_REGISTRY", {})


def test_register_get_all():
    t = registry.register(Toy("b"))
    registry.register(Toy("a"))
    assert registry.get("b") is t
    assert [s.name for s in registry.all_scanners()] == ["a", "b"]


def test_duplicate_and_unknown():
    registry.register(Toy())
    with pytest.raises(ValueError):
        registry.register(Toy())
    registry.register(Toy(), replace=True)
    with pytest.raises(KeyError, match="unknown scanner 'nope'"):
        registry.get("nope")


def test_load_entry_points(monkeypatch):
    good = SimpleNamespace(name="ep_toy", load=lambda: Toy("ep_toy"))
    factory = SimpleNamespace(name="ep_cls", load=lambda: lambda: Toy("ep_cls"))

    def boom():
        raise ImportError("broken plugin")

    bad = SimpleNamespace(name="bad", load=boom)
    monkeypatch.setattr(registry, "entry_points", lambda group: [good, factory, bad])
    loaded = registry.load_entry_points()
    assert sorted(loaded) == ["ep_cls", "ep_toy"]
    assert registry.get("ep_toy").name == "ep_toy"
