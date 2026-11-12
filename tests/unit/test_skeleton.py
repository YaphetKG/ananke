"""Every module in the package imports and has a docstring; stubs name their milestone."""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import ananke

MODULES = sorted(m.name for m in pkgutil.walk_packages(ananke.__path__, prefix="ananke.") if m.name)


@pytest.mark.parametrize("name", MODULES)
def test_module_imports_with_docstring(name):
    mod = importlib.import_module(name)
    assert (mod.__doc__ or "").strip(), f"{name} has no docstring"
    if hasattr(mod, "MILESTONE"):
        with pytest.raises(NotImplementedError, match=mod.MILESTONE):
            mod.something_not_yet_written  # noqa: B018
