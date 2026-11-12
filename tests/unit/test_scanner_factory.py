"""build_scanners / register_builtin."""

from __future__ import annotations

import pytest

from ananke.config import ScannersConfig
from ananke.scanners import BUILTIN, build_scanners, register_builtin, registry
from ananke.scanners.gitleaks import GitleaksScanner
from ananke.scanners.osv import OsvScanner
from ananke.scanners.trivy import TrivyScanner


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    monkeypatch.setattr(registry, "_REGISTRY", {})


def test_builtin_names():
    assert BUILTIN == ("trivy", "osv", "gitleaks")


def test_register_builtin_idempotent(tmp_path):
    register_builtin()
    register_builtin(raw_dir=tmp_path)
    assert [s.name for s in registry.all_scanners()] == sorted(BUILTIN)
    assert registry.get("trivy").raw_dir == tmp_path
    assert isinstance(registry.get("trivy"), TrivyScanner)
    assert isinstance(registry.get("osv"), OsvScanner)
    assert isinstance(registry.get("gitleaks"), GitleaksScanner)


def test_build_scanners_config_order_and_options(tmp_path):
    cfg = ScannersConfig.model_validate(
        {
            "enabled": ["gitleaks", "trivy", "osv", "trivy"],
            "trivy": {"scanners": ["vuln"], "ignore_unfixed": False},
            "osv": {"offline": False},
        }
    )
    scanners = build_scanners(cfg, raw_dir=tmp_path)
    assert [s.name for s in scanners] == ["gitleaks", "trivy", "osv"]
    trivy = scanners[1]
    assert trivy.options["scanners"] == ["vuln"]
    assert "--ignore-unfixed" not in trivy.command(tmp_path)
    assert "--offline" not in scanners[2].command(tmp_path)
    assert all(s.raw_dir == tmp_path for s in scanners)


def test_build_scanners_default_config():
    assert [s.name for s in build_scanners(ScannersConfig())] == list(BUILTIN)


def test_build_scanners_subset():
    cfg = ScannersConfig.model_validate({"enabled": ["osv"]})
    assert [s.name for s in build_scanners(cfg)] == ["osv"]


def test_unknown_name_lists_registered():
    cfg = ScannersConfig.model_validate({"enabled": ["trivy", "grype"]})
    with pytest.raises(ValueError, match="grype") as exc:
        build_scanners(cfg)
    assert "gitleaks, osv, trivy" in str(exc.value)


def test_entry_points_loaded(monkeypatch):
    calls = []
    monkeypatch.setattr(registry, "load_entry_points", lambda: calls.append(1) or [])
    build_scanners(ScannersConfig())
    assert calls == [1]
