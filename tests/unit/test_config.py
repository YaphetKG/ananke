from __future__ import annotations

import logging
from pathlib import Path

import pytest

from ananke.config import (
    AnankeConfig,
    ConfigError,
    RepoWorkflowConfig,
    config_from_dict,
    expand_string,
    load_config,
    parse_repo_workflow,
    split_front_matter,
)

ROOT = Path(__file__).resolve().parents[2]


def test_minimal_config_defaults(tmp_config: Path):
    cfg = load_config(tmp_config)
    assert isinstance(cfg, AnankeConfig)
    assert cfg.path == tmp_config.resolve()
    assert cfg.repos == ["RENCI/example-repo"]
    assert cfg.sources == ["github_dependabot", "local_sweep"]
    assert cfg.scanners.enabled == ["trivy", "osv", "gitleaks"]
    assert cfg.scanners.trivy.ignore_unfixed is True
    assert cfg.polling.interval_s == 600
    assert cfg.agent.model == "claude-opus-5-5" and cfg.agent.effort == "high"
    assert cfg.agent.max_concurrent == 3 and cfg.agent.max_attempts == 3
    assert cfg.policy.min_severity == "medium" and cfg.policy.grouping == "per_manifest"
    assert cfg.policy.auto_merge.enabled is False
    assert cfg.sandbox.allow_local is True
    assert cfg.server.port == 0
    assert cfg.live_model is False
    assert cfg.github.auth_mode == "none"


def test_relative_paths_resolve_against_config_dir(tmp_config: Path):
    cfg = load_config(tmp_config)
    assert cfg.workspace.root == tmp_config.parent.resolve() / "workspaces"
    assert cfg.sandbox.scanner_db_volume == tmp_config.parent.resolve() / "scanner-db"


def test_example_config_loads_and_mirrors_plan(monkeypatch):
    monkeypatch.setenv("HOME", "/home/someone")
    for v in ("ANANKE_GH_APP_ID", "ANANKE_GH_INSTALLATION_ID", "ANANKE_GH_PRIVATE_KEY_PATH"):
        monkeypatch.delenv(v, raising=False)
    cfg = load_config(ROOT / "ananke.yaml.example")
    assert cfg.unknown_keys == []
    assert cfg.workspace.root == Path("/home/someone/ananke-workspaces")
    assert cfg.github.app_id is None  # unset $VAR -> null
    assert cfg.policy.dependabot_prs == "supersede"
    assert "pypi.org" in cfg.sandbox.network_allowlist


def test_var_and_tilde_expansion(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("APP_ID", "1234")
    monkeypatch.setenv("KEYDIR", "keys")
    monkeypatch.setenv("TOK", "ghp_secret")
    monkeypatch.setenv("HOME", "/home/someone")
    p = tmp_path / "ananke.yaml"
    p.write_text(
        "github:\n"
        "  app_id: $APP_ID\n"
        "  installation_id: ${APP_ID}9\n"
        "  private_key_path: ${KEYDIR}/app.pem\n"
        "  token: $TOK\n"
        "workspace:\n  root: ~/ws\n"
        "notify:\n  slack_webhook: $NOT_SET_ANYWHERE\n"
    )
    cfg = load_config(p)
    assert cfg.github.app_id == "1234"
    assert cfg.github.installation_id == "12349"
    assert cfg.github.private_key_path == tmp_path.resolve() / "keys" / "app.pem"
    assert cfg.github.token.get_secret_value() == "ghp_secret"
    assert "ghp_secret" not in repr(cfg)
    assert cfg.github.auth_mode == "app"
    assert cfg.workspace.root == Path("/home/someone/ws")
    assert cfg.notify.slack_webhook is None


def test_expand_string_rules():
    env = {"A": "x", "EMPTY": ""}
    assert expand_string("$A", env) == "x"
    assert expand_string("$MISSING", env) is None
    assert expand_string("$EMPTY", env) is None
    assert expand_string("pre-$MISSING-post", env) == "pre--post"
    assert expand_string("no vars", env) == "no vars"


def test_pat_fallback_auth_mode():
    cfg = config_from_dict({"github": {"token": "abc"}})
    assert cfg.github.auth_mode == "token"


def test_validation_error_names_key(tmp_path: Path):
    p = tmp_path / "ananke.yaml"
    p.write_text("polling:\n  interval_s: soon\npolicy:\n  min_severity: catastrophic\n")
    with pytest.raises(ConfigError) as ei:
        load_config(p)
    keys = [k for k, _ in ei.value.problems]
    assert "polling.interval_s" in keys
    assert "policy.min_severity" in keys
    assert "polling.interval_s" in str(ei.value)


def test_invalid_yaml(tmp_path: Path):
    p = tmp_path / "ananke.yaml"
    p.write_text("repos: [unclosed\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_unknown_keys_warn_and_ignored(tmp_path: Path, caplog):
    p = tmp_path / "ananke.yaml"
    p.write_text("repos: []\nfrobnicate: 1\nagent:\n  modle: x\nscanners:\n  toy: {level: 3}\n")
    with caplog.at_level(logging.WARNING, logger="ananke.config"):
        cfg = load_config(p)
    assert cfg.unknown_keys == ["frobnicate", "agent.modle"]
    assert "key=agent.modle" in caplog.text
    assert "key=frobnicate" in caplog.text
    # scanner option sections are not "unknown"
    assert cfg.scanners.options_for("toy") == {"level": 3}
    assert cfg.scanners.options_for("osv") == {"offline": True}
    assert cfg.scanners.options_for("missing") == {}


def test_front_matter_parsing():
    text = (ROOT / "templates" / "ANANKE.default.md").read_text()
    wf, body = parse_repo_workflow(text)
    assert isinstance(wf, RepoWorkflowConfig)
    assert wf.test_command == "uv run pytest -q -x"
    assert wf.tests == "required"
    assert ".github/workflows/**" in wf.protected_paths
    assert wf.hooks.after_create == "git lfs pull || true"
    assert wf.hooks.timeout_s == 60
    assert body.lstrip().startswith("You are Ananke")
    assert "{{ repo }}" in body


def test_front_matter_defaults_and_missing():
    data, body = split_front_matter("no front matter here")
    assert data == {} and body == "no front matter here"
    wf, _ = parse_repo_workflow("---\nunknown_thing: 1\n---\nbody")
    assert wf.max_diff_lines == 800 and wf.tests == "required"
    with pytest.raises(ConfigError) as ei:
        parse_repo_workflow("---\ntests: sometimes\n---\n")
    assert ei.value.problems[0][0] == "tests"
