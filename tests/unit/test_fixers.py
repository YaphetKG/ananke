"""Deterministic fixers (pip, npm, go): manifest edits and the commands they run. Offline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fakes import OK, ScriptedSandbox, finding, item_for

from ananke.worker.fixers.base import result_for, target_versions
from ananke.worker.fixers.go import GoFixer, go_version
from ananke.worker.fixers.npm import NpmFixer, npm_spec
from ananke.worker.fixers.pip import (
    PipFixer,
    edit_pyproject,
    edit_requirements,
    poetry_spec,
    rewrite_requirement,
)
from ananke.worker.sandbox import CommandResult

# --- shared ----------------------------------------------------------------------------------


def test_target_versions_takes_highest_fix_regardless_of_order():
    item = item_for(
        finding("requests", "2.32.0", number=1),
        finding("requests", "2.31.0", number=2),
        finding("urllib3", "1.26.19", number=3),
        finding("urllib3", "1.26.17", number=4),
    )
    assert target_versions(item, "pip") == {"requests": "2.32.0", "urllib3": "1.26.19"}
    assert target_versions(item, "npm") == {}


def test_unknown_ecosystem_is_unsupported(tmp_path):
    item = item_for(finding("x", "1.0", ecosystem="maven"))
    r = result_for(item, "maven", tmp_path, ScriptedSandbox(tmp_path))
    assert not r.supported and "maven" in (r.error or "")


# --- pip: requirement strings --------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("requests==2.25.1", "requests==2.32.0"),
        ("Requests == 2.25.1", "Requests==2.32.0"),
        ("requests[socks]==2.25.1", "requests[socks]==2.32.0"),
        ("requests==2.25.*", "requests==2.32.0"),
        ("requests>=2.0,<2.30", "requests>=2.32.0"),
        ("requests>=2.0", "requests>=2.0"),  # already admits the fix: lockfile-only bump
        ("requests", "requests"),
        (
            "requests==2.25.1; python_version >= '3.8'",
            "requests==2.32.0 ; python_version >= '3.8'",
        ),
        ("urllib3==1.26.5", "urllib3==1.26.5"),  # different package
        ("not a requirement !!", "not a requirement !!"),
    ],
)
def test_rewrite_requirement(raw, expected):
    assert rewrite_requirement(raw, "requests", "2.32.0")[1] == expected


def test_rewrite_requirement_reports_declaration_even_without_edit():
    assert rewrite_requirement("requests>=2.0", "requests", "2.32.0") == (True, "requests>=2.0")
    assert rewrite_requirement("urllib3", "requests", "2.32.0") == (False, "urllib3")


def test_edit_requirements_keeps_comments_and_skips_hashed_lines(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text(
        "# top comment\n"
        "requests==2.25.1  # pinned for reasons\n"
        "-r base.txt\n"
        "urllib3==1.26.5 \\\n"
        "    --hash=sha256:abc\n"
    )
    assert edit_requirements(p, "requests", "2.32.0") == (True, True)
    assert edit_requirements(p, "urllib3", "1.26.19") == (False, False)
    assert p.read_text() == (
        "# top comment\n"
        "requests==2.32.0  # pinned for reasons\n"
        "-r base.txt\n"
        "urllib3==1.26.5 \\\n"
        "    --hash=sha256:abc\n"
    )


PYPROJECT = """\
[project]
name = "requests"
description = "requests"
dependencies = [
    "requests==2.25.1",
    "pywin32>=300; sys_platform == 'win32'",
]

[project.optional-dependencies]
http = ["requests[socks]==2.25.1", "urllib3"]

[dependency-groups]
dev = ["pytest", "requests>=1,<2"]

[tool.poetry.dependencies]
requests = "^2.25.1"
urllib3 = { version = "1.26.5", optional = true }

[tool.other]
requests = "unrelated"
"""


def test_edit_pyproject_touches_only_dependency_declarations(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text(PYPROJECT)
    assert edit_pyproject(p, "requests", "2.32.0") == (True, True)
    text = p.read_text()
    assert 'name = "requests"' in text and 'description = "requests"' in text
    assert '    "requests==2.32.0",' in text
    assert "\"pywin32>=300; sys_platform == 'win32'\"" in text  # marker quoting untouched
    assert 'http = ["requests[socks]==2.32.0", "urllib3"]' in text
    assert 'dev = ["pytest", "requests>=2.32.0"]' in text
    assert 'requests = "^2.32.0"' in text
    assert 'requests = "unrelated"' in text


def test_edit_pyproject_poetry_inline_table(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text(PYPROJECT)
    assert edit_pyproject(p, "urllib3", "1.26.19") == (True, True)
    assert 'urllib3 = { version = "1.26.19", optional = true }' in p.read_text()


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("^1.2", "^1.5.0"),
        ("~1.2", "~1.5.0"),
        ("1.2.0", "1.5.0"),
        ("==1.2", "1.5.0"),
        ("*", ">=1.5.0"),
    ],
)
def test_poetry_spec(old, new):
    assert poetry_spec(old, "1.5.0") == new


# --- pip: fixer ------------------------------------------------------------------------------


def test_pip_fixer_requirements_without_lockfile(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.1\n")
    (tmp_path / "requirements-dev.txt").write_text("requests==2.25.1\npytest\n")
    item = item_for(
        finding("requests", "2.31.0", number=1), finding("requests", "2.32.0", number=2)
    )
    sandbox = ScriptedSandbox(tmp_path)
    r = PipFixer().fix(item, tmp_path, sandbox)
    assert r.changed and r.error is None
    assert (tmp_path / "requirements.txt").read_text() == "requests==2.32.0\n"
    assert (tmp_path / "requirements-dev.txt").read_text() == "requests==2.32.0\npytest\n"
    assert sandbox.calls == []


def test_pip_fixer_regenerates_uv_lock_with_exact_upgrades(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["requests==2.25.1"]\n')
    lock = tmp_path / "uv.lock"
    lock.write_text("old")

    def fake_lock(cmd):
        lock.write_text("new")
        return OK

    sandbox = ScriptedSandbox(tmp_path, {"uv lock": fake_lock})
    item = item_for(
        finding("requests", "2.32.0", manifest="uv.lock"),
        finding("idna", "3.7", manifest="uv.lock", number=2),  # transitive: not in pyproject
        manifest="uv.lock",
    )
    r = PipFixer().fix(item, tmp_path, sandbox)
    assert r.error is None and r.changed
    assert sandbox.calls == [
        ["uv", "lock", "--upgrade-package", "requests==2.32.0", "--upgrade-package", "idna==3.7"]
    ]
    assert any(c.startswith("uv.lock: regenerated") for c in r.changes)
    assert r.commands[0]["exit_code"] == 0


def test_pip_fixer_reports_uv_lock_conflict(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["requests==2.25.1"]\n')
    (tmp_path / "uv.lock").write_text("old")
    sandbox = ScriptedSandbox(tmp_path, {"uv lock": CommandResult(1, "", "No solution found")})
    r = PipFixer().fix(
        item_for(finding("idna", "3.7", manifest="uv.lock"), manifest="uv.lock"), tmp_path, sandbox
    )
    assert not r.changed
    assert "uv lock failed" in (r.error or "") and "No solution" in (r.error or "")


def test_pip_fixer_undeclared_without_lockfile_is_an_error(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0\n")
    r = PipFixer().fix(item_for(finding("idna", "3.7")), tmp_path, ScriptedSandbox(tmp_path))
    assert not r.changed and "idna" in (r.error or "")


def test_pip_fixer_works_in_the_manifest_directory(tmp_path):
    sub = tmp_path / "services" / "api"
    sub.mkdir(parents=True)
    (sub / "requirements.txt").write_text("requests==2.25.1\n")
    (tmp_path / "requirements.txt").write_text("requests==2.25.1\n")
    item = item_for(
        finding("requests", "2.32.0", manifest="services/api/requirements.txt"),
        manifest="services/api/requirements.txt",
    )
    r = PipFixer().fix(item, tmp_path, ScriptedSandbox(tmp_path))
    assert r.changes == ["services/api/requirements.txt: requests -> 2.32.0"]
    assert (tmp_path / "requirements.txt").read_text() == "requests==2.25.1\n"


def test_pip_fixer_rejects_manifest_outside_workspace(tmp_path):
    item = item_for(
        finding(manifest="../../etc/requirements.txt"), manifest="../../etc/requirements.txt"
    )
    r = PipFixer().fix(item, tmp_path / "ws", ScriptedSandbox(tmp_path))
    assert not r.changed and "escapes" in (r.error or "")


# --- npm -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("old", "new"), [("^4.17.15", "^4.17.21"), ("~4.17.15", "~4.17.21"), ("4.17.15", "4.17.21")]
)
def test_npm_spec_keeps_range_prefix(old, new):
    assert npm_spec(old, "4.17.21") == new


def _npm_repo(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"lodash": "^4.17.15"}}, indent=2) + "\n"
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "dependencies": {"lodash": {"version": "4.17.15"}}})
    )


def test_npm_fixer_edits_package_json_even_when_manifest_is_the_lockfile(tmp_path):
    _npm_repo(tmp_path)
    lock_before = (tmp_path / "package-lock.json").read_text()
    sandbox = ScriptedSandbox(tmp_path, {"npm install": OK})
    item = item_for(
        finding("lodash", "4.17.19", ecosystem="npm", manifest="package-lock.json", number=1),
        finding("lodash", "4.17.21", ecosystem="npm", manifest="package-lock.json", number=2),
        finding("minimist", "1.2.6", ecosystem="npm", manifest="package-lock.json", number=3),
        manifest="package-lock.json",
    )
    r = NpmFixer().fix(item, tmp_path, sandbox)
    assert json.loads((tmp_path / "package.json").read_text())["dependencies"] == {
        "lodash": "^4.17.21"
    }
    assert (tmp_path / "package-lock.json").read_text() == lock_before  # never hand-edited
    assert sandbox.calls == [
        ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
    ]
    assert r.changed and "minimist" in (r.error or "")


def test_npm_fixer_missing_package_json(tmp_path):
    r = NpmFixer().fix(
        item_for(finding("lodash", "4.17.21", ecosystem="npm")), tmp_path, ScriptedSandbox(tmp_path)
    )
    assert not r.changed and "package.json" in (r.error or "")


# --- go --------------------------------------------------------------------------------------


def test_go_version_prefix():
    assert go_version("0.17.0") == "v0.17.0"
    assert go_version("v0.17.0") == "v0.17.0"


def test_go_fixer_runs_get_and_tidy(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/x\n")

    def bump(cmd):
        (tmp_path / "go.mod").write_text("module example.com/x\nrequire golang.org/x/net v0.17.0\n")
        return OK

    sandbox = ScriptedSandbox(tmp_path, {"go get": bump, "go mod tidy": OK})
    item = item_for(
        finding("golang.org/x/net", "0.17.0", ecosystem="go", manifest="go.mod"), manifest="go.mod"
    )
    r = GoFixer().fix(item, tmp_path, sandbox)
    assert sandbox.calls == [["go", "get", "golang.org/x/net@v0.17.0"], ["go", "mod", "tidy"]]
    assert r.changed and r.error is None


def test_go_fixer_without_go_mod(tmp_path):
    item = item_for(
        finding("golang.org/x/net", "0.17.0", ecosystem="go", manifest="go.mod"), manifest="go.mod"
    )
    r = GoFixer().fix(item, tmp_path, ScriptedSandbox(tmp_path))
    assert not r.changed and r.error == "go.mod not found"
