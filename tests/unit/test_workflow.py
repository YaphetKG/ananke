"""workflow.py: loading, strict rendering, validation, reload cache."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import pytest

from ananke.model import Finding, WorkItem
from ananke.workflow import (
    Workflow,
    WorkflowCache,
    WorkflowError,
    WorkflowRenderError,
    default_workflow_text,
    findings_table,
    load_workflow,
    make_environment,
    render_prompt,
    validate_workflow,
)

REPO = "RENCI/example-repo"


def _finding(n: int = 1, **kw) -> Finding:
    base = dict(
        key=Finding.make_key(REPO, "github_dependabot", str(n)),
        repo=REPO,
        source="github_dependabot",
        source_id=str(n),
        severity="high",
        advisory_ids=[f"GHSA-aaaa-bbbb-000{n}", f"CVE-2026-000{n}"],
        summary="bad thing",
        url=f"https://github.com/{REPO}/security/dependabot/{n}",
        ecosystem="pip",
        package=f"pkg{n}",
        manifest_path="requirements.txt",
        vulnerable_range="< 2.0",
        fixed_version="2.0",
        created_at=datetime(2026, 1, n, tzinfo=UTC),
    )
    base.update(kw)
    return Finding(**base)


def _item(*findings: Finding) -> WorkItem:
    return WorkItem.from_findings(REPO, "requirements.txt", list(findings or [_finding()]))


CUSTOM = """---
test_command: "make test"
tests: advisory
max_diff_lines: 100
reviewers: ["RENCI/platform"]
some_unknown_key: 1
---
Patch {{ repo }} attempt={{ attempt }} cmd={{ workflow.test_command }} n={{ findings | length }}
{% if prior_failure %}PRIOR: {{ prior_failure }}{% endif %}
"""


def test_load_default_on_none_and_empty():
    for text in (None, "", "   \n"):
        wf = load_workflow(text)
        assert isinstance(wf, Workflow)
        assert wf.source.endswith("ANANKE.default.md")
        assert wf.config.test_command == "uv run pytest -q -x"
        assert "report_result" in wf.body
    assert default_workflow_text().startswith("---")


def test_load_custom_front_matter_ignores_unknown_keys():
    wf = load_workflow(CUSTOM, source="RENCI/x:ANANKE.md")
    assert wf.config.test_command == "make test"
    assert wf.config.tests == "advisory"
    assert wf.config.max_diff_lines == 100
    assert wf.config.reviewers == ["RENCI/platform"]
    assert wf.source == "RENCI/x:ANANKE.md"
    assert wf.body.startswith("Patch {{ repo }}")


def test_front_matter_must_be_mapping():
    with pytest.raises(WorkflowError):
        load_workflow("---\n- a\n- b\n---\nbody\n")


def test_render_custom_prompt():
    wf = load_workflow(CUSTOM)
    item = _item(_finding(1), _finding(2))
    out = render_prompt(wf, item=item, repo=REPO, attempt=2, prior_failure="pip exploded")
    assert f"Patch {REPO} attempt=2 cmd=make test n=2" in out
    assert "PRIOR: pip exploded" in out
    out2 = render_prompt(wf, item=item, repo=REPO)
    assert "PRIOR" not in out2 and "attempt=None" in out2


def test_unknown_variable_raises():
    wf = load_workflow("Hello {{ nope }}")
    with pytest.raises(WorkflowRenderError, match="nope"):
        render_prompt(wf, item=_item(), repo=REPO)


def test_unknown_attribute_raises():
    wf = load_workflow("Hello {{ item.no_such_field }}")
    with pytest.raises(WorkflowRenderError):
        render_prompt(wf, item=_item(), repo=REPO)


def test_unknown_filter_raises_at_load():
    with pytest.raises(WorkflowRenderError):
        load_workflow("{{ findings | no_such_filter }}")


def test_unknown_filter_inside_branch_raises_at_render():
    wf = load_workflow("{% if prior_failure %}{{ prior_failure | no_such_filter }}{% endif %}")
    render_prompt(wf, item=_item(), repo=REPO)  # branch not taken
    with pytest.raises(WorkflowRenderError):
        render_prompt(wf, item=_item(), repo=REPO, prior_failure="x")


def test_syntax_error_raises():
    with pytest.raises(WorkflowRenderError):
        load_workflow("{% if %}")


def test_default_template_renders_findings_rows():
    wf = load_workflow(None)
    item = _item(_finding(1), _finding(2, severity="critical", package="urllib3"))
    out = render_prompt(wf, item=item, repo=REPO, attempt=1, prior_failure="tests failed")
    assert "| Advisory | Package | Installed/Vulnerable range | Fixed in | Severity | Link |" in out
    assert "| GHSA-aaaa-bbbb-0001, CVE-2026-0001 | pkg1 | < 2.0 | 2.0 | **HIGH** |" in out
    assert "urllib3" in out and "**CRITICAL**" in out
    assert "tests failed" in out
    assert "`uv run pytest -q -x`" in out
    assert "untrusted data" in out
    assert "{{" not in out and "{%" not in out
    no_prior = render_prompt(wf, item=item, repo=REPO)
    assert "deterministic rung already tried" not in no_prior
    assert len(default_workflow_text().splitlines()) <= 75


def test_findings_table_escapes_and_accepts_dicts():
    table = findings_table(
        [{"advisory_ids": [], "source_id": "7", "package": None, "vulnerable_range": "<1 || >3"}]
    )
    rows = table.splitlines()
    assert len(rows) == 3
    assert "\\|\\|" in rows[2] and "| 7 |" in rows[2] and "n/a" in rows[2]


def test_environment_is_strict():
    env = make_environment()
    assert env.autoescape is False
    assert env.trim_blocks and env.lstrip_blocks
    assert {"findings_table", "severity_badge"} <= set(env.filters)


def test_validate_workflow_accepts_default_and_rejects_bad_body():
    validate_workflow(load_workflow(None))
    validate_workflow(load_workflow(CUSTOM))
    with pytest.raises(WorkflowRenderError):
        validate_workflow(load_workflow("---\ntests: required\n---\n{{ item.oops }}\n"))
    # error only in the prior_failure branch is still caught
    with pytest.raises(WorkflowRenderError):
        validate_workflow(load_workflow("{% if prior_failure %}{{ missing }}{% endif %}"))


def test_cache_reparses_on_change_and_keeps_last_good(caplog):
    cache = WorkflowCache()
    texts = iter([CUSTOM, CUSTOM, "{{ broken }}", "{{ broken }}", None])
    calls: list[int] = []

    def fetch():
        calls.append(1)
        return next(texts)

    wf1 = cache.get(REPO, fetch)
    assert wf1.config.test_command == "make test"
    assert cache.get(REPO, fetch) is wf1  # unchanged text -> same object
    with caplog.at_level(logging.WARNING, logger="ananke.workflow"):
        assert cache.get(REPO, fetch) is wf1  # broken -> last good
        assert cache.get(REPO, fetch) is wf1  # same broken text -> no second log
    msgs = [r.getMessage() for r in caplog.records if "workflow_reload_failed" in r.getMessage()]
    assert len(msgs) == 1
    assert f"repo={REPO}" in msgs[0] and "error=" in msgs[0]
    wf_default = cache.get(REPO, fetch)  # None -> default template
    assert wf_default is not wf1
    assert wf_default.config.test_command == "uv run pytest -q -x"
    assert len(calls) == 5


def test_cache_without_last_good_raises_and_invalidate():
    cache = WorkflowCache()
    with pytest.raises(WorkflowError):
        cache.get(REPO, lambda: "{{ broken }}")
    wf = cache.get(REPO, lambda: CUSTOM)
    cache.invalidate(REPO)
    wf2 = cache.get(REPO, lambda: CUSTOM)
    assert wf2 is not wf and wf2.config == wf.config


def test_cache_fetch_error_keeps_last_good(caplog):
    cache = WorkflowCache()
    wf = cache.get(REPO, lambda: CUSTOM)

    def boom():
        raise RuntimeError("github down")

    with caplog.at_level(logging.WARNING, logger="ananke.workflow"):
        assert cache.get(REPO, boom) is wf
    assert any("github down" in r.getMessage() for r in caplog.records)
