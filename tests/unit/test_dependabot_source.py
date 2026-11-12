"""DependabotSource + parse_alert against recorded fixtures. Offline (respx)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from ananke.config import GitHubConfig
from ananke.github.auth import GitHubAuth
from ananke.github.client import GitHubClient
from ananke.sources.base import Source, SourceError
from ananke.sources.github_dependabot import DependabotSource, cvss_score, parse_alert, parse_key

API = "https://api.github.com"
REPO = "RENCI/example-repo"
ALERTS = f"{API}/repos/{REPO}/dependabot/alerts"


def load(fixtures_dir, name):
    return json.loads((fixtures_dir / "dependabot_alerts" / name).read_text())


@pytest.fixture
async def source():
    auth = GitHubAuth.from_config(GitHubConfig(token="ghp_test"))

    async def no_sleep(_: float) -> None:
        return None

    async with httpx.AsyncClient() as http:
        yield DependabotSource(GitHubClient(auth, api_url=API, client=http, sleep=no_sleep))


EXPECTED = {
    # number: (severity, advisory_ids, ecosystem, package, manifest, range, fixed)
    1: ("medium", ["GHSA-j8r2-6x86-q33q", "CVE-2023-32681"], "pip", "requests",
        "requirements.txt", ">= 2.3.0, < 2.31.0", "2.31.0"),
    2: ("high", ["GHSA-v845-jxx5-vc9f", "CVE-2023-43804"], "pip", "urllib3",
        "requirements.txt", "< 1.26.17", "1.26.17"),
    3: ("medium", ["GHSA-34jh-p97f-mpxf", "CVE-2024-37891"], "pip", "urllib3",
        "requirements.txt", "< 1.26.19", "1.26.19"),
    4: ("high", ["GHSA-p6mc-m468-83gw", "CVE-2020-8203"], "npm", "lodash",
        "package.json", ">= 3.7.0, < 4.17.19", "4.17.19"),
    5: ("high", ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], "npm", "lodash",
        "package.json", "< 4.17.21", "4.17.21"),
    6: ("high", ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], "npm", "lodash.template",
        "package.json", "<= 4.5.0", None),
}  # fmt: skip


def test_parse_alert_open_fixture(fixtures_dir):
    alerts = load(fixtures_dir, "open.json")
    assert sorted(a["number"] for a in alerts) == [1, 2, 3, 4, 5, 6]
    for alert in alerts:
        f = parse_alert(REPO, alert)
        n = alert["number"]
        sev, ids, eco, pkg, manifest, rng, fixed = EXPECTED[n]
        assert f.key == f"{REPO}:github_dependabot:{n}"
        assert f.repo == REPO and f.source == "github_dependabot" and f.source_id == str(n)
        assert f.severity == sev
        assert f.advisory_ids == ids
        assert f.ecosystem == eco and f.package == pkg and f.manifest_path == manifest
        assert f.vulnerable_range == rng
        assert f.fixed_version == fixed
        assert f.state == "open"
        assert f.url == f"https://github.com/{REPO}/security/dependabot/{n}"
        assert f.summary == alert["security_advisory"]["summary"]
        assert f.created_at.tzinfo is not None
        assert f.raw == alert


def test_parse_alert_created_at_and_cvss(fixtures_dir):
    alert6 = next(a for a in load(fixtures_dir, "open.json") if a["number"] == 6)
    assert parse_alert(REPO, alert6).created_at == datetime(2026, 10, 2, 14, 11, 9, tzinfo=UTC)
    assert cvss_score(alert6) == 7.2


def test_parse_alert_tolerates_missing_optional_fields(fixtures_dir):
    alert = json.loads(json.dumps(load(fixtures_dir, "open.json")[0]))
    alert["security_advisory"].pop("cvss_severities", None)
    alert["security_advisory"]["cve_id"] = None
    alert["security_vulnerability"]["first_patched_version"] = None
    f = parse_alert(REPO, alert)
    assert cvss_score(alert) is None
    assert f.advisory_ids == [alert["security_advisory"]["ghsa_id"]]
    assert f.fixed_version is None


def test_state_mapping(fixtures_dir):
    states = {
        a["number"]: parse_alert(REPO, a).state for a in load(fixtures_dir, "mixed_states.json")
    }
    assert states == {7: "open", 8: "fixed", 9: "dismissed", 10: "dismissed"}
    alert = dict(load(fixtures_dir, "mixed_states.json")[0], state="weird")
    assert parse_alert(REPO, alert).state == "unknown"


def test_parse_key():
    assert parse_key(f"{REPO}:github_dependabot:12") == (REPO, "12")
    for bad in ("RENCI/x:osv:1", "nope:github_dependabot:1", f"{REPO}:github_dependabot:x"):
        with pytest.raises(ValueError):
            parse_key(bad)


async def test_is_a_source(source):
    assert isinstance(source, Source)
    assert source.name == "github_dependabot"


@respx.mock
async def test_fetch_open_paginated(source, fixtures_dir):
    alerts = load(fixtures_dir, "open.json")
    page2 = f"{API}/repositories/99/dependabot/alerts?state=open&per_page=100&after=abc"
    route1 = respx.get(ALERTS).mock(
        return_value=httpx.Response(
            200, json=alerts[:4], headers={"Link": f'<{page2}>; rel="next"'}
        )
    )
    respx.get(page2).mock(return_value=httpx.Response(200, json=alerts[4:]))
    findings = await source.fetch_open(REPO)
    assert sorted(int(f.source_id) for f in findings) == [1, 2, 3, 4, 5, 6]
    assert route1.calls.last.request.url.params["state"] == "open"


@respx.mock
async def test_fetch_open_empty(source, fixtures_dir):
    respx.get(ALERTS).mock(return_value=httpx.Response(200, json=load(fixtures_dir, "empty.json")))
    assert await source.fetch_open(REPO) == []


@respx.mock
async def test_fetch_open_403_disabled_is_source_error(source):
    respx.get(ALERTS).mock(
        return_value=httpx.Response(403, json={"message": "Dependabot alerts are disabled"})
    )
    with pytest.raises(SourceError) as ei:
        await source.fetch_open(REPO)
    msg = str(ei.value)
    assert "enable Dependabot alerts" in msg
    assert '"Dependabot alerts: read"' in msg


@respx.mock
async def test_fetch_by_keys_omits_404(source, fixtures_dir):
    by_num = {a["number"]: a for a in load(fixtures_dir, "mixed_states.json")}
    respx.get(f"{ALERTS}/7").mock(return_value=httpx.Response(200, json=by_num[7]))
    respx.get(f"{ALERTS}/8").mock(return_value=httpx.Response(200, json=by_num[8]))
    respx.get(f"{ALERTS}/99").mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
    keys = [f"{REPO}:github_dependabot:{n}" for n in (7, 8, 99)]
    findings = await source.fetch_by_keys(keys)
    assert {f.key: f.state for f in findings} == {keys[0]: "open", keys[1]: "fixed"}
