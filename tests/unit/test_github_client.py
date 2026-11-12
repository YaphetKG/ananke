"""GitHubClient: headers, pagination, ETag 304, retries, rate limits, errors. Offline (respx)."""

from __future__ import annotations

import httpx
import pytest
import respx

from ananke.config import GitHubConfig
from ananke.github.auth import GitHubAuth
from ananke.github.client import GitHubClient, GitHubError, NotFound, parse_next_link

API = "https://api.github.com"


class Sleeps:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


@pytest.fixture
def sleeps() -> Sleeps:
    return Sleeps()


@pytest.fixture
async def gh(sleeps: Sleeps):
    auth = GitHubAuth.from_config(GitHubConfig(token="ghp_test"))
    async with httpx.AsyncClient() as http:
        yield GitHubClient(auth, api_url=API, client=http, sleep=sleeps, clock=lambda: 1000.0)


def test_parse_next_link():
    header = (
        '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; '
        'rel="last"'
    )
    assert parse_next_link(header) == "https://api.github.com/x?page=2"
    assert parse_next_link('<https://api.github.com/x?page=1>; rel="prev"') is None
    assert parse_next_link(None) is None


@respx.mock
async def test_headers(gh):
    route = respx.get(f"{API}/repos/o/r").mock(return_value=httpx.Response(200, json={"id": 1}))
    assert await gh.get("/repos/o/r") == {"id": 1}
    req = route.calls.last.request
    assert req.headers["Accept"] == "application/vnd.github+json"
    assert req.headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert req.headers["Authorization"] == "Bearer ghp_test"


@respx.mock
async def test_pagination_follows_link(gh):
    page2 = f"{API}/repositories/1/items?per_page=100&page=2"
    route1 = respx.get(f"{API}/repos/o/r/items").mock(
        return_value=httpx.Response(
            200, json=[1, 2], headers={"Link": f'<{page2}>; rel="next", <{page2}>; rel="last"'}
        )
    )
    route2 = respx.get(page2).mock(return_value=httpx.Response(200, json=[3]))
    assert await gh.get_paginated("/repos/o/r/items", {"state": "open"}) == [1, 2, 3]
    first = route1.calls.last.request.url
    assert first.params["per_page"] == "100" and first.params["state"] == "open"
    assert route2.call_count == 1


@respx.mock
async def test_etag_304_returns_cached(gh):
    route = respx.get(f"{API}/repos/o/r").mock(
        side_effect=[
            httpx.Response(200, json={"v": 1}, headers={"ETag": '"abc"'}),
            httpx.Response(304),
        ]
    )
    assert await gh.get("/repos/o/r", {"a": 1}) == {"v": 1}
    assert await gh.get("/repos/o/r", {"a": 1}) == {"v": 1}
    assert "If-None-Match" not in route.calls[0].request.headers
    assert route.calls[1].request.headers["If-None-Match"] == '"abc"'


@respx.mock
async def test_etag_cache_keyed_by_params(gh):
    route = respx.get(f"{API}/repos/o/r").mock(
        return_value=httpx.Response(200, json={}, headers={"ETag": '"x"'})
    )
    await gh.get("/repos/o/r", {"a": 1})
    await gh.get("/repos/o/r", {"a": 2})
    assert "If-None-Match" not in route.calls[1].request.headers


@respx.mock
async def test_retry_on_500_then_success(gh, sleeps):
    route = respx.get(f"{API}/x").mock(
        side_effect=[httpx.Response(500), httpx.Response(502), httpx.Response(200, json=[1])]
    )
    assert await gh.get("/x") == [1]
    assert route.call_count == 3
    assert len(sleeps.delays) == 2
    assert 0.5 <= sleeps.delays[0] <= 1.0 and 1.0 <= sleeps.delays[1] <= 2.0


@respx.mock
async def test_5xx_gives_up_after_max_retries(gh, sleeps):
    route = respx.get(f"{API}/x").mock(return_value=httpx.Response(503, json={"message": "down"}))
    with pytest.raises(GitHubError) as ei:
        await gh.get("/x")
    assert ei.value.status == 503 and ei.value.message == "down"
    assert route.call_count == 5  # 1 + max_retries
    assert len(sleeps.delays) == 4


@respx.mock
async def test_403_rate_limit_sleeps_until_reset(gh, sleeps):
    respx.get(f"{API}/x").mock(
        side_effect=[
            httpx.Response(
                403,
                json={"message": "API rate limit exceeded"},
                headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1030"},
            ),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    assert await gh.get("/x") == {"ok": True}
    assert sleeps.delays == [31.0]  # reset 1030 - now 1000 + 1 s slack


@respx.mock
async def test_429_honours_retry_after(gh, sleeps):
    respx.get(f"{API}/x").mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "7"}),
            httpx.Response(200, json={}),
        ]
    )
    await gh.get("/x")
    assert sleeps.delays == [7.0]


@respx.mock
async def test_plain_403_and_4xx_not_retried(gh, sleeps):
    route = respx.get(f"{API}/x").mock(
        return_value=httpx.Response(403, json={"message": "Resource not accessible"})
    )
    with pytest.raises(GitHubError) as ei:
        await gh.get("/x")
    assert ei.value.status == 403
    assert route.call_count == 1 and sleeps.delays == []

    respx.get(f"{API}/y").mock(return_value=httpx.Response(422, json={"message": "bad"}))
    with pytest.raises(GitHubError, match="422"):
        await gh.get("/y")


@respx.mock
async def test_404_raises_not_found(gh):
    respx.get(f"{API}/x").mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
    with pytest.raises(NotFound) as ei:
        await gh.get("/x")
    assert ei.value.url == f"{API}/x"


@respx.mock
async def test_request_post_json(gh):
    route = respx.post(f"{API}/repos/o/r/issues").mock(
        return_value=httpx.Response(201, json={"number": 9})
    )
    assert await gh.request("post", "/repos/o/r/issues", json={"title": "t"}) == {"number": 9}
    assert route.calls.last.request.content == b'{"title":"t"}'


@respx.mock
async def test_transport_error_retried(gh, sleeps):
    respx.get(f"{API}/x").mock(
        side_effect=[httpx.ConnectError("boom"), httpx.Response(200, json=1)]
    )
    assert await gh.get("/x") == 1
    assert len(sleeps.delays) == 1
