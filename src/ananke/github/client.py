"""Thin httpx GitHub REST wrapper with retries, rate-limit handling and ETag caching.

    client = GitHubClient(auth, api_url=cfg.github.api_url)
    alerts = await client.get_paginated("/repos/RENCI/x/dependabot/alerts", {"state": "open"})

- Retries (exponential, jittered, capped backoff) on transport errors, 5xx, 429, and 403 that
  is a rate limit (`x-ratelimit-remaining: 0` -> sleep until `x-ratelimit-reset`; or a
  `retry-after` header, which GitHub sends for secondary rate limits). Other 4xx are not retried.
- GETs carry `If-None-Match` from an in-memory ETag cache keyed by URL + params; a 304 returns
  the cached body (304s do not count against the primary rate limit).
- Errors raise `GitHubError(status, message, url)`; 404 raises `NotFound`.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from ananke.github.auth import GitHubAuth
from ananke.logging import get_logger

log = get_logger(__name__)

API_VERSION = "2022-11-28"
BACKOFF_BASE_S = 1.0
BACKOFF_CAP_S = 60.0
RATE_LIMIT_MAX_SLEEP_S = 3600.0

_LINK_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')


class GitHubError(Exception):
    """A GitHub API call failed."""

    def __init__(self, status: int, message: str, url: str) -> None:
        super().__init__(f"GitHub API {status} for {url}: {message}")
        self.status = status
        self.message = message
        self.url = url


class NotFound(GitHubError):
    """404 from the GitHub API."""


@dataclass
class _CacheEntry:
    etag: str
    body: Any
    link: str | None


def parse_next_link(link_header: str | None) -> str | None:
    """The `rel="next"` URL from an RFC 5988 Link header, or None."""
    if not link_header:
        return None
    for part in link_header.split(","):
        m = _LINK_NEXT.search(part)
        if m:
            return m.group(1)
    return None


class GitHubClient:
    """Async GitHub REST client. Pass an `httpx.AsyncClient` to control transport/lifetime."""

    def __init__(
        self,
        auth: GitHubAuth,
        *,
        api_url: str = "https://api.github.com",
        client: httpx.AsyncClient | None = None,
        max_retries: int = 4,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        clock: Callable[[], float] = time.time,
        timeout: float = 30.0,
    ) -> None:
        self.auth = auth
        self.api_url = api_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self.max_retries = max_retries
        self._sleep = sleep
        self._clock = clock
        self._etags: dict[str, _CacheEntry] = {}

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # -- public API ---------------------------------------------------------------------------

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET `path` (relative to api_url, or absolute URL) and return the decoded JSON."""
        body, _ = await self._send("GET", path, params=params)
        return body

    async def get_paginated(
        self, path: str, params: dict[str, Any] | None = None, per_page: int = 100
    ) -> list[Any]:
        """GET every page (following `Link: rel="next"`) and concatenate the list bodies."""
        items: list[Any] = []
        url: str | None = path
        page_params: dict[str, Any] | None = {**(params or {}), "per_page": per_page}
        while url:
            body, headers = await self._send("GET", url, params=page_params)
            if isinstance(body, list):
                items.extend(body)
            elif body is not None:
                items.append(body)
            url = parse_next_link(headers.get("link"))
            page_params = None  # the next URL already carries the query string
        return items

    async def request(
        self,
        method: str,
        path: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Any method (POST/PATCH/PUT/DELETE for PR and issue writes). Returns decoded JSON."""
        body, _ = await self._send(method.upper(), path, params=params, json=json)
        return body

    # -- internals ----------------------------------------------------------------------------

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return f"{self.api_url}/{path.lstrip('/')}"

    @staticmethod
    def _cache_key(url: str, params: dict[str, Any] | None) -> str:
        if not params:
            return url
        return f"{url}?{urlencode(sorted((k, str(v)) for k, v in params.items()))}"

    def _backoff(self, attempt: int) -> float:
        """Full-jitter-ish exponential backoff: base*2^attempt, jittered 50-100%, capped."""
        delay = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2**attempt))
        return delay * (0.5 + random.random() / 2)

    def _rate_limit_delay(self, resp: httpx.Response, attempt: int) -> float | None:
        """Seconds to wait if `resp` is a rate-limit response, else None."""
        retry_after = resp.headers.get("retry-after")
        if resp.status_code in (403, 429) and retry_after is not None:
            try:
                return min(RATE_LIMIT_MAX_SLEEP_S, max(0.0, float(retry_after)))
            except ValueError:
                return self._backoff(attempt)
        if resp.status_code in (403, 429) and resp.headers.get("x-ratelimit-remaining") == "0":
            reset = resp.headers.get("x-ratelimit-reset")
            try:
                wait = float(reset) - self._clock() + 1 if reset is not None else None
            except ValueError:
                wait = None
            if wait is None:
                return self._backoff(attempt)
            return min(RATE_LIMIT_MAX_SLEEP_S, max(0.0, wait))
        if resp.status_code == 429:
            return self._backoff(attempt)
        return None

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> tuple[Any, httpx.Headers]:
        url = self._url(path)
        cache_key = self._cache_key(url, params) if method == "GET" else None
        reauthed = False
        attempt = 0
        while True:
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "Authorization": f"Bearer {await self.auth.token()}",
            }
            cached = self._etags.get(cache_key) if cache_key else None
            if cached:
                headers["If-None-Match"] = cached.etag
            try:
                resp = await self._client.request(
                    method, url, params=params, json=json, headers=headers
                )
            except httpx.TransportError as e:
                if attempt >= self.max_retries:
                    raise GitHubError(0, f"transport error: {e.__class__.__name__}", url) from e
                delay = self._backoff(attempt)
                log.warning(
                    "github_retry",
                    url=url,
                    reason=e.__class__.__name__,
                    attempt=attempt + 1,
                    delay_s=round(delay, 2),
                )
                await self._sleep(delay)
                attempt += 1
                continue

            status = resp.status_code
            if status == 304 and cached is not None:
                return cached.body, httpx.Headers({"link": cached.link} if cached.link else {})
            if status < 300:
                body = resp.json() if resp.content else None
                etag = resp.headers.get("etag")
                if cache_key and etag:
                    self._etags[cache_key] = _CacheEntry(etag, body, resp.headers.get("link"))
                return body, resp.headers

            if status == 401 and self.auth.mode == "app" and not reauthed:
                self.auth.invalidate()  # installation token may have been revoked/expired early
                reauthed = True
                continue

            delay = self._rate_limit_delay(resp, attempt)
            if delay is None and status >= 500:
                delay = self._backoff(attempt)
            if delay is not None and attempt < self.max_retries:
                log.warning(
                    "github_retry",
                    url=url,
                    status=status,
                    attempt=attempt + 1,
                    delay_s=round(delay, 2),
                )
                await self._sleep(delay)
                attempt += 1
                continue

            message = _message(resp)
            if status == 404:
                raise NotFound(status, message, url)
            raise GitHubError(status, message, url)


def _message(resp: httpx.Response) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict) and "message" in data:
            return str(data["message"])
    except Exception:
        pass
    return resp.text[:200] or resp.reason_phrase
