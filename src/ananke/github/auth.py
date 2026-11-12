"""GitHub authentication: App installation tokens (preferred) or a PAT fallback (PLAN.md §11).

    auth = GitHubAuth.from_config(cfg.github)
    token = await auth.token()

App mode mints an RS256 JWT (iss=app_id, iat=now-60, exp=now+9min) and exchanges it at
POST {api_url}/app/installations/{installation_id}/access_tokens. The installation token is
cached until 60 s before its `expires_at`. Token values are never logged.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import httpx
import jwt

from ananke.logging import get_logger

if TYPE_CHECKING:
    from ananke.config import GitHubConfig

log = get_logger(__name__)

AuthMode = Literal["app", "token", "none"]

JWT_BACKDATE_S = 60
JWT_LIFETIME_S = 9 * 60
TOKEN_REFRESH_MARGIN_S = 60
_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


class AuthError(Exception):
    """Auth is not configured or the token exchange failed."""


class GitHubAuth:
    """Produces bearer tokens for the GitHub REST API."""

    def __init__(
        self,
        mode: AuthMode,
        *,
        api_url: str = "https://api.github.com",
        app_id: str | None = None,
        installation_id: str | None = None,
        private_key: str | None = None,
        pat: str | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if mode == "app" and not (app_id and installation_id and private_key):
            raise AuthError("app auth needs app_id, installation_id and a private key")
        if mode == "token" and not pat:
            raise AuthError("token auth needs a non-empty token")
        self.mode: AuthMode = mode
        self.api_url = api_url.rstrip("/")
        self.app_id = app_id
        self.installation_id = installation_id
        self._private_key = private_key
        self._pat = pat
        self._client = client
        self._clock = clock
        self._cached: str | None = None
        self._cached_expiry: float = 0.0
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:  # never show secrets
        return f"GitHubAuth(mode={self.mode!r}, api_url={self.api_url!r}, app_id={self.app_id!r})"

    @classmethod
    def from_config(
        cls,
        cfg: GitHubConfig,
        *,
        private_key: str | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
    ) -> GitHubAuth:
        """Build from `cfg.github`; `private_key` (PEM text) overrides reading private_key_path."""
        mode = cfg.auth_mode
        if mode == "app":
            if private_key is None:
                path = Path(str(cfg.private_key_path)).expanduser()
                try:
                    private_key = path.read_text(encoding="utf-8")
                except OSError as e:
                    raise AuthError(f"cannot read GitHub App private key at {path}: {e}") from e
            return cls(
                "app",
                api_url=cfg.api_url,
                app_id=str(cfg.app_id),
                installation_id=str(cfg.installation_id),
                private_key=private_key,
                client=client,
                clock=clock,
            )
        if mode == "token":
            assert cfg.token is not None
            return cls(
                "token",
                api_url=cfg.api_url,
                pat=cfg.token.get_secret_value(),
                client=client,
                clock=clock,
            )
        return cls("none", api_url=cfg.api_url, client=client, clock=clock)

    def app_jwt(self) -> str:
        """An RS256 JWT identifying the App (valid ~9 minutes)."""
        if self.mode != "app":
            raise AuthError("app_jwt() is only available in app auth mode")
        now = int(self._clock())
        payload = {"iat": now - JWT_BACKDATE_S, "exp": now + JWT_LIFETIME_S, "iss": self.app_id}
        return jwt.encode(payload, self._private_key, algorithm="RS256")  # type: ignore[arg-type]

    async def token(self) -> str:
        """A bearer token for API calls."""
        if self.mode == "token":
            return self._pat  # type: ignore[return-value]
        if self.mode == "none":
            raise AuthError(
                "GitHub auth is not configured: set github.app_id/installation_id/"
                "private_key_path (GitHub App) or github.token (PAT)"
            )
        async with self._lock:
            if self._cached and self._clock() < self._cached_expiry - TOKEN_REFRESH_MARGIN_S:
                return self._cached
            self._cached, self._cached_expiry = await self._exchange()
            return self._cached

    def invalidate(self) -> None:
        """Drop the cached installation token (e.g. after a 401)."""
        self._cached = None
        self._cached_expiry = 0.0

    async def _exchange(self) -> tuple[str, float]:
        url = f"{self.api_url}/app/installations/{self.installation_id}/access_tokens"
        headers = {**_HEADERS, "Authorization": f"Bearer {self.app_jwt()}"}
        client = self._client or httpx.AsyncClient(timeout=30)
        try:
            resp = await client.post(url, headers=headers)
        except httpx.HTTPError as e:
            raise AuthError(f"installation token exchange failed: {e.__class__.__name__}") from e
        finally:
            if self._client is None:
                await client.aclose()
        if resp.status_code != 201 and resp.status_code != 200:
            msg = _error_message(resp)
            log.error("github_token_exchange_failed", status=resp.status_code, message=msg)
            raise AuthError(f"installation token exchange failed: HTTP {resp.status_code}: {msg}")
        data = resp.json()
        token = data.get("token")
        if not token:
            raise AuthError("installation token exchange returned no token")
        expires_at = data.get("expires_at")
        if expires_at:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
        else:
            expiry = self._clock() + 3600
        log.info(
            "github_installation_token_minted",
            installation_id=self.installation_id,
            expires_at=expires_at,
        )
        return token, expiry


def _error_message(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("message", ""))[:200]
    except Exception:
        return resp.text[:200]
