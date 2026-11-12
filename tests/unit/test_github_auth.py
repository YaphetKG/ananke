"""GitHubAuth: App JWT minting + installation-token caching, PAT mode, none mode. Offline."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ananke.config import GitHubConfig
from ananke.github.auth import AuthError, GitHubAuth

API = "https://api.github.com"
TOKEN_URL = f"{API}/app/installations/42/access_tokens"
NOW = 1_800_000_000.0  # 2027-01-15T08:00:00Z


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def pem(rsa_key: rsa.RSAPrivateKey) -> str:
    return rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _iso(ts: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _app_cfg(tmp_path: Path, pem: str) -> GitHubConfig:
    key = tmp_path / "app.pem"
    key.write_text(pem)
    return GitHubConfig(app_id="1234", installation_id="42", private_key_path=key)


def test_app_jwt_claims(tmp_path, pem, rsa_key):
    auth = GitHubAuth.from_config(_app_cfg(tmp_path, pem), clock=Clock(NOW))
    assert auth.mode == "app"
    token = auth.app_jwt()
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    claims = jwt.decode(
        token,
        rsa_key.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims == {"iss": "1234", "iat": int(NOW) - 60, "exp": int(NOW) + 540}


@respx.mock
async def test_app_token_exchange_and_cache(tmp_path, pem, rsa_key):
    clock = Clock(NOW)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bearer = request.headers["Authorization"].removeprefix("Bearer ")
        claims = jwt.decode(
            bearer,
            rsa_key.public_key(),
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_iat": False},
        )
        assert claims["iss"] == "1234"
        assert request.headers["Accept"] == "application/vnd.github+json"
        seen.append(bearer)
        n = len(seen)
        return httpx.Response(
            201, json={"token": f"ghs_token{n}", "expires_at": _iso(clock.t + 3600)}
        )

    route = respx.post(TOKEN_URL).mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        auth = GitHubAuth.from_config(_app_cfg(tmp_path, pem), client=http, clock=clock)
        assert await auth.token() == "ghs_token1"
        clock.t += 3000  # still > 60 s before expiry
        assert await auth.token() == "ghs_token1"
        assert route.call_count == 1
        clock.t += 541  # within 60 s of expiry -> refresh
        assert await auth.token() == "ghs_token2"
        assert route.call_count == 2
        auth.invalidate()
        assert await auth.token() == "ghs_token3"


@respx.mock
async def test_app_token_exchange_failure(tmp_path, pem):
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(401, json={"message": "A JSON web token could not be decoded"})
    )
    async with httpx.AsyncClient() as http:
        auth = GitHubAuth.from_config(_app_cfg(tmp_path, pem), client=http)
        with pytest.raises(AuthError, match="401"):
            await auth.token()


def test_private_key_override_skips_file(pem):
    cfg = GitHubConfig(app_id="1", installation_id="2", private_key_path=Path("/nonexistent.pem"))
    auth = GitHubAuth.from_config(cfg, private_key=pem)
    assert auth.mode == "app"
    assert auth.app_jwt()


def test_missing_key_file_is_auth_error():
    cfg = GitHubConfig(app_id="1", installation_id="2", private_key_path=Path("/nonexistent.pem"))
    with pytest.raises(AuthError, match="private key"):
        GitHubAuth.from_config(cfg)


async def test_pat_mode():
    auth = GitHubAuth.from_config(GitHubConfig(token="ghp_secret"))
    assert auth.mode == "token"
    assert await auth.token() == "ghp_secret"
    assert "ghp_secret" not in repr(auth)


async def test_none_mode_raises():
    auth = GitHubAuth.from_config(GitHubConfig())
    assert auth.mode == "none"
    with pytest.raises(AuthError, match="not configured"):
        await auth.token()


@respx.mock
async def test_token_values_never_logged(tmp_path, pem, caplog):
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            201, json={"token": "ghs_supersecret", "expires_at": _iso(NOW + 3600)}
        )
    )
    caplog.set_level("DEBUG")
    async with httpx.AsyncClient() as http:
        auth = GitHubAuth.from_config(_app_cfg(tmp_path, pem), client=http, clock=Clock(NOW))
        await auth.token()
    assert "ghs_supersecret" not in caplog.text
    assert json.dumps("ghs_supersecret") not in caplog.text
