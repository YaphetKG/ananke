"""Ananke test fixture package. Intentionally depends on vulnerable versions."""

import requests

__all__ = ["build_request"]


def build_request(url: str, token: str | None = None) -> requests.PreparedRequest:
    """Prepare (but never send) a GET request, optionally with a bearer token."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.Request("GET", url, headers=headers).prepare()
