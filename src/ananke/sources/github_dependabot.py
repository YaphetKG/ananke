"""Dependabot alerts source: GET /repos/{o}/{r}/dependabot/alerts?state=open -> Finding.

Stub: implemented in milestone M0.
"""

MILESTONE = "M0"


def __getattr__(name: str):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"{__name__}.{name} is implemented in milestone M0")
