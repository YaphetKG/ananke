"""Source protocol for remote feeds: fetch_open(repo) -> list[Finding]; fetch_by_keys(keys).

Stub: implemented in milestone M0.
"""

MILESTONE = "M0"


def __getattr__(name: str):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"{__name__}.{name} is implemented in milestone M0")
