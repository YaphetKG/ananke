"""Load a repo's ANANKE.md (front matter via config.parse_repo_workflow) and
strict-render its Jinja2 prompt body (StrictUndefined).

Stub: implemented in milestone M0.
"""

MILESTONE = "M0"


def __getattr__(name: str):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"{__name__}.{name} is implemented in milestone M0")
