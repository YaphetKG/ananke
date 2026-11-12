"""Policy filters, grouping into WorkItems, priority sort, state derivation from open PRs.

Stub: implemented in milestone M0.
"""

MILESTONE = "M0"


def __getattr__(name: str):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"{__name__}.{name} is implemented in milestone M0")
