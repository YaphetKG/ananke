"""Deep Agent construction (create_deep_agent) and cap middleware; model comes from ananke.llm only.

Stub: implemented in milestone M1.
"""

MILESTONE = "M1"


def __getattr__(name: str):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"{__name__}.{name} is implemented in milestone M1")
