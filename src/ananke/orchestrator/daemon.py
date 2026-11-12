"""asyncio tick loop: claims, slots, retry queue, reconciliation, restart recovery.

Stub: implemented in milestone M3.
"""

MILESTONE = "M3"


def __getattr__(name: str):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"{__name__}.{name} is implemented in milestone M3")
