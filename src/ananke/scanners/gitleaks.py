"""gitleaks scanner plugin: `gitleaks detect --no-git --report-format json`; parse() is pure.

Stub: implemented in milestone M0.
"""

MILESTONE = "M0"


def __getattr__(name: str):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"{__name__}.{name} is implemented in milestone M0")
