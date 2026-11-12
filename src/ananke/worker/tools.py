"""Agent tools: run_command, advisory_details, package_release_notes, scan_workspace, report_result.

Stub: implemented in milestone M1.
"""

MILESTONE = "M1"


def __getattr__(name: str):
    if name.startswith("__"):
        raise AttributeError(name)
    raise NotImplementedError(f"{__name__}.{name} is implemented in milestone M1")
