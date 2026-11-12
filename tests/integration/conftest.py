"""Integration tests: need a Docker daemon.

Mark with @pytest.mark.docker (deselected by default).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if docker_available():
        return
    skip = pytest.mark.skip(reason="no reachable Docker daemon")
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)
