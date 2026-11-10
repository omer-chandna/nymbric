"""Runtime metadata recorded with an experiment. GPU details are included only when visible."""

from __future__ import annotations

import importlib.metadata
import os
import platform
import shutil
import subprocess
from typing import Any

from nymbric import __version__


def runtime_metadata() -> dict[str, Any]:
    gpu = None
    if shutil.which("nvidia-smi"):
        try:
            completed = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if completed.returncode == 0 and completed.stdout.strip():
                gpu = completed.stdout.strip().splitlines()[0]
        except (OSError, subprocess.TimeoutExpired):
            gpu = None
    packages = {}
    for name in ("pydantic", "fastapi", "networkx", "httpx", "typer"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return {
        "nymbric_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "gpu": gpu,
        "packages": packages,
    }
