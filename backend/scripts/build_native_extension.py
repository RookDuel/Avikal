"""
Build the Avikal Rust extension module in-place for source-tree development.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _build_env() -> dict[str, str]:
    env = os.environ.copy()
    cargo_home = Path.home() / ".cargo" / "bin"
    if cargo_home.exists():
        env["PATH"] = str(cargo_home) + os.pathsep + env.get("PATH", "")
    return env


def main() -> None:
    command = [sys.executable, "setup.py", "build_ext", "--inplace"]
    subprocess.run(command, cwd=str(BACKEND_ROOT), check=True, env=_build_env())


if __name__ == "__main__":
    main()
