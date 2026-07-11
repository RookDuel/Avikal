"""Private runtime workspace helpers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
import csv
import subprocess
from pathlib import Path


def _windows_current_user_sid() -> str:
    result = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    row = next(csv.reader([result.stdout.strip()]), None)
    if not row or len(row) < 2 or not row[1].startswith("S-1-"):
        raise RuntimeError("Unable to determine the current Windows user SID")
    return row[1]


def _apply_windows_private_acl(path: Path) -> None:
    sid = _windows_current_user_sid()
    result = subprocess.run(
        [
            "icacls.exe",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:(OI)(CI)F",
            "/Q",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "ACL command failed").strip()
        raise RuntimeError(f"Unable to secure the private workspace: {detail}")


def ensure_private_dir(path: str | os.PathLike[str]) -> Path:
    resolved = Path(path).resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        _apply_windows_private_acl(resolved)
    else:
        os.chmod(resolved, 0o700)
    return resolved
