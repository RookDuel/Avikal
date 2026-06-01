"""Private runtime workspace helpers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
from pathlib import Path


def ensure_private_dir(path: str | os.PathLike[str]) -> Path:
    resolved = Path(path).resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(resolved, 0o700)
    except OSError:
        # Windows ACL hardening is best-effort here; the directory is still per-user.
        pass
    return resolved
