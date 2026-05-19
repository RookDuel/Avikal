"""
Runtime path helpers for source and frozen desktop builds.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_internal_root() -> Path:
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass).resolve()
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def backend_root() -> Path:
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def project_root() -> Path:
    if is_frozen():
        return backend_root().parent
    return backend_root().parent


def drand_helper_path() -> Path:
    return bundle_internal_root() / "scripts" / "drand_timelock_helper.mjs"
