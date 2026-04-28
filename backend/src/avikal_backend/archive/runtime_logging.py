"""
Runtime logging helpers for backend archive operations.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import builtins
import os


def _verbose_runtime_enabled() -> bool:
    flag = os.getenv("AVIKAL_VERBOSE_LOGS", "").strip().lower()
    if flag in {"1", "true", "yes", "on"}:
        return True

    node_env = os.getenv("NODE_ENV", "").strip().lower()
    return node_env == "development"


def runtime_debug_print(*args, **kwargs) -> None:
    if _verbose_runtime_enabled():
        builtins.print(*args, **kwargs)
