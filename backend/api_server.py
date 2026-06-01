"""
Project-root compatibility HTTP API launcher.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import sys
from pathlib import Path


_SRC_DIR = Path(__file__).resolve().parent / "src"
if not getattr(sys, "frozen", False) and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from avikal_backend.api.server import *  # noqa: F401,F403
from avikal_backend.api.server import start_server
from avikal_backend.runtime_requirements import ensure_native_crypto_runtime


if __name__ == "__main__":
    if "--verify-native-runtime" in sys.argv:
        try:
            ensure_native_crypto_runtime("Avikal packaged backend")
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            raise SystemExit(1) from exc
        raise SystemExit(0)
    start_server()
