"""
Short launcher for the Avikal CLI.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import sys
from pathlib import Path


_SRC_DIR = Path(__file__).resolve().parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from avikal_backend.cli.main import main


if __name__ == "__main__":
    sys.exit(main())
