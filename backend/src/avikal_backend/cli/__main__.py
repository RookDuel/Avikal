"""
Allow running as: python -m avikal_backend.cli

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import sys

from .main import main


if __name__ == "__main__":
    sys.exit(main())
