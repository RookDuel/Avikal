"""
Allow running as: python -m avikal_backend

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import sys
from .cli.main import main

if __name__ == '__main__':
    sys.exit(main())
