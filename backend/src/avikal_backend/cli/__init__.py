"""
Public CLI package for the Avikal backend.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from .main import main
from .parser import build_parser

__all__ = ["build_parser", "main"]
