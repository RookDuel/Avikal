"""
Core chess encoding/decoding components for Avikal format.
Self-contained implementation based on timecapsule algorithm.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from .encoder import ChessGenerator
from .decoder import PGNDecoder

__all__ = ['ChessGenerator', 'PGNDecoder']
