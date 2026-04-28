"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

WHITE = True
BLACK = False

COLORS = (WHITE, BLACK)

FILES = "abcdefgh"
RANKS = "12345678"

STARTING_FEN = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"

PROMOTION_PIECES = ("q", "r", "b", "n")

KNIGHT_DELTAS = (
    (1, 2),
    (2, 1),
    (2, -1),
    (1, -2),
    (-1, -2),
    (-2, -1),
    (-2, 1),
    (-1, 2),
)

KING_DELTAS = (
    (-1, -1),
    (0, -1),
    (1, -1),
    (-1, 0),
    (1, 0),
    (-1, 1),
    (0, 1),
    (1, 1),
)

ROOK_RAYS = ((1, 0), (-1, 0), (0, 1), (0, -1))
BISHOP_RAYS = ((1, 1), (1, -1), (-1, 1), (-1, -1))
QUEEN_RAYS = ROOK_RAYS + BISHOP_RAYS

PIECE_ORDER = {"K": 0, "Q": 1, "R": 2, "B": 3, "N": 4, "P": 5}
"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""
