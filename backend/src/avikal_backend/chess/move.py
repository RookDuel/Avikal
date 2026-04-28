"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations
from dataclasses import dataclass
from .constants import FILES, RANKS


Square = int

def file_of(square: Square) -> int:
    return square % 8

def rank_of(square: Square) -> int:
    return square // 8

def to_square(file_index: int, rank_index: int) -> Square:
    return rank_index * 8 + file_index

def square_name(square: Square) -> str:
    return f"{FILES[file_of(square)]}{RANKS[rank_of(square)]}"

def parse_square(name: str) -> Square:
    if len(name) != 2 or name[0] not in FILES or name[1] not in RANKS:
        raise ValueError(f"invalid square: {name!r}")
    return to_square(FILES.index(name[0]), RANKS.index(name[1]))


@dataclass(frozen=True, slots=True)
class Move:
    from_square: Square
    to_square: Square
    promotion: str | None = None

    def uci(self) -> str:
        token = f"{square_name(self.from_square)}{square_name(self.to_square)}"
        return token if self.promotion is None else token + self.promotion.lower()

    @classmethod
    def from_uci(cls, token: str) -> "Move":
        if len(token) not in (4, 5):
            raise ValueError(f"invalid uci move: {token!r}")
        promotion = token[4].lower() if len(token) == 5 else None
        return cls(parse_square(token[:2]), parse_square(token[2:4]), promotion)

    def __str__(self) -> str:
        return self.uci()
"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""
