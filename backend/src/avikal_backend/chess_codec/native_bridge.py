"""Native Chess-PGN codec bridge.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from typing import Any


NATIVE_IMPORT_ERROR: Exception | None = None

try:
    from .. import _native as native_module
except Exception as exc:  # pragma: no cover - depends on local native build
    native_module = None
    NATIVE_IMPORT_ERROR = exc


def native_chess_available() -> bool:
    return (
        native_module is not None
        and hasattr(native_module, "encode_chess_pgn_integer")
        and hasattr(native_module, "decode_chess_pgn_integer")
    )


def require_native_chess_available() -> None:
    if not native_chess_available():
        raise RuntimeError(
            "Avikal native Chess-PGN codec is not available. "
            "Rebuild the backend extension before enabling native codec routing."
        ) from NATIVE_IMPORT_ERROR


def native_encode_chess_pgn_integer(num: int, variations_per_round: int = 5) -> tuple[str, dict[str, Any]]:
    require_native_chess_available()
    if not isinstance(num, int) or num < 1:
        raise ValueError("NUM must be >= 1")
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
    pgn_text, stats = native_module.encode_chess_pgn_integer(num_bytes, int(variations_per_round))
    return str(pgn_text), dict(stats)


def native_decode_chess_pgn_integer(pgn_text: str) -> tuple[int, dict[str, Any]]:
    require_native_chess_available()
    if not isinstance(pgn_text, str) or not pgn_text.strip():
        raise ValueError("Invalid PGN")
    try:
        num_bytes, stats = native_module.decode_chess_pgn_integer(pgn_text)
    except ValueError as exc:
        raise ValueError(f"Invalid PGN move stream: {exc}") from exc
    return int.from_bytes(bytes(num_bytes), byteorder="big"), dict(stats)
