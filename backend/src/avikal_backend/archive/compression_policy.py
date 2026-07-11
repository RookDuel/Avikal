"""Shared adaptive compression policy for current archive writers."""

from __future__ import annotations

import os
import zlib


ADAPTIVE_COMPRESSION_SAMPLE_BYTES = 4 * 1024 * 1024
ADAPTIVE_COMPRESSION_MIN_BYTES = 64 * 1024 * 1024
ADAPTIVE_COMPRESSION_MIN_SAVINGS_RATIO = 0.03

COMPRESSED_EXTENSIONS = frozenset(
    {
        ".7z",
        ".apk",
        ".avif",
        ".br",
        ".bz2",
        ".cab",
        ".deb",
        ".docx",
        ".dll",
        ".dmg",
        ".exe",
        ".gz",
        ".heic",
        ".heif",
        ".img",
        ".iso",
        ".jpeg",
        ".jpg",
        ".m4a",
        ".m4v",
        ".mov",
        ".mp3",
        ".mp4",
        ".msi",
        ".msix",
        ".msixbundle",
        ".ogg",
        ".pdf",
        ".pkg",
        ".png",
        ".rar",
        ".rpm",
        ".vhd",
        ".vhdx",
        ".webm",
        ".webp",
        ".xlsx",
        ".xz",
        ".zip",
        ".zst",
    }
)


def choose_payload_compression(
    *,
    input_path: str | None = None,
    total_input_size: int | None = None,
    sample_bytes: bytes | None = None,
    force_compress: bool | None = None,
    minimum_input_bytes: int = ADAPTIVE_COMPRESSION_MIN_BYTES,
    minimum_savings_ratio: float = ADAPTIVE_COMPRESSION_MIN_SAVINGS_RATIO,
) -> dict:
    """Return a bounded, deterministic compression decision."""
    if total_input_size is not None and total_input_size < 0:
        raise ValueError("Payload input size must be non-negative")
    if force_compress is not None:
        return {"enabled": bool(force_compress), "reason": "forced", "sample_ratio": None}

    extension = os.path.splitext(input_path or "")[1].lower()
    if extension in COMPRESSED_EXTENSIONS:
        return {"enabled": False, "reason": "extension", "sample_ratio": None}

    if total_input_size is not None and total_input_size < minimum_input_bytes:
        return {"enabled": True, "reason": "small_input", "sample_ratio": None}

    if sample_bytes:
        compressed = zlib.compress(sample_bytes, level=1)
        ratio = len(compressed) / len(sample_bytes)
        return {
            "enabled": (1.0 - ratio) >= minimum_savings_ratio,
            "reason": "sample",
            "sample_ratio": ratio,
        }

    return {"enabled": True, "reason": "default", "sample_ratio": None}
