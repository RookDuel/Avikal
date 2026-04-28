"""
Adaptive Brotli compression for Avikal format.
Optimized to avoid wasting CPU on already-compressed inputs.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import os

import brotli


FIXED_MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB hard safety ceiling

INCOMPRESSIBLE_EXTENSIONS = {
    ".7z", ".aac", ".apk", ".avif", ".avk", ".br", ".bz2", ".cab", ".docx",
    ".epub", ".exe", ".gif", ".gz", ".iso", ".jar", ".jpeg", ".jpg", ".m4a",
    ".mkv", ".mov", ".mp3", ".mp4", ".odt", ".ogg", ".pdf", ".png", ".pptx",
    ".rar", ".svgz", ".vsix", ".webm", ".webp", ".xlsx", ".zip", ".zst",
}


def _choose_brotli_quality(data_length: int, source_name: str = None, hint: str = None) -> int:
    """Pick a faster Brotli quality without changing the archive format."""
    if source_name:
        extension = os.path.splitext(source_name)[1].lower()
        if extension in INCOMPRESSIBLE_EXTENSIONS:
            return 1

    if hint == "container":
        if data_length >= 128 * 1024 * 1024:
            return 2
        if data_length >= 32 * 1024 * 1024:
            return 3
        if data_length >= 8 * 1024 * 1024:
            return 4
        return 5

    if data_length >= 128 * 1024 * 1024:
        return 2
    if data_length >= 32 * 1024 * 1024:
        return 3
    if data_length >= 8 * 1024 * 1024:
        return 4
    if data_length >= 1 * 1024 * 1024:
        return 6
    return 8


def compress_data(data: bytes, source_name: str = None, hint: str = None) -> bytes:
    """
    Compress using adaptive Brotli quality.

    Args:
        data: Raw bytes to compress
        source_name: Optional source filename for compression heuristics
        hint: Optional logical hint such as "container"

    Returns:
        Compressed bytes
    """
    quality = _choose_brotli_quality(len(data), source_name=source_name, hint=hint)
    return brotli.compress(data, quality=quality)


def decompress_data(data: bytes, max_size: int = None) -> bytes:
    """
    Decompress Brotli compressed data with a fixed safety ceiling.

    Args:
        data: Compressed bytes
        max_size: Maximum allowed decompressed size

    Returns:
        Original decompressed bytes

    Raises:
        ValueError: If decompressed size exceeds max_size (compression bomb protection)
    """
    if max_size is None:
        max_size = FIXED_MAX_DECOMPRESSED_SIZE

    try:
        decompressed = brotli.decompress(data)
    except Exception as e:
        raise ValueError(f"Decompression failed: {str(e)}")

    if len(decompressed) > max_size:
        max_size_gb = max_size / (1024 * 1024 * 1024)
        decompressed_gb = len(decompressed) / (1024 * 1024 * 1024)
        raise ValueError(
            f"Decompression bomb detected! "
            f"Decompressed size ({decompressed_gb:.2f} GB) exceeds the built-in safety limit ({max_size_gb:.2f} GB). "
            f"This may be a malicious file or an unsupported oversized payload."
        )

    # Highly compressible data can still be legitimate; this guard only trips on extreme ratios.
    if len(data) > 0:
        ratio = len(decompressed) / len(data)
        if ratio > 100000:
            raise ValueError(
                f"Extreme compression ratio detected: {ratio:.0f}:1. "
                f"This may be a compression bomb attack."
            )

    return decompressed
