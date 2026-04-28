"""
Avikal Time-Locked File Format (.avk)
Hybrid encryption system combining chess-based steganography with traditional encryption.

Architecture:
- Large files: AES-256-GCM encryption (fast, efficient)
- Metadata/keys: Chess PGN steganography (innovative, time-locked)
- Time-locking: trusted UTC validation with timezone-safe unlock timestamps

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from .archive.pipeline.decoder import extract_avk_file
from .archive.pipeline.encoder import create_avk_file
from .archive.security.time_lock import datetime_to_timestamp, get_ist_now, get_trusted_now, timestamp_to_datetime
from .version import __version__

__all__ = [
    "create_avk_file",
    "extract_avk_file",
    "get_ist_now",
    "get_trusted_now",
    "datetime_to_timestamp",
    "timestamp_to_datetime",
    "__version__",
]
