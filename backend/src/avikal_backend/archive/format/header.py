"""
Avk archive header handling.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import struct


HEADER_MAGIC = b"AVK2"
HEADER_FORMAT_VERSION = 0x01
HEADER_STRUCTURE_ID = 0x01
HEADER_SIZE = 8
HEADER_FILENAME = "header.bin"

ARCHIVE_MODE_SINGLE = 0x01
ARCHIVE_MODE_MULTI = 0x02

PROVIDER_ID_NONE = 0x00
PROVIDER_ID_DRAND = 0x02
PROVIDER_ID_AAVRIT = 0x03

_VALID_ARCHIVE_MODES = {ARCHIVE_MODE_SINGLE, ARCHIVE_MODE_MULTI}
_VALID_PROVIDER_IDS = {PROVIDER_ID_NONE, PROVIDER_ID_DRAND, PROVIDER_ID_AAVRIT}


def provider_name_to_id(provider: str | None) -> int:
    normalized = (provider or "").strip().lower()
    if not normalized:
        return PROVIDER_ID_NONE
    if normalized == "drand":
        return PROVIDER_ID_DRAND
    if normalized == "aavrit":
        return PROVIDER_ID_AAVRIT
    raise ValueError(f"Unsupported time-capsule provider: {provider}")


def provider_id_to_name(provider_id: int) -> str | None:
    if provider_id == PROVIDER_ID_NONE:
        return None
    if provider_id == PROVIDER_ID_DRAND:
        return "drand"
    if provider_id == PROVIDER_ID_AAVRIT:
        return "aavrit"
    raise ValueError(f"Unsupported provider_id: {provider_id}")


def build_header_bytes(*, archive_mode: int, provider_id: int) -> bytes:
    if archive_mode not in _VALID_ARCHIVE_MODES:
        raise ValueError(f"Invalid archive_mode: {archive_mode}")
    if provider_id not in _VALID_PROVIDER_IDS:
        raise ValueError(f"Invalid provider_id: {provider_id}")

    return struct.pack(
        ">4sBBBB",
        HEADER_MAGIC,
        HEADER_FORMAT_VERSION,
        archive_mode,
        HEADER_STRUCTURE_ID,
        provider_id,
    )


def parse_header_bytes(header_bytes: bytes) -> dict:
    if not isinstance(header_bytes, (bytes, bytearray)):
        raise ValueError("Invalid Avk header: header must be bytes")
    if len(header_bytes) != HEADER_SIZE:
        raise ValueError("Invalid Avk header: header size is out of bounds")

    magic, format_version, archive_mode, structure_id, provider_id = struct.unpack(
        ">4sBBBB",
        bytes(header_bytes),
    )

    if magic != HEADER_MAGIC:
        raise ValueError("Invalid Avk header: magic mismatch")
    if format_version != HEADER_FORMAT_VERSION:
        raise ValueError("Invalid Avk header: unsupported format version")
    if archive_mode not in _VALID_ARCHIVE_MODES:
        raise ValueError("Invalid Avk header: archive mode is invalid")
    if structure_id != HEADER_STRUCTURE_ID:
        raise ValueError("Invalid Avk header: structure identifier is invalid")
    if provider_id not in _VALID_PROVIDER_IDS:
        raise ValueError("Invalid Avk header: provider identifier is invalid")

    return {
        "magic": magic.decode("ascii"),
        "format_version": format_version,
        "archive_mode": archive_mode,
        "structure_id": structure_id,
        "provider_id": provider_id,
        "provider": provider_id_to_name(provider_id),
        "aad": bytes(header_bytes),
    }


def validate_metadata_against_header(header_info: dict, metadata: dict) -> None:
    archive_mode = header_info.get("archive_mode")
    provider = header_info.get("provider")

    archive_type = metadata.get("archive_type")
    metadata_provider = metadata.get("timecapsule_provider")

    if archive_mode == ARCHIVE_MODE_MULTI:
        if archive_type != "multi_file":
            raise ValueError("Header and metadata disagree about archive mode")
    elif archive_type not in {None, "single_file"}:
        raise ValueError("Header and metadata disagree about archive mode")

    if provider is None:
        if metadata_provider is not None:
            raise ValueError("Header and metadata disagree about provider")
        return

    if provider != metadata_provider:
        raise ValueError("Header and metadata disagree about provider")
