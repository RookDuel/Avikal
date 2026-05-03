"""
Current Avikal metadata packing helpers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import hashlib
import struct

from ..path_safety import normalize_single_archive_filename
from ..security.key_wrap import PAYLOAD_KEY_WRAP_ALGORITHM


METADATA_FORMAT_VERSION = 0x01
MAX_METADATA_SIZE = 10 * 1024


def pack_cascade_metadata(
    salt: bytes,
    pqc_ciphertext: bytes,
    pqc_private_key: bytes,
    unlock_timestamp: int,
    filename: str,
    checksum: bytes,
    encryption_method: str,
    keyphrase_protected: bool = False,
    chess_salt: bytes = None,
    timelock_mode: str = "convenience",
    file_id: str = None,
    server_url: str = None,
    time_key_hash: bytes = None,
    timecapsule_provider: str = None,
    aavrit_data_hash: str = None,
    aavrit_commit_hash: str = None,
    aavrit_server_key_id: str = None,
    aavrit_commit_signature: str = None,
    drand_round: int = None,
    drand_chain_hash: str = None,
    drand_chain_url: str = None,
    drand_ciphertext: str = None,
    drand_beacon_id: str = None,
    pqc_required: bool = False,
    pqc_algorithm: str = None,
    pqc_key_id: str = None,
    keyphrase_format_version: int = None,
    keyphrase_wordlist_id: str = None,
    archive_type: str = None,
    entry_count: int = None,
    total_original_size: int = None,
    manifest_hash: bytes = None,
    payload_key_wrap_algorithm: str = None,
    wrapped_payload_key: bytes = None,
) -> bytes:
    """
    Pack current public metadata format v1.

    The v1 layout always includes the full field set. Inactive optional fields
    are encoded as empty values instead of selecting older layouts.
    """
    if len(salt) != 32:
        raise ValueError("Payload salt must be 32 bytes")
    if len(checksum) != 32:
        raise ValueError("Checksum must be 32 bytes (SHA-256)")

    if chess_salt is None:
        chess_salt = hashlib.sha256(b"avikal_chess_v1").digest()
    elif len(chess_salt) != 32:
        raise ValueError("Chess salt must be 32 bytes")

    filename = normalize_single_archive_filename(filename)
    filename_bytes = filename.encode("utf-8")
    if len(filename_bytes) > 255:
        raise ValueError("Filename too long (max 255 bytes UTF-8)")

    method_bytes = encryption_method.encode("utf-8")
    if len(method_bytes) > 255:
        raise ValueError("Encryption method name too long")

    pqc_ciphertext = pqc_ciphertext or b""
    pqc_private_key = pqc_private_key or b""
    wrapped_payload_key = wrapped_payload_key or b""

    if len(pqc_ciphertext) > 2048:
        raise ValueError("PQC ciphertext too large (max 2048 bytes)")
    if pqc_private_key:
        raise ValueError("PQC private key must not be embedded in archive metadata")
    if pqc_required:
        if not pqc_ciphertext:
            raise ValueError("PQC keyfile mode requires PQC ciphertext")
        if not pqc_algorithm:
            raise ValueError("PQC keyfile mode requires PQC algorithm")
        if not pqc_key_id:
            raise ValueError("PQC keyfile mode requires PQC key identifier")
    elif any(value is not None for value in [pqc_algorithm, pqc_key_id]) or pqc_ciphertext:
        raise ValueError("Inactive PQC fields must be empty")

    if archive_type not in {"multi_file", "single_file"}:
        raise ValueError("archive_type must be 'multi_file' or 'single_file'")
    if not isinstance(entry_count, int) or entry_count <= 0:
        raise ValueError("entry_count must be a positive integer")
    if not isinstance(total_original_size, int) or total_original_size < 0:
        raise ValueError("total_original_size must be a non-negative integer")
    if not isinstance(manifest_hash, (bytes, bytearray)) or len(manifest_hash) != 32:
        raise ValueError("manifest_hash must be 32 bytes")

    if keyphrase_protected:
        if keyphrase_format_version != 1:
            raise ValueError("Keyphrase-protected archives require keyphrase_format_version=1")
        if keyphrase_wordlist_id != "avikal-hi-2048-v1":
            raise ValueError("Keyphrase-protected archives require keyphrase_wordlist_id='avikal-hi-2048-v1'")
    else:
        if keyphrase_format_version not in {None, 0}:
            raise ValueError("Inactive keyphrase format field must be zero")
        if keyphrase_wordlist_id not in {None, ""}:
            raise ValueError("Inactive keyphrase wordlist field must be empty")
        keyphrase_format_version = 0
        keyphrase_wordlist_id = ""

    if wrapped_payload_key:
        if encryption_method == "plaintext_archive":
            raise ValueError("Plaintext archives cannot contain wrapped payload keys")
        if payload_key_wrap_algorithm != PAYLOAD_KEY_WRAP_ALGORITHM:
            raise ValueError(f"Wrapped payload keys require {PAYLOAD_KEY_WRAP_ALGORITHM}")
        if len(wrapped_payload_key) > 255:
            raise ValueError("Wrapped payload key too large")
    else:
        if payload_key_wrap_algorithm is not None:
            raise ValueError("Payload key wrap algorithm requires wrapped payload key material")
        payload_key_wrap_algorithm = ""

    flags = 0x01 if keyphrase_protected else 0x00
    packed = struct.pack(">BBB", METADATA_FORMAT_VERSION, flags, len(method_bytes))
    packed += method_bytes
    packed += salt
    packed += chess_salt
    packed += struct.pack(">I", len(pqc_ciphertext))
    packed += pqc_ciphertext
    packed += struct.pack(">I", 0)
    packed += struct.pack(">I", unlock_timestamp)
    packed += checksum
    packed += struct.pack(">B", len(filename_bytes))
    packed += filename_bytes

    packed += _pack_short_text(timelock_mode, 255, "Timelock mode")
    packed += _pack_short_text(file_id or "", 255, "File ID")
    packed += _pack_long_text(server_url or "", 65535, "Server URL")
    if time_key_hash:
        if len(time_key_hash) != 32:
            raise ValueError("Time key hash must be 32 bytes (SHA-256)")
        packed += struct.pack(">B", 1) + time_key_hash
    else:
        packed += struct.pack(">B", 0)

    packed += _pack_short_text(timecapsule_provider or "", 32, "Timecapsule provider")
    if drand_round is not None:
        packed += struct.pack(">BQ", 1, int(drand_round))
    else:
        packed += struct.pack(">B", 0)
    packed += _pack_short_text(drand_chain_hash or "", 255, "drand chain hash")
    packed += _pack_long_text(drand_chain_url or "", 65535, "drand chain URL")
    packed += _pack_long_text(drand_ciphertext or "", 65535, "drand ciphertext")
    packed += _pack_short_text(drand_beacon_id or "", 255, "drand beacon ID")

    packed += struct.pack(">B", 1 if pqc_required else 0)
    packed += _pack_short_text(pqc_algorithm or "", 64, "PQC algorithm")
    packed += _pack_short_text(pqc_key_id or "", 128, "PQC key identifier")

    packed += _pack_short_text(archive_type, 32, "Archive type")
    packed += struct.pack(">IQ", entry_count, total_original_size)
    packed += bytes(manifest_hash)

    packed += struct.pack(">B", keyphrase_format_version)
    packed += _pack_short_text(keyphrase_wordlist_id, 64, "Keyphrase wordlist identifier")

    packed += _pack_short_text(aavrit_data_hash or "", 128, "Aavrit data hash")
    packed += _pack_short_text(aavrit_commit_hash or "", 128, "Aavrit commit hash")
    packed += _pack_short_text(aavrit_server_key_id or "", 128, "Aavrit server key identifier")
    packed += _pack_long_text(aavrit_commit_signature or "", 1024, "Aavrit commit signature")

    packed += _pack_short_text(payload_key_wrap_algorithm, 64, "Payload key wrap algorithm")
    packed += struct.pack(">B", len(wrapped_payload_key))
    packed += wrapped_payload_key

    if len(packed) > MAX_METADATA_SIZE:
        raise ValueError(
            f"Metadata size ({len(packed)} bytes) exceeds maximum allowed ({MAX_METADATA_SIZE} bytes). "
            "This may indicate a malicious file or corrupted data."
        )

    return packed


def _pack_short_text(value: str, max_length: int, field_name: str) -> bytes:
    field_bytes = value.encode("utf-8")
    if len(field_bytes) > max_length or max_length > 255:
        raise ValueError(f"{field_name} too long")
    return struct.pack(">B", len(field_bytes)) + field_bytes


def _pack_long_text(value: str, max_length: int, field_name: str) -> bytes:
    field_bytes = value.encode("utf-8")
    if len(field_bytes) > max_length or max_length > 65535:
        raise ValueError(f"{field_name} too long")
    return struct.pack(">H", len(field_bytes)) + field_bytes
