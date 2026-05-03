"""
Current Avikal metadata unpacking helpers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import struct

from .metadata_pack import METADATA_FORMAT_VERSION
from .metadata_validation import validate_cascade_metadata_dict


MAX_METADATA_SIZE = 16 * 1024


def unpack_cascade_metadata(packed: bytes) -> dict:
    """Unpack current public metadata format v1."""
    if len(packed) > MAX_METADATA_SIZE:
        raise ValueError(
            f"Metadata size ({len(packed)} bytes) exceeds maximum allowed ({MAX_METADATA_SIZE} bytes). "
            "This may be a malicious file designed to cause DOS attack."
        )
    if len(packed) < 3:
        raise ValueError("Metadata too short")

    reader = _MetadataReader(packed)
    version = reader.read_u8("metadata version")
    if version != METADATA_FORMAT_VERSION:
        raise ValueError(f"Unsupported metadata version: {version}")

    flags = reader.read_u8("metadata flags")
    keyphrase_protected = bool(flags & 0x01)
    encryption_method = reader.read_short_text("encryption method")
    salt = reader.read_bytes(32, "payload salt")
    chess_salt = reader.read_bytes(32, "chess salt")
    pqc_ciphertext = reader.read_length_prefixed_bytes(">I", "PQC ciphertext") or None
    pqc_private_key = reader.read_length_prefixed_bytes(">I", "PQC private key") or None
    unlock_timestamp = reader.read_u32("unlock timestamp")
    checksum = reader.read_bytes(32, "checksum")
    filename = reader.read_short_text("filename")

    timelock_mode = reader.read_short_text("timelock mode")
    file_id = reader.read_short_text("file ID") or None
    server_url = reader.read_long_text("server URL") or None
    time_key_hash = reader.read_optional_fixed_bytes(32, "time key hash")

    timecapsule_provider = reader.read_short_text("timecapsule provider") or None
    drand_round = reader.read_optional_u64("drand round")
    drand_chain_hash = reader.read_short_text("drand chain hash") or None
    drand_chain_url = reader.read_long_text("drand chain URL") or None
    drand_ciphertext = reader.read_long_text("drand ciphertext") or None
    drand_beacon_id = reader.read_short_text("drand beacon ID") or None

    pqc_required = bool(reader.read_u8("PQC required flag"))
    pqc_algorithm = reader.read_short_text("PQC algorithm") or None
    pqc_key_id = reader.read_short_text("PQC key ID") or None

    archive_type = reader.read_short_text("archive type") or None
    entry_count = reader.read_u32("entry count")
    total_original_size = reader.read_u64("total original size")
    manifest_hash = reader.read_bytes(32, "manifest hash")

    keyphrase_format_version = reader.read_u8("keyphrase format version")
    keyphrase_wordlist_id = reader.read_short_text("keyphrase wordlist ID") or None

    aavrit_data_hash = reader.read_short_text("Aavrit data hash") or None
    aavrit_commit_hash = reader.read_short_text("Aavrit commit hash") or None
    aavrit_server_key_id = reader.read_short_text("Aavrit server key ID") or None
    aavrit_commit_signature = reader.read_long_text("Aavrit commit signature") or None

    payload_key_wrap_algorithm = reader.read_short_text("payload key wrap algorithm") or None
    wrapped_payload_key_length = reader.read_u8("wrapped payload key length")
    wrapped_payload_key = reader.read_bytes(wrapped_payload_key_length, "wrapped payload key") if wrapped_payload_key_length else None

    reader.ensure_finished()

    metadata = {
        "version": version,
        "salt": salt,
        "chess_salt": chess_salt,
        "pqc_ciphertext": pqc_ciphertext,
        "pqc_private_key": pqc_private_key,
        "unlock_timestamp": unlock_timestamp,
        "checksum": checksum,
        "filename": filename,
        "encryption_method": encryption_method,
        "keyphrase_protected": keyphrase_protected,
        "timelock_mode": timelock_mode,
        "file_id": file_id,
        "server_url": server_url,
        "time_key_hash": time_key_hash,
        "timecapsule_provider": timecapsule_provider,
        "drand_round": drand_round,
        "drand_chain_hash": drand_chain_hash,
        "drand_chain_url": drand_chain_url,
        "drand_ciphertext": drand_ciphertext,
        "drand_beacon_id": drand_beacon_id,
        "pqc_required": pqc_required,
        "pqc_algorithm": pqc_algorithm,
        "pqc_key_id": pqc_key_id,
        "keyphrase_format_version": keyphrase_format_version,
        "keyphrase_wordlist_id": keyphrase_wordlist_id,
        "archive_type": archive_type,
        "entry_count": entry_count,
        "total_original_size": total_original_size,
        "manifest_hash": manifest_hash,
        "aavrit_data_hash": aavrit_data_hash,
        "aavrit_commit_hash": aavrit_commit_hash,
        "aavrit_server_key_id": aavrit_server_key_id,
        "aavrit_commit_signature": aavrit_commit_signature,
        "payload_key_wrap_algorithm": payload_key_wrap_algorithm,
        "wrapped_payload_key": wrapped_payload_key,
    }
    return validate_cascade_metadata_dict(metadata)


class _MetadataReader:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    def read_u8(self, field_name: str) -> int:
        return self.read_struct(">B", field_name)

    def read_u32(self, field_name: str) -> int:
        return self.read_struct(">I", field_name)

    def read_u64(self, field_name: str) -> int:
        return self.read_struct(">Q", field_name)

    def read_struct(self, fmt: str, field_name: str) -> int:
        size = struct.calcsize(fmt)
        raw = self.read_bytes(size, field_name)
        return struct.unpack(fmt, raw)[0]

    def read_short_text(self, field_name: str) -> str:
        length = self.read_u8(f"{field_name} length")
        return self.read_text(length, field_name)

    def read_long_text(self, field_name: str) -> str:
        length = self.read_struct(">H", f"{field_name} length")
        return self.read_text(length, field_name)

    def read_text(self, length: int, field_name: str) -> str:
        try:
            return self.read_bytes(length, field_name).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Metadata corrupted: {field_name} is not valid UTF-8") from exc

    def read_length_prefixed_bytes(self, length_format: str, field_name: str) -> bytes:
        length = self.read_struct(length_format, f"{field_name} length")
        return self.read_bytes(length, field_name)

    def read_optional_fixed_bytes(self, size: int, field_name: str) -> bytes | None:
        present = self.read_u8(f"{field_name} flag")
        if not present:
            return None
        return self.read_bytes(size, field_name)

    def read_optional_u64(self, field_name: str) -> int | None:
        present = self.read_u8(f"{field_name} flag")
        if not present:
            return None
        return self.read_u64(field_name)

    def read_bytes(self, size: int, field_name: str) -> bytes:
        if size < 0:
            raise ValueError(f"Metadata corrupted: invalid {field_name} length")
        end = self._offset + size
        if len(self._data) < end:
            raise ValueError(f"Metadata corrupted: {field_name} truncated")
        value = self._data[self._offset:end]
        self._offset = end
        return value

    def ensure_finished(self) -> None:
        if self._offset != len(self._data):
            raise ValueError("Metadata corrupted: unexpected trailing bytes")
