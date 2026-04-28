"""
Cascade metadata packing helpers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import struct

from ..path_safety import normalize_single_archive_filename


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
) -> bytes:
    """
    Pack cascade encryption metadata into binary structure.

    Maximum total size: ~10 KB (enforced for security)
    """
    max_metadata_size = 10 * 1024

    if len(salt) != 32:
        raise ValueError("Payload salt must be 32 bytes")
    if len(checksum) != 32:
        raise ValueError("Checksum must be 32 bytes (SHA-256)")

    if chess_salt is None:
        import hashlib

        chess_salt = hashlib.sha256(b"avikal_chess_v3").digest()
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

    if len(pqc_ciphertext) > 2048:
        raise ValueError("PQC ciphertext too large (max 2048 bytes)")
    if len(pqc_private_key) > 4096:
        raise ValueError("PQC private key too large (max 4096 bytes)")

    flags = 0x01 if keyphrase_protected else 0x00

    if pqc_required and pqc_private_key:
        raise ValueError("PQC private key must not be embedded in the archive metadata")
    if pqc_required and not pqc_ciphertext:
        raise ValueError("PQC keyfile mode requires PQC ciphertext")
    if pqc_required and not pqc_algorithm:
        raise ValueError("PQC keyfile mode requires PQC algorithm")
    if pqc_required and not pqc_key_id:
        raise ValueError("PQC keyfile mode requires PQC key identifier")

    has_manifest_binding = any(
        value is not None for value in [archive_type, entry_count, total_original_size, manifest_hash]
    )
    if has_manifest_binding:
        if archive_type not in {"multi_file", "single_file"}:
            raise ValueError("Manifest binding requires archive_type to be 'multi_file' or 'single_file'")
        if not isinstance(entry_count, int) or entry_count <= 0:
            raise ValueError("entry_count must be a positive integer")
        if not isinstance(total_original_size, int) or total_original_size < 0:
            raise ValueError("total_original_size must be a non-negative integer")
        if not isinstance(manifest_hash, (bytes, bytearray)) or len(manifest_hash) != 32:
            raise ValueError("manifest_hash must be 32 bytes")

    if timecapsule_provider == "aavrit":
        version = 0x0C
    elif keyphrase_protected and has_manifest_binding:
        version = 0x0B
    elif keyphrase_protected:
        version = 0x0A
    elif has_manifest_binding:
        version = 0x09
    elif pqc_required or pqc_algorithm or pqc_key_id:
        version = 0x08
    elif timecapsule_provider:
        version = 0x07
    else:
        version = 0x05 if timelock_mode == "secure" else 0x04

    if keyphrase_protected:
        if keyphrase_format_version != 1:
            raise ValueError("Keyphrase-protected archives require keyphrase_format_version=1")
        if keyphrase_wordlist_id != "avikal-hi-2048-v1":
            raise ValueError("Keyphrase-protected archives require keyphrase_wordlist_id='avikal-hi-2048-v1'")
    elif version == 0x0C:
        if keyphrase_format_version not in {None, 0}:
            raise ValueError("Inactive Aavrit keyphrase format field must be zero")
        if keyphrase_wordlist_id not in {None, ""}:
            raise ValueError("Inactive Aavrit keyphrase wordlist field must be empty")
        keyphrase_format_version = 0
        keyphrase_wordlist_id = ""
    elif keyphrase_format_version is not None or keyphrase_wordlist_id is not None:
        raise ValueError("Inactive keyphrase format fields must be empty")

    if version == 0x0C and not has_manifest_binding:
        raise ValueError("Aavrit metadata version 0x0C requires archive binding fields")

    packed = struct.pack(">BBB", version, flags, len(method_bytes))
    packed += method_bytes
    packed += salt
    packed += chess_salt
    packed += struct.pack(">I", len(pqc_ciphertext))
    packed += pqc_ciphertext
    packed += struct.pack(">I", len(pqc_private_key))
    packed += pqc_private_key
    packed += struct.pack(">I", unlock_timestamp)
    packed += checksum
    packed += struct.pack(">B", len(filename_bytes))
    packed += filename_bytes

    if version >= 0x05:
        mode_bytes = timelock_mode.encode("utf-8")
        if len(mode_bytes) > 255:
            raise ValueError("Timelock mode string too long")
        packed += struct.pack(">B", len(mode_bytes))
        packed += mode_bytes

        if file_id:
            file_id_bytes = file_id.encode("utf-8")
            if len(file_id_bytes) > 255:
                raise ValueError("File ID too long (max 255 bytes)")
            packed += struct.pack(">B", len(file_id_bytes))
            packed += file_id_bytes
        else:
            packed += struct.pack(">B", 0)

        if server_url:
            server_url_bytes = server_url.encode("utf-8")
            if len(server_url_bytes) > 65535:
                raise ValueError("Server URL too long (max 65535 bytes)")
            packed += struct.pack(">H", len(server_url_bytes))
            packed += server_url_bytes
        else:
            packed += struct.pack(">H", 0)

        if time_key_hash:
            if len(time_key_hash) != 32:
                raise ValueError("Time key hash must be 32 bytes (SHA-256)")
            packed += struct.pack(">B", 1)
            packed += time_key_hash
        else:
            packed += struct.pack(">B", 0)


    if version >= 0x07:
        provider_bytes = (timecapsule_provider or "").encode("utf-8")
        if len(provider_bytes) > 32:
            raise ValueError("Timecapsule provider string too long")
        packed += struct.pack(">B", len(provider_bytes))
        packed += provider_bytes

        if drand_round is not None:
            packed += struct.pack(">BQ", 1, int(drand_round))
        else:
            packed += struct.pack(">B", 0)

        drand_chain_hash_bytes = (drand_chain_hash or "").encode("utf-8")
        if len(drand_chain_hash_bytes) > 255:
            raise ValueError("drand chain hash too long")
        packed += struct.pack(">B", len(drand_chain_hash_bytes))
        packed += drand_chain_hash_bytes

        drand_chain_url_bytes = (drand_chain_url or "").encode("utf-8")
        if len(drand_chain_url_bytes) > 65535:
            raise ValueError("drand chain URL too long")
        packed += struct.pack(">H", len(drand_chain_url_bytes))
        packed += drand_chain_url_bytes

        drand_ciphertext_bytes = (drand_ciphertext or "").encode("utf-8")
        if len(drand_ciphertext_bytes) > 65535:
            raise ValueError("drand ciphertext too large")
        packed += struct.pack(">H", len(drand_ciphertext_bytes))
        packed += drand_ciphertext_bytes

        drand_beacon_id_bytes = (drand_beacon_id or "").encode("utf-8")
        if len(drand_beacon_id_bytes) > 255:
            raise ValueError("drand beacon ID too long")
        packed += struct.pack(">B", len(drand_beacon_id_bytes))
        packed += drand_beacon_id_bytes

    if version >= 0x08:
        packed += struct.pack(">B", 1 if pqc_required else 0)

        pqc_algorithm_bytes = (pqc_algorithm or "").encode("utf-8")
        if len(pqc_algorithm_bytes) > 64:
            raise ValueError("PQC algorithm string too long")
        packed += struct.pack(">B", len(pqc_algorithm_bytes))
        packed += pqc_algorithm_bytes

        pqc_key_id_bytes = (pqc_key_id or "").encode("utf-8")
        if len(pqc_key_id_bytes) > 128:
            raise ValueError("PQC key identifier too long")
        packed += struct.pack(">B", len(pqc_key_id_bytes))
        packed += pqc_key_id_bytes

    if version in {0x09, 0x0B, 0x0C}:
        archive_type_bytes = archive_type.encode("utf-8")
        if len(archive_type_bytes) > 32:
            raise ValueError("Archive type string too long")
        packed += struct.pack(">B", len(archive_type_bytes))
        packed += archive_type_bytes
        packed += struct.pack(">IQ", entry_count, total_original_size)
        packed += bytes(manifest_hash)

    if version in {0x0A, 0x0B, 0x0C}:
        packed += struct.pack(">B", keyphrase_format_version)
        keyphrase_wordlist_id_bytes = keyphrase_wordlist_id.encode("utf-8")
        if len(keyphrase_wordlist_id_bytes) > 64:
            raise ValueError("Keyphrase wordlist identifier too long")
        packed += struct.pack(">B", len(keyphrase_wordlist_id_bytes))
        packed += keyphrase_wordlist_id_bytes

    if version >= 0x0C:
        for field_name, field_value, max_length, length_format in (
            ("Aavrit data hash", aavrit_data_hash or "", 128, ">B"),
            ("Aavrit commit hash", aavrit_commit_hash or "", 128, ">B"),
            ("Aavrit server key identifier", aavrit_server_key_id or "", 128, ">B"),
            ("Aavrit commit signature", aavrit_commit_signature or "", 1024, ">H"),
        ):
            field_bytes = field_value.encode("utf-8")
            if len(field_bytes) > max_length:
                raise ValueError(f"{field_name} too long")
            packed += struct.pack(length_format, len(field_bytes))
            packed += field_bytes

    if len(packed) > max_metadata_size:
        raise ValueError(
            f"Metadata size ({len(packed)} bytes) exceeds maximum allowed ({max_metadata_size} bytes). "
            f"This may indicate a malicious file or corrupted data."
        )

    return packed

