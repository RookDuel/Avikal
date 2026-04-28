"""
Cascade metadata unpacking helpers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import struct

from .metadata_validation import validate_cascade_metadata_dict


def unpack_cascade_metadata(packed: bytes) -> dict:
    """
    Unpack cascade encryption metadata.
    Supports v0x04 through v0x0C.
    """
    max_metadata_size = 16 * 1024

    if len(packed) > max_metadata_size:
        raise ValueError(
            f"Metadata size ({len(packed)} bytes) exceeds maximum allowed ({max_metadata_size} bytes). "
            f"This may be a malicious file designed to cause DOS attack."
        )

    if len(packed) < 3:
        raise ValueError("Metadata too short")

    offset = 0

    version = packed[offset]
    if version not in [0x04, 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]:
        raise ValueError(f"Unsupported metadata version: {version}")
    offset += 1

    flags = packed[offset]
    keyphrase_protected = bool(flags & 0x01)
    offset += 1

    method_length = packed[offset]
    offset += 1
    if len(packed) < offset + method_length:
        raise ValueError("Metadata corrupted: method truncated")
    encryption_method = packed[offset:offset + method_length].decode("utf-8")
    offset += method_length

    if len(packed) < offset + 32:
        raise ValueError("Metadata corrupted: payload salt truncated")
    salt = packed[offset:offset + 32]
    offset += 32

    if len(packed) < offset + 32:
        raise ValueError("Metadata corrupted: chess salt truncated")
    chess_salt = packed[offset:offset + 32]
    offset += 32

    if len(packed) < offset + 4:
        raise ValueError("Metadata corrupted: PQC ciphertext length missing")
    pqc_ciphertext_len = struct.unpack(">I", packed[offset:offset + 4])[0]
    offset += 4
    if len(packed) < offset + pqc_ciphertext_len:
        raise ValueError("Metadata corrupted: PQC ciphertext truncated")
    pqc_ciphertext = packed[offset:offset + pqc_ciphertext_len] if pqc_ciphertext_len > 0 else None
    offset += pqc_ciphertext_len

    if len(packed) < offset + 4:
        raise ValueError("Metadata corrupted: PQC private key length missing")
    pqc_private_key_len = struct.unpack(">I", packed[offset:offset + 4])[0]
    offset += 4
    if len(packed) < offset + pqc_private_key_len:
        raise ValueError("Metadata corrupted: PQC private key truncated")
    pqc_private_key = packed[offset:offset + pqc_private_key_len] if pqc_private_key_len > 0 else None
    offset += pqc_private_key_len

    if len(packed) < offset + 4:
        raise ValueError("Metadata corrupted: timestamp missing")
    unlock_timestamp = struct.unpack(">I", packed[offset:offset + 4])[0]
    offset += 4

    if len(packed) < offset + 32:
        raise ValueError("Metadata corrupted: checksum missing")
    checksum = packed[offset:offset + 32]
    offset += 32

    if len(packed) < offset + 1:
        raise ValueError("Metadata corrupted: filename length missing")
    filename_length = packed[offset]
    offset += 1
    if len(packed) < offset + filename_length:
        raise ValueError("Metadata corrupted: filename truncated")
    filename_bytes = packed[offset:offset + filename_length]
    filename = filename_bytes.decode("utf-8")
    offset += filename_length

    timelock_mode = "convenience"
    file_id = None
    server_url = None
    time_key_hash = None
    timecapsule_provider = None
    drand_round = None
    drand_chain_hash = None
    drand_chain_url = None
    drand_ciphertext = None
    drand_beacon_id = None
    pqc_required = False
    pqc_algorithm = None
    pqc_key_id = None
    archive_type = None
    entry_count = None
    total_original_size = None
    manifest_hash = None
    keyphrase_format_version = None
    keyphrase_wordlist_id = None
    aavrit_data_hash = None
    aavrit_commit_hash = None
    aavrit_server_key_id = None
    aavrit_commit_signature = None

    if version >= 0x05:
        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: timelock mode length missing")
        mode_length = packed[offset]
        offset += 1
        if len(packed) < offset + mode_length:
            raise ValueError("Metadata corrupted: timelock mode truncated")
        timelock_mode = packed[offset:offset + mode_length].decode("utf-8")
        offset += mode_length

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: file ID length missing")
        file_id_length = packed[offset]
        offset += 1
        if file_id_length > 0:
            if len(packed) < offset + file_id_length:
                raise ValueError("Metadata corrupted: file ID truncated")
            file_id = packed[offset:offset + file_id_length].decode("utf-8")
            offset += file_id_length

        if len(packed) < offset + 2:
            raise ValueError("Metadata corrupted: server URL length missing")
        server_url_length = struct.unpack(">H", packed[offset:offset + 2])[0]
        offset += 2
        if server_url_length > 0:
            if len(packed) < offset + server_url_length:
                raise ValueError("Metadata corrupted: server URL truncated")
            server_url = packed[offset:offset + server_url_length].decode("utf-8")
            offset += server_url_length

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: time key hash flag missing")
        time_key_hash_present = packed[offset]
        offset += 1
        if time_key_hash_present:
            if len(packed) < offset + 32:
                raise ValueError("Metadata corrupted: time key hash truncated")
            time_key_hash = packed[offset:offset + 32]
            offset += 32


    if version >= 0x07:
        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: provider length missing")
        provider_length = packed[offset]
        offset += 1
        if len(packed) < offset + provider_length:
            raise ValueError("Metadata corrupted: provider truncated")
        if provider_length > 0:
            timecapsule_provider = packed[offset:offset + provider_length].decode("utf-8")
            offset += provider_length

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: drand round flag missing")
        drand_round_present = packed[offset]
        offset += 1
        if drand_round_present:
            if len(packed) < offset + 8:
                raise ValueError("Metadata corrupted: drand round truncated")
            drand_round = struct.unpack(">Q", packed[offset:offset + 8])[0]
            offset += 8

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: drand chain hash length missing")
        drand_chain_hash_length = packed[offset]
        offset += 1
        if len(packed) < offset + drand_chain_hash_length:
            raise ValueError("Metadata corrupted: drand chain hash truncated")
        if drand_chain_hash_length > 0:
            drand_chain_hash = packed[offset:offset + drand_chain_hash_length].decode("utf-8")
            offset += drand_chain_hash_length

        if len(packed) < offset + 2:
            raise ValueError("Metadata corrupted: drand chain URL length missing")
        drand_chain_url_length = struct.unpack(">H", packed[offset:offset + 2])[0]
        offset += 2
        if len(packed) < offset + drand_chain_url_length:
            raise ValueError("Metadata corrupted: drand chain URL truncated")
        if drand_chain_url_length > 0:
            drand_chain_url = packed[offset:offset + drand_chain_url_length].decode("utf-8")
            offset += drand_chain_url_length

        if len(packed) < offset + 2:
            raise ValueError("Metadata corrupted: drand ciphertext length missing")
        drand_ciphertext_length = struct.unpack(">H", packed[offset:offset + 2])[0]
        offset += 2
        if len(packed) < offset + drand_ciphertext_length:
            raise ValueError("Metadata corrupted: drand ciphertext truncated")
        if drand_ciphertext_length > 0:
            drand_ciphertext = packed[offset:offset + drand_ciphertext_length].decode("utf-8")
            offset += drand_ciphertext_length

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: drand beacon ID length missing")
        drand_beacon_id_length = packed[offset]
        offset += 1
        if len(packed) < offset + drand_beacon_id_length:
            raise ValueError("Metadata corrupted: drand beacon ID truncated")
        if drand_beacon_id_length > 0:
            drand_beacon_id = packed[offset:offset + drand_beacon_id_length].decode("utf-8")
            offset += drand_beacon_id_length

    if version >= 0x08:
        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: PQC required flag missing")
        pqc_required = bool(packed[offset])
        offset += 1

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: PQC algorithm length missing")
        pqc_algorithm_length = packed[offset]
        offset += 1
        if len(packed) < offset + pqc_algorithm_length:
            raise ValueError("Metadata corrupted: PQC algorithm truncated")
        if pqc_algorithm_length > 0:
            pqc_algorithm = packed[offset:offset + pqc_algorithm_length].decode("utf-8")
            offset += pqc_algorithm_length

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: PQC key ID length missing")
        pqc_key_id_length = packed[offset]
        offset += 1
        if len(packed) < offset + pqc_key_id_length:
            raise ValueError("Metadata corrupted: PQC key ID truncated")
        if pqc_key_id_length > 0:
            pqc_key_id = packed[offset:offset + pqc_key_id_length].decode("utf-8")
            offset += pqc_key_id_length

    if version in {0x09, 0x0B, 0x0C}:
        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: archive type length missing")
        archive_type_length = packed[offset]
        offset += 1
        if len(packed) < offset + archive_type_length:
            raise ValueError("Metadata corrupted: archive type truncated")
        if archive_type_length > 0:
            archive_type = packed[offset:offset + archive_type_length].decode("utf-8")
            offset += archive_type_length

        if len(packed) < offset + 12:
            raise ValueError("Metadata corrupted: archive summary truncated")
        entry_count = struct.unpack(">I", packed[offset:offset + 4])[0]
        offset += 4
        total_original_size = struct.unpack(">Q", packed[offset:offset + 8])[0]
        offset += 8

        if len(packed) < offset + 32:
            raise ValueError("Metadata corrupted: manifest hash truncated")
        manifest_hash = packed[offset:offset + 32]
        offset += 32
    if version in {0x0A, 0x0B, 0x0C}:
        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: keyphrase format version missing")
        keyphrase_format_version = packed[offset]
        offset += 1

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: keyphrase wordlist length missing")
        keyphrase_wordlist_id_length = packed[offset]
        offset += 1
        if len(packed) < offset + keyphrase_wordlist_id_length:
            raise ValueError("Metadata corrupted: keyphrase wordlist ID truncated")
        if keyphrase_wordlist_id_length > 0:
            keyphrase_wordlist_id = packed[offset:offset + keyphrase_wordlist_id_length].decode("utf-8")
            offset += keyphrase_wordlist_id_length

    if version >= 0x0C:
        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: Aavrit data hash length missing")
        aavrit_data_hash_length = packed[offset]
        offset += 1
        if len(packed) < offset + aavrit_data_hash_length:
            raise ValueError("Metadata corrupted: Aavrit data hash truncated")
        if aavrit_data_hash_length > 0:
            aavrit_data_hash = packed[offset:offset + aavrit_data_hash_length].decode("utf-8")
            offset += aavrit_data_hash_length

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: Aavrit commit hash length missing")
        aavrit_commit_hash_length = packed[offset]
        offset += 1
        if len(packed) < offset + aavrit_commit_hash_length:
            raise ValueError("Metadata corrupted: Aavrit commit hash truncated")
        if aavrit_commit_hash_length > 0:
            aavrit_commit_hash = packed[offset:offset + aavrit_commit_hash_length].decode("utf-8")
            offset += aavrit_commit_hash_length

        if len(packed) < offset + 1:
            raise ValueError("Metadata corrupted: Aavrit server key ID length missing")
        aavrit_server_key_id_length = packed[offset]
        offset += 1
        if len(packed) < offset + aavrit_server_key_id_length:
            raise ValueError("Metadata corrupted: Aavrit server key ID truncated")
        if aavrit_server_key_id_length > 0:
            aavrit_server_key_id = packed[offset:offset + aavrit_server_key_id_length].decode("utf-8")
            offset += aavrit_server_key_id_length

        if len(packed) < offset + 2:
            raise ValueError("Metadata corrupted: Aavrit commit signature length missing")
        aavrit_commit_signature_length = struct.unpack(">H", packed[offset:offset + 2])[0]
        offset += 2
        if len(packed) < offset + aavrit_commit_signature_length:
            raise ValueError("Metadata corrupted: Aavrit commit signature truncated")
        if aavrit_commit_signature_length > 0:
            aavrit_commit_signature = packed[offset:offset + aavrit_commit_signature_length].decode("utf-8")
            offset += aavrit_commit_signature_length

    if offset != len(packed):
        raise ValueError("Metadata corrupted: unexpected trailing bytes")

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
    }

    return validate_cascade_metadata_dict(metadata)

