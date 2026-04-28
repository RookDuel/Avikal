"""Validation helpers for archive metadata structures."""

from __future__ import annotations

from ..path_safety import normalize_single_archive_filename


def validate_cascade_metadata_dict(metadata: dict) -> dict:
    """Validate parsed metadata and reject inconsistent provider/version state."""
    version = metadata.get("version")
    if version not in {0x04, 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}:
        raise ValueError("Metadata corrupted: unsupported metadata version")

    salt = metadata.get("salt")
    chess_salt = metadata.get("chess_salt")
    checksum = metadata.get("checksum")
    filename = metadata.get("filename")
    encryption_method = metadata.get("encryption_method")

    if not isinstance(salt, (bytes, bytearray)) or len(salt) != 32:
        raise ValueError("Metadata corrupted: invalid payload salt")
    if not isinstance(chess_salt, (bytes, bytearray)) or len(chess_salt) != 32:
        raise ValueError("Metadata corrupted: invalid chess salt")
    if not isinstance(checksum, (bytes, bytearray)) or len(checksum) != 32:
        raise ValueError("Metadata corrupted: invalid checksum")
    if not isinstance(filename, str) or not filename or len(filename.encode("utf-8")) > 255:
        raise ValueError("Metadata corrupted: invalid filename")
    try:
        filename = normalize_single_archive_filename(filename)
    except ValueError as exc:
        raise ValueError(f"Metadata corrupted: unsafe filename ({exc})") from exc
    if encryption_method not in {"aes256gcm_stream", "plaintext_archive", "aes256gcm_stream_timekey"}:
        raise ValueError("Metadata corrupted: unsupported encryption method")

    provider = metadata.get("timecapsule_provider")
    drand_round = metadata.get("drand_round")
    drand_chain_hash = metadata.get("drand_chain_hash")
    drand_chain_url = metadata.get("drand_chain_url")
    drand_ciphertext = metadata.get("drand_ciphertext")
    drand_beacon_id = metadata.get("drand_beacon_id")
    pqc_required = bool(metadata.get("pqc_required"))
    pqc_algorithm = metadata.get("pqc_algorithm")
    pqc_key_id = metadata.get("pqc_key_id")
    pqc_ciphertext = metadata.get("pqc_ciphertext")
    pqc_private_key = metadata.get("pqc_private_key")
    keyphrase_protected = bool(metadata.get("keyphrase_protected"))
    keyphrase_format_version = metadata.get("keyphrase_format_version")
    keyphrase_wordlist_id = metadata.get("keyphrase_wordlist_id")
    archive_type = metadata.get("archive_type")
    entry_count = metadata.get("entry_count")
    total_original_size = metadata.get("total_original_size")
    manifest_hash = metadata.get("manifest_hash")
    aavrit_data_hash = metadata.get("aavrit_data_hash")
    aavrit_commit_hash = metadata.get("aavrit_commit_hash")
    aavrit_server_key_id = metadata.get("aavrit_server_key_id")
    aavrit_commit_signature = metadata.get("aavrit_commit_signature")
    file_id = metadata.get("file_id")
    server_url = metadata.get("server_url")

    if provider is not None and provider not in {"aavrit", "drand"}:
        raise ValueError("Metadata corrupted: invalid time-capsule provider")

    if version < 0x07:
        if provider is not None:
            raise ValueError("Metadata corrupted: invalid provider for this metadata version")
        if any(value is not None for value in [drand_round, drand_chain_hash, drand_chain_url, drand_ciphertext, drand_beacon_id]):
            raise ValueError("Metadata corrupted: drand fields are invalid for this metadata version")
    if version < 0x0C and any(value is not None for value in [aavrit_data_hash, aavrit_commit_hash, aavrit_server_key_id, aavrit_commit_signature]):
        raise ValueError("Metadata corrupted: Aavrit fields are invalid for this metadata version")

    if provider == "aavrit":
        if version != 0x0C:
            raise ValueError("Metadata corrupted: Aavrit provider requires metadata version 0x0C")
        if any(value is not None for value in [drand_round, drand_chain_hash, drand_chain_url, drand_ciphertext, drand_beacon_id]):
            raise ValueError("Metadata corrupted: Aavrit capsule cannot contain drand fields")
        if not isinstance(file_id, str) or not file_id:
            raise ValueError("Metadata corrupted: Aavrit capsule requires a commit identifier")
        if not isinstance(server_url, str) or not server_url:
            raise ValueError("Metadata corrupted: Aavrit capsule requires a server URL")
        for field_name, field_value in (
            ("aavrit_data_hash", aavrit_data_hash),
            ("aavrit_commit_hash", aavrit_commit_hash),
            ("aavrit_server_key_id", aavrit_server_key_id),
            ("aavrit_commit_signature", aavrit_commit_signature),
        ):
            if not isinstance(field_value, str) or not field_value:
                raise ValueError(f"Metadata corrupted: Aavrit capsule requires {field_name}")
    elif provider == "drand":
        if version not in {0x07, 0x08, 0x09, 0x0A, 0x0B}:
            raise ValueError("Metadata corrupted: drand provider requires a drand-capable metadata version")
        if any(value is not None for value in [aavrit_data_hash, aavrit_commit_hash, aavrit_server_key_id, aavrit_commit_signature]):
            raise ValueError("Metadata corrupted: drand capsule cannot contain Aavrit fields")
        if not isinstance(drand_round, int) or drand_round <= 0:
            raise ValueError("Metadata corrupted: drand capsule requires a valid round")
        if not isinstance(drand_chain_hash, str) or not drand_chain_hash:
            raise ValueError("Metadata corrupted: drand capsule requires chain hash")
        if not isinstance(drand_chain_url, str) or not drand_chain_url:
            raise ValueError("Metadata corrupted: drand capsule requires chain URL")
        if not isinstance(drand_ciphertext, str) or not drand_ciphertext:
            raise ValueError("Metadata corrupted: drand capsule requires ciphertext")
        if drand_beacon_id is not None and not isinstance(drand_beacon_id, str):
            raise ValueError("Metadata corrupted: invalid drand beacon ID")
    else:
        if any(value is not None for value in [drand_round, drand_chain_hash, drand_chain_url, drand_ciphertext, drand_beacon_id]):
            raise ValueError("Metadata corrupted: non-time-capsule file cannot contain drand fields")
        if any(value is not None for value in [aavrit_data_hash, aavrit_commit_hash, aavrit_server_key_id, aavrit_commit_signature]):
            raise ValueError("Metadata corrupted: non-time-capsule file cannot contain Aavrit fields")

    if version < 0x08:
        if any(value is not None for value in [pqc_algorithm, pqc_key_id]) or pqc_required:
            raise ValueError("Metadata corrupted: external PQC keyfile fields require version 0x08")
    elif version == 0x08:
        if not pqc_required:
            raise ValueError("Metadata corrupted: version 0x08 requires PQC keyfile mode")
        if not isinstance(pqc_algorithm, str) or pqc_algorithm != "ml-kem-1024":
            raise ValueError("Metadata corrupted: unsupported PQC algorithm")
        if not isinstance(pqc_key_id, str) or len(pqc_key_id) != 64:
            raise ValueError("Metadata corrupted: invalid PQC key identifier")
        if not isinstance(pqc_ciphertext, (bytes, bytearray)) or len(pqc_ciphertext) == 0:
            raise ValueError("Metadata corrupted: PQC keyfile mode requires ciphertext")
        if pqc_private_key is not None:
            raise ValueError("Metadata corrupted: PQC private key must not be embedded in the archive")
    else:
        if pqc_required:
            if not isinstance(pqc_algorithm, str) or pqc_algorithm != "ml-kem-1024":
                raise ValueError("Metadata corrupted: unsupported PQC algorithm")
            if not isinstance(pqc_key_id, str) or len(pqc_key_id) != 64:
                raise ValueError("Metadata corrupted: invalid PQC key identifier")
            if not isinstance(pqc_ciphertext, (bytes, bytearray)) or len(pqc_ciphertext) == 0:
                raise ValueError("Metadata corrupted: PQC keyfile mode requires ciphertext")
        else:
            if any(value is not None for value in [pqc_algorithm, pqc_key_id, pqc_ciphertext]):
                raise ValueError("Metadata corrupted: inactive PQC fields must be empty")
        if pqc_private_key is not None:
            raise ValueError("Metadata corrupted: PQC private key must not be embedded in the archive")

    if keyphrase_protected:
        if version not in {0x0A, 0x0B, 0x0C}:
            raise ValueError("Metadata corrupted: keyphrase format is not supported for this metadata version")
        if keyphrase_format_version != 1:
            raise ValueError("Metadata corrupted: unsupported keyphrase format version")
        if keyphrase_wordlist_id != "avikal-hi-2048-v1":
            raise ValueError("Metadata corrupted: unsupported keyphrase wordlist")
    else:
        if version == 0x0C:
            if keyphrase_format_version not in {None, 0}:
                raise ValueError("Metadata corrupted: inactive Aavrit keyphrase format field must be zero")
            if keyphrase_wordlist_id not in {None, ""}:
                raise ValueError("Metadata corrupted: inactive Aavrit keyphrase wordlist field must be empty")
        elif keyphrase_format_version is not None or keyphrase_wordlist_id is not None:
            raise ValueError("Metadata corrupted: inactive keyphrase format fields must be empty")

    if version in {0x09, 0x0B, 0x0C}:
        if archive_type not in {"multi_file", "single_file"}:
            raise ValueError("Metadata corrupted: unsupported archive type")
        if not isinstance(entry_count, int) or entry_count <= 0:
            raise ValueError("Metadata corrupted: invalid multi-file entry count")
        if not isinstance(total_original_size, int) or total_original_size < 0:
            raise ValueError("Metadata corrupted: invalid multi-file total size")
        if not isinstance(manifest_hash, (bytes, bytearray)) or len(manifest_hash) != 32:
            raise ValueError("Metadata corrupted: invalid multi-file manifest hash")
    else:
        if any(value is not None for value in [archive_type, entry_count, total_original_size, manifest_hash]):
            raise ValueError("Metadata corrupted: archive manifest fields require version 0x09 or 0x0B")

    return metadata
