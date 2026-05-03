"""Validation helpers for the current Avikal archive metadata format."""

from __future__ import annotations

from ..path_safety import normalize_single_archive_filename
from ..security.key_wrap import PAYLOAD_KEY_WRAP_ALGORITHM
from ..security.pqc_provider import PQC_SUITE_ID
from .metadata_pack import METADATA_FORMAT_VERSION


def validate_cascade_metadata_dict(metadata: dict) -> dict:
    """Validate parsed metadata for the public v1 archive format."""
    if metadata.get("version") != METADATA_FORMAT_VERSION:
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
        metadata["filename"] = normalize_single_archive_filename(filename)
    except ValueError as exc:
        raise ValueError(f"Metadata corrupted: unsafe filename ({exc})") from exc
    if encryption_method not in {"aes256gcm_stream", "plaintext_archive", "aes256gcm_stream_timekey"}:
        raise ValueError("Metadata corrupted: unsupported encryption method")

    _validate_provider_fields(metadata)
    _validate_pqc_fields(metadata)
    _validate_keyphrase_fields(metadata)
    _validate_archive_binding(metadata)
    _validate_wrapped_payload_key(metadata)
    return metadata


def _validate_provider_fields(metadata: dict) -> None:
    provider = metadata.get("timecapsule_provider")
    drand_fields = [
        metadata.get("drand_round"),
        metadata.get("drand_chain_hash"),
        metadata.get("drand_chain_url"),
        metadata.get("drand_ciphertext"),
        metadata.get("drand_beacon_id"),
    ]
    aavrit_fields = [
        metadata.get("aavrit_data_hash"),
        metadata.get("aavrit_commit_hash"),
        metadata.get("aavrit_server_key_id"),
        metadata.get("aavrit_commit_signature"),
    ]

    if provider is not None and provider not in {"aavrit", "drand"}:
        raise ValueError("Metadata corrupted: invalid time-capsule provider")

    if provider == "aavrit":
        if any(value is not None for value in drand_fields):
            raise ValueError("Metadata corrupted: Aavrit capsule cannot contain drand fields")
        if not isinstance(metadata.get("file_id"), str) or not metadata["file_id"]:
            raise ValueError("Metadata corrupted: Aavrit capsule requires a commit identifier")
        if not isinstance(metadata.get("server_url"), str) or not metadata["server_url"]:
            raise ValueError("Metadata corrupted: Aavrit capsule requires a server URL")
        for field_name in (
            "aavrit_data_hash",
            "aavrit_commit_hash",
            "aavrit_server_key_id",
            "aavrit_commit_signature",
        ):
            if not isinstance(metadata.get(field_name), str) or not metadata[field_name]:
                raise ValueError(f"Metadata corrupted: Aavrit capsule requires {field_name}")
    elif provider == "drand":
        if any(value is not None for value in aavrit_fields):
            raise ValueError("Metadata corrupted: drand capsule cannot contain Aavrit fields")
        if not isinstance(metadata.get("drand_round"), int) or metadata["drand_round"] <= 0:
            raise ValueError("Metadata corrupted: drand capsule requires a valid round")
        for field_name in ("drand_chain_hash", "drand_chain_url", "drand_ciphertext"):
            if not isinstance(metadata.get(field_name), str) or not metadata[field_name]:
                raise ValueError(f"Metadata corrupted: drand capsule requires {field_name}")
        if metadata.get("drand_beacon_id") is not None and not isinstance(metadata["drand_beacon_id"], str):
            raise ValueError("Metadata corrupted: invalid drand beacon ID")
    else:
        if any(value is not None for value in drand_fields):
            raise ValueError("Metadata corrupted: non-time-capsule file cannot contain drand fields")
        if any(value is not None for value in aavrit_fields):
            raise ValueError("Metadata corrupted: non-time-capsule file cannot contain Aavrit fields")


def _validate_pqc_fields(metadata: dict) -> None:
    pqc_required = bool(metadata.get("pqc_required"))
    pqc_algorithm = metadata.get("pqc_algorithm")
    pqc_key_id = metadata.get("pqc_key_id")
    pqc_ciphertext = metadata.get("pqc_ciphertext")
    pqc_private_key = metadata.get("pqc_private_key")

    if pqc_required:
        if pqc_algorithm != PQC_SUITE_ID:
            raise ValueError("Metadata corrupted: unsupported PQC algorithm")
        if not isinstance(pqc_key_id, str) or len(pqc_key_id) != 64:
            raise ValueError("Metadata corrupted: invalid PQC key identifier")
        if not isinstance(pqc_ciphertext, (bytes, bytearray)) or len(pqc_ciphertext) == 0:
            raise ValueError("Metadata corrupted: PQC keyfile mode requires ciphertext")
    elif any(value is not None for value in [pqc_algorithm, pqc_key_id, pqc_ciphertext]):
        raise ValueError("Metadata corrupted: inactive PQC fields must be empty")

    if pqc_private_key is not None:
        raise ValueError("Metadata corrupted: PQC private key must not be embedded in the archive")


def _validate_keyphrase_fields(metadata: dict) -> None:
    keyphrase_protected = bool(metadata.get("keyphrase_protected"))
    keyphrase_format_version = metadata.get("keyphrase_format_version")
    keyphrase_wordlist_id = metadata.get("keyphrase_wordlist_id")

    if keyphrase_protected:
        if keyphrase_format_version != 1:
            raise ValueError("Metadata corrupted: unsupported keyphrase format version")
        if keyphrase_wordlist_id != "avikal-hi-2048-v1":
            raise ValueError("Metadata corrupted: unsupported keyphrase wordlist")
    else:
        if keyphrase_format_version not in {None, 0}:
            raise ValueError("Metadata corrupted: inactive keyphrase format field must be zero")
        if keyphrase_wordlist_id not in {None, ""}:
            raise ValueError("Metadata corrupted: inactive keyphrase wordlist field must be empty")
        metadata["keyphrase_format_version"] = 0
        metadata["keyphrase_wordlist_id"] = None


def _validate_archive_binding(metadata: dict) -> None:
    if metadata.get("archive_type") not in {"multi_file", "single_file"}:
        raise ValueError("Metadata corrupted: unsupported archive type")
    if not isinstance(metadata.get("entry_count"), int) or metadata["entry_count"] <= 0:
        raise ValueError("Metadata corrupted: invalid archive entry count")
    if not isinstance(metadata.get("total_original_size"), int) or metadata["total_original_size"] < 0:
        raise ValueError("Metadata corrupted: invalid archive total size")
    if not isinstance(metadata.get("manifest_hash"), (bytes, bytearray)) or len(metadata["manifest_hash"]) != 32:
        raise ValueError("Metadata corrupted: invalid archive manifest hash")


def _validate_wrapped_payload_key(metadata: dict) -> None:
    wrap_algorithm = metadata.get("payload_key_wrap_algorithm")
    wrapped_payload_key = metadata.get("wrapped_payload_key")
    encryption_method = metadata.get("encryption_method")

    if wrapped_payload_key is None:
        if wrap_algorithm is not None:
            raise ValueError("Metadata corrupted: inactive payload key wrap algorithm")
        return

    if wrap_algorithm != PAYLOAD_KEY_WRAP_ALGORITHM:
        raise ValueError("Metadata corrupted: unsupported payload key wrap algorithm")
    if not isinstance(wrapped_payload_key, (bytes, bytearray)) or len(wrapped_payload_key) == 0:
        raise ValueError("Metadata corrupted: missing wrapped payload key")
    if encryption_method == "plaintext_archive":
        raise ValueError("Metadata corrupted: plaintext archive cannot contain a wrapped payload key")
