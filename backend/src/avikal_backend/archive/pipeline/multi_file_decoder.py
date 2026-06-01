"""Multi-file Avikal archive decoder.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import hashlib
import os
import shutil
import tempfile
import time
import uuid
import zipfile
from typing import Dict

from avikal_backend.core.temp_janitor import register_temp_artifact, unregister_temp_artifact

from ..format.header import parse_header_bytes, validate_metadata_against_header
from ..format.manifest import MAX_MANIFEST_BYTES, is_internal_manifest_path, load_archive_manifest
from ..format.multifile_stream import (
    extract_multifile_stream_from_plaintext_chunks,
    extract_multifile_stream_container,
    is_multifile_stream_container,
    read_multifile_stream_manifest,
)
from ..format.container import open_avk_payload_stream
from ..security.crypto import (
    compute_checksum,
    derive_time_only_payload_key,
    derive_pqc_hybrid_payload_key,
    secure_zero,
)
from ..chess_metadata import decode_chess_to_metadata_enhanced
from ..path_safety import normalize_multi_archive_relative_path, resolve_safe_relative_output_path
from .payload_streaming import LegacyPayloadStreamingRequired, iter_payload_plaintext_chunks, stream_payload_to_file
from .progress import get_progress_tracker
from ..security.pqc_keyfile import (
    PQC_STORAGE_MODE_EMBEDDED,
    PQC_STORAGE_MODE_EXTERNAL,
    read_embedded_pqc_blob,
    read_pqc_keyfile,
)
from ..security.pqc_provider import decapsulate_pqc_archive_material
from ..security.key_wrap import unwrap_payload_key
from ..runtime_logging import runtime_debug_print as print


def _payload_container_output_limit(metadata: dict) -> int:
    total_original_size = int(metadata.get("total_original_size") or 0)
    entry_count = int(metadata.get("entry_count") or 0)
    zip_overhead_budget = max(1, entry_count) * 512
    return total_original_size + MAX_MANIFEST_BYTES + zip_overhead_budget + (1024 * 1024)


def inspect_multi_file_avk(
    avk_filepath: str,
    password: str = None,
    keyphrase: list = None,
    time_key: bytes = None,
    pqc_keyfile_path: str = None,
    pqc_keyfile_password: str = None,
) -> Dict:
    """Inspect a multi-file .avk archive without extracting files."""
    temp_container_path = None
    temp_extract_root = None
    extracted_files = []
    pqc_shared_secret = None
    master_key = None
    payload_key = None
    payload_decryption_key = None
    pqc_private_bundle = None
    payload_salt = None
    try:
        tracker = get_progress_tracker()
        print(f"Opening multi-file {avk_filepath}...")
        try:
            with open_avk_payload_stream(avk_filepath) as (header_bytes, keychain_pgn, payload_stream, embedded_pqc_blob):
                header_info = parse_header_bytes(header_bytes)
                if tracker:
                    tracker.update("metadata", "Reading archive metadata", 0.05, force=True)

                print("Decoding chess PGN...")
                try:
                    start_chess = time.time()
                    metadata = decode_chess_to_metadata_enhanced(
                        keychain_pgn,
                        password,
                        keyphrase,
                        skip_timelock=False,
                        aad=header_bytes,
                        progress_tracker=tracker,
                    )
                    validate_metadata_against_header(header_info, metadata)
                    chess_decoding_time = time.time() - start_chess
                    if tracker:
                        tracker.update("metadata", "Decoding secure metadata", 1.0)
                    print(f"Chess decoding completed in {chess_decoding_time:.2f} seconds")
                except ValueError as exc:
                    error_msg = str(exc)
                    if "password protected" in error_msg.lower():
                        raise ValueError("This file is password protected. Please provide password.") from exc
                    if "incorrect password" in error_msg.lower() or "decryption failed" in error_msg.lower():
                        raise ValueError("Incorrect password or keyphrase.") from exc
                    if "time capsule is locked" in error_msg.lower():
                        raise ValueError(error_msg) from exc
                    raise ValueError(f"Chess decoding failed: {error_msg}") from exc

                print("Extracting salts from metadata...")
                try:
                    payload_salt = metadata["salt"]
                    print(f"Payload salt extracted: {len(payload_salt)} bytes")

                    from ..security.crypto import derive_hierarchical_keys

                    if metadata["encryption_method"] == "plaintext_archive":
                        if tracker:
                            tracker.update("payload", "Archive payload is not encrypted", 0.03)
                        master_key = None
                        payload_key = None
                    elif metadata["encryption_method"] == "aes256gcm_stream_timekey":
                        if not time_key:
                            raise ValueError("This archive requires the time-capsule unlock flow.")
                        print("[Multi] Deriving payload key from provider-held time key only...")
                        if tracker:
                            tracker.update("payload", "Deriving time-capsule payload key", 0.08)
                        master_key = None
                        payload_key = derive_time_only_payload_key(time_key, payload_salt)
                    else:
                        print("Deriving payload key with extracted salt...")
                        if tracker:
                            tracker.update("payload", "Deriving access key with Argon2id", 0.08, force=True)
                        master_key, payload_key, _, _ = derive_hierarchical_keys(password, keyphrase, payload_salt)
                        if tracker:
                            tracker.update("payload", "Payload key hierarchy ready", 0.14)

                    if time_key and metadata["encryption_method"] == "aes256gcm_stream":
                        print("[Multi] Combining Key A (password) and Key B (Aavrit) for split-key decryption...")
                        from ..security.crypto import combine_split_keys

                        if tracker:
                            tracker.update("payload", "Combining local and time-release keys", 0.18)
                        combined_key = combine_split_keys(payload_key, time_key, payload_salt)
                        payload_key = combined_key[:32]
                except KeyError as exc:
                    raise ValueError("Invalid metadata: salt not found") from exc

                try:
                    encryption_method = metadata["encryption_method"]
                    pqc_ciphertext = metadata.get("pqc_ciphertext")
                    pqc_required = bool(metadata.get("pqc_required"))
                    pqc_algorithm = metadata.get("pqc_algorithm")
                    pqc_key_id = metadata.get("pqc_key_id")
                    pqc_storage_mode = metadata.get("pqc_storage_mode") or (
                        PQC_STORAGE_MODE_EXTERNAL if pqc_required else None
                    )
                    expected_checksum = metadata["checksum"]
                    keyphrase_protected = metadata.get("keyphrase_protected", False)

                    print(f"Detected encryption: {encryption_method}")

                    if keyphrase_protected and not keyphrase:
                        raise ValueError(
                            "This file is protected with a 21-word Hindi keyphrase. Please provide the keyphrase to inspect it."
                        )

                    if keyphrase:
                        from ...mnemonic.generator import normalize_mnemonic_words

                        keyphrase = normalize_mnemonic_words(keyphrase)

                    if pqc_required:
                        if pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED:
                            if tracker:
                                tracker.update("payload", "Unlocking embedded PQC", 0.05)
                            print("[Multi] Unlocking embedded PQC bundle...")
                            pqc_key_bundle = read_embedded_pqc_blob(
                                embedded_pqc_blob,
                                password=password,
                                keyphrase=keyphrase,
                                header_aad=header_bytes,
                                expected_key_id=pqc_key_id,
                                expected_algorithm=pqc_algorithm,
                            )
                        else:
                            if embedded_pqc_blob is not None:
                                raise ValueError("Archive metadata expects an external PQC keyfile, but an embedded PQC bundle was found.")
                            if tracker:
                                tracker.update("payload", "Loading PQC keyfile", 0.05)
                            print("[Multi] Loading external PQC keyfile...")
                            pqc_key_bundle = read_pqc_keyfile(
                                pqc_keyfile_path,
                                password=password,
                                keyphrase=keyphrase,
                                expected_key_id=pqc_key_id,
                                expected_algorithm=pqc_algorithm,
                                pqc_keyfile_password=pqc_keyfile_password,
                            )
                        pqc_private_bundle = pqc_key_bundle["private_bundle"]
                        if tracker:
                            tracker.update("payload", "Verifying PQC bundle signatures", 0.10)
                        pqc_shared_secret = decapsulate_pqc_archive_material(
                            private_bundle=pqc_private_bundle,
                            public_bundle=pqc_key_bundle["public_bundle"],
                            pqc_ciphertext=pqc_ciphertext,
                            expected_key_id=pqc_key_id,
                        )
                        if tracker:
                            tracker.update("payload", "Mixing PQC shared secret into payload key", 0.16)
                        payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, payload_salt)
                    elif embedded_pqc_blob is not None:
                        raise ValueError("Archive contains an unexpected embedded PQC bundle.")

                    wrapped_payload_key = metadata.get("wrapped_payload_key")
                    if wrapped_payload_key:
                        if tracker:
                            tracker.update("payload", "Unwrapping payload data key", 0.20)
                        payload_decryption_key = unwrap_payload_key(wrapped_payload_key, payload_key, header_bytes)
                    else:
                        payload_decryption_key = payload_key

                    expected_time_key_hash = metadata.get("time_key_hash")
                    if time_key is not None and expected_time_key_hash is not None:
                        from ..security.crypto import verify_time_key_hash

                        if not verify_time_key_hash(time_key, expected_time_key_hash):
                            raise ValueError("Provider unlock key verification failed. The archive or unlock response is invalid.")

                    temp_container = tempfile.NamedTemporaryFile(
                        suffix=".zip",
                        prefix=".avikal-inspect-",
                        delete=False,
                    )
                    temp_container_path = temp_container.name
                    temp_container.close()
                    register_temp_artifact(temp_container_path)

                    print("Streaming payload decode into temporary container...")
                    if tracker:
                        tracker.update("payload", "Preparing multi-file payload stream", 0.24)
                    start_decrypt = time.time()
                    stream_payload_to_file(
                        payload_stream=payload_stream,
                        output_path=temp_container_path,
                        aad=header_bytes,
                        decrypt_key=payload_decryption_key,
                        expected_checksum=expected_checksum,
                        max_output_size=_payload_container_output_limit(metadata),
                        progress_callback=(
                            (lambda processed, total: tracker.update(
                                "payload",
                                "Decrypting multi-file payload",
                                (processed / total) if total else 0.0,
                            ))
                            if tracker else None
                        ),
                    )
                    decrypt_time = time.time() - start_decrypt
                    print(f"Streaming payload decode completed in {decrypt_time:.2f}s")
                except KeyError as exc:
                    raise ValueError(f"Invalid metadata structure: missing {str(exc)}") from exc
        except Exception as exc:
            raise ValueError(f"Failed to open .avk file: {str(exc)}") from exc

        with zipfile.ZipFile(temp_container_path, "r") as container_zip:
            manifest, manifest_bytes = load_archive_manifest(container_zip)
            expected_manifest_hash = metadata.get("manifest_hash")
            expected_entry_count = metadata.get("entry_count")
            expected_total_size = metadata.get("total_original_size")

            if metadata.get("archive_type") != "multi_file":
                raise ValueError("Archive metadata is missing multi-file manifest protection")
            if not isinstance(expected_manifest_hash, (bytes, bytearray)) or len(expected_manifest_hash) != 32:
                raise ValueError("Archive metadata is missing a valid manifest hash")
            if compute_checksum(manifest_bytes) != expected_manifest_hash:
                raise ValueError(
                    "Payload manifest verification failed. keychain.pgn does not match payload.enc."
                )
            if manifest["file_count"] != expected_entry_count:
                raise ValueError("Payload manifest file count does not match keychain metadata")
            if manifest["total_original_size"] != expected_total_size:
                raise ValueError("Payload manifest size summary does not match keychain metadata")
        total_time = chess_decoding_time + decrypt_time
        print(f"\nSuccess! Inspected {manifest['file_count']} files")
        print(f"  Total size: {manifest['total_original_size']:,} bytes")
        print(
            f"  Total time: {total_time:.2f}s "
            f"(chess: {chess_decoding_time:.2f}s, payload: {decrypt_time:.2f}s)"
        )

        return {
            "manifest": manifest,
            "file_count": manifest["file_count"],
            "total_size": manifest["total_original_size"],
        }
    except zipfile.BadZipFile as exc:
        raise ValueError("Encrypted multi-file payload is not a valid container ZIP") from exc
    finally:
        if temp_container_path and os.path.exists(temp_container_path):
            os.remove(temp_container_path)
            unregister_temp_artifact(temp_container_path)
        if master_key:
            secure_zero(master_key)
        if payload_salt:
            secure_zero(payload_salt)
        if pqc_shared_secret:
            secure_zero(pqc_shared_secret)
        if payload_key:
            secure_zero(payload_key)
        if payload_decryption_key and payload_decryption_key is not payload_key:
            secure_zero(payload_decryption_key)
        if password:
            secure_zero(password.encode("utf-8"))


def extract_multi_file_avk(
    avk_filepath: str,
    output_directory: str,
    password: str = None,
    keyphrase: list = None,
    time_key: bytes = None,
    pqc_keyfile_path: str = None,
    pqc_keyfile_password: str = None,
    metadata_override: dict | None = None,
) -> Dict:
    """Extract a multi-file .avk archive."""
    temp_container_path = None
    temp_extract_root = None
    extracted_files = []
    pqc_shared_secret = None
    master_key = None
    payload_key = None
    payload_decryption_key = None
    pqc_private_bundle = None
    payload_salt = None
    used_streaming_payload = False
    print(f"Opening multi-file {avk_filepath}...")
    chess_decoding_time = 0.0
    try:
        tracker = get_progress_tracker()
        try:
            with open_avk_payload_stream(avk_filepath) as (header_bytes, keychain_pgn, payload_stream, embedded_pqc_blob):
                header_info = parse_header_bytes(header_bytes)
                if tracker:
                    tracker.update("metadata", "Reading archive metadata", 0.05, force=True)

                if metadata_override is not None:
                    metadata = metadata_override
                    validate_metadata_against_header(header_info, metadata)
                    if tracker:
                        tracker.update("metadata", "Validated secure metadata", 1.0)
                else:
                    print("Decoding chess PGN...")
                    try:
                        start_chess = time.time()
                        metadata = decode_chess_to_metadata_enhanced(
                            keychain_pgn,
                            password,
                            keyphrase,
                            skip_timelock=False,
                            aad=header_bytes,
                            progress_tracker=tracker,
                        )
                        validate_metadata_against_header(header_info, metadata)
                        chess_decoding_time = time.time() - start_chess
                        if tracker:
                            tracker.update("metadata", "Decoding secure metadata", 1.0)
                        print(f"Chess decoding completed in {chess_decoding_time:.2f} seconds")
                    except ValueError as exc:
                        error_msg = str(exc)
                        if "password protected" in error_msg.lower():
                            raise ValueError("This file is password protected. Please provide password.") from exc
                        if "incorrect password" in error_msg.lower() or "decryption failed" in error_msg.lower():
                            raise ValueError("Incorrect password or keyphrase.") from exc
                        if "time capsule is locked" in error_msg.lower():
                            raise ValueError(error_msg) from exc
                        raise ValueError(f"Chess decoding failed: {error_msg}") from exc

                print("Extracting salts from metadata...")
                try:
                    payload_salt = metadata["salt"]
                    print(f"Payload salt extracted: {len(payload_salt)} bytes")

                    from ..security.crypto import derive_hierarchical_keys

                    if metadata["encryption_method"] == "plaintext_archive":
                        if tracker:
                            tracker.update("payload", "Archive payload is not encrypted", 0.03)
                        master_key = None
                        payload_key = None
                    elif metadata["encryption_method"] == "aes256gcm_stream_timekey":
                        if not time_key:
                            raise ValueError("This archive requires the time-capsule unlock flow.")
                        print("[Multi] Deriving payload key from provider-held time key only...")
                        if tracker:
                            tracker.update("payload", "Deriving time-capsule payload key", 0.08)
                        master_key = None
                        payload_key = derive_time_only_payload_key(time_key, payload_salt)
                    else:
                        print("Deriving payload key with extracted salt...")
                        if tracker:
                            tracker.update("payload", "Deriving access key with Argon2id", 0.08, force=True)
                        master_key, payload_key, _, _ = derive_hierarchical_keys(password, keyphrase, payload_salt)
                        if tracker:
                            tracker.update("payload", "Payload key hierarchy ready", 0.14)

                    if time_key and metadata["encryption_method"] == "aes256gcm_stream":
                        print("[Multi] Combining Key A (password) and Key B (Aavrit) for split-key decryption...")
                        from ..security.crypto import combine_split_keys

                        if tracker:
                            tracker.update("payload", "Combining local and time-release keys", 0.18)
                        combined_key = combine_split_keys(payload_key, time_key, payload_salt)
                        payload_key = combined_key[:32]
                except KeyError as exc:
                    raise ValueError("Invalid metadata: salt not found") from exc

                try:
                    encryption_method = metadata["encryption_method"]
                    pqc_ciphertext = metadata.get("pqc_ciphertext")
                    pqc_required = bool(metadata.get("pqc_required"))
                    pqc_algorithm = metadata.get("pqc_algorithm")
                    pqc_key_id = metadata.get("pqc_key_id")
                    pqc_storage_mode = metadata.get("pqc_storage_mode") or (
                        PQC_STORAGE_MODE_EXTERNAL if pqc_required else None
                    )
                    expected_checksum = metadata["checksum"]
                    keyphrase_protected = metadata.get("keyphrase_protected", False)

                    print(f"Detected encryption: {encryption_method}")

                    if keyphrase_protected and not keyphrase:
                        raise ValueError(
                            "This file is protected with a 21-word Hindi keyphrase. Please provide the keyphrase to decrypt."
                        )

                    if keyphrase:
                        from ...mnemonic.generator import normalize_mnemonic_words

                        keyphrase = normalize_mnemonic_words(keyphrase)

                    if pqc_required:
                        if pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED:
                            if tracker:
                                tracker.update("payload", "Unlocking embedded PQC", 0.05)
                            print("[Multi] Unlocking embedded PQC bundle...")
                            pqc_key_bundle = read_embedded_pqc_blob(
                                embedded_pqc_blob,
                                password=password,
                                keyphrase=keyphrase,
                                header_aad=header_bytes,
                                expected_key_id=pqc_key_id,
                                expected_algorithm=pqc_algorithm,
                            )
                        else:
                            if embedded_pqc_blob is not None:
                                raise ValueError("Archive metadata expects an external PQC keyfile, but an embedded PQC bundle was found.")
                            if tracker:
                                tracker.update("payload", "Loading PQC keyfile", 0.05)
                            print("[Multi] Loading external PQC keyfile...")
                            pqc_key_bundle = read_pqc_keyfile(
                                pqc_keyfile_path,
                                password=password,
                                keyphrase=keyphrase,
                                expected_key_id=pqc_key_id,
                                expected_algorithm=pqc_algorithm,
                                pqc_keyfile_password=pqc_keyfile_password,
                            )
                        pqc_private_bundle = pqc_key_bundle["private_bundle"]
                        if tracker:
                            tracker.update("payload", "Verifying PQC bundle signatures", 0.10)
                        pqc_shared_secret = decapsulate_pqc_archive_material(
                            private_bundle=pqc_private_bundle,
                            public_bundle=pqc_key_bundle["public_bundle"],
                            pqc_ciphertext=pqc_ciphertext,
                            expected_key_id=pqc_key_id,
                        )
                        if tracker:
                            tracker.update("payload", "Mixing PQC shared secret into payload key", 0.16)
                        payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, payload_salt)
                    elif embedded_pqc_blob is not None:
                        raise ValueError("Archive contains an unexpected embedded PQC bundle.")

                    wrapped_payload_key = metadata.get("wrapped_payload_key")
                    if wrapped_payload_key:
                        if tracker:
                            tracker.update("payload", "Unwrapping payload data key", 0.20)
                        payload_decryption_key = unwrap_payload_key(wrapped_payload_key, payload_key, header_bytes)
                    else:
                        payload_decryption_key = payload_key

                    expected_time_key_hash = metadata.get("time_key_hash")
                    if time_key is not None and expected_time_key_hash is not None:
                        from ..security.crypto import verify_time_key_hash

                        if not verify_time_key_hash(time_key, expected_time_key_hash):
                            raise ValueError("Provider unlock key verification failed. The archive or unlock response is invalid.")

                    if tracker:
                        tracker.update("payload", "Preparing multi-file payload stream", 0.24)
                    start_decrypt = time.time()
                    expected_manifest_hash = metadata.get("manifest_hash")
                    expected_entry_count = metadata.get("entry_count")
                    expected_total_size = metadata.get("total_original_size")
                    if metadata.get("archive_type") != "multi_file":
                        raise ValueError("Archive metadata is missing multi-file manifest protection")
                    try:
                        print("Streaming current multi-file payload directly into preview storage...")
                        temp_extract_root = os.path.join(tempfile.gettempdir(), f"avikal_extract_{uuid.uuid4().hex}")
                        os.makedirs(temp_extract_root, exist_ok=False)
                        register_temp_artifact(temp_extract_root, kind="dir")
                        plaintext_chunks = iter_payload_plaintext_chunks(
                            payload_stream=payload_stream,
                            aad=header_bytes,
                            decrypt_key=payload_decryption_key,
                            expected_checksum=expected_checksum,
                            max_output_size=_payload_container_output_limit(metadata),
                            progress_callback=(
                                (lambda processed, total: tracker.update(
                                    "payload",
                                    "Decrypting multi-file payload",
                                    (processed / total) if total else 0.0,
                                ))
                                if tracker else None
                            ),
                        )
                        extracted_files = extract_multifile_stream_from_plaintext_chunks(
                            plaintext_chunks,
                            temp_extract_root,
                            expected_manifest_hash=expected_manifest_hash,
                            expected_entry_count=expected_entry_count,
                            expected_total_size=expected_total_size,
                        )
                        if tracker:
                            tracker.update("payload", "Multi-file payload decrypted", 1.0, force=True)
                        used_streaming_payload = True
                    except LegacyPayloadStreamingRequired:
                        if temp_extract_root:
                            shutil.rmtree(temp_extract_root, ignore_errors=True)
                            unregister_temp_artifact(temp_extract_root)
                            temp_extract_root = None
                        temp_container = tempfile.NamedTemporaryFile(
                            suffix=".zip",
                            prefix=".avikal-container-dec-",
                            delete=False,
                        )
                        temp_container_path = temp_container.name
                        temp_container.close()
                        register_temp_artifact(temp_container_path)
                        print("Streaming legacy payload decode into temporary container...")
                        stream_payload_to_file(
                            payload_stream=payload_stream,
                            output_path=temp_container_path,
                            aad=header_bytes,
                            decrypt_key=payload_decryption_key,
                            expected_checksum=expected_checksum,
                            max_output_size=_payload_container_output_limit(metadata),
                            progress_callback=(
                                (lambda processed, total: tracker.update(
                                    "payload",
                                    "Decrypting multi-file payload",
                                    (processed / total) if total else 0.0,
                                ))
                                if tracker else None
                            ),
                        )
                    except Exception:
                        if temp_extract_root:
                            shutil.rmtree(temp_extract_root, ignore_errors=True)
                            unregister_temp_artifact(temp_extract_root)
                            temp_extract_root = None
                        raise
                    decrypt_time = time.time() - start_decrypt
                    print(f"Streaming payload decode completed in {decrypt_time:.2f}s")
                except KeyError as exc:
                    raise ValueError(f"Invalid metadata structure: missing {str(exc)}") from exc
        except Exception as exc:
            raise ValueError(f"Failed to open .avk file: {str(exc)}") from exc

        if not used_streaming_payload:
            print("Extracting files from container...")
            temp_extract_root = os.path.join(tempfile.gettempdir(), f"avikal_extract_{uuid.uuid4().hex}")
            os.makedirs(temp_extract_root, exist_ok=False)
            register_temp_artifact(temp_extract_root, kind="dir")
            try:
                with open(temp_container_path, "rb") as container_handle:
                    if is_multifile_stream_container(container_handle):
                        manifest, manifest_bytes = read_multifile_stream_manifest(container_handle)
                        expected_manifest_hash = metadata.get("manifest_hash")
                        expected_entry_count = metadata.get("entry_count")
                        expected_total_size = metadata.get("total_original_size")
                        if metadata.get("archive_type") != "multi_file":
                            raise ValueError("Archive metadata is missing multi-file manifest protection")
                        if not isinstance(expected_manifest_hash, (bytes, bytearray)) or len(expected_manifest_hash) != 32:
                            raise ValueError("Archive metadata is missing a valid manifest hash")
                        if compute_checksum(manifest_bytes) != expected_manifest_hash:
                            raise ValueError("Payload manifest verification failed. keychain.pgn does not match payload.enc.")
                        if manifest["file_count"] != expected_entry_count:
                            raise ValueError("Payload manifest file count does not match keychain metadata")
                        if manifest["total_original_size"] != expected_total_size:
                            raise ValueError("Payload manifest size summary does not match keychain metadata")
                        extracted_files = extract_multifile_stream_container(temp_container_path, temp_extract_root, manifest)
                        if tracker:
                            tracker.update("finalize", "Preparing preview files", 1.0)
                    else:
                        with zipfile.ZipFile(temp_container_path, "r") as container_zip:
                            all_members = container_zip.infolist()
                            member_names = [member.filename for member in all_members]
                            if len(member_names) != len(set(member_names)):
                                raise ValueError("Encrypted payload container contains duplicate entries")

                            manifest, manifest_bytes = load_archive_manifest(container_zip)
                            expected_manifest_hash = metadata.get("manifest_hash")
                            expected_entry_count = metadata.get("entry_count")
                            expected_total_size = metadata.get("total_original_size")

                            if metadata.get("archive_type") != "multi_file":
                                raise ValueError("Archive metadata is missing multi-file manifest protection")
                            if not isinstance(expected_manifest_hash, (bytes, bytearray)) or len(expected_manifest_hash) != 32:
                                raise ValueError("Archive metadata is missing a valid manifest hash")
                            if compute_checksum(manifest_bytes) != expected_manifest_hash:
                                raise ValueError("Payload manifest verification failed. keychain.pgn does not match payload.enc.")
                            if manifest["file_count"] != expected_entry_count:
                                raise ValueError("Payload manifest file count does not match keychain metadata")
                            if manifest["total_original_size"] != expected_total_size:
                                raise ValueError("Payload manifest size summary does not match keychain metadata")

                            file_members = {
                                member.filename: member
                                for member in all_members
                                if not member.filename.endswith("/") and not is_internal_manifest_path(member.filename)
                            }
                            manifest_entries = manifest["files"]
                            manifest_names = [entry["filename"] for entry in manifest_entries]
                            if set(file_members) != set(manifest_names):
                                raise ValueError("Payload manifest entries do not match encrypted container contents")

                            total_verified_size = 0
                            for index, entry in enumerate(manifest_entries):
                                arcname = entry["filename"]
                                member = file_members[arcname]
                                if tracker:
                                    tracker.update("finalize", f"Preparing preview: {arcname}", index / max(1, len(manifest_entries)))
                                safe_relpath = normalize_multi_archive_relative_path(arcname)
                                output_filepath = resolve_safe_relative_output_path(temp_extract_root, safe_relpath)
                                os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
                                file_size = 0
                                digest = hashlib.sha256()
                                with container_zip.open(member.filename, "r") as source, open(output_filepath, "wb") as handle:
                                    while True:
                                        chunk = source.read(1024 * 1024)
                                        if not chunk:
                                            break
                                        file_size += len(chunk)
                                        if file_size > entry["size"]:
                                            raise ValueError(f"Manifest size mismatch for {arcname}")
                                        digest.update(chunk)
                                        handle.write(chunk)
                                if file_size != entry["size"]:
                                    raise ValueError(f"Manifest size mismatch for {arcname}")
                                if digest.hexdigest() != entry["checksum"]:
                                    raise ValueError(f"Manifest checksum mismatch for {arcname}")
                                total_verified_size += file_size
                                extracted_files.append({"filename": safe_relpath.replace("/", os.sep), "path": output_filepath, "size": file_size})
                            if total_verified_size != manifest["total_original_size"]:
                                raise ValueError("Payload manifest total size verification failed")
                            if tracker:
                                tracker.update("finalize", "Preparing preview files", 1.0)
            except Exception:
                shutil.rmtree(temp_extract_root, ignore_errors=True)
                unregister_temp_artifact(temp_extract_root)
                raise
    except zipfile.BadZipFile as exc:
        raise ValueError("Encrypted multi-file payload is not a valid container ZIP") from exc
    finally:
        if temp_container_path and os.path.exists(temp_container_path):
            os.remove(temp_container_path)
            unregister_temp_artifact(temp_container_path)
        if master_key:
            secure_zero(master_key)
        if payload_salt:
            secure_zero(payload_salt)
        if pqc_shared_secret:
            secure_zero(pqc_shared_secret)
        if payload_key:
            secure_zero(payload_key)
        if payload_decryption_key and payload_decryption_key is not payload_key:
            secure_zero(payload_decryption_key)
        if password:
            secure_zero(password.encode("utf-8"))

    os.makedirs(output_directory, exist_ok=True)
    committed_files = []
    try:
        for file_info in extracted_files:
            rel_path = file_info["filename"]
            temp_path = file_info["path"]
            final_path = resolve_safe_relative_output_path(output_directory, rel_path.replace(os.sep, "/"))
            if os.path.exists(final_path):
                raise ValueError(f"Refusing to overwrite existing extracted file: {rel_path}")
            os.makedirs(os.path.dirname(final_path), exist_ok=True)
            shutil.move(temp_path, final_path)
            file_info["path"] = final_path
            committed_files.append(file_info)
    except Exception:
        for file_info in committed_files:
            try:
                if os.path.exists(file_info["path"]):
                    os.remove(file_info["path"])
            except OSError as exc:
                print(f"Cleanup warning: failed to remove partial extracted file {file_info['path']}: {exc}")
        raise
    finally:
        if temp_extract_root:
            shutil.rmtree(temp_extract_root, ignore_errors=True)
            unregister_temp_artifact(temp_extract_root)

    total_time = chess_decoding_time + decrypt_time
    total_size = sum(file_info["size"] for file_info in extracted_files)

    print(f"\nSuccess! Extracted {len(extracted_files)} files")
    print(f"  Total size: {total_size:,} bytes")
    print("  Checksum: Verified")
    print(
        f"  Total time: {total_time:.2f}s "
        f"(chess: {chess_decoding_time:.2f}s, payload: {decrypt_time:.2f}s)"
    )

    security_features = []
    if encryption_method == "plaintext_archive":
        security_features.append("Explicit Standard Archive (not encrypted)")
    elif encryption_method == "aes256gcm_stream_timekey":
        security_features.append("Time-Key Encryption (provider-held unlock shard)")
        security_features.append("Chess Metadata Encoding")
    else:
        security_features.append("Hierarchical Keys (Argon2id + HKDF)")
        security_features.append("Streaming AES-256-GCM Payload Decryption")
        if metadata.get("pqc_required"):
            if metadata.get("pqc_storage_mode") == PQC_STORAGE_MODE_EMBEDDED:
                security_features.append("Embedded Quantum Protection (OpenSSL ML-KEM + X25519 + ML-DSA + SLH-DSA)")
            else:
                security_features.append("External Quantum Keyfile (OpenSSL ML-KEM + X25519 + ML-DSA + SLH-DSA)")
        elif metadata.get("pqc_ciphertext"):
            security_features.append("Post-Quantum Cryptography (OpenSSL PQC Suite)")
        security_features.append("Chess Cascade Security (AES + ChaCha)")
    security_features.append("Manifest-Bound Multi-File Payload")
    if metadata.get("keyphrase_protected"):
        security_features.append("Hindi Mnemonic Keyphrase (21-word, checksum-validated)")

    print(f"  Security: {', '.join(security_features)}")
    print("\nExtracted Files:")
    for file_info in extracted_files:
        print(f"  - {file_info['filename']} ({file_info['size']:,} bytes)")
    if tracker:
        tracker.complete("Preview ready")

    return {
        "files": extracted_files,
        "file_count": len(extracted_files),
        "total_size": total_size,
        "output_directory": output_directory,
    }
