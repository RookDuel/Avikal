"""Multi-file Avikal archive encoder.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import os
import time
import zipfile
import tempfile
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Tuple

from avikal_backend.core.temp_janitor import register_temp_artifact, unregister_temp_artifact

from ..format.container import read_avk_header_and_keychain
from ..format.header import (
    ARCHIVE_MODE_MULTI,
    attach_public_route_tags_to_keychain_pgn,
    attach_header_to_keychain_pgn,
    build_header_bytes,
    provider_name_to_id,
)
from ..format.manifest import normalize_user_archive_path
from ..format.multifile_stream import (
    build_multifile_stream_manifest,
    iter_multifile_stream_chunks,
    multifile_stream_size,
    scan_multifile_entries,
)
from ..security.crypto import (
    secure_zero,
    derive_pqc_hybrid_payload_key,
    derive_time_only_payload_key,
    has_user_secret,
)
from ..security.key_wrap import (
    PAYLOAD_KEY_WRAP_ALGORITHM,
    generate_payload_key,
    wrap_payload_key,
)
from ..chess_metadata import encode_metadata_to_chess_enhanced
from ..security.pqc_keyfile import (
    PQC_EMBEDDED_MEMBER_NAME,
    PQC_KEYFILE_ALGORITHM,
    PQC_STORAGE_MODE_EMBEDDED,
    PQC_STORAGE_MODE_EXTERNAL,
    build_embedded_pqc_blob,
    default_keyfile_path_for_archive,
    write_pqc_keyfile,
)
from ..security.pqc_provider import create_pqc_archive_material
from ..security.time_lock import datetime_to_timestamp, format_unlock_time, get_trusted_now
from .payload_streaming import stream_chunks_to_payload_writer
from .progress import get_progress_tracker
from ..runtime_logging import runtime_debug_print as print



def _normalize_path_for_compare(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(path)))


def _is_same_or_child_path(candidate: str, parent: str) -> bool:
    candidate_norm = _normalize_path_for_compare(candidate)
    parent_norm = _normalize_path_for_compare(parent)
    try:
        return os.path.commonpath([candidate_norm, parent_norm]) == parent_norm
    except ValueError:
        return False


def _normalize_excluded_input_paths(paths: List[str], excluded_paths: List[str] | None) -> set[str]:
    if not excluded_paths:
        return set()

    input_roots = [_normalize_path_for_compare(path) for path in paths]
    normalized_exclusions: set[str] = set()
    for excluded_path in excluded_paths:
        if not isinstance(excluded_path, str) or not excluded_path.strip():
            continue
        excluded_norm = _normalize_path_for_compare(excluded_path)
        if not any(_is_same_or_child_path(excluded_norm, root) for root in input_roots):
            raise ValueError("Excluded input path must be inside the selected input files or folders")
        normalized_exclusions.add(excluded_norm)
    return normalized_exclusions


def _is_excluded_path(path: str, excluded_paths: set[str]) -> bool:
    return any(_is_same_or_child_path(path, excluded_path) for excluded_path in excluded_paths)


def _collect_entries(paths: List[str], excluded_paths: List[str] | None = None) -> List[Tuple[str, str]]:
    """Expand file and directory paths into deterministic archive entries."""
    entries: List[Tuple[str, str]] = []
    seen_arcnames: set[str] = set()
    normalized_exclusions = _normalize_excluded_input_paths(paths, excluded_paths)
    for path in paths:
        path = os.path.normpath(path)
        if _is_excluded_path(path, normalized_exclusions):
            continue
        if os.path.isfile(path):
            arcname = normalize_user_archive_path(os.path.basename(path))
            if arcname in seen_arcnames:
                raise ValueError(f"Duplicate archive entry detected: {arcname}")
            seen_arcnames.add(arcname)
            entries.append((path, arcname))
        elif os.path.isdir(path):
            folder_name = os.path.basename(path)
            parent = os.path.dirname(path)
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames[:] = [
                    dirname
                    for dirname in sorted(dirnames)
                    if not _is_excluded_path(os.path.join(dirpath, dirname), normalized_exclusions)
                ]
                for filename in sorted(filenames):  # sorted for determinism
                    abs_file = os.path.join(dirpath, filename)
                    if _is_excluded_path(abs_file, normalized_exclusions):
                        continue
                    rel = os.path.relpath(abs_file, parent)
                    arcname = normalize_user_archive_path(rel.replace(os.sep, '/'))
                    if arcname in seen_arcnames:
                        raise ValueError(f"Duplicate archive entry detected: {arcname}")
                    seen_arcnames.add(arcname)
                    entries.append((abs_file, arcname))
        else:
            raise ValueError(f"Path not found or unsupported type: {path}")
    return sorted(entries, key=lambda item: item[1])


def create_multi_file_avk(
    input_filepaths: List[str],
    output_filepath: str,
    unlock_datetime: datetime = None,
    password: str = None,
    keyphrase: list = None,
    username: str = "",
    variations_per_round: int = 5,
    use_timecapsule: bool = False,
    file_id: str = None,
    server_url: str = None,
    time_key: bytes = None,
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
    pqc_enabled: bool = False,
    pqc_storage_mode: str = PQC_STORAGE_MODE_EXTERNAL,
    pqc_keyfile_output: str = None,
    pqc_keyfile_protection_mode: str = None,
    pqc_keyfile_password: str = None,
    excluded_input_paths: List[str] | None = None,
) -> dict:
    """Create a multi-file .avk archive."""
    result = {}
    operation_started = time.time()
    pqc_ms = 0.0
    argon2_ms = 0.0
    payload_stream_ms = 0.0
    metadata_ms = 0.0
    zip_finalize_ms = 0.0
    
    if not input_filepaths:
        raise ValueError("At least one input file or folder is required")
    
    if keyphrase:
        from ...mnemonic.generator import normalize_mnemonic_words
        keyphrase = normalize_mnemonic_words(keyphrase)
        result['keyphrase'] = keyphrase

    user_secret_enabled = has_user_secret(password, keyphrase)

    if pqc_storage_mode is None:
        pqc_storage_mode = PQC_STORAGE_MODE_EXTERNAL

    if pqc_enabled and not user_secret_enabled:
        raise ValueError(
            "PQC keyfile mode requires a password or keyphrase. "
            "Enable PQC only with archive secrets configured."
        )
    if pqc_storage_mode not in {PQC_STORAGE_MODE_EXTERNAL, PQC_STORAGE_MODE_EMBEDDED}:
        raise ValueError("Unsupported PQC storage mode")
    if not pqc_enabled:
        pqc_storage_mode = PQC_STORAGE_MODE_EXTERNAL
    
    # Validate password strength (if provided)
    if password:
        from ..security.password_validator import validate_password_strength
        try:
            validate_password_strength(password, min_length=12)
        except ValueError as e:
            # Re-raise with clear context
            raise ValueError(f"Password validation failed:\n{str(e)}")
    
    # Validate inputs based on mode
    if use_timecapsule:
        if not unlock_datetime:
            raise ValueError("Unlock datetime is REQUIRED when time-capsule is enabled.")
        
        # Trusted-time validation (ALWAYS for timecapsule)
        try:
            current_time = get_trusted_now()
        except ConnectionError as e:
            raise ConnectionError(f"NTP time synchronization required for timecapsule: {str(e)}")

        if unlock_datetime <= current_time:
            raise ValueError(
                f"Unlock time must be in the future. "
                f"Provided: {unlock_datetime.strftime('%Y-%m-%d %H:%M UTC')}, "
                f"Current: {current_time.strftime('%Y-%m-%d %H:%M UTC')}"
            )
    
    # If not using timecapsule, set unlock_datetime to current time (no lock)
    if not use_timecapsule:
        from datetime import datetime, timezone
        unlock_datetime = datetime.now(timezone.utc)
    
    pqc_private_bundle = None
    pqc_public_bundle = None
    pqc_ciphertext = None
    pqc_shared_secret = None
    pqc_key_id = None
    pqc_keyfile_path = None
    embedded_pqc_blob = None

    if pqc_enabled:
        if pqc_storage_mode == PQC_STORAGE_MODE_EXTERNAL:
            if pqc_keyfile_output:
                pqc_keyfile_path = os.path.abspath(pqc_keyfile_output)
            else:
                pqc_keyfile_path = default_keyfile_path_for_archive(output_filepath)

            if os.path.abspath(output_filepath) == pqc_keyfile_path:
                raise ValueError("PQC keyfile path must be different from the .avk output path")

        pqc_start = time.time()
        pqc_material = create_pqc_archive_material(archive_filename=os.path.basename(output_filepath))
        pqc_ms = (time.time() - pqc_start) * 1000
        pqc_public_bundle = pqc_material["public_bundle"]
        pqc_private_bundle = pqc_material["private_bundle"]
        pqc_ciphertext = pqc_material["ciphertext"]
        pqc_shared_secret = pqc_material["shared_secret"]
        pqc_key_id = pqc_material["key_id"]
    
    # Step 1: Build a manifest without writing plaintext file contents to temp storage.
    all_entries = _collect_entries(input_filepaths, excluded_input_paths)
    if not all_entries:
        raise ValueError("No files were found in the selected inputs")
    print(f"Processing {len(all_entries)} file(s) from {len(input_filepaths)} input path(s)...")
    tracker = get_progress_tracker()
    if tracker:
        tracker.update("prepare", "Preparing multi-file archive", 0.05, force=True)

    output_dir = os.path.dirname(output_filepath) or os.getcwd()
    temp_archive_path = None

    try:
        file_info, total_original_size = scan_multifile_entries(all_entries)
        manifest, manifest_bytes = build_multifile_stream_manifest(file_info, total_original_size)
        manifest_hash = hashlib.sha256(manifest_bytes).digest()
        container_size = multifile_stream_size(manifest_bytes, manifest)
        print(f"Prepared encrypted multi-file stream: {container_size:,} bytes from {len(all_entries)} files")
        if tracker:
            tracker.set_file_size(container_size)

        start_encrypt = time.time()

        import secrets
        payload_salt = secrets.token_bytes(32)

        provider_id = provider_name_to_id(timecapsule_provider if use_timecapsule else None)
        header_bytes = build_header_bytes(
            archive_mode=ARCHIVE_MODE_MULTI,
            provider_id=provider_id,
        )

        master_key = None
        payload_key = None
        payload_encryption_key = None
        wrapped_payload_key = None
        payload_key_wrap_algorithm = None
        if user_secret_enabled:
            if tracker:
                tracker.update("payload", "Deriving protection keys", 0.02)
            print("Deriving payload key with Argon2id...")
            from ..security.crypto import derive_hierarchical_keys

            argon2_start = time.time()
            master_key, payload_key, _, _ = derive_hierarchical_keys(password, keyphrase, payload_salt)
            argon2_ms = (time.time() - argon2_start) * 1000

            if use_timecapsule and time_key:
                print("[Multi] Combining Key A (password) and Key B (time_key) for split-key encryption...")
                from ..security.crypto import combine_split_keys

                combined_key = combine_split_keys(payload_key, time_key, payload_salt)
                payload_key = combined_key[:32]

            if pqc_enabled:
                print("[Multi] Applying external PQC keyfile protection to payload key...")
                payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, payload_salt)

            payload_encryption_key = generate_payload_key()
            wrapped_payload_key = wrap_payload_key(payload_encryption_key, payload_key, header_bytes)
            payload_key_wrap_algorithm = PAYLOAD_KEY_WRAP_ALGORITHM
            encryption_method = "aes256gcm_stream"
        elif use_timecapsule:
            if tracker:
                tracker.update("payload", "Deriving provider-held unlock key", 0.02)
            if not time_key:
                raise ValueError("Time-capsule archives without password or keyphrase require a provider time key")
            print("[Multi] Deriving payload key from provider-held time key only...")
            payload_key = derive_time_only_payload_key(time_key, payload_salt)
            payload_encryption_key = payload_key
            encryption_method = "aes256gcm_stream_timekey"
        else:
            print("[Multi] Creating explicit unencrypted standard archive...")
            encryption_method = "plaintext_archive"

        temp_archive = tempfile.NamedTemporaryFile(
            suffix=".avk",
            prefix=".avikal-archive-",
            delete=False,
            dir=output_dir,
        )
        temp_archive_path = temp_archive.name
        temp_archive.close()
        register_temp_artifact(temp_archive_path)

        payload_stream_start = time.time()
        with zipfile.ZipFile(temp_archive_path, "w") as zf:
            payload_info = zipfile.ZipInfo("payload.enc")
            payload_info.compress_type = zipfile.ZIP_STORED
            with zf.open(payload_info, "w", force_zip64=True) as payload_writer:
                payload_result = stream_chunks_to_payload_writer(
                    chunks=iter_multifile_stream_chunks(all_entries, manifest_bytes),
                    total_input_size=container_size,
                    target=payload_writer,
                    aad=header_bytes,
                    encrypt_key=payload_encryption_key if encryption_method != "plaintext_archive" else None,
                    compress_payload=None,
                    progress_callback=(
                        (lambda processed, _total: tracker.update(
                            "payload",
                            "Streaming encrypted payload" if encryption_method != "plaintext_archive" else "Streaming payload",
                            (processed / container_size) if container_size else 1.0,
                        ))
                        if tracker else None
                    ),
                )
        payload_stream_ms = (time.time() - payload_stream_start) * 1000
        container_checksum = payload_result["checksum"]
        compressed_size = payload_result["compressed_size"]
        compression_ratio = (1 - compressed_size / container_size) * 100 if container_size else 0.0
        encrypt_time = time.time() - start_encrypt
        print(f"Streamed payload ready in {encrypt_time:.2f}s")
        # Step 5: Create compact multi-file metadata
        unlock_timestamp = datetime_to_timestamp(unlock_datetime, use_ntp=use_timecapsule)

        from ..format.metadata import pack_cascade_metadata
        from ...mnemonic.generator import MNEMONIC_FORMAT_VERSION
        from ...mnemonic.wordlist import WORDLIST_ID
        metadata_bytes = pack_cascade_metadata(
            payload_salt, pqc_ciphertext, None, unlock_timestamp,
            "multi_file_container.zip", container_checksum, encryption_method, bool(keyphrase),
            chess_salt=None,
            timelock_mode="convenience",
            file_id=file_id, server_url=server_url, time_key_hash=(hashlib.sha256(time_key).digest() if time_key else None),
            timecapsule_provider=timecapsule_provider,
            aavrit_data_hash=aavrit_data_hash,
            aavrit_commit_hash=aavrit_commit_hash,
            aavrit_server_key_id=aavrit_server_key_id,
            aavrit_commit_signature=aavrit_commit_signature,
            drand_round=drand_round,
            drand_chain_hash=drand_chain_hash,
            drand_chain_url=drand_chain_url,
            drand_ciphertext=drand_ciphertext,
            drand_beacon_id=drand_beacon_id,
            pqc_required=pqc_enabled,
            pqc_algorithm=PQC_KEYFILE_ALGORITHM if pqc_enabled else None,
            pqc_key_id=pqc_key_id,
            pqc_storage_mode=pqc_storage_mode,
            keyphrase_format_version=MNEMONIC_FORMAT_VERSION if keyphrase else None,
            keyphrase_wordlist_id=WORDLIST_ID if keyphrase else None,
            archive_type="multi_file",
            entry_count=len(all_entries),
            total_original_size=total_original_size,
            manifest_hash=manifest_hash,
            payload_key_wrap_algorithm=payload_key_wrap_algorithm,
            wrapped_payload_key=wrapped_payload_key,
        )

        # Step 6: Enhanced chess encoding
        print("Encoding metadata with enhanced chess security...")
        if tracker:
            tracker.update("metadata", "Encoding secure metadata", 0.1)
        start_chess = time.time()
        metadata_start = start_chess
        keychain_pgn = encode_metadata_to_chess_enhanced(
            metadata_bytes,
            password,
            keyphrase,
            variations_per_round,
            use_timecapsule,
            aad=header_bytes,
        )
        keychain_pgn = attach_header_to_keychain_pgn(keychain_pgn, header_bytes)
        keychain_pgn = attach_public_route_tags_to_keychain_pgn(
            keychain_pgn,
            requires_password=bool(password),
            requires_keyphrase=bool(keyphrase),
            requires_pqc=bool(pqc_enabled),
            pqc_storage_mode=pqc_storage_mode if pqc_enabled else None,
            unlock_timestamp=unlock_timestamp if use_timecapsule else None,
            drand_round=drand_round,
            keyphrase_wordlist_id=WORDLIST_ID if keyphrase else None,
        )
        chess_encoding_time = time.time() - start_chess
        metadata_ms = (time.time() - metadata_start) * 1000
        if tracker:
            tracker.update("metadata", "Encoding secure metadata", 1.0)
        print(f"Enhanced chess encoding completed in {chess_encoding_time:.2f} seconds")

        if pqc_enabled and pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED:
            embedded_pqc_blob = build_embedded_pqc_blob(
                password=password,
                keyphrase=keyphrase,
                private_bundle=pqc_private_bundle,
                public_bundle=pqc_public_bundle,
                pqc_ciphertext=pqc_ciphertext,
                archive_filename=os.path.basename(output_filepath),
                header_aad=header_bytes,
                key_id=pqc_key_id,
                algorithm=PQC_KEYFILE_ALGORITHM,
            )

        print(f"Creating {output_filepath}...")
        if tracker:
            tracker.update("finalize", "Writing metadata", 0.25)
        zip_finalize_start = time.time()
        with zipfile.ZipFile(temp_archive_path, "a") as zf:
            zf.writestr("keychain.pgn", keychain_pgn, compress_type=zipfile.ZIP_DEFLATED)
            if embedded_pqc_blob is not None:
                zf.writestr(PQC_EMBEDDED_MEMBER_NAME, embedded_pqc_blob, compress_type=zipfile.ZIP_STORED)
        read_avk_header_and_keychain(temp_archive_path)
        zip_finalize_ms = (time.time() - zip_finalize_start) * 1000

        if pqc_enabled:
            result["pqc"] = {
                "enabled": True,
                "storage_mode": pqc_storage_mode,
                "algorithm": PQC_KEYFILE_ALGORITHM,
                "key_id": pqc_key_id,
            }
            if pqc_storage_mode == PQC_STORAGE_MODE_EXTERNAL:
                keyfile_result = write_pqc_keyfile(
                    pqc_keyfile_path,
                    password=password,
                    keyphrase=keyphrase,
                    private_bundle=pqc_private_bundle,
                    public_bundle=pqc_public_bundle,
                    pqc_ciphertext=pqc_ciphertext,
                    archive_filename=os.path.basename(output_filepath),
                    algorithm=PQC_KEYFILE_ALGORITHM,
                    protection_mode=pqc_keyfile_protection_mode,
                    keyfile_password=pqc_keyfile_password,
                )
                result["pqc"]["keyfile"] = keyfile_result["path"]
            else:
                result["pqc"]["member"] = PQC_EMBEDDED_MEMBER_NAME

        os.replace(temp_archive_path, output_filepath)
        unregister_temp_artifact(temp_archive_path)
        temp_archive_path = None
        if tracker:
            tracker.update("finalize", "Finalizing Avk container", 1.0, compression_ratio=(compressed_size / container_size) if container_size else None)
    finally:
        if temp_archive_path and os.path.exists(temp_archive_path):
            os.remove(temp_archive_path)
            unregister_temp_artifact(temp_archive_path)

    # Clean up sensitive data from memory
    if master_key:
        secure_zero(master_key)
    if payload_salt:
        secure_zero(payload_salt)
    if payload_key:
        secure_zero(payload_key)
    if payload_encryption_key and payload_encryption_key is not payload_key:
        secure_zero(payload_encryption_key)
    if pqc_shared_secret:
        secure_zero(pqc_shared_secret)
    if password:
        secure_zero(password.encode('utf-8'))
    
    avk_size = os.path.getsize(output_filepath)
    total_time = time.time() - operation_started
    
    print(f"\nSuccess! Created multi-file {output_filepath}")
    print(f"  Input paths: {len(input_filepaths)} (files/folders), {len(all_entries)} file(s) total")
    print(f"  Total original size: {total_original_size:,} bytes")
    print(f"  Payload manifest: {len(manifest_bytes):,} bytes inside encrypted container")
    print(f"  Container size: {container_size:,} bytes")
    print(f"  Compressed size: {compressed_size:,} bytes")
    print("  Padding added: 0 bytes")
    print(f"  AVK size: {avk_size:,} bytes")
    print(f"  Unlock time: {format_unlock_time(unlock_timestamp)}")
    print(f"  Total time: {total_time:.2f}s (encrypt: {encrypt_time:.2f}s, chess: {chess_encoding_time:.2f}s)")
    
    # Enhanced security features summary
    security_features = []
    if encryption_method == "plaintext_archive":
        security_features.append("Explicit Standard Archive (not encrypted)")
    elif encryption_method == "aes256gcm_stream_timekey":
        security_features.append("Time-Key Encryption (provider-held unlock shard)")
        security_features.append("Chess Metadata Encoding")
    else:
        security_features.append("Hierarchical Keys (Argon2id + HKDF)")
        security_features.append("Streaming AES-256-GCM Payload Encryption")
        security_features.append("Chess Cascade Security (AES + ChaCha)")
    security_features.append("Manifest-Bound Multi-File Payload")
    if keyphrase:
        security_features.append("Hindi Mnemonic Keyphrase (21-word, checksum-validated)")
    if use_timecapsule:
        security_features.append("NTP Time Synchronization (time.google.com)")
    if pqc_enabled:
        if pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED:
            security_features.append("Embedded Quantum Protection (OpenSSL ML-KEM + X25519 + ML-DSA + SLH-DSA)")
        else:
            security_features.append("External Quantum Keyfile (OpenSSL ML-KEM + X25519 + ML-DSA + SLH-DSA)")
    
    print(f"  Security: {', '.join(security_features)}")
    
    # Add file info to result
    result['files'] = file_info
    result['file_count'] = len(all_entries)
    result['total_size'] = total_original_size
    result['telemetry'] = {
        'archive_kind': 'multi_file',
        'selected_input_count': len(input_filepaths),
        'expanded_entry_count': len(all_entries),
        'compression_ms': 0.0,
        'encryption_ms': round(encrypt_time * 1000, 2),
        'pqc_ms': round(pqc_ms, 2),
        'argon2_ms': round(argon2_ms, 2),
        'payload_stream_ms': round(payload_stream_ms, 2),
        'metadata_ms': round(metadata_ms, 2),
        'zip_finalize_ms': round(zip_finalize_ms, 2),
        'chess_encoding_ms': round(chess_encoding_time * 1000, 2),
        'total_processing_ms': round(total_time * 1000, 2),
        'source_bytes_read': payload_result.get("source_bytes_read", container_size),
        'payload_bytes_written': payload_result.get("payload_bytes_written", payload_result["payload_size"]),
        'compression_enabled': payload_result.get("compression_enabled"),
        'compression_reason': payload_result.get("compression_reason"),
        'compression_sample_ratio': payload_result.get("compression_sample_ratio"),
        'compression_ratio': (compressed_size / container_size) if container_size else None,
        'output_archive_size_bytes': avk_size,
        'use_timecapsule': use_timecapsule,
        'timecapsule_provider': timecapsule_provider,
        'pqc_enabled': pqc_enabled,
        'pqc_storage_mode': pqc_storage_mode if pqc_enabled else None,
    }
    if tracker:
        tracker.complete("Archive created")
    
    return result
