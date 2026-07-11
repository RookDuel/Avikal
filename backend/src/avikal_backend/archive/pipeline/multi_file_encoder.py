"""Multi-file Avikal archive encoder.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import os
import shutil
import time
import zipfile
import tempfile
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Tuple

from avikal_backend.core.secure_delete import secure_remove_file
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
from ..format.indexed_payload import DEFAULT_CHUNK_SIZE, MAX_INDEX_BYTES, write_indexed_multifile_payload
from ..format.metadata_pack import (
    FEATURE_ASSURED_REPORTS,
    FEATURE_INDEXED_PAYLOAD,
    FEATURE_MANDATORY_SIGNATURE,
    normalize_sender_message,
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
from ..chess_metadata import build_pqc_keychain_bootstrap, encode_metadata_to_chess_enhanced
from ..security.archive_signature import (
    build_archive_signature_evidence,
    build_archive_signature_manifest,
    build_timestamp_statement,
    extract_archive_signature,
    sign_and_attach_archive_manifest,
)
from ..reporting import finalize_assurance_report
from ..security.pqc_keyfile import (
    PQC_EMBEDDED_MEMBER_NAME,
    PQC_STORAGE_MODE_EMBEDDED,
    PQC_STORAGE_MODE_EXTERNAL,
    build_embedded_pqc_blob,
    default_keyfile_path_for_archive,
    write_pqc_keyfile,
)
from ..security.pqc_provider import create_archive_signing_identity, create_pqc_archive_material
from ..security.time_lock import datetime_to_timestamp, format_unlock_time, get_trusted_now
from ..security.trusted_timestamp import request_rfc3161_timestamp
from .progress import get_progress_tracker
from ..runtime_logging import runtime_debug_print as print
from avikal_backend.version import __version__
from ..input_safety import assert_safe_input_directory, assert_safe_input_file, is_link_or_reparse_point



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
        if is_link_or_reparse_point(path):
            raise ValueError(f"Archive input links and reparse points are not allowed: {path}")
        if os.path.isfile(path):
            assert_safe_input_file(path)
            arcname = normalize_user_archive_path(os.path.basename(path))
            if arcname in seen_arcnames:
                raise ValueError(f"Duplicate archive entry detected: {arcname}")
            seen_arcnames.add(arcname)
            entries.append((path, arcname))
        elif os.path.isdir(path):
            assert_safe_input_directory(path)
            folder_name = os.path.basename(path)
            parent = os.path.dirname(path)
            for dirpath, dirnames, filenames in os.walk(path):
                safe_dirnames: list[str] = []
                for dirname in sorted(dirnames):
                    child_dir = os.path.join(dirpath, dirname)
                    if _is_excluded_path(child_dir, normalized_exclusions):
                        continue
                    assert_safe_input_directory(child_dir)
                    safe_dirnames.append(dirname)
                dirnames[:] = safe_dirnames
                for filename in sorted(filenames):  # sorted for determinism
                    abs_file = os.path.join(dirpath, filename)
                    if _is_excluded_path(abs_file, normalized_exclusions):
                        continue
                    assert_safe_input_file(abs_file)
                    rel = os.path.relpath(abs_file, parent)
                    arcname = normalize_user_archive_path(rel.replace(os.sep, '/'))
                    if arcname in seen_arcnames:
                        raise ValueError(f"Duplicate archive entry detected: {arcname}")
                    seen_arcnames.add(arcname)
                    entries.append((abs_file, arcname))
        else:
            raise ValueError(f"Path not found or unsupported type: {path}")
    return sorted(entries, key=lambda item: item[1])


def _collect_directory_entries(paths: List[str], excluded_paths: List[str] | None = None) -> List[str]:
    """Collect explicit logical directories, including empty directories."""
    directories: set[str] = set()
    normalized_exclusions = _normalize_excluded_input_paths(paths, excluded_paths)
    for raw_path in paths:
        path = os.path.normpath(raw_path)
        if not os.path.isdir(path) or _is_excluded_path(path, normalized_exclusions):
            continue
        assert_safe_input_directory(path)
        parent = os.path.dirname(path)
        for dirpath, dirnames, _filenames in os.walk(path):
            safe_dirnames: list[str] = []
            for name in sorted(dirnames):
                child_dir = os.path.join(dirpath, name)
                if _is_excluded_path(child_dir, normalized_exclusions):
                    continue
                assert_safe_input_directory(child_dir)
                safe_dirnames.append(name)
            dirnames[:] = safe_dirnames
            logical = os.path.relpath(dirpath, parent).replace(os.sep, "/")
            directories.add(normalize_user_archive_path(logical))
    return sorted(directories)


def _source_size(entries: List[Tuple[str, str]]) -> int:
    total = 0
    for source_path, archive_path in entries:
        try:
            size = os.path.getsize(source_path)
        except OSError as exc:
            raise ValueError(f"Unable to inspect archive input: {archive_path}") from exc
        if size < 0:
            raise ValueError(f"Archive input size is invalid: {archive_path}")
        total += size
    return total


def _estimated_temporary_archive_bytes(total_source_size: int, file_count: int) -> int:
    estimated_chunks = (total_source_size + DEFAULT_CHUNK_SIZE - 1) // DEFAULT_CHUNK_SIZE
    estimated_index = min(MAX_INDEX_BYTES, 64 * 1024 + (file_count * 512) + (estimated_chunks * 192))
    payload_overhead = estimated_chunks * 96
    fixed_margin = 16 * 1024 * 1024
    return total_source_size + estimated_index + payload_overhead + fixed_margin


def _preflight_destination_space(output_filepath: str, total_source_size: int, file_count: int) -> None:
    output_dir = os.path.abspath(os.path.dirname(output_filepath) or os.getcwd())
    if not os.path.isdir(output_dir):
        raise ValueError(f"Archive destination directory does not exist: {output_dir}")
    required = _estimated_temporary_archive_bytes(total_source_size, file_count)
    try:
        available = shutil.disk_usage(output_dir).free
    except OSError as exc:
        raise OSError(f"Unable to inspect free space for archive destination: {output_dir}") from exc
    if available < required:
        raise OSError(
            f"Insufficient free space for atomic archive creation: requires approximately {required:,} bytes, "
            f"but only {available:,} bytes are available."
        )


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
    aavrit_route: dict | None = None,
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
    pqc_suite_id: str = None,
    pqc_custom_algorithms: dict = None,
    excluded_input_paths: List[str] | None = None,
    sender_message: str = "",
    creator_signing_identity: dict | None = None,
) -> dict:
    """Create a multi-file .avk archive."""
    result = {}
    operation_started = time.time()
    pqc_ms = 0.0
    argon2_ms = 0.0
    payload_stream_ms = 0.0
    metadata_ms = 0.0
    zip_finalize_ms = 0.0
    input_discovery_ms = 0.0
    archive_signing_ms = 0.0
    trusted_timestamp_ms = 0.0
    keyfile_ms = 0.0
    keyfile_telemetry: dict = {}
    chess_encoding_ms = 0.0
    embedded_pqc_ms = 0.0
    
    if not input_filepaths:
        raise ValueError("At least one input file or folder is required")
    output_filepath = os.path.abspath(output_filepath)
    if os.path.lexists(output_filepath):
        raise ValueError(f"Refusing to overwrite an existing archive: {output_filepath}")
    
    if keyphrase:
        from ...mnemonic.generator import normalize_mnemonic_words
        keyphrase = normalize_mnemonic_words(keyphrase)
        result['keyphrase'] = keyphrase

    user_secret_enabled = has_user_secret(password, keyphrase)
    sender_message = normalize_sender_message(sender_message)
    if sender_message and not (user_secret_enabled or use_timecapsule or pqc_enabled):
        raise ValueError("Sender messages require password, keyphrase, TimeCapsule, or PQC protection")

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
        
        # drand uses client-side trusted time. Aavrit validates against the
        # authority's guarded multi-source clock when creating the escrow.
        if timecapsule_provider != "aavrit":
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

    tracker = get_progress_tracker()
    discovery_started = time.perf_counter()
    if tracker:
        tracker.update("prepare", "Discovering archive inputs", 0.05, force=True)
    all_entries = _collect_entries(input_filepaths, excluded_input_paths)
    directory_entries = _collect_directory_entries(input_filepaths, excluded_input_paths)
    if not all_entries:
        raise ValueError("No files were found in the selected inputs")
    total_original_size = _source_size(all_entries)
    _preflight_destination_space(output_filepath, total_original_size, len(all_entries))
    input_discovery_ms = (time.perf_counter() - discovery_started) * 1000
    print(f"Processing {len(all_entries)} file(s) from {len(input_filepaths)} input path(s)...")
    if tracker:
        tracker.set_file_size(total_original_size)
        tracker.update("prepare", "Archive inputs validated", 0.2, force=True)

    pqc_private_bundle = None
    pqc_public_bundle = None
    pqc_ciphertext = None
    pqc_shared_secret = None
    pqc_key_id = None
    pqc_keyfile_path = None
    embedded_pqc_blob = None
    pqc_algorithm = None
    archive_id = os.urandom(16)
    archive_created_at = int(time.time())
    if tracker:
        tracker.update("identity", "Preparing archive signing identity", 0.05, force=True)
    signing_started = time.time()
    signing_material = creator_signing_identity or create_archive_signing_identity(persistent=False)
    signing_public_bundle = signing_material.get("public_bundle")
    signing_private_bundle = signing_material.get("private_bundle")
    if not isinstance(signing_public_bundle, dict) or not isinstance(signing_private_bundle, dict):
        raise ValueError("Creator signing identity is incomplete")
    signing_identity_id = signing_public_bundle.get("identity_id")
    if signing_identity_id != signing_private_bundle.get("identity_id"):
        raise ValueError("Creator signing identity key material does not match")
    signing_identity_kind = "creator" if signing_public_bundle.get("persistent") else "archive"
    signing_keygen_ms = (time.time() - signing_started) * 1000
    signing_keygen_ms = float((signing_material.get("telemetry") or {}).get("keygen_ms") or signing_keygen_ms)
    if tracker:
        tracker.update("identity", "Archive signing identity ready", 1.0, force=True)
    pqc_archive_id = None
    pqc_created_at = None

    if pqc_enabled:
        if tracker:
            tracker.update("pqc", "Preparing quantum protection", 0.05, force=True)
        if pqc_storage_mode == PQC_STORAGE_MODE_EXTERNAL:
            if pqc_keyfile_output:
                pqc_keyfile_path = os.path.abspath(pqc_keyfile_output)
            else:
                pqc_keyfile_path = default_keyfile_path_for_archive(output_filepath)

            if os.path.abspath(output_filepath) == pqc_keyfile_path:
                raise ValueError("PQC keyfile path must be different from the .avk output path")

        pqc_start = time.time()
        pqc_material = create_pqc_archive_material(
            archive_filename=os.path.basename(output_filepath),
            suite_id=pqc_suite_id,
            custom_algorithms=pqc_custom_algorithms,
        )
        pqc_ms = (time.time() - pqc_start) * 1000
        pqc_public_bundle = pqc_material["public_bundle"]
        pqc_private_bundle = pqc_material["private_bundle"]
        pqc_ciphertext = pqc_material["ciphertext"]
        pqc_shared_secret = pqc_material["shared_secret"]
        pqc_key_id = pqc_material["key_id"]
        pqc_algorithm = pqc_material["algorithm"]
        pqc_archive_id = archive_id
        pqc_created_at = archive_created_at
        if tracker:
            tracker.update("pqc", "Quantum protection material ready", 1.0, force=True)

    output_dir = os.path.dirname(output_filepath) or os.getcwd()
    temp_archive_path = None

    try:
        container_size = total_original_size
        file_info = []
        print(f"Prepared single-pass indexed stream from {len(all_entries)} files")

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
                tracker.update("kdf", "Deriving protection keys", 0.05, force=True)
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
                tracker.update("kdf", "Deriving provider-held unlock key", 0.05, force=True)
            if not time_key:
                raise ValueError("Time-capsule archives without password or keyphrase require a provider time key")
            print("[Multi] Deriving payload key from provider-held time key only...")
            payload_key = derive_time_only_payload_key(time_key, payload_salt)
            payload_encryption_key = payload_key
            encryption_method = "aes256gcm_stream_timekey"
        else:
            print("[Multi] Creating explicit unencrypted standard archive...")
            encryption_method = "plaintext_archive"

        if tracker:
            tracker.update("kdf", "Archive key hierarchy ready", 1.0, force=True)

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
                payload_result = write_indexed_multifile_payload(
                    entries=all_entries,
                    explicit_directories=directory_entries,
                    target=payload_writer,
                    payload_key=payload_encryption_key if encryption_method != "plaintext_archive" else None,
                    archive_id=archive_id,
                    header_aad=header_bytes,
                    progress_callback=(
                        (lambda processed, total: tracker.update(
                            "payload",
                            "Streaming encrypted payload" if encryption_method != "plaintext_archive" else "Streaming payload",
                            (processed / total) if total else 1.0,
                            processed_bytes=processed,
                            total_bytes=total,
                        ))
                        if tracker else None
                    ),
                )
                payload_sha256 = payload_result["payload_sha256"]
        payload_stream_ms = (time.time() - payload_stream_start) * 1000
        container_checksum = payload_result["checksum"]
        manifest_hash = payload_result["manifest_hash"]
        compressed_size = payload_result["stored_plaintext_bytes"]
        compression_ratio = (1 - compressed_size / container_size) * 100 if container_size else 0.0
        file_info = [
            {"filename": item["path"], "size": item["size"], "checksum": item["sha256"]}
            for item in payload_result["files"]
        ]
        encrypt_time = time.time() - start_encrypt
        print(f"Streamed payload ready in {encrypt_time:.2f}s")
        # Step 5: Create compact multi-file metadata
        unlock_timestamp = int(unlock_datetime.timestamp()) if timecapsule_provider == "aavrit" else datetime_to_timestamp(unlock_datetime, use_ntp=use_timecapsule)

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
            pqc_algorithm=pqc_algorithm if pqc_enabled else None,
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
            created_with_version=__version__,
            minimum_reader_version=__version__,
            required_features=FEATURE_ASSURED_REPORTS | FEATURE_INDEXED_PAYLOAD | FEATURE_MANDATORY_SIGNATURE,
            sender_message=sender_message,
            folder_count=payload_result["folder_count"],
            content_index_hash=payload_result["index_hash"],
            payload_merkle_root=payload_result["merkle_root"],
        )

        # Step 6: Enhanced chess encoding
        print("Encoding metadata with enhanced chess security...")
        if tracker:
            tracker.update("chess", "Preparing secure metadata", 0.02, force=True)
        if pqc_enabled and pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED:
            embedded_pqc_started = time.perf_counter()
            embedded_pqc_blob = build_embedded_pqc_blob(
                password=password,
                keyphrase=keyphrase,
                private_bundle=pqc_private_bundle,
                public_bundle=pqc_public_bundle,
                pqc_ciphertext=pqc_ciphertext,
                archive_filename=os.path.basename(output_filepath),
                header_aad=header_bytes,
                key_id=pqc_key_id,
                algorithm=pqc_algorithm,
            )
            embedded_pqc_ms = (time.perf_counter() - embedded_pqc_started) * 1000

        pqc_bootstrap = None
        if pqc_enabled:
            pqc_bootstrap = build_pqc_keychain_bootstrap(
                algorithm=pqc_algorithm,
                key_id=pqc_key_id,
                storage_mode=pqc_storage_mode,
                pqc_ciphertext=pqc_ciphertext,
                archive_id=pqc_archive_id,
                created_at=pqc_created_at,
                signature_required=True,
            )

        if tracker:
            tracker.update("chess", "Encoding metadata into Chess-PGN", 0.05, force=True)
        chess_started = time.perf_counter()
        keychain_pgn, chess_stats = encode_metadata_to_chess_enhanced(
            metadata_bytes,
            password,
            keyphrase,
            variations_per_round,
            use_timecapsule,
            aad=header_bytes,
            pqc_shared_secret=pqc_shared_secret if pqc_enabled else None,
            pqc_bootstrap=pqc_bootstrap,
            time_key=time_key,
            time_key_gated=bool(timecapsule_provider == "aavrit" and aavrit_route),
            return_stats=True,
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
            aavrit_route=aavrit_route,
            time_key_gated=bool(timecapsule_provider == "aavrit" and aavrit_route),
        )
        chess_encoding_ms = (time.perf_counter() - chess_started) * 1000
        if tracker:
            tracker.update("chess", "Chess-PGN metadata encoded", 1.0, force=True)

        timestamp_statement = build_timestamp_statement(
            archive_id=archive_id.hex(), created_at=archive_created_at, payload_sha256=payload_sha256,
            keychain_core_pgn=keychain_pgn, content_index_sha256=payload_result["index_hash"].hex(),
            canonical_manifest_sha256=payload_result["manifest_hash"].hex(),
            payload_merkle_root=payload_result["merkle_root"].hex(),
        )
        if tracker:
            tracker.update("timestamp", "Requesting trusted timestamp evidence", 0.05, force=True)
        timestamp_started = time.perf_counter()
        timestamp_evidence = request_rfc3161_timestamp(timestamp_statement)
        trusted_timestamp_ms = (time.perf_counter() - timestamp_started) * 1000
        if tracker:
            tracker.update("timestamp", "Timestamp evidence recorded", 1.0, force=True)

        signature_manifest = build_archive_signature_manifest(
            header_bytes=header_bytes,
            keychain_core_pgn=keychain_pgn,
            payload_sha256=payload_sha256,
            payload_size=payload_result["payload_size"],
            embedded_pqc_blob=embedded_pqc_blob,
            pqc_algorithm=pqc_algorithm,
            pqc_key_id=pqc_key_id,
            pqc_storage_mode=pqc_storage_mode if pqc_enabled else None,
            archive_id=archive_id.hex(),
            created_at=archive_created_at,
            created_with_version=__version__,
            minimum_reader_version=__version__,
            required_features=FEATURE_ASSURED_REPORTS | FEATURE_INDEXED_PAYLOAD | FEATURE_MANDATORY_SIGNATURE,
            content_index_sha256=payload_result["index_hash"].hex(),
            canonical_manifest_sha256=payload_result["manifest_hash"].hex(),
            payload_merkle_root=payload_result["merkle_root"].hex(),
            signing_identity_id=signing_identity_id,
            timestamp_statement=timestamp_statement,
            timestamp_evidence=timestamp_evidence,
        )
        if tracker:
            tracker.update("signature", "Signing archive commitments", 0.05, force=True)
        archive_signing_started = time.perf_counter()
        keychain_pgn = sign_and_attach_archive_manifest(
            keychain_pgn,
            manifest=signature_manifest,
            private_bundle=signing_private_bundle,
            public_bundle=signing_public_bundle,
            identity_kind=signing_identity_kind,
        )
        archive_signing_ms = (time.perf_counter() - archive_signing_started) * 1000
        metadata_ms = embedded_pqc_ms + chess_encoding_ms + trusted_timestamp_ms + archive_signing_ms
        if tracker:
            tracker.update("signature", "Archive commitments signed", 1.0, force=True)
        print(f"Enhanced chess encoding completed in {chess_encoding_ms / 1000:.2f} seconds")

        print(f"Creating {output_filepath}...")
        if tracker:
            tracker.update("finalize", "Writing metadata", 0.25)
        zip_finalize_start = time.time()
        with zipfile.ZipFile(temp_archive_path, "a") as zf:
            zf.writestr("keychain.pgn", keychain_pgn, compress_type=zipfile.ZIP_DEFLATED)
            if embedded_pqc_blob is not None:
                zf.writestr(PQC_EMBEDDED_MEMBER_NAME, embedded_pqc_blob, compress_type=zipfile.ZIP_STORED)
        read_avk_header_and_keychain(temp_archive_path)
        with open(temp_archive_path, "r+b") as archive_handle:
            os.fsync(archive_handle.fileno())
        zip_finalize_ms = (time.time() - zip_finalize_start) * 1000

        if pqc_enabled:
            result["pqc"] = {
                "enabled": True,
                "storage_mode": pqc_storage_mode,
                "algorithm": pqc_algorithm,
                "suite": pqc_material["suite"],
                "key_id": pqc_key_id,
                "keychain_pqc_gated": True,
                "archive_signature": "ML-DSA+SLH-DSA",
                "signed_created_at_utc": pqc_created_at,
                "archive_id": pqc_archive_id.hex(),
            }
            if pqc_storage_mode == PQC_STORAGE_MODE_EXTERNAL:
                if tracker:
                    tracker.update("keyfile", "Protecting external quantum keyfile", 0.05, force=True)
                keyfile_started = time.perf_counter()
                keyfile_result = write_pqc_keyfile(
                    pqc_keyfile_path,
                    password=password,
                    keyphrase=keyphrase,
                    private_bundle=pqc_private_bundle,
                    public_bundle=pqc_public_bundle,
                    pqc_ciphertext=pqc_ciphertext,
                    archive_filename=os.path.basename(output_filepath),
                    algorithm=pqc_algorithm,
                    protection_mode=pqc_keyfile_protection_mode,
                    keyfile_password=pqc_keyfile_password,
                )
                keyfile_ms = (time.perf_counter() - keyfile_started) * 1000
                keyfile_telemetry = dict(keyfile_result.get("telemetry") or {})
                result["pqc"]["keyfile"] = keyfile_result["path"]
                if tracker:
                    tracker.update("keyfile", "External quantum keyfile written", 1.0, force=True)
            else:
                result["pqc"]["member"] = PQC_EMBEDDED_MEMBER_NAME

        if os.path.lexists(output_filepath):
            raise ValueError(f"Refusing to overwrite an existing archive: {output_filepath}")
        os.replace(temp_archive_path, output_filepath)
        unregister_temp_artifact(temp_archive_path)
        temp_archive_path = None
        if tracker:
            tracker.update("finalize", "Finalizing Avk container", 1.0, compression_ratio=(compressed_size / container_size) if container_size else None)
    finally:
        if temp_archive_path and os.path.exists(temp_archive_path):
            secure_remove_file(temp_archive_path)
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
    print("  Source passes: 1 (hash, compression, and encryption are streamed together)")
    print(f"  Compressed size: {compressed_size:,} bytes")
    print("  Padding added: 0 bytes")
    print(f"  AVK size: {avk_size:,} bytes")
    print(f"  Unlock time: {format_unlock_time(unlock_timestamp)}")
    print(f"  Total time: {total_time:.2f}s (payload: {payload_stream_ms / 1000:.2f}s, chess: {chess_encoding_ms / 1000:.2f}s)")
    
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
        'input_discovery_ms': round(input_discovery_ms, 2),
        'compression_ms': round(payload_result.get("compression_ms", 0.0), 2),
        'encryption_ms': round(payload_result.get("encryption_ms", 0.0), 2),
        'key_setup_and_payload_ms': round(encrypt_time * 1000, 2),
        'pqc_ms': round(pqc_ms, 2),
        'pqc_keygen_ms': (pqc_material.get("telemetry") or {}).get("keygen_ms") if pqc_enabled else None,
        'pqc_kem_ms': (pqc_material.get("telemetry") or {}).get("kem_ms") if pqc_enabled else None,
        'pqc_bundle_signing_ms': (pqc_material.get("telemetry") or {}).get("bundle_signing_ms") if pqc_enabled else None,
        'pqc_execution_mode': (pqc_material.get("telemetry") or {}).get("execution_mode") if pqc_enabled else None,
        'argon2_ms': round(argon2_ms, 2),
        'payload_stream_ms': round(payload_stream_ms, 2),
        'metadata_ms': round(metadata_ms, 2),
        'zip_finalize_ms': round(zip_finalize_ms, 2),
        'chess_encoding_ms': round(chess_encoding_ms, 2),
        'keychain_argon2_ms': chess_stats.get("keychain_argon2_ms"),
        'keychain_encryption_ms': chess_stats.get("keychain_encryption_ms"),
        'chess_codec_ms': chess_stats.get("chess_codec_ms"),
        'embedded_pqc_ms': round(embedded_pqc_ms, 2),
        'trusted_timestamp_ms': round(trusted_timestamp_ms, 2),
        'archive_signing_ms': round(archive_signing_ms, 2),
        'keyfile_ms': round(keyfile_ms, 2),
        'keyfile_inner_kdf_ms': keyfile_telemetry.get("inner_kdf_ms"),
        'keyfile_outer_wrapper_ms': keyfile_telemetry.get("outer_wrapper_ms"),
        'keyfile_write_ms': keyfile_telemetry.get("write_ms"),
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
        'signing_ms': round(signing_keygen_ms, 2),
        'signing_identity_keygen_ms': round(signing_keygen_ms, 2),
        'indexed_payload': True,
        'folder_count': payload_result["folder_count"],
        'chunk_count': payload_result["chunk_count"],
        'index_bytes': payload_result["index_bytes"],
        'payload_worker_count': payload_result.get("worker_count"),
        'payload_queue_depth': payload_result.get("queue_depth"),
        'payload_chunk_size': payload_result.get("chunk_size"),
        'source_storage_profile': payload_result.get("source_storage_profile"),
        'throughput_mib_s': round((total_original_size / (1024 * 1024)) / (payload_stream_ms / 1000), 2) if payload_stream_ms else None,
        'source_read_throughput_mib_s': round(
            (payload_result.get("source_bytes_read", container_size) / (1024 * 1024))
            / (payload_stream_ms / 1000),
            2,
        ) if payload_stream_ms else None,
        'archive_write_throughput_mib_s': round(
            (payload_result.get("payload_bytes_written", payload_result["payload_size"]) / (1024 * 1024))
            / (payload_stream_ms / 1000),
            2,
        ) if payload_stream_ms else None,
    }
    logical_kind = (
        "single_file_indexed"
        if len(input_filepaths) == 1 and os.path.isfile(input_filepaths[0])
        else "multi_file"
    )
    creation_report = {
        "schema_version": 1,
        "ephemeral": True,
        "archive": {
            "archive_id": archive_id.hex(),
            "created_with_version": __version__,
            "minimum_reader_version": __version__,
            "created_at_utc": archive_created_at,
            "kind": logical_kind,
            "file_count": len(all_entries),
            "folder_count": payload_result["folder_count"],
            "total_original_size": total_original_size,
            "output_archive_size": avk_size,
        },
        "payload": {
            "format": payload_result["format"],
            "chunk_count": payload_result["chunk_count"],
            "index_bytes": payload_result["index_bytes"],
            "index_sha256": payload_result["index_hash"].hex(),
            "manifest_sha256": payload_result["manifest_hash"].hex(),
            "merkle_root_sha256": payload_result["merkle_root"].hex(),
            "payload_sha256": payload_sha256,
            "compression": "per_chunk_adaptive",
            "original_bytes": total_original_size,
            "stored_payload_bytes": payload_result["stored_plaintext_bytes"],
            "encrypted_payload_bytes": payload_result["payload_size"],
            "compression_ratio": (payload_result["stored_plaintext_bytes"] / total_original_size) if total_original_size else None,
            "bytes_saved": max(0, total_original_size - payload_result["stored_plaintext_bytes"]),
        },
        "chess": {"pgn_bytes": len(keychain_pgn.encode("utf-8")), **chess_stats},
        "protection": {
            "encryption_method": encryption_method,
            "password_protection_enabled": bool(password),
            "keyphrase_protection_enabled": bool(keyphrase),
            "pqc": bool(pqc_enabled),
            "pqc_suite": pqc_algorithm if pqc_enabled else None,
            "pqc_suite_details": pqc_material.get("suite") if pqc_enabled else None,
            "pqc_storage_mode": pqc_storage_mode if pqc_enabled else None,
            "timecapsule_provider": timecapsule_provider,
            "archive_signature": "ML-DSA-87+SLH-DSA-SHA2-256s",
            "signature_algorithms": {"ml_dsa": "ML-DSA-87", "slh_dsa": "SLH-DSA-SHA2-256s"},
            "signing_identity_id": signing_identity_id,
            "signing_identity_fingerprint": signing_identity_id,
            "signing_identity_kind": signing_identity_kind,
            "timestamp_status": timestamp_evidence.get("status"),
            "timestamp_authority": timestamp_evidence.get("tsa_url"),
            "timestamp_imprint_sha256": timestamp_evidence.get("imprint_sha256"),
        },
        "timings": dict(result["telemetry"]),
    }
    signature = extract_archive_signature(keychain_pgn, required=True)
    result["creation_report"] = finalize_assurance_report(
        creation_report,
        report_type="archive_creation",
        signature_evidence=build_archive_signature_evidence(signature),
    )
    if tracker:
        tracker.complete("Archive created")
    
    return result
