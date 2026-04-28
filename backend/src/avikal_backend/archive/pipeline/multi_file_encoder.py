"""
Multi-file container encoder for Avikal format.
Packs multiple files into a single .avk container with enhanced security.

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

from ..format.header import (
    ARCHIVE_MODE_MULTI,
    HEADER_FILENAME,
    build_header_bytes,
    provider_name_to_id,
)
from ..format.manifest import (
    INTERNAL_MANIFEST_PATH,
    build_archive_manifest,
    normalize_user_archive_path,
    serialize_archive_manifest,
)
from ..security.crypto import (
    secure_zero,
    derive_pqc_hybrid_payload_key,
    derive_time_only_payload_key,
    generate_pqc_keypair,
    has_user_secret,
    pqc_encapsulate,
)
from ..chess_metadata import encode_metadata_to_chess_enhanced
from ..security.pqc_keyfile import (
    PQC_KEYFILE_ALGORITHM,
    compute_pqc_key_id,
    default_keyfile_path_for_archive,
    write_pqc_keyfile,
)
from ..security.time_lock import datetime_to_timestamp, format_unlock_time, get_trusted_now
from .payload_streaming import stream_file_to_payload
from .progress import get_progress_tracker
from ..runtime_logging import runtime_debug_print as print



def _collect_entries(paths: List[str]) -> List[Tuple[str, str]]:
    """
    Expand a mixed list of file and directory paths into (abs_path, arcname) pairs.

    - For a file:      arcname = basename  (same behaviour as before)
    - For a directory: arcname = <folder_name>/<relative_path_inside>  (tree preserved)

    This is the *only* change to the container-packing logic; everything downstream
    (crypto, chess encoding, metadata) is completely untouched.
    """
    entries: List[Tuple[str, str]] = []
    seen_arcnames: set[str] = set()
    for path in paths:
        path = os.path.normpath(path)
        if os.path.isfile(path):
            arcname = normalize_user_archive_path(os.path.basename(path))
            if arcname in seen_arcnames:
                raise ValueError(f"Duplicate archive entry detected: {arcname}")
            seen_arcnames.add(arcname)
            entries.append((path, arcname))
        elif os.path.isdir(path):
            folder_name = os.path.basename(path)
            parent = os.path.dirname(path)
            for dirpath, _dirnames, filenames in os.walk(path):
                for filename in sorted(filenames):  # sorted for determinism
                    abs_file = os.path.join(dirpath, filename)
                    # arcname keeps the folder name as root, then relative path
                    rel = os.path.relpath(abs_file, parent)
                    # Normalise to forward slashes for ZIP portability
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
    pqc_keyfile_output: str = None,
) -> dict:
    """
    Create single .avk file from multiple input files with enhanced security.
    
    Args:
        input_filepaths: List of paths to files to encrypt
        output_filepath: Path for output .avk file
        unlock_datetime: UTC datetime when file should unlock (required if use_timecapsule=True)
        password: Password for protection (optional)
        keyphrase: 21-word Hindi mnemonic keyphrase (optional, list of strings)
        username: Optional user identifier
        variations_per_round: Chess encoding parameter (default 5)
        use_timecapsule: Enable time-lock feature (default False)
    
    Returns:
        dict: Contains 'keyphrase' if generated, file info, etc.
    
    Raises:
        ValueError: If timecapsule enabled but password/unlock_datetime missing
        ConnectionError: If NTP time synchronization fails (timecapsule mode)
    """
    result = {}
    
    if not input_filepaths:
        raise ValueError("At least one input file or folder is required")
    
    # Validate keyphrase if provided
    if keyphrase:
        from ...mnemonic.generator import normalize_mnemonic_words
        keyphrase = normalize_mnemonic_words(keyphrase)
        result['keyphrase'] = keyphrase

    user_secret_enabled = has_user_secret(password, keyphrase)

    if pqc_enabled and not user_secret_enabled:
        raise ValueError(
            "PQC keyfile mode requires a password or keyphrase. "
            "Enable PQC only with archive secrets configured."
        )
    
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
    
    pqc_private_key = None
    pqc_public_key = None
    pqc_ciphertext = None
    pqc_shared_secret = None
    pqc_key_id = None
    pqc_keyfile_path = None

    if pqc_enabled:
        if pqc_keyfile_output:
            pqc_keyfile_path = os.path.abspath(pqc_keyfile_output)
        else:
            pqc_keyfile_path = default_keyfile_path_for_archive(output_filepath)

        if os.path.abspath(output_filepath) == pqc_keyfile_path:
            raise ValueError("PQC keyfile path must be different from the .avk output path")

        keypair = generate_pqc_keypair()
        if not keypair:
            raise ValueError(
                "PQC mode is unavailable. Install pqcrypto with ML-KEM-1024 support to enable it."
            )
        pqc_public_key, pqc_private_key = keypair

        encapsulated = pqc_encapsulate(pqc_public_key)
        if not encapsulated:
            raise ValueError("PQC encapsulation failed. Unable to create external keyfile protection.")

        pqc_ciphertext, pqc_shared_secret = encapsulated
        pqc_key_id = compute_pqc_key_id(pqc_public_key, pqc_ciphertext)
    
    # Step 1: Create multi-file container as a temp ZIP on disk.
    all_entries = _collect_entries(input_filepaths)
    if not all_entries:
        raise ValueError("No files were found in the selected inputs")
    print(f"Processing {len(all_entries)} file(s) from {len(input_filepaths)} input path(s)...")
    tracker = get_progress_tracker()
    if tracker:
        tracker.update("prepare", "Preparing multi-file archive", 0.05, force=True)

    file_info = []
    total_original_size = 0
    output_dir = os.path.dirname(output_filepath) or os.getcwd()
    temp_container = tempfile.NamedTemporaryFile(
        suffix=".zip",
        prefix=".avikal-container-",
        delete=False,
        dir=output_dir,
    )
    temp_container_path = temp_container.name
    temp_container.close()

    temp_payload = tempfile.NamedTemporaryFile(
        suffix=".payload",
        prefix=".avikal-payload-",
        delete=False,
        dir=output_dir,
    )
    temp_payload_path = temp_payload.name
    temp_payload.close()

    temp_archive_path = None

    try:
        with zipfile.ZipFile(temp_container_path, "w", zipfile.ZIP_STORED) as container_zip:
            for i, (abs_path, arcname) in enumerate(all_entries):
                print(f"  Streaming file {i+1}/{len(all_entries)}: {arcname}")
                file_size = 0
                file_checksum = hashlib.sha256()
                with open(abs_path, "rb") as source, container_zip.open(arcname, "w", force_zip64=True) as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        file_size += len(chunk)
                        file_checksum.update(chunk)
                        target.write(chunk)

                file_info.append(
                    {
                        "filename": arcname,
                        "size": file_size,
                        "checksum": file_checksum.hexdigest(),
                    }
                )
                total_original_size += file_size
                if tracker:
                    tracker.update("prepare", f"Building container: {arcname}", (i + 1) / max(1, len(all_entries)))

            manifest = build_archive_manifest(file_info, total_original_size)
            manifest_bytes = serialize_archive_manifest(manifest)
            manifest_hash = hashlib.sha256(manifest_bytes).digest()
            container_zip.writestr(INTERNAL_MANIFEST_PATH, manifest_bytes)

        container_checksum_hasher = hashlib.sha256()
        with open(temp_container_path, "rb") as container_handle:
            while True:
                chunk = container_handle.read(1024 * 1024)
                if not chunk:
                    break
                container_checksum_hasher.update(chunk)
        container_checksum = container_checksum_hasher.digest()
        container_size = os.path.getsize(temp_container_path)
        print(f"Created streamed multi-file container: {container_size:,} bytes from {len(all_entries)} files")
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
        if user_secret_enabled:
            if tracker:
                tracker.update("payload", "Deriving protection keys", 0.02)
            print("Deriving payload key with Argon2id...")
            from ..security.crypto import derive_hierarchical_keys

            master_key, payload_key, _, _ = derive_hierarchical_keys(password, keyphrase, payload_salt)

            if use_timecapsule and time_key:
                print("[Multi] Combining Key A (password) and Key B (time_key) for split-key encryption...")
                from ..security.crypto import combine_split_keys

                combined_key = combine_split_keys(payload_key, time_key, payload_salt)
                payload_key = combined_key[:32]

            if pqc_enabled:
                print("[Multi] Applying external PQC keyfile protection to payload key...")
                payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, payload_salt)

            encryption_method = "aes256gcm_stream"
        elif use_timecapsule:
            if tracker:
                tracker.update("payload", "Deriving provider-held unlock key", 0.02)
            if not time_key:
                raise ValueError("Time-capsule archives without password or keyphrase require a provider time key")
            print("[Multi] Deriving payload key from provider-held time key only...")
            payload_key = derive_time_only_payload_key(time_key, payload_salt)
            encryption_method = "aes256gcm_stream_timekey"
        else:
            print("[Multi] Creating explicit unencrypted standard archive...")
            encryption_method = "plaintext_archive"

        payload_result = stream_file_to_payload(
            input_path=temp_container_path,
            payload_path=temp_payload_path,
            aad=header_bytes,
            encrypt_key=payload_key if encryption_method != "plaintext_archive" else None,
            progress_callback=(
                (lambda processed, _total: tracker.update(
                    "payload",
                    "Encrypting multi-file payload" if encryption_method != "plaintext_archive" else "Packaging multi-file payload",
                    (processed / container_size) if container_size else 1.0,
                ))
                if tracker else None
            ),
        )
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
            keyphrase_format_version=MNEMONIC_FORMAT_VERSION if keyphrase else None,
            keyphrase_wordlist_id=WORDLIST_ID if keyphrase else None,
            archive_type="multi_file",
            entry_count=len(all_entries),
            total_original_size=total_original_size,
            manifest_hash=manifest_hash,
        )

        # Step 6: Enhanced chess encoding
        print("Encoding metadata with enhanced chess security...")
        if tracker:
            tracker.update("metadata", "Encoding secure metadata", 0.1)
        start_chess = time.time()
        keychain_pgn = encode_metadata_to_chess_enhanced(
            metadata_bytes,
            password,
            keyphrase,
            variations_per_round,
            use_timecapsule,
            aad=header_bytes,
        )
        chess_encoding_time = time.time() - start_chess
        if tracker:
            tracker.update("metadata", "Encoding secure metadata", 1.0)
        print(f"Enhanced chess encoding completed in {chess_encoding_time:.2f} seconds")

        print(f"Creating {output_filepath}...")
        if tracker:
            tracker.update("finalize", "Finalizing Avk container", 0.25)
        temp_archive = tempfile.NamedTemporaryFile(
            suffix=".avk",
            prefix=".avikal-archive-",
            delete=False,
            dir=output_dir,
        )
        temp_archive_path = temp_archive.name
        temp_archive.close()
        with zipfile.ZipFile(temp_archive_path, "w") as zf:
            zf.writestr(HEADER_FILENAME, header_bytes, compress_type=zipfile.ZIP_DEFLATED)
            zf.writestr("keychain.pgn", keychain_pgn, compress_type=zipfile.ZIP_DEFLATED)
            zf.write(temp_payload_path, arcname="payload.enc", compress_type=zipfile.ZIP_STORED)

        if pqc_enabled:
            keyfile_result = write_pqc_keyfile(
                pqc_keyfile_path,
                password=password,
                keyphrase=keyphrase,
                private_key=pqc_private_key,
                public_key=pqc_public_key,
                pqc_ciphertext=pqc_ciphertext,
                archive_filename=os.path.basename(output_filepath),
                algorithm=PQC_KEYFILE_ALGORITHM,
            )
            result["pqc"] = {
                "enabled": True,
                "algorithm": keyfile_result["algorithm"],
                "key_id": keyfile_result["key_id"],
                "keyfile": keyfile_result["path"],
            }

        os.replace(temp_archive_path, output_filepath)
        temp_archive_path = None
        if tracker:
            tracker.update("finalize", "Finalizing Avk container", 1.0, compression_ratio=(compressed_size / container_size) if container_size else None)
    finally:
        if temp_archive_path and os.path.exists(temp_archive_path):
            os.remove(temp_archive_path)
        if os.path.exists(temp_payload_path):
            os.remove(temp_payload_path)
        if os.path.exists(temp_container_path):
            os.remove(temp_container_path)

    # Clean up sensitive data from memory
    if master_key:
        secure_zero(master_key)
    if payload_salt:
        secure_zero(payload_salt)
    if payload_key:
        secure_zero(payload_key)
    if pqc_shared_secret:
        secure_zero(pqc_shared_secret)
    if pqc_private_key:
        secure_zero(pqc_private_key)
    if pqc_public_key:
        secure_zero(pqc_public_key)
    if password:
        secure_zero(password.encode('utf-8'))
    
    avk_size = os.path.getsize(output_filepath)
    total_time = encrypt_time + chess_encoding_time
    
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
        security_features.append("External PQC Keyfile (ML-KEM-1024)")
    
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
        'chess_encoding_ms': round(chess_encoding_time * 1000, 2),
        'total_processing_ms': round(total_time * 1000, 2),
        'output_archive_size_bytes': avk_size,
        'use_timecapsule': use_timecapsule,
        'timecapsule_provider': timecapsule_provider,
        'pqc_enabled': pqc_enabled,
    }
    if tracker:
        tracker.complete("Archive created")
    
    return result
