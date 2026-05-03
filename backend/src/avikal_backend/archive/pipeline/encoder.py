"""
Enhanced encoder for Avikal format with Option 1 + Option B security.
Creates .avk files with hierarchical keys and maximum security.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import os
import time
import zipfile
import tempfile
import hashlib
from datetime import datetime

from ..format.header import (
    ARCHIVE_MODE_SINGLE,
    attach_public_route_tags_to_keychain_pgn,
    attach_header_to_keychain_pgn,
    build_header_bytes,
    provider_name_to_id,
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
    PQC_KEYFILE_ALGORITHM,
    default_keyfile_path_for_archive,
    write_pqc_keyfile,
)
from ..security.pqc_provider import create_pqc_archive_material
from ..security.time_lock import datetime_to_timestamp, format_unlock_time, get_trusted_now
from .payload_streaming import stream_file_to_payload
from .progress import get_progress_tracker
from ..runtime_logging import runtime_debug_print as print


def generate_key_b() -> bytes:
    """
    Generate random 256-bit Key B for split-key architecture.
    
    Returns:
        32-byte random key
    """
    import secrets
    return secrets.token_bytes(32)


def create_avk_file_enhanced(
    input_filepath: str,
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
    Create .avk file with enhanced security (Option 1 + Option B).
    
    Args:
        input_filepath: Path to file to encrypt
        output_filepath: Path for output .avk file
        unlock_datetime: UTC datetime when file should unlock (required if use_timecapsule=True)
        password: Password for protection (optional)
        keyphrase: 21-word Hindi mnemonic keyphrase (optional, list of strings)
        username: Optional user identifier
        variations_per_round: Chess encoding parameter (default 5)
        use_timecapsule: Enable time-lock feature (default False)
        file_id: Generic provider file/commit identifier stored in archive metadata
        server_url: Provider endpoint stored in archive metadata
        time_key: Server's time key (Key B) to combine with password key (Key A) for encryption
        timecapsule_provider: Explicit provider for new time-capsule files
        aavrit_data_hash: Aavrit data hash used for commit/reveal binding
        aavrit_commit_hash: Signed Aavrit commit hash returned by the Aavrit service
        aavrit_server_key_id: Aavrit signing key identifier
        aavrit_commit_signature: Aavrit commit envelope signature
        pqc_enabled: Whether to require an external PQC keyfile for decryption
        pqc_keyfile_output: Optional custom path for the generated .avkkey file
    
    Returns:
        dict: Contains 'keyphrase' if generated, empty dict otherwise
    
    Raises:
        ValueError: If timecapsule enabled but password/unlock_datetime missing
        ConnectionError: If NTP time synchronization fails (timecapsule mode)
    """
    result = {}
    
    # Enhanced security features:
    # - Hierarchical key derivation: Argon2id + HKDF expansion
    # - Protected payload encryption: AES-256-GCM
    # - Enhanced chess security for metadata
    # - NTP time sync for timecapsule mode
    
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
    
    # Validate inputs based on mode
    if use_timecapsule:
        if not unlock_datetime:
            raise ValueError(
                "Unlock datetime is REQUIRED when time-capsule is enabled."
            )
        
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
        # For non-timecapsule files, use current UTC time (no trusted-time dependency required)
        from datetime import datetime, timezone
        unlock_datetime = datetime.now(timezone.utc)
    
    pqc_public_bundle = None
    pqc_private_bundle = None
    pqc_shared_secret = None
    pqc_ciphertext = None
    pqc_key_id = None
    pqc_keyfile_path = None

    if pqc_enabled:
        if pqc_keyfile_output:
            pqc_keyfile_path = os.path.abspath(pqc_keyfile_output)
        else:
            pqc_keyfile_path = default_keyfile_path_for_archive(output_filepath)

        if os.path.abspath(output_filepath) == pqc_keyfile_path:
            raise ValueError("PQC keyfile path must be different from the .avk output path")

        pqc_material = create_pqc_archive_material(archive_filename=os.path.basename(output_filepath))
        pqc_public_bundle = pqc_material["public_bundle"]
        pqc_private_bundle = pqc_material["private_bundle"]
        pqc_ciphertext = pqc_material["ciphertext"]
        pqc_shared_secret = pqc_material["shared_secret"]
        pqc_key_id = pqc_material["key_id"]
    
    original_size = os.path.getsize(input_filepath)
    tracker = get_progress_tracker()
    if tracker:
        tracker.set_file_size(original_size)
        tracker.update("prepare", "Preparing archive inputs", 0.15, force=True)
    print(f"Streaming {original_size} bytes into payload.enc...")
    start_encrypt = time.time()
    
    # Generate random salt for payload encryption
    import secrets
    salt = secrets.token_bytes(32)
    
    provider_id = provider_name_to_id(timecapsule_provider if use_timecapsule else None)
    header_bytes = build_header_bytes(
        archive_mode=ARCHIVE_MODE_SINGLE,
        provider_id=provider_id,
    )

    master_key = None
    payload_key = None
    payload_encryption_key = None
    wrapped_payload_key = None
    payload_key_wrap_algorithm = None
    if user_secret_enabled:
        if tracker:
            tracker.update("prepare", "Deriving protection keys", 0.5)
        print("Deriving payload key with Argon2id...")
        from ..security.crypto import derive_hierarchical_keys
        master_key, payload_key, _, _ = derive_hierarchical_keys(password, keyphrase, salt)

        if use_timecapsule and time_key:
            print("Combining Key A (from password) and Key B (time_key) for payload encryption...")
            from ..security.crypto import combine_split_keys
            combined_key = combine_split_keys(payload_key, time_key, salt)
            payload_key = combined_key[:32]

        if pqc_enabled:
            print("Applying external PQC keyfile protection to payload key...")
            payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, salt)

        payload_encryption_key = generate_payload_key()
        wrapped_payload_key = wrap_payload_key(payload_encryption_key, payload_key, header_bytes)
        payload_key_wrap_algorithm = PAYLOAD_KEY_WRAP_ALGORITHM
        encryption_method = "aes256gcm_stream"
    elif use_timecapsule:
        if tracker:
            tracker.update("prepare", "Deriving provider-held unlock key", 0.7)
        if not time_key:
            raise ValueError("Time-capsule archives without password or keyphrase require a provider time key")
        print("Deriving payload key from provider-held time key only...")
        payload_key = derive_time_only_payload_key(time_key, salt)
        payload_encryption_key = payload_key
        encryption_method = "aes256gcm_stream_timekey"
    else:
        if tracker:
            tracker.update("prepare", "Preparing explicit standard archive", 0.85)
        print("Creating explicit unencrypted standard archive...")
        encryption_method = "plaintext_archive"
    if tracker:
        tracker.update("prepare", "Initialization complete", 1.0)

    output_dir = os.path.dirname(output_filepath) or os.getcwd()
    temp_payload = tempfile.NamedTemporaryFile(
        suffix='.payload',
        prefix='.avikal-payload-',
        delete=False,
        dir=output_dir,
    )
    temp_payload_path = temp_payload.name
    temp_payload.close()

    temp_archive_path = None
    try:
        payload_result = stream_file_to_payload(
            input_path=input_filepath,
            payload_path=temp_payload_path,
            aad=header_bytes,
            encrypt_key=payload_encryption_key if encryption_method != "plaintext_archive" else None,
            progress_callback=(
                (lambda processed, _total: tracker.update(
                    "payload",
                    "Encrypting payload stream" if encryption_method != "plaintext_archive" else "Packaging payload stream",
                    (processed / original_size) if original_size else 1.0,
                    compression_ratio=None,
                ))
                if tracker else None
            ),
        )
        original_checksum = payload_result["checksum"]
        compressed_size = payload_result["compressed_size"]
        compression_ratio = (1 - compressed_size / original_size) * 100 if original_size else 0.0
        encrypt_time = time.time() - start_encrypt
        print(f"Streamed payload ready in {encrypt_time:.2f}s")

        # Enhanced encryption metadata
        keyphrase_protected = bool(keyphrase)

        # Step 5: Create metadata packet (enhanced cascade format)
        unlock_timestamp = datetime_to_timestamp(unlock_datetime, use_ntp=use_timecapsule)
        filename = os.path.basename(input_filepath)

        from ..format.metadata import pack_cascade_metadata
        from ...mnemonic.generator import MNEMONIC_FORMAT_VERSION
        from ...mnemonic.wordlist import WORDLIST_ID
        metadata_bytes = pack_cascade_metadata(
            salt, pqc_ciphertext, None, unlock_timestamp,
            filename, original_checksum, encryption_method, keyphrase_protected,
            chess_salt=None, timelock_mode="convenience",
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
            keyphrase_format_version=MNEMONIC_FORMAT_VERSION if keyphrase_protected else None,
            keyphrase_wordlist_id=WORDLIST_ID if keyphrase_protected else None,
            archive_type="single_file",
            entry_count=1,
            total_original_size=original_size,
            manifest_hash=original_checksum,
            payload_key_wrap_algorithm=payload_key_wrap_algorithm,
            wrapped_payload_key=wrapped_payload_key,
        )

        # Step 6: Enhanced chess encoding with original design (password/keyphrase)
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
        keychain_pgn = attach_header_to_keychain_pgn(keychain_pgn, header_bytes)
        keychain_pgn = attach_public_route_tags_to_keychain_pgn(
            keychain_pgn,
            requires_password=bool(password),
            requires_keyphrase=bool(keyphrase),
            requires_pqc=bool(pqc_enabled),
            unlock_timestamp=unlock_timestamp if use_timecapsule else None,
            drand_round=drand_round,
            keyphrase_wordlist_id=WORDLIST_ID if keyphrase_protected else None,
        )
        chess_encoding_time = time.time() - start_chess
        if tracker:
            tracker.update("metadata", "Encoding secure metadata", 1.0)
        print(f"Enhanced chess encoding completed in {chess_encoding_time:.2f} seconds")

        print(f"Creating {output_filepath}...")
        if tracker:
            tracker.update("finalize", "Finalizing Avk container", 0.2)
        temp_archive = tempfile.NamedTemporaryFile(
            suffix='.avk',
            prefix='.avikal-archive-',
            delete=False,
            dir=output_dir,
        )
        temp_archive_path = temp_archive.name
        temp_archive.close()

        with zipfile.ZipFile(temp_archive_path, 'w') as zf:
            zf.writestr('keychain.pgn', keychain_pgn, compress_type=zipfile.ZIP_DEFLATED)
            zf.write(temp_payload_path, arcname='payload.enc', compress_type=zipfile.ZIP_STORED)

        if pqc_enabled:
            keyfile_result = write_pqc_keyfile(
                pqc_keyfile_path,
                password=password,
                keyphrase=keyphrase,
                private_bundle=pqc_private_bundle,
                public_bundle=pqc_public_bundle,
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
            tracker.update("finalize", "Finalizing Avk container", 1.0, compression_ratio=(compressed_size / original_size) if original_size else None)
    finally:
        if temp_archive_path and os.path.exists(temp_archive_path):
            os.remove(temp_archive_path)
        if os.path.exists(temp_payload_path):
            os.remove(temp_payload_path)
    
    # Clean up sensitive data from memory
    if master_key:
        secure_zero(master_key)
    if salt:
        secure_zero(salt)
    if payload_key:
        secure_zero(payload_key)
    if payload_encryption_key and payload_encryption_key is not payload_key:
        secure_zero(payload_encryption_key)
    if pqc_shared_secret:
        secure_zero(pqc_shared_secret)
    if password:
        secure_zero(password.encode('utf-8'))
    
    avk_size = os.path.getsize(output_filepath)
    total_time = encrypt_time + chess_encoding_time
    
    print(f"\nSuccess! Created {output_filepath}")
    print(f"  Original size: {original_size:,} bytes")
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
    if keyphrase:
        security_features.append("Hindi Mnemonic Keyphrase (21-word, checksum-validated)")
    if use_timecapsule:
        security_features.append("NTP Time Synchronization (time.google.com)")
    if pqc_enabled:
        security_features.append("External Quantum Keyfile (OpenSSL ML-KEM + X25519 + ML-DSA + SLH-DSA)")
    
    print(f"  Security: {', '.join(security_features)}")

    result["telemetry"] = {
        "archive_kind": "single_file",
        "selected_input_count": 1,
        "expanded_entry_count": 1,
        "compression_ms": 0.0,
        "encryption_ms": round(encrypt_time * 1000, 2),
        "chess_encoding_ms": round(chess_encoding_time * 1000, 2),
        "total_processing_ms": round(total_time * 1000, 2),
        "output_archive_size_bytes": avk_size,
        "use_timecapsule": use_timecapsule,
        "timecapsule_provider": timecapsule_provider,
        "pqc_enabled": pqc_enabled,
    }
    if tracker:
        tracker.complete("Archive created")
    
    return result


def create_avk_file(
    input_filepath: str,
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
    """Create a single-file .avk archive."""
    return create_avk_file_enhanced(
        input_filepath, output_filepath, unlock_datetime,
        password, keyphrase, username, variations_per_round, use_timecapsule, file_id, server_url,
        time_key=time_key,
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
        pqc_enabled=pqc_enabled,
        pqc_keyfile_output=pqc_keyfile_output,
    )
