"""
Enhanced decoder for Avikal format with Option 1 + Option B security.
Extracts and decrypts .avk files with hierarchical keys and maximum security.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import os
import time
import tempfile

from ..security.crypto import (
    secure_zero,
    derive_time_only_payload_key,
    derive_pqc_hybrid_payload_key,
)
from ..format.header import parse_header_bytes, validate_metadata_against_header
from ..format.container import open_avk_payload_stream
from ..chess_metadata import decode_chess_to_metadata_enhanced
from ..path_safety import resolve_safe_output_path
from .payload_streaming import stream_payload_to_file
from .progress import get_progress_tracker
from ..security.pqc_keyfile import read_pqc_keyfile
from ..security.pqc_provider import decapsulate_pqc_archive_material
from ..security.key_wrap import unwrap_payload_key
from ..runtime_logging import runtime_debug_print as print


def extract_avk_file_enhanced(
    avk_filepath: str,
    output_directory: str,
    password: str = None,
    keyphrase: list = None,
    pqc_keyfile_path: str = None,
    time_key: bytes = None,
    metadata_override: dict | None = None,
) -> str:
    """
    Extract and decrypt .avk file with enhanced security (Option 1 + Option B).
    
    Args:
        avk_filepath: Path to .avk file
        output_directory: Where to save decrypted file
        password: Password for decryption
        keyphrase: 21-word Hindi mnemonic keyphrase (list of strings)
    
    Returns:
        Path to extracted file
    
    Raises:
        ValueError: If password/keyphrase wrong, time-lock not reached, or file corrupted
    """
    master_key = None
    payload_key = None
    payload_decryption_key = None
    pqc_shared_secret = None
    pqc_private_bundle = None
    salt = None

    try:
        tracker = get_progress_tracker()
        print(f"Opening {avk_filepath}...")
        try:
            with open_avk_payload_stream(avk_filepath) as (header_bytes, keychain_pgn, payload_stream):
                header_info = parse_header_bytes(header_bytes)
                if tracker:
                    tracker.update("metadata", "Reading archive metadata", 0.05, force=True)

                if metadata_override is not None:
                    metadata = metadata_override
                    validate_metadata_against_header(header_info, metadata)
                    chess_decoding_time = 0.0
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
                        )
                        validate_metadata_against_header(header_info, metadata)
                        chess_decoding_time = time.time() - start_chess
                        if tracker:
                            tracker.update("metadata", "Decoding secure metadata", 1.0)
                        print(f"Chess decoding completed in {chess_decoding_time:.2f} seconds")
                    except ValueError as e:
                        error_msg = str(e)
                        if "password protected" in error_msg.lower():
                            raise ValueError("This file is password protected. Please provide password.")
                        if "incorrect password" in error_msg.lower() or "decryption failed" in error_msg.lower():
                            raise ValueError("Incorrect password or keyphrase.")
                        if "time capsule is locked" in error_msg.lower():
                            raise ValueError(error_msg)
                        raise ValueError(f"Chess decoding failed: {error_msg}")

                print("Extracting salt from metadata...")
                try:
                    salt = metadata['salt']
                    print(f"Salt extracted: {len(salt)} bytes")

                    if metadata['encryption_method'] == "plaintext_archive":
                        payload_key = None
                    elif metadata['encryption_method'] == "aes256gcm_stream_timekey":
                        if not time_key:
                            raise ValueError("This archive requires the time-capsule unlock flow.")
                        payload_key = derive_time_only_payload_key(time_key, salt)
                    else:
                        print("Deriving payload key with extracted salt...")
                        from ..security.crypto import derive_hierarchical_keys
                        master_key, payload_key, _, _ = derive_hierarchical_keys(password, keyphrase, salt)
                        if time_key:
                            from ..security.crypto import combine_split_keys

                            combined_key = combine_split_keys(payload_key, time_key, salt)
                            payload_key = combined_key[:32]
                except KeyError:
                    raise ValueError("Invalid metadata: salt not found")

                try:
                    encryption_method = metadata['encryption_method']
                    pqc_ciphertext = metadata.get('pqc_ciphertext')
                    pqc_required = bool(metadata.get('pqc_required'))
                    pqc_algorithm = metadata.get('pqc_algorithm')
                    pqc_key_id = metadata.get('pqc_key_id')
                    expected_checksum = metadata['checksum']
                    expected_output_size = metadata.get('total_original_size')
                    original_filename = metadata['filename']
                    keyphrase_protected = metadata.get('keyphrase_protected', False)

                    print(f"Detected encryption: {encryption_method}")

                    if keyphrase_protected and not keyphrase:
                        raise ValueError(
                            "This file is protected with a 21-word Hindi keyphrase. "
                            "Please provide the keyphrase to decrypt."
                        )

                    if keyphrase:
                        from ...mnemonic.generator import normalize_mnemonic_words
                        keyphrase = normalize_mnemonic_words(keyphrase)

                    if pqc_required:
                        if tracker:
                            tracker.update("payload", "Loading PQC keyfile", 0.05)
                        print("Loading external PQC keyfile...")
                        pqc_key_bundle = read_pqc_keyfile(
                            pqc_keyfile_path,
                            password=password,
                            keyphrase=keyphrase,
                            expected_key_id=pqc_key_id,
                            expected_algorithm=pqc_algorithm,
                        )
                        pqc_private_bundle = pqc_key_bundle["private_bundle"]
                        pqc_shared_secret = decapsulate_pqc_archive_material(
                            private_bundle=pqc_private_bundle,
                            public_bundle=pqc_key_bundle["public_bundle"],
                            pqc_ciphertext=pqc_ciphertext,
                            expected_key_id=pqc_key_id,
                        )
                        payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, salt)

                    expected_time_key_hash = metadata.get("time_key_hash")
                    if time_key is not None and expected_time_key_hash is not None:
                        from ..security.crypto import verify_time_key_hash

                        if not verify_time_key_hash(time_key, expected_time_key_hash):
                            raise ValueError("Provider unlock key verification failed. The archive or unlock response is invalid.")

                    wrapped_payload_key = metadata.get("wrapped_payload_key")
                    if wrapped_payload_key:
                        payload_decryption_key = unwrap_payload_key(wrapped_payload_key, payload_key, header_bytes)
                    else:
                        payload_decryption_key = payload_key

                    output_filepath = resolve_safe_output_path(output_directory, original_filename)
                    print("Streaming payload decode...")
                    start_decrypt = time.time()
                    stream_result = stream_payload_to_file(
                        payload_stream=payload_stream,
                        output_path=output_filepath,
                        aad=header_bytes,
                        decrypt_key=payload_decryption_key,
                        expected_checksum=expected_checksum,
                        expected_output_size=expected_output_size,
                        progress_callback=(
                            (lambda processed, total: tracker.update(
                                "payload",
                                "Decrypting and validating payload",
                                (processed / total) if total else 0.0,
                            ))
                            if tracker else None
                        ),
                    )
                    decrypt_time = time.time() - start_decrypt
                    if tracker:
                        tracker.update("finalize", "Finalizing preview file", 1.0)
                    print(f"Streaming payload decode completed in {decrypt_time:.2f}s")
                except KeyError as e:
                    raise ValueError(f"Invalid metadata structure: missing {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to open .avk file: {str(e)}")

        total_time = chess_decoding_time + decrypt_time

        print(f"\nSuccess! Extracted to {output_filepath}")
        print(f"  File size: {stream_result['size']:,} bytes")
        print("  Checksum: Verified")
        print(f"  Total time: {total_time:.2f}s (chess: {chess_decoding_time:.2f}s, payload: {decrypt_time:.2f}s)")

        security_features = []
        if encryption_method == "plaintext_archive":
            security_features.append("Explicit Standard Archive (not encrypted)")
        elif encryption_method == "aes256gcm_stream_timekey":
            security_features.append("Time-Key Encryption (provider-held unlock shard)")
            security_features.append("Chess Metadata Encoding")
        else:
            security_features.append("Hierarchical Keys (Argon2id + HKDF)")
            security_features.append("Streaming AES-256-GCM Payload Decryption")
            if metadata.get('pqc_required'):
                security_features.append("External Quantum Keyfile (OpenSSL ML-KEM + X25519 + ML-DSA + SLH-DSA)")
            elif metadata.get('pqc_ciphertext'):
                security_features.append("Post-Quantum Cryptography (OpenSSL PQC Suite)")
            security_features.append("Chess Metadata Security (AES-256-GCM)")
        if metadata.get('keyphrase_protected'):
            security_features.append("Hindi Mnemonic Keyphrase (21-word, checksum-validated)")

        print(f"  Security: {', '.join(security_features)}")
        if tracker:
            tracker.complete("Preview ready")
        return output_filepath
    finally:
        if master_key:
            secure_zero(master_key)
        if salt:
            secure_zero(salt)
        if pqc_shared_secret:
            secure_zero(pqc_shared_secret)
        if payload_key:
            secure_zero(payload_key)
        if payload_decryption_key and payload_decryption_key is not payload_key:
            secure_zero(payload_decryption_key)
        if password:
            secure_zero(password.encode('utf-8'))


def extract_avk_file(
    avk_filepath: str,
    output_directory: str,
    password: str = None,
    keyphrase: list = None,
    pqc_keyfile_path: str = None,
    time_key: bytes = None,
    metadata_override: dict | None = None,
) -> str:
    """Extract a single-file .avk archive."""
    return extract_avk_file_enhanced(
        avk_filepath,
        output_directory,
        password,
        keyphrase,
        pqc_keyfile_path,
        time_key=time_key,
        metadata_override=metadata_override,
    )
