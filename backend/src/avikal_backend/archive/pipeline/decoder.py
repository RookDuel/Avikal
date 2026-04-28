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
    pqc_decapsulate,
)
from ..format.header import parse_header_bytes, validate_metadata_against_header
from ..format.container import open_avk_payload_stream
from ..chess_metadata import decode_chess_to_metadata_enhanced
from ..path_safety import resolve_safe_output_path
from .payload_streaming import stream_payload_to_file
from .progress import get_progress_tracker
from ..security.pqc_keyfile import read_pqc_keyfile
from ..runtime_logging import runtime_debug_print as print


def extract_avk_file_enhanced(
    avk_filepath: str,
    output_directory: str,
    password: str = None,
    keyphrase: list = None,
    pqc_keyfile_path: str = None,
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
    pqc_shared_secret = None
    pqc_private_key = None
    salt = None

    try:
        tracker = get_progress_tracker()
        print(f"Opening {avk_filepath}...")
        try:
            with open_avk_payload_stream(avk_filepath) as (header_bytes, keychain_pgn, payload_stream):
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
                        raise ValueError("This archive requires the time-capsule unlock flow.")
                    else:
                        print("Deriving payload key with extracted salt...")
                        from ..security.crypto import derive_hierarchical_keys
                        master_key, payload_key, _, _ = derive_hierarchical_keys(password, keyphrase, salt)
                except KeyError:
                    raise ValueError("Invalid metadata: salt not found")

                try:
                    encryption_method = metadata['encryption_method']
                    pqc_ciphertext = metadata.get('pqc_ciphertext')
                    pqc_private_key = metadata.get('pqc_private_key')
                    pqc_required = bool(metadata.get('pqc_required'))
                    pqc_algorithm = metadata.get('pqc_algorithm')
                    pqc_key_id = metadata.get('pqc_key_id')
                    expected_checksum = metadata['checksum']
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
                        pqc_private_key = pqc_key_bundle["private_key"]
                        pqc_shared_secret = pqc_decapsulate(pqc_private_key, pqc_ciphertext)
                        if not pqc_shared_secret:
                            raise ValueError(
                                "PQC decapsulation failed. The keyfile does not match this archive or the archive is corrupted."
                            )
                        payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, salt)

                    output_filepath = resolve_safe_output_path(output_directory, original_filename)
                    print("Streaming payload decode...")
                    start_decrypt = time.time()
                    stream_result = stream_payload_to_file(
                        payload_stream=payload_stream,
                        output_path=output_filepath,
                        aad=header_bytes,
                        decrypt_key=payload_key,
                        expected_checksum=expected_checksum,
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
                security_features.append("External PQC Keyfile (ML-KEM-1024)")
            elif metadata.get('pqc_ciphertext'):
                security_features.append("Post-Quantum Cryptography (ML-KEM-1024)")
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
        if pqc_private_key:
            secure_zero(pqc_private_key)
        if payload_key:
            secure_zero(payload_key)
        if password:
            secure_zero(password.encode('utf-8'))


def extract_avk_file(
    avk_filepath: str,
    output_directory: str,
    password: str = None,
    keyphrase: list = None,
    pqc_keyfile_path: str = None,
) -> str:
    """Extract a single-file .avk archive."""
    return extract_avk_file_enhanced(avk_filepath, output_directory, password, keyphrase, pqc_keyfile_path)
