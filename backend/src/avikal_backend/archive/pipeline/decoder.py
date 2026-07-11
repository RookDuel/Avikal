"""Single-file Avikal archive decoder.

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
from ..format.indexed_payload import is_indexed_payload
from ..path_safety import resolve_safe_output_path
from .payload_streaming import stream_payload_to_file
from .progress import get_progress_tracker
from .keychain_security import unlock_archive_keychain
from ..security.pqc_keyfile import (
    PQC_STORAGE_MODE_EMBEDDED,
    PQC_STORAGE_MODE_EXTERNAL,
    read_embedded_pqc_blob,
    read_pqc_keyfile,
)
from ..security.pqc_provider import decapsulate_pqc_archive_material
from ..security.key_wrap import unwrap_payload_key
from ..runtime_logging import runtime_debug_print as print


def extract_avk_file_enhanced(
    avk_filepath: str,
    output_directory: str,
    password: str = None,
    keyphrase: list = None,
    pqc_keyfile_path: str = None,
    pqc_keyfile_password: str = None,
    time_key: bytes = None,
    metadata_override: dict | None = None,
    return_details: bool = False,
) -> str | dict:
    """Extract and decrypt a single-file .avk archive."""
    with open_avk_payload_stream(avk_filepath) as (_header, _keychain, payload_stream, _embedded):
        indexed_payload = is_indexed_payload(payload_stream)
    if indexed_payload:
        from .multi_file_decoder import extract_multi_file_avk

        indexed_result = extract_multi_file_avk(
            avk_filepath=avk_filepath,
            output_directory=output_directory,
            password=password,
            keyphrase=keyphrase,
            time_key=time_key,
            pqc_keyfile_path=pqc_keyfile_path,
            pqc_keyfile_password=pqc_keyfile_password,
            metadata_override=metadata_override,
        )
        files = [item for item in indexed_result.get("files", []) if item.get("type") != "directory"]
        if len(files) != 1:
            raise ValueError("Single-file extraction expected exactly one indexed file")
        output_path = files[0]["path"]
        if return_details:
            return {"output_path": output_path, "metadata": indexed_result.get("metadata") or {}}
        return output_path

    master_key = None
    payload_key = None
    payload_decryption_key = None
    pqc_shared_secret = None
    pqc_private_bundle = None
    salt = None
    keychain_result = None

    try:
        tracker = get_progress_tracker()
        print(f"Opening {avk_filepath}...")
        try:
            with open_avk_payload_stream(avk_filepath) as (header_bytes, keychain_pgn, payload_stream, embedded_pqc_blob):
                header_info = parse_header_bytes(header_bytes)
                if tracker:
                    tracker.update("metadata", "Reading archive metadata", 0.05, force=True)

                if metadata_override is not None:
                    keychain_result = unlock_archive_keychain(
                        keychain_pgn=keychain_pgn,
                        header_bytes=header_bytes,
                        password=password,
                        keyphrase=keyphrase,
                        embedded_pqc_blob=embedded_pqc_blob,
                        pqc_keyfile_path=pqc_keyfile_path,
                        pqc_keyfile_password=pqc_keyfile_password,
                        skip_timelock=True,
                        progress_tracker=tracker,
                        time_key=time_key,
                    )
                    metadata = keychain_result.metadata
                    if metadata != metadata_override:
                        raise ValueError("Verified keychain metadata changed during the unlock flow")
                    validate_metadata_against_header(header_info, metadata)
                    chess_decoding_time = 0.0
                    if tracker:
                        tracker.update("metadata", "Validated secure metadata", 1.0)
                else:
                    print("Decoding chess PGN...")
                    try:
                        start_chess = time.time()
                        keychain_result = unlock_archive_keychain(
                            keychain_pgn=keychain_pgn,
                            header_bytes=header_bytes,
                            password=password,
                            keyphrase=keyphrase,
                            embedded_pqc_blob=embedded_pqc_blob,
                            pqc_keyfile_path=pqc_keyfile_path,
                            pqc_keyfile_password=pqc_keyfile_password,
                            skip_timelock=False,
                            progress_tracker=tracker,
                            time_key=time_key,
                        )
                        metadata = keychain_result.metadata
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
                        if tracker:
                            tracker.update("payload", "Archive payload is not encrypted", 0.03)
                        payload_key = None
                    elif metadata['encryption_method'] == "aes256gcm_stream_timekey":
                        if not time_key:
                            raise ValueError("This archive requires the time-capsule unlock flow.")
                        if tracker:
                            tracker.update("payload", "Deriving time-capsule payload key", 0.08)
                        payload_key = derive_time_only_payload_key(time_key, salt)
                    else:
                        print("Deriving payload key with extracted salt...")
                        if tracker:
                            tracker.update("payload", "Deriving access key with Argon2id", 0.08, force=True)
                        from ..security.crypto import derive_hierarchical_keys
                        master_key, payload_key, _, _ = derive_hierarchical_keys(password, keyphrase, salt)
                        if tracker:
                            tracker.update("payload", "Payload key hierarchy ready", 0.14)
                        if time_key:
                            from ..security.crypto import combine_split_keys

                            if tracker:
                                tracker.update("payload", "Combining local and time-release keys", 0.18)
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
                    pqc_storage_mode = metadata.get('pqc_storage_mode') or (
                        PQC_STORAGE_MODE_EXTERNAL if pqc_required else None
                    )
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
                        if keychain_result is not None and keychain_result.pqc_resolved:
                            pqc_shared_secret = keychain_result.pqc_shared_secret
                            pqc_private_bundle = keychain_result.pqc_private_bundle
                        elif pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED:
                            if tracker:
                                tracker.update("payload", "Unlocking embedded PQC", 0.05)
                            print("Unlocking embedded PQC bundle...")
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
                            print("Loading external PQC keyfile...")
                            pqc_key_bundle = read_pqc_keyfile(
                                pqc_keyfile_path,
                                password=password,
                                keyphrase=keyphrase,
                                expected_key_id=pqc_key_id,
                                expected_algorithm=pqc_algorithm,
                                pqc_keyfile_password=pqc_keyfile_password,
                            )
                        if not (keychain_result is not None and keychain_result.pqc_resolved):
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
                        payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, salt)
                    elif embedded_pqc_blob is not None:
                        raise ValueError("Archive contains an unexpected embedded PQC bundle.")

                    expected_time_key_hash = metadata.get("time_key_hash")
                    if time_key is not None and expected_time_key_hash is not None:
                        from ..security.crypto import verify_time_key_hash

                        if not verify_time_key_hash(time_key, expected_time_key_hash):
                            raise ValueError("Provider unlock key verification failed. The archive or unlock response is invalid.")

                    wrapped_payload_key = metadata.get("wrapped_payload_key")
                    if wrapped_payload_key:
                        if tracker:
                            tracker.update("payload", "Unwrapping payload data key", 0.20)
                        payload_decryption_key = unwrap_payload_key(wrapped_payload_key, payload_key, header_bytes)
                    else:
                        payload_decryption_key = payload_key

                    output_filepath = resolve_safe_output_path(output_directory, original_filename)
                    expected_payload_sha256 = (
                        keychain_result.expected_payload_sha256
                        if keychain_result is not None and keychain_result.archive_signature_verified
                        else None
                    )
                    if keychain_result is not None and keychain_result.signed_payload_size is not None:
                        actual_payload_size = getattr(payload_stream, "avikal_file_size", None)
                        if actual_payload_size != keychain_result.signed_payload_size:
                            raise ValueError("Archive signature payload size binding failed")
                    print("Streaming payload decode...")
                    if tracker:
                        tracker.update("payload", "Preparing payload stream", 0.24)
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
                        expected_ciphertext_sha256=expected_payload_sha256,
                    )
                    metadata.setdefault("archive_integrity", {})["whole_payload_verified"] = True
                    metadata["archive_integrity"]["selected_content_verified"] = True
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
                if metadata.get("pqc_storage_mode") == PQC_STORAGE_MODE_EMBEDDED:
                    security_features.append("Embedded Quantum Protection (OpenSSL ML-KEM + X25519 + ML-DSA + SLH-DSA)")
                else:
                    security_features.append("External Quantum Keyfile (OpenSSL ML-KEM + X25519 + ML-DSA + SLH-DSA)")
            elif metadata.get('pqc_ciphertext'):
                security_features.append("Post-Quantum Cryptography (OpenSSL PQC Suite)")
            security_features.append("Chess Metadata Security (AES-256-GCM)")
        if metadata.get('keyphrase_protected'):
            security_features.append("Hindi Mnemonic Keyphrase (21-word, checksum-validated)")

        print(f"  Security: {', '.join(security_features)}")
        if tracker:
            tracker.complete("Preview ready")
        if return_details:
            return {"output_path": output_filepath, "metadata": metadata}
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
    pqc_keyfile_password: str = None,
    time_key: bytes = None,
    metadata_override: dict | None = None,
    return_details: bool = False,
) -> str | dict:
    """Extract a single-file .avk archive."""
    return extract_avk_file_enhanced(
        avk_filepath,
        output_directory,
        password,
        keyphrase,
        pqc_keyfile_path,
        pqc_keyfile_password,
        time_key=time_key,
        metadata_override=metadata_override,
        return_details=return_details,
    )
