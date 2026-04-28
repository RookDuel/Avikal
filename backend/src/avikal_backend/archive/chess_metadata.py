"""
Enhanced chess PGN integration for Avikal metadata.
Uses AES-256-GCM with AAD-bound header integrity for metadata protection.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import secrets
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .runtime_logging import runtime_debug_print as print

from ..chess_codec.encoder import ChessGenerator
from ..chess_codec.decoder import PGNDecoder


def _extract_unlock_timestamp(metadata: bytes) -> int:
    if len(metadata) < 3:
        raise ValueError("Metadata too short")

    offset = 0
    version = metadata[offset]
    if version not in {0x04, 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}:
        raise ValueError(f"Unsupported metadata version: {version}")
    offset += 1  # version
    offset += 1  # flags

    method_length = metadata[offset]
    offset += 1
    if len(metadata) < offset + method_length:
        raise ValueError("Metadata corrupted: method truncated")
    offset += method_length

    if len(metadata) < offset + 32 + 32:
        raise ValueError("Metadata corrupted: salts truncated")
    offset += 32  # payload salt
    offset += 32  # chess salt

    if len(metadata) < offset + 4:
        raise ValueError("Metadata corrupted: PQC ciphertext length missing")
    pqc_ciphertext_length = struct.unpack(">I", metadata[offset:offset + 4])[0]
    offset += 4
    if len(metadata) < offset + pqc_ciphertext_length:
        raise ValueError("Metadata corrupted: PQC ciphertext truncated")
    offset += pqc_ciphertext_length

    if len(metadata) < offset + 4:
        raise ValueError("Metadata corrupted: PQC private key length missing")
    pqc_private_key_length = struct.unpack(">I", metadata[offset:offset + 4])[0]
    offset += 4
    if len(metadata) < offset + pqc_private_key_length + 4:
        raise ValueError("Metadata corrupted: unlock timestamp truncated")
    offset += pqc_private_key_length

    return struct.unpack(">I", metadata[offset:offset + 4])[0]


def encode_metadata_to_chess_enhanced(metadata: bytes, password: str, keyphrase: list = None, variations_per_round: int = 5, use_timecapsule: bool = False, aad: bytes = b"") -> str:
    """
    Chess encoding with original design: password/keyphrase directly used for chess encryption.
    No separate PQC layer in chess - payload already has PQC protection.
    
    Args:
        metadata: Binary metadata packet (~100 bytes)
        password: User password for chess encryption
        keyphrase: 21-word Hindi mnemonic keyphrase (optional)
        variations_per_round: Number of variations per position (default 5)
        use_timecapsule: Enable time-capsule validation (default False)
    
    Returns:
        Chess PGN string with embedded salt
    """
    from .security.crypto import derive_argon2id_key, has_user_secret
    
    unlock_ts = _extract_unlock_timestamp(metadata)
    
    # 1. Add time-capsule marker
    tc_marker = b'TMCPSULE' if use_timecapsule else b'AVKLFILE'
    tc_payload = tc_marker + struct.pack('>I', unlock_ts) + metadata
    aad_bytes = bytes(aad)

    if not has_user_secret(password, keyphrase):
        num = int.from_bytes(b'\x03' + tc_payload, byteorder='big')
        encoder = ChessGenerator(variations_per_round=variations_per_round)
        return encoder.encode_to_pgn(num)

    # Generate random chess_salt for this encoding (original design)
    chess_salt = secrets.token_bytes(32)

    # Derive chess_key with random chess_salt
    chess_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=chess_salt)
    
    # 2. Metadata protection: AES-256-GCM bound to header AAD
    print("Applying chess metadata security (AES-256-GCM)...")

    nonce1 = secrets.token_bytes(12)
    aesgcm = AESGCM(chess_key)
    encrypted_payload = aesgcm.encrypt(nonce1, tc_payload, associated_data=aad_bytes)

    # Combine: chess_salt + nonce + encrypted_data
    # Format: [32B chess_salt][12B nonce1][encrypted_data]
    final_payload = chess_salt + nonce1 + encrypted_payload
    
    # 3. Convert to integer
    num = int.from_bytes(b'\x02' + final_payload, byteorder='big')  # 0x02 = enhanced format
    
    # 4. Encode in chess
    encoder = ChessGenerator(variations_per_round=variations_per_round)
    pgn_string = encoder.encode_to_pgn(num)
    
    return pgn_string


def decode_chess_to_metadata_enhanced(pgn_string: str, password: str = None, keyphrase: list = None, skip_timelock: bool = False, aad: bytes = b"") -> dict:
    """
    Chess decoding with original design: password/keyphrase directly used for chess decryption.
    
    Args:
        pgn_string: Chess PGN containing encoded metadata
        password: User password for chess decryption
        keyphrase: 21-word Hindi mnemonic keyphrase (optional)
        skip_timelock: Skip time-lock validation (default False)
    
    Returns:
        dict: Unpacked metadata
    
    Raises:
        ValueError: If time-lock not reached or decryption failed
    """
    from .security.crypto import derive_argon2id_key
    
    # 1. Decode chess to NUM
    decoder = PGNDecoder()
    num = decoder.decode_from_pgn(pgn_string)
    
    # 2. Convert to bytes
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
    
    # Check format version
    if num_bytes[0] == 0x03:
        tc_payload = num_bytes[1:]
    elif num_bytes[0] == 0x02:
        # Enhanced format with embedded chess_salt
        final_payload = num_bytes[1:]
    else:
        raise ValueError("Invalid encoded data format")

    if num_bytes[0] == 0x02:
        # 3. Extract chess_salt (first 32 bytes of payload)
        if len(final_payload) < 32 + 12 + 16:  # 32B salt + 12B nonce + 16B GCM tag minimum
            raise ValueError("Invalid chess payload - too short")

        chess_salt = final_payload[:32]
        nonce1 = final_payload[32:44]
        encrypted_payload = final_payload[44:]

        # 4. Derive chess_key with extracted chess_salt
        chess_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=chess_salt)
        aad_bytes = bytes(aad)

        # 5. Decrypt AES-256-GCM layer
        try:
            aesgcm = AESGCM(chess_key)
            tc_payload = aesgcm.decrypt(nonce1, encrypted_payload, associated_data=aad_bytes)

        except Exception as e:
            raise ValueError(f"Chess metadata decryption failed: {e}")
    
    # 6. Verify marker
    marker = tc_payload[0:8]
    is_timecapsule = (marker == b'TMCPSULE')
    is_avikal = (marker == b'AVKLFILE')
    
    if not (is_timecapsule or is_avikal):
        raise ValueError("Invalid file format")
    
    # 7. Extract and verify unlock timestamp (only if timecapsule and not skipping)
    unlock_ts = struct.unpack('>I', tc_payload[8:12])[0]
    
    if is_timecapsule and not skip_timelock:
        # Import here to avoid circular dependency
        from .security.time_lock import validate_unlock_time, format_unlock_time, get_trusted_now
        
        if not validate_unlock_time(unlock_ts):
            unlock_time_str = format_unlock_time(unlock_ts)
            current_time_str = get_trusted_now().strftime("%Y-%m-%d %H:%M UTC")
            raise ValueError(
                f"Time capsule is locked until {unlock_time_str}. "
                f"Current time: {current_time_str}"
            )
    
    # 8. Extract metadata
    metadata_bytes = tc_payload[12:]
    
    try:
        from .format.metadata import unpack_cascade_metadata
        metadata = unpack_cascade_metadata(metadata_bytes)
    except Exception as e:
        raise ValueError(f"Failed to unpack metadata: {str(e)}")
    
    return metadata

