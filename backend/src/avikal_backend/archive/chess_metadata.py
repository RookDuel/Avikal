"""Chess PGN metadata envelopes for Avikal archives.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import secrets
import struct
from .runtime_logging import runtime_debug_print as print

from ..chess_codec.encoder import ChessGenerator
from ..chess_codec.decoder import PGNDecoder
from .format.metadata import unpack_cascade_metadata
from .security.native_bridge import aes256gcm_decrypt, aes256gcm_encrypt, random_bytes

CHESS_ENVELOPE_PUBLIC = 0x10
CHESS_ENVELOPE_PROTECTED = 0x11


def _extract_unlock_timestamp(metadata: bytes) -> int:
    parsed = unpack_cascade_metadata(metadata)
    unlock_timestamp = parsed.get("unlock_timestamp")
    if not isinstance(unlock_timestamp, int):
        raise ValueError("Metadata corrupted: unlock timestamp is missing")
    return unlock_timestamp


def encode_metadata_to_chess_enhanced(metadata: bytes, password: str, keyphrase: list = None, variations_per_round: int = 5, use_timecapsule: bool = False, aad: bytes = b"") -> str:
    """Encode archive metadata into a protected chess PGN envelope."""
    from .security.crypto import derive_argon2id_key, has_user_secret
    
    unlock_ts = _extract_unlock_timestamp(metadata)
    
    tc_marker = b'TMCPSULE' if use_timecapsule else b'AVKLFILE'
    tc_payload = tc_marker + struct.pack('>I', unlock_ts) + metadata
    aad_bytes = bytes(aad)

    if not has_user_secret(password, keyphrase):
        num = int.from_bytes(bytes([CHESS_ENVELOPE_PUBLIC]) + tc_payload, byteorder='big')
        encoder = ChessGenerator(variations_per_round=variations_per_round)
        return encoder.encode_to_pgn(num)

    chess_salt = random_bytes(32)

    chess_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=chess_salt)
    
    print("Applying chess metadata security (AES-256-GCM)...")

    nonce1 = random_bytes(12)
    encrypted_payload = aes256gcm_encrypt(chess_key, nonce1, tc_payload, aad_bytes)

    final_payload = chess_salt + nonce1 + encrypted_payload
    
    num = int.from_bytes(bytes([CHESS_ENVELOPE_PROTECTED]) + final_payload, byteorder='big')
    
    encoder = ChessGenerator(variations_per_round=variations_per_round)
    pgn_string = encoder.encode_to_pgn(num)
    
    return pgn_string


def decode_chess_to_metadata_enhanced(
    pgn_string: str,
    password: str = None,
    keyphrase: list = None,
    skip_timelock: bool = False,
    aad: bytes = b"",
    progress_tracker=None,
) -> dict:
    """Decode and decrypt archive metadata from a chess PGN envelope."""
    from .security.crypto import derive_argon2id_key

    def _progress(description: str, fraction: float) -> None:
        if progress_tracker is not None:
            progress_tracker.update("metadata", description, fraction)
    
    _progress("Reading keychain PGN", 0.10)
    decoder = PGNDecoder()
    _progress("Converting PGN moves to metadata bytes", 0.18)
    def _decoder_progress(description: str, fraction: float) -> None:
        _progress(description, 0.18 + (max(0.0, min(1.0, fraction)) * 0.10))

    num = decoder.decode_from_pgn(pgn_string, progress_callback=_decoder_progress)
    
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
    
    _progress("Parsing metadata envelope", 0.30)
    envelope_version = num_bytes[0]
    if envelope_version == CHESS_ENVELOPE_PUBLIC:
        tc_payload = num_bytes[1:]
    elif envelope_version == CHESS_ENVELOPE_PROTECTED:
        final_payload = num_bytes[1:]
    else:
        raise ValueError("Invalid encoded data format")

    if envelope_version == CHESS_ENVELOPE_PROTECTED:
        if len(final_payload) < 32 + 12 + 16:  # 32B salt + 12B nonce + 16B GCM tag minimum
            raise ValueError("Invalid chess payload - too short")

        chess_salt = final_payload[:32]
        nonce1 = final_payload[32:44]
        encrypted_payload = final_payload[44:]

        _progress("Deriving metadata key with Argon2id", 0.42)
        chess_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=chess_salt)
        aad_bytes = bytes(aad)

        try:
            _progress("Authenticating metadata envelope", 0.62)
            tc_payload = aes256gcm_decrypt(chess_key, nonce1, encrypted_payload, aad_bytes)
            _progress("Metadata envelope decrypted", 0.75)

        except Exception as e:
            raise ValueError(f"Chess metadata decryption failed: {e}")
    
    marker = tc_payload[0:8]
    is_timecapsule = (marker == b'TMCPSULE')
    is_avikal = (marker == b'AVKLFILE')
    
    if not (is_timecapsule or is_avikal):
        raise ValueError("Invalid file format")
    
    unlock_ts = struct.unpack('>I', tc_payload[8:12])[0]
    
    if is_timecapsule and not skip_timelock:
        _progress("Checking time-lock metadata", 0.84)
        # Import here to avoid circular dependency
        from .security.time_lock import validate_unlock_time, format_unlock_time, get_trusted_now
        
        if not validate_unlock_time(unlock_ts):
            unlock_time_str = format_unlock_time(unlock_ts)
            current_time_str = get_trusted_now().strftime("%Y-%m-%d %H:%M UTC")
            raise ValueError(
                f"Time capsule is locked until {unlock_time_str}. "
                f"Current time: {current_time_str}"
            )
    
    metadata_bytes = tc_payload[12:]
    
    try:
        _progress("Parsing archive metadata", 0.92)
        metadata = unpack_cascade_metadata(metadata_bytes)
    except Exception as e:
        raise ValueError(f"Failed to unpack metadata: {str(e)}")
    
    return metadata

