"""Chess PGN metadata envelopes for Avikal archives.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import hashlib
import re
import struct
import time
from .runtime_logging import runtime_debug_print as print

from ..chess_codec.encoder import ChessGenerator
from ..chess_codec.decoder import PGNDecoder
from .format.metadata import unpack_cascade_metadata
from .security.native_bridge import aes256gcm_decrypt, aes256gcm_encrypt, random_bytes

CHESS_ENVELOPE_PUBLIC = 0x10
CHESS_ENVELOPE_PROTECTED = 0x11
CHESS_ENVELOPE_PQC_PROTECTED = 0x12

PQC_BOOTSTRAP_MAGIC = b"AVKB"
PQC_BOOTSTRAP_VERSION = 1
PQC_BOOTSTRAP_FLAG_EMBEDDED = 0x01
PQC_BOOTSTRAP_FLAG_SIGNATURE_REQUIRED = 0x02
PQC_BOOTSTRAP_STRUCT = struct.Struct(">4sBBBH16s32sQ")
MAX_PQC_BOOTSTRAP_BYTES = 4 * 1024
MAX_PQC_SUITE_ID_BYTES = 128
MAX_PQC_CIPHERTEXT_BYTES = 2048

_CHESS_REPORT_STAT_FIELDS = (
    "mainline_plies",
    "variation_plies",
    "total_variations",
    "total_plies",
    "max_variations_at_position",
    "positions_with_variations",
    "max_nesting_depth",
    "total_variation_branches",
)


def _normalize_chess_report_stats(stats: dict | None) -> dict:
    """Return one bounded report schema or an explicit unavailable state."""
    normalized: dict[str, int | str] = {}
    try:
        for field in _CHESS_REPORT_STAT_FIELDS:
            value = int((stats or {}).get(field, 0))
            if value < 0:
                raise ValueError(field)
            normalized[field] = value
    except (TypeError, ValueError):
        return {"statistics_status": "unavailable", "statistics_reason": "invalid_codec_statistics"}

    mainline = int(normalized["mainline_plies"])
    variation = int(normalized["variation_plies"])
    total = int(normalized["total_plies"])
    if mainline <= 0 or total != mainline + variation:
        return {"statistics_status": "unavailable", "statistics_reason": "inconsistent_codec_statistics"}
    normalized["branch_count"] = int(normalized["total_variation_branches"])
    normalized["statistics_status"] = "measured"
    return normalized


def _measure_pgn_structure(pgn_string: str) -> dict:
    """Count PGN plies and explicit branches without replaying chess positions."""
    body_lines = [line for line in pgn_string.splitlines() if not line.lstrip().startswith("[")]
    body = "\n".join(body_lines)
    body = re.sub(r"\{[^}]*\}", " ", body, flags=re.DOTALL)
    body = re.sub(r";[^\r\n]*", " ", body)
    tokens = re.findall(r"\(|\)|[^\s()]+", body)
    depth = 0
    mainline_plies = 0
    variation_plies = 0
    branch_count = 0
    max_depth = 0
    for raw_token in tokens:
        if raw_token == "(":
            depth += 1
            branch_count += 1
            max_depth = max(max_depth, depth)
            continue
        if raw_token == ")":
            depth = max(0, depth - 1)
            continue
        token = re.sub(r"^\d+\.(?:\.\.)?", "", raw_token)
        if not token or token.startswith("$") or token in {"*", "1-0", "0-1", "1/2-1/2", "!", "?", "!!", "??", "!?", "?!"}:
            continue
        if depth == 0:
            mainline_plies += 1
        else:
            variation_plies += 1
    if mainline_plies <= 0:
        return {"statistics_status": "unavailable", "statistics_reason": "pgn_structure_unreadable"}
    return {
        "mainline_plies": mainline_plies,
        "variation_plies": variation_plies,
        "total_variations": branch_count,
        "total_plies": mainline_plies + variation_plies,
        "max_variations_at_position": 0,
        "positions_with_variations": 0,
        "max_nesting_depth": max_depth,
        "total_variation_branches": branch_count,
        "branch_count": branch_count,
        "statistics_status": "measured_from_pgn",
    }


def _extract_unlock_timestamp(metadata: bytes) -> int:
    parsed = unpack_cascade_metadata(metadata)
    unlock_timestamp = parsed.get("unlock_timestamp")
    if not isinstance(unlock_timestamp, int):
        raise ValueError("Metadata corrupted: unlock timestamp is missing")
    return unlock_timestamp


def build_pqc_keychain_bootstrap(
    *,
    algorithm: str,
    key_id: str,
    storage_mode: str,
    pqc_ciphertext: bytes,
    archive_id: bytes,
    created_at: int,
    signature_required: bool = True,
) -> bytes:
    """Build the bounded public bootstrap needed before PQC-gated metadata can open."""
    from .security.pqc_keyfile import PQC_STORAGE_MODE_EMBEDDED, PQC_STORAGE_MODE_EXTERNAL
    from .security.pqc_provider import is_supported_pqc_suite_id

    if not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Unsupported PQC keychain algorithm")
    if storage_mode not in {PQC_STORAGE_MODE_EMBEDDED, PQC_STORAGE_MODE_EXTERNAL}:
        raise ValueError("Unsupported PQC keychain storage mode")
    try:
        key_id_bytes = bytes.fromhex(key_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid PQC keychain identifier") from exc
    if len(key_id_bytes) != 32:
        raise ValueError("Invalid PQC keychain identifier")
    if not isinstance(archive_id, (bytes, bytearray)) or len(archive_id) != 16:
        raise ValueError("Invalid PQC archive identifier")
    if not isinstance(created_at, int) or created_at <= 0:
        raise ValueError("Invalid PQC archive creation time")
    algorithm_bytes = algorithm.encode("ascii")
    ciphertext = bytes(pqc_ciphertext)
    if not algorithm_bytes or len(algorithm_bytes) > MAX_PQC_SUITE_ID_BYTES:
        raise ValueError("PQC keychain algorithm is too long")
    if not ciphertext or len(ciphertext) > MAX_PQC_CIPHERTEXT_BYTES:
        raise ValueError("PQC keychain ciphertext size is out of bounds")

    flags = PQC_BOOTSTRAP_FLAG_SIGNATURE_REQUIRED if signature_required else 0
    if storage_mode == PQC_STORAGE_MODE_EMBEDDED:
        flags |= PQC_BOOTSTRAP_FLAG_EMBEDDED
    encoded = (
        PQC_BOOTSTRAP_STRUCT.pack(
            PQC_BOOTSTRAP_MAGIC,
            PQC_BOOTSTRAP_VERSION,
            flags,
            len(algorithm_bytes),
            len(ciphertext),
            bytes(archive_id),
            key_id_bytes,
            created_at,
        )
        + algorithm_bytes
        + ciphertext
    )
    if len(encoded) > MAX_PQC_BOOTSTRAP_BYTES:
        raise ValueError("PQC keychain bootstrap is too large")
    return encoded


def parse_pqc_keychain_bootstrap(encoded: bytes) -> dict:
    """Parse the untrusted public bootstrap with strict length and suite validation."""
    from .security.pqc_keyfile import PQC_STORAGE_MODE_EMBEDDED, PQC_STORAGE_MODE_EXTERNAL
    from .security.pqc_provider import is_supported_pqc_suite_id

    value = bytes(encoded)
    if len(value) < PQC_BOOTSTRAP_STRUCT.size or len(value) > MAX_PQC_BOOTSTRAP_BYTES:
        raise ValueError("PQC keychain bootstrap size is out of bounds")
    magic, version, flags, algorithm_len, ciphertext_len, archive_id, key_id, created_at = PQC_BOOTSTRAP_STRUCT.unpack(
        value[:PQC_BOOTSTRAP_STRUCT.size]
    )
    if magic != PQC_BOOTSTRAP_MAGIC or version != PQC_BOOTSTRAP_VERSION:
        raise ValueError("Unsupported PQC keychain bootstrap")
    known_flags = PQC_BOOTSTRAP_FLAG_EMBEDDED | PQC_BOOTSTRAP_FLAG_SIGNATURE_REQUIRED
    if flags & ~known_flags:
        raise ValueError("PQC keychain bootstrap flags are invalid")
    if algorithm_len == 0 or algorithm_len > MAX_PQC_SUITE_ID_BYTES:
        raise ValueError("PQC keychain algorithm length is invalid")
    if ciphertext_len == 0 or ciphertext_len > MAX_PQC_CIPHERTEXT_BYTES:
        raise ValueError("PQC keychain ciphertext length is invalid")
    expected_length = PQC_BOOTSTRAP_STRUCT.size + algorithm_len + ciphertext_len
    if len(value) != expected_length:
        raise ValueError("PQC keychain bootstrap is truncated")
    algorithm_start = PQC_BOOTSTRAP_STRUCT.size
    ciphertext_start = algorithm_start + algorithm_len
    try:
        algorithm = value[algorithm_start:ciphertext_start].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("PQC keychain algorithm is malformed") from exc
    if not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Unsupported PQC keychain algorithm")
    if created_at <= 0:
        raise ValueError("PQC keychain creation time is invalid")
    return {
        "version": version,
        "algorithm": algorithm,
        "key_id": key_id.hex(),
        "storage_mode": (
            PQC_STORAGE_MODE_EMBEDDED if flags & PQC_BOOTSTRAP_FLAG_EMBEDDED else PQC_STORAGE_MODE_EXTERNAL
        ),
        "signature_required": bool(flags & PQC_BOOTSTRAP_FLAG_SIGNATURE_REQUIRED),
        "archive_id": archive_id.hex(),
        "created_at": created_at,
        "pqc_ciphertext": value[ciphertext_start:],
        "encoded": value,
    }


def inspect_chess_keychain_envelope(pgn_string: str, progress_callback=None) -> dict:
    """Decode the PGN carrier once and expose only bounded public envelope fields."""
    decoder = PGNDecoder()
    num = decoder.decode_from_pgn(pgn_string, progress_callback=progress_callback)
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
    if not num_bytes:
        raise ValueError("Invalid encoded data format")
    envelope_version = num_bytes[0]
    chess_stats = _normalize_chess_report_stats(decoder.last_stats)
    if chess_stats.get("statistics_status") == "unavailable":
        chess_stats = _measure_pgn_structure(pgn_string)
    result = {
        "version": envelope_version,
        "raw": num_bytes,
        "pqc_bootstrap": None,
        "chess_stats": chess_stats,
        "pgn_bytes": len(pgn_string.encode("utf-8")),
        "encoded_envelope_bytes": len(num_bytes),
    }
    if envelope_version == CHESS_ENVELOPE_PQC_PROTECTED:
        if len(num_bytes) < 5:
            raise ValueError("PQC keychain envelope is truncated")
        bootstrap_length = struct.unpack(">I", num_bytes[1:5])[0]
        if bootstrap_length == 0 or bootstrap_length > MAX_PQC_BOOTSTRAP_BYTES:
            raise ValueError("PQC keychain bootstrap length is invalid")
        bootstrap_end = 5 + bootstrap_length
        if len(num_bytes) < bootstrap_end + 32 + 12 + 16:
            raise ValueError("PQC keychain envelope is truncated")
        result["pqc_bootstrap"] = parse_pqc_keychain_bootstrap(num_bytes[5:bootstrap_end])
        result["protected_offset"] = bootstrap_end
    return result


def encode_metadata_to_chess_enhanced(
    metadata: bytes,
    password: str,
    keyphrase: list = None,
    variations_per_round: int = 5,
    use_timecapsule: bool = False,
    aad: bytes = b"",
    *,
    pqc_shared_secret: bytes | None = None,
    pqc_bootstrap: bytes | None = None,
    time_key: bytes | None = None,
    time_key_gated: bool = False,
    return_stats: bool = False,
) -> str | tuple[str, dict]:
    """Encode archive metadata into a protected chess PGN envelope."""
    from .security.crypto import derive_argon2id_key, has_user_secret
    
    unlock_ts = _extract_unlock_timestamp(metadata)
    
    tc_marker = b'TMCPSULE' if use_timecapsule else b'AVKLFILE'
    tc_payload = tc_marker + struct.pack('>I', unlock_ts) + metadata
    aad_bytes = bytes(aad)

    if time_key_gated and (not use_timecapsule or not isinstance(time_key, bytes) or len(time_key) != 32):
        raise ValueError("Time-Capsule keychain protection requires a 32-byte provider release key")

    if not has_user_secret(password, keyphrase) and not time_key_gated:
        num = int.from_bytes(bytes([CHESS_ENVELOPE_PUBLIC]) + tc_payload, byteorder='big')
        encoder = ChessGenerator(variations_per_round=variations_per_round)
        codec_started = time.perf_counter()
        pgn = encoder.encode_to_pgn(num)
        codec_ms = (time.perf_counter() - codec_started) * 1000
        stats = _normalize_chess_report_stats(encoder.get_stats())
        stats.update({
            "metadata_bytes": len(metadata),
            "encoded_envelope_bytes": (num.bit_length() + 7) // 8,
            "keychain_argon2_ms": 0.0,
            "keychain_encryption_ms": 0.0,
            "chess_codec_ms": round(codec_ms, 2),
        })
        return (pgn, stats) if return_stats else pgn

    chess_salt = random_bytes(32)

    keychain_kdf_started = time.perf_counter()
    has_secret = has_user_secret(password, keyphrase)
    chess_key = None
    if has_secret:
        chess_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=chess_salt)
    if time_key_gated:
        from .security.crypto import derive_time_gated_metadata_key

        chess_key = derive_time_gated_metadata_key(chess_key, bytes(time_key), chess_salt)
    if chess_key is None:
        raise ValueError("Protected Chess-PGN metadata has no key material")
    keychain_argon2_ms = (time.perf_counter() - keychain_kdf_started) * 1000
    envelope_version = CHESS_ENVELOPE_PROTECTED
    bootstrap_prefix = b""
    if (pqc_shared_secret is None) != (pqc_bootstrap is None):
        raise ValueError("PQC keychain protection requires both shared secret and bootstrap")
    if pqc_shared_secret is not None:
        from .security.crypto import derive_pqc_hybrid_metadata_key

        parsed_bootstrap = parse_pqc_keychain_bootstrap(bytes(pqc_bootstrap))
        if not parsed_bootstrap["signature_required"]:
            raise ValueError("PQC keychain signatures must be required")
        chess_key = derive_pqc_hybrid_metadata_key(chess_key, bytes(pqc_shared_secret), chess_salt)
        envelope_version = CHESS_ENVELOPE_PQC_PROTECTED
        bootstrap_prefix = struct.pack(">I", len(pqc_bootstrap)) + bytes(pqc_bootstrap)
    
    print("Applying chess metadata security (AES-256-GCM)...")

    nonce1 = random_bytes(12)
    metadata_aad = aad_bytes
    if pqc_bootstrap is not None:
        metadata_aad += hashlib.sha256(bytes(pqc_bootstrap)).digest()
    keychain_encryption_started = time.perf_counter()
    encrypted_payload = aes256gcm_encrypt(chess_key, nonce1, tc_payload, metadata_aad)
    keychain_encryption_ms = (time.perf_counter() - keychain_encryption_started) * 1000

    final_payload = bootstrap_prefix + chess_salt + nonce1 + encrypted_payload
    
    num = int.from_bytes(bytes([envelope_version]) + final_payload, byteorder='big')
    
    encoder = ChessGenerator(variations_per_round=variations_per_round)
    codec_started = time.perf_counter()
    pgn_string = encoder.encode_to_pgn(num)
    codec_ms = (time.perf_counter() - codec_started) * 1000
    
    stats = _normalize_chess_report_stats(encoder.get_stats())
    stats.update({
        "metadata_bytes": len(metadata),
        "encoded_envelope_bytes": (num.bit_length() + 7) // 8,
        "keychain_argon2_ms": round(keychain_argon2_ms, 2),
        "keychain_encryption_ms": round(keychain_encryption_ms, 2),
        "chess_codec_ms": round(codec_ms, 2),
    })
    return (pgn_string, stats) if return_stats else pgn_string


def decode_chess_to_metadata_enhanced(
    pgn_string: str,
    password: str = None,
    keyphrase: list = None,
    skip_timelock: bool = False,
    aad: bytes = b"",
    progress_tracker=None,
    *,
    pqc_shared_secret: bytes | None = None,
    time_key: bytes | None = None,
    time_key_gated: bool = False,
    decoded_envelope: dict | None = None,
) -> dict:
    """Decode and decrypt archive metadata from a chess PGN envelope."""
    from .security.crypto import derive_argon2id_key, has_user_secret

    def _progress(description: str, fraction: float) -> None:
        if progress_tracker is not None:
            progress_tracker.update("metadata", description, fraction)
    
    _progress("Reading keychain PGN", 0.10)
    if decoded_envelope is None:
        _progress("Converting PGN moves to metadata bytes", 0.18)

        def _decoder_progress(description: str, fraction: float) -> None:
            _progress(description, 0.18 + (max(0.0, min(1.0, fraction)) * 0.10))

        decoded_envelope = inspect_chess_keychain_envelope(pgn_string, progress_callback=_decoder_progress)
    num_bytes = bytes(decoded_envelope.get("raw", b""))
    
    _progress("Parsing metadata envelope", 0.30)
    envelope_version = num_bytes[0]
    if envelope_version == CHESS_ENVELOPE_PUBLIC:
        tc_payload = num_bytes[1:]
    elif envelope_version in {CHESS_ENVELOPE_PROTECTED, CHESS_ENVELOPE_PQC_PROTECTED}:
        final_payload = num_bytes[1:]
    else:
        raise ValueError("Invalid encoded data format")

    if envelope_version in {CHESS_ENVELOPE_PROTECTED, CHESS_ENVELOPE_PQC_PROTECTED}:
        bootstrap = None
        if envelope_version == CHESS_ENVELOPE_PQC_PROTECTED:
            bootstrap = decoded_envelope.get("pqc_bootstrap")
            if not isinstance(bootstrap, dict):
                raise ValueError("PQC keychain bootstrap is missing")
            if not pqc_shared_secret:
                raise ValueError("This keychain requires verified PQC material")
            protected_offset = decoded_envelope.get("protected_offset")
            if not isinstance(protected_offset, int):
                raise ValueError("PQC keychain envelope is malformed")
            final_payload = num_bytes[protected_offset:]
        if len(final_payload) < 32 + 12 + 16:  # 32B salt + 12B nonce + 16B GCM tag minimum
            raise ValueError("Invalid chess payload - too short")

        chess_salt = final_payload[:32]
        nonce1 = final_payload[32:44]
        encrypted_payload = final_payload[44:]

        _progress("Deriving metadata key with Argon2id", 0.42)
        has_secret = has_user_secret(password, keyphrase)
        chess_key = None
        if has_secret:
            chess_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=chess_salt)
        if time_key_gated:
            if not isinstance(time_key, bytes) or len(time_key) != 32:
                raise ValueError("This keychain requires a verified 32-byte provider release key")
            from .security.crypto import derive_time_gated_metadata_key

            chess_key = derive_time_gated_metadata_key(chess_key, bytes(time_key), chess_salt)
        if chess_key is None:
            raise ValueError("This protected keychain requires archive credentials or a verified release key")
        if bootstrap is not None:
            from .security.crypto import derive_pqc_hybrid_metadata_key

            chess_key = derive_pqc_hybrid_metadata_key(chess_key, bytes(pqc_shared_secret), chess_salt)
        aad_bytes = bytes(aad)
        if bootstrap is not None:
            aad_bytes += hashlib.sha256(bootstrap["encoded"]).digest()

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
    
    metadata["_report_chess"] = {
        "pgn_bytes": int(decoded_envelope.get("pgn_bytes") or len(pgn_string.encode("utf-8"))),
        "encoded_envelope_bytes": int(decoded_envelope.get("encoded_envelope_bytes") or 0),
        "metadata_bytes": len(metadata_bytes),
        **dict(decoded_envelope.get("chess_stats") or {}),
    }
    return metadata

