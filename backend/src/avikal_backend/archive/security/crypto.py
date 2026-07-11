"""Cryptographic helpers for Avikal archive protection.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import logging
import os
import secrets

from ..runtime_logging import runtime_debug_print as print
from .native_bridge import (
    aes256gcm_decrypt as native_aes256gcm_decrypt,
    aes256gcm_encrypt as native_aes256gcm_encrypt,
    derive_argon2id_key as native_derive_argon2id_key,
    hkdf_sha256 as native_hkdf_sha256,
    random_bytes as native_random_bytes,
    sha256_digest as native_sha256_digest,
)

log = logging.getLogger("avikal.crypto")


ARGON2_SALT_BYTES = 32
ARGON2_OUTPUT_BYTES = 32
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_COST_KIB = 262144  # 256 MiB


def _normalize_secret_input(password: str, keyphrase: list = None) -> bytearray:
    """Combine password and keyphrase into a single canonical secret."""
    combined_secret = password or ""
    if keyphrase and isinstance(keyphrase, list):
        from ...mnemonic.generator import normalize_mnemonic_words

        canonical_keyphrase = normalize_mnemonic_words(keyphrase)
        keyphrase_str = " ".join(canonical_keyphrase)
        combined_secret = combined_secret + "|" + keyphrase_str if combined_secret else keyphrase_str

    if not combined_secret:
        raise ValueError("Password or keyphrase is required for protected archive mode")

    return bytearray(combined_secret.encode("utf-8"))


def has_user_secret(password: str | None, keyphrase: list | None = None) -> bool:
    """Return True when archive protection should use user-supplied secrets."""
    if password:
        return True
    if keyphrase and isinstance(keyphrase, list):
        return any(str(word).strip() for word in keyphrase)
    return False


def derive_argon2id_key(password: str, keyphrase: list = None, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive a 32-byte master key using Argon2id."""
    if salt is None:
        salt = native_random_bytes(ARGON2_SALT_BYTES)

    if len(salt) != ARGON2_SALT_BYTES:
        raise ValueError(f"salt must be {ARGON2_SALT_BYTES} bytes")

    secret = _normalize_secret_input(password, keyphrase)

    print(
        "Deriving master key with Argon2id "
        f"({ARGON2_MEMORY_COST_KIB // 1024} MiB, t={ARGON2_ITERATIONS}, p={ARGON2_LANES})..."
    )
    try:
        derived = native_derive_argon2id_key(
            secret,
            salt,
            iterations=ARGON2_ITERATIONS,
            lanes=ARGON2_LANES,
            memory_cost_kib=ARGON2_MEMORY_COST_KIB,
            length=ARGON2_OUTPUT_BYTES,
        )
        return derived, salt
    finally:
        secure_zero(secret)


def derive_time_only_payload_key(time_key: bytes, salt: bytes) -> bytes:
    """Derive a payload key for time-capsules that intentionally use no user secret."""
    if len(time_key) != 32:
        raise ValueError("time_key must be 32 bytes")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")

    return native_hkdf_sha256(time_key, salt, b"avikal_time_only_payload_v1", length=32)


def derive_time_gated_metadata_key(master_key: bytes | None, time_key: bytes, salt: bytes) -> bytes:
    """Bind Chess-PGN metadata confidentiality to the provider-held release key."""
    if master_key is not None and len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes when supplied")
    if len(time_key) != 32:
        raise ValueError("time_key must be 32 bytes")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    user_component = master_key if master_key is not None else bytes(32)
    return native_hkdf_sha256(
        user_component + time_key,
        salt,
        b"avikal_time_gated_keychain_v1",
        length=32,
    )


def _normalize_aad(aad: bytes | None) -> bytes:
    if aad is None:
        raise ValueError("AAD is required")
    if not isinstance(aad, (bytes, bytearray)):
        raise ValueError("AAD must be bytes")
    return bytes(aad)


def encrypt_payload(data: bytes, key: bytes, aad: bytes) -> bytes:
    """Encrypt bytes as [12B nonce][ciphertext+16B tag]."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")

    nonce = native_random_bytes(12)
    ciphertext = native_aes256gcm_encrypt(key, nonce, data, _normalize_aad(aad))
    return nonce + ciphertext


def decrypt_payload(encrypted: bytes, key: bytes, aad: bytes) -> bytes:
    """Decrypt [12B nonce][ciphertext+16B tag]."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    if len(encrypted) < 28:  # 12 + 16
        raise ValueError("Encrypted data too short")

    nonce = encrypted[:12]
    ciphertext = encrypted[12:]

    try:
        return native_aes256gcm_decrypt(key, nonce, ciphertext, _normalize_aad(aad))
    except Exception:
        raise ValueError("Decryption failed - data corrupted or wrong key")


def compute_checksum(data: bytes) -> bytes:
    """SHA-256 hash of original file."""
    return native_sha256_digest(data)


def verify_checksum(data: bytes, expected_checksum: bytes) -> bool:
    """Constant-time checksum verification."""
    actual = compute_checksum(data)
    return secrets.compare_digest(actual, expected_checksum)


def secure_zero(data):
    """Best-effort cleanup for mutable sensitive buffers."""
    if data is None:
        return
    try:
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        # Immutable bytes cannot be safely overwritten in CPython.
        import gc

        gc.collect()
    except Exception as exc:
        log.debug("secure_zero best-effort cleanup failed: %s", exc)


def add_random_padding(data: bytes, min_padding: int = 1024, max_padding: int = 10240) -> tuple:
    """Add random prefix padding and return padded bytes plus padding size."""
    padding_size = secrets.randbelow(max_padding - min_padding + 1) + min_padding
    padding = os.urandom(padding_size)

    padded = padding_size.to_bytes(4, "big") + padding + data
    return padded, padding_size


def remove_padding(padded_data: bytes) -> bytes:
    """Remove the padding produced by add_random_padding."""
    if len(padded_data) < 4:
        raise ValueError("Invalid padded data")

    padding_size = int.from_bytes(padded_data[:4], "big")

    if len(padded_data) < 4 + padding_size:
        raise ValueError("Invalid padding size")

    return padded_data[4 + padding_size :]


def derive_hierarchical_keys(password: str, keyphrase: list = None, salt: bytes = None) -> tuple:
    """Derive master, payload, and metadata keys."""
    master_key, salt = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=salt)

    print("Expanding to hierarchical keys...")
    payload_key = native_hkdf_sha256(master_key, salt, b"avikal_payload_v1", length=32)
    chess_key = native_hkdf_sha256(master_key, salt, b"avikal_chess_v1", length=32)

    return master_key, payload_key, chess_key, salt


def derive_pqc_hybrid_payload_key(payload_key: bytes, pqc_shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a payload key from classical and PQC material."""
    if len(payload_key) != 32:
        raise ValueError("payload_key must be 32 bytes")
    if not pqc_shared_secret:
        raise ValueError("pqc_shared_secret is required")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")

    return native_hkdf_sha256(payload_key + pqc_shared_secret, salt, b"avikal_payload_pqc_v1", length=32)


def derive_pqc_hybrid_metadata_key(master_key: bytes, pqc_shared_secret: bytes, salt: bytes) -> bytes:
    """Derive the PQC-gated key used by the protected chess metadata envelope."""
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    if not pqc_shared_secret:
        raise ValueError("pqc_shared_secret is required")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")

    return native_hkdf_sha256(
        master_key + pqc_shared_secret,
        salt,
        b"avikal_keychain_pqc_v1",
        length=32,
    )


def combine_split_keys(user_key: bytes, time_key: bytes, salt: bytes) -> bytes:
    """Combine user and provider-held time keys."""
    if len(user_key) != 32:
        raise ValueError("user_key must be 32 bytes")
    if len(time_key) != 32:
        raise ValueError("time_key must be 32 bytes")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")

    combined_material = user_key + time_key
    return native_hkdf_sha256(combined_material, salt, b"avikal_split_key_v1", length=64)


def verify_time_key_hash(time_key: bytes, expected_hash: bytes) -> bool:
    """Verify provider time-key material against metadata."""
    if len(time_key) != 32:
        raise ValueError("time_key must be 32 bytes")
    if len(expected_hash) != 32:
        raise ValueError("expected_hash must be 32 bytes (SHA-256)")

    actual_hash = native_sha256_digest(time_key)
    return secrets.compare_digest(actual_hash, expected_hash)
