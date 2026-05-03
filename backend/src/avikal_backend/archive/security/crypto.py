"""
Cryptographic operations for Avikal format.
Handles AES-256-GCM encryption, key generation, checksums, and memory protection.

Phase 1 & 2 Security Enhancements:
- Argon2id KDF for password hardening
- Random padding for size obfuscation
- Memory protection (secure zeroing)
- Memory-hard password derivation (GPU-resistant)
- Key file support

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import hashlib
import logging
import secrets
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ..runtime_logging import runtime_debug_print as print

log = logging.getLogger("avikal.crypto")


ARGON2_SALT_BYTES = 32
ARGON2_OUTPUT_BYTES = 32
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_COST_KIB = 262144  # 256 MiB


def _normalize_secret_input(password: str, keyphrase: list = None) -> bytes:
    """Combine password and keyphrase into a single canonical secret."""
    combined_secret = password or ""
    if keyphrase and isinstance(keyphrase, list):
        from ...mnemonic.generator import normalize_mnemonic_words

        canonical_keyphrase = normalize_mnemonic_words(keyphrase)
        keyphrase_str = " ".join(canonical_keyphrase)
        combined_secret = combined_secret + "|" + keyphrase_str if combined_secret else keyphrase_str

    if not combined_secret:
        raise ValueError("Password or keyphrase is required for protected archive mode")

    return combined_secret.encode("utf-8")


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
        salt = secrets.token_bytes(ARGON2_SALT_BYTES)

    if len(salt) != ARGON2_SALT_BYTES:
        raise ValueError(f"salt must be {ARGON2_SALT_BYTES} bytes")

    secret = _normalize_secret_input(password, keyphrase)

    print(
        "Deriving master key with Argon2id "
        f"({ARGON2_MEMORY_COST_KIB // 1024} MiB, t={ARGON2_ITERATIONS}, p={ARGON2_LANES})..."
    )
    kdf = Argon2id(
        salt=salt,
        length=ARGON2_OUTPUT_BYTES,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST_KIB,
    )
    return kdf.derive(secret), salt


def derive_time_only_payload_key(time_key: bytes, salt: bytes) -> bytes:
    """Derive a payload key for time-capsules that intentionally use no user secret."""
    if len(time_key) != 32:
        raise ValueError("time_key must be 32 bytes")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"avikal_time_only_payload_v1",
    )
    return hkdf.derive(time_key)


def _normalize_aad(aad: bytes | None) -> bytes:
    if aad is None:
        raise ValueError("AAD is required")
    if not isinstance(aad, (bytes, bytearray)):
        raise ValueError("AAD must be bytes")
    return bytes(aad)


def encrypt_payload(data: bytes, key: bytes, aad: bytes) -> bytes:
    """
    Encrypt data with AES-256-GCM.
    
    Args:
        data: Compressed file data
        key: 32-byte random AES key
    
    Returns:
        [12B nonce][encrypted data][16B GCM tag]
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=_normalize_aad(aad))
    return nonce + ciphertext


def decrypt_payload(encrypted: bytes, key: bytes, aad: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.
    
    Args:
        encrypted: [12B nonce][encrypted data][16B GCM tag]
        key: 32-byte AES key
    
    Returns:
        Decrypted data
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    if len(encrypted) < 28:  # 12 + 16
        raise ValueError("Encrypted data too short")
    
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=_normalize_aad(aad))
    except Exception:
        raise ValueError("Decryption failed - data corrupted or wrong key")


def compute_checksum(data: bytes) -> bytes:
    """SHA-256 hash of original file."""
    return hashlib.sha256(data).digest()


def verify_checksum(data: bytes, expected_checksum: bytes) -> bool:
    """Constant-time checksum verification."""
    actual = compute_checksum(data)
    return secrets.compare_digest(actual, expected_checksum)



def secure_zero(data):
    """
    Best-effort in-place zeroing of sensitive key material.

    For ``bytearray`` the buffer is zeroed in-place.  For immutable ``bytes``
    objects Python's memory model does not allow in-place mutation, so the
    function drops the caller's reference and requests a GC cycle — the
    underlying memory will be reclaimed when no further references exist.

    IMPORTANT: True memory security requires OS-level controls (locked pages,
    disabled swap/hibernation). This helper is a best-effort defence-in-depth
    measure only.

    Args:
        data: bytes or bytearray containing sensitive material.
    """
    if data is None:
        return
    try:
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        # For immutable bytes: drop reference and request GC.
        # ctypes.memset into a bytes object's interior is undefined behaviour
        # in CPython (the offset into the object header is platform-dependent
        # and can corrupt the heap).  We intentionally do not attempt it.
        import gc
        gc.collect()
    except Exception as exc:
        log.debug("secure_zero best-effort cleanup failed: %s", exc)


def add_random_padding(data: bytes, min_padding: int = 1024, max_padding: int = 10240) -> tuple:
    """
    Add random padding to hide actual file size.
    
    Args:
        data: Original data
        min_padding: Minimum padding size in bytes (default 1KB)
        max_padding: Maximum padding size in bytes (default 10KB)
    
    Returns:
        Tuple of (padded_data, padding_size)
    """
    padding_size = secrets.randbelow(max_padding - min_padding + 1) + min_padding
    padding = os.urandom(padding_size)
    
    # Add padding marker: [4 bytes: padding size][padding][original data]
    padded = padding_size.to_bytes(4, 'big') + padding + data
    
    return padded, padding_size


def remove_padding(padded_data: bytes) -> bytes:
    """
    Remove random padding from data.
    
    Args:
        padded_data: Data with padding
    
    Returns:
        Original data without padding
    """
    if len(padded_data) < 4:
        raise ValueError("Invalid padded data")
    
    padding_size = int.from_bytes(padded_data[:4], 'big')
    
    if len(padded_data) < 4 + padding_size:
        raise ValueError("Invalid padding size")
    
    return padded_data[4 + padding_size:]


def derive_hierarchical_keys(password: str, keyphrase: list = None, salt: bytes = None) -> tuple:
    """
    Derive hierarchical keys using Argon2id + HKDF expansion.

    Args:
        password: User password
        keyphrase: 21-word Hindi mnemonic keyphrase (optional)
        salt: Random salt (16 bytes)

    Returns:
        tuple: (master_key, payload_key, chess_key, salt)
    """
    master_key, salt = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=salt)

    # Fast HKDF expansion for multiple keys
    print("Expanding to hierarchical keys...")

    # Payload key (for main file encryption)
    hkdf_payload = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"avikal_payload_v1",
    )
    payload_key = hkdf_payload.derive(master_key)

    # Chess key (for metadata encryption)
    hkdf_chess = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"avikal_chess_v1",
    )
    chess_key = hkdf_chess.derive(master_key)

    return master_key, payload_key, chess_key, salt


def derive_pqc_hybrid_payload_key(payload_key: bytes, pqc_shared_secret: bytes, salt: bytes) -> bytes:
    """
    Derive a payload key that depends on both classical and PQC material.

    PQC material is produced through the OpenSSL provider boundary and stored
    outside the .avk container in the encrypted .avkkey bundle.
    """
    if len(payload_key) != 32:
        raise ValueError("payload_key must be 32 bytes")
    if not pqc_shared_secret:
        raise ValueError("pqc_shared_secret is required")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"avikal_payload_pqc_v1",
    )
    return hkdf.derive(payload_key + pqc_shared_secret)


def combine_split_keys(user_key: bytes, time_key: bytes, salt: bytes) -> bytes:
    """
    Combine user_key and time_key to derive combined encryption key.
    Used during decryption after retrieving time_key from server.
    
    Args:
        user_key: 32-byte key derived from password
        time_key: 32-byte random key from server
        salt: Salt used during key derivation
    
    Returns:
        64-byte combined key (32 for AES + 32 for ChaCha20)
    """
    if len(user_key) != 32:
        raise ValueError("user_key must be 32 bytes")
    if len(time_key) != 32:
        raise ValueError("time_key must be 32 bytes")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    
    # Combine using HKDF (same as derive_split_keys)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"avikal_split_key_v1",
    )
    combined_material = user_key + time_key
    combined_key = hkdf.derive(combined_material)
    
    return combined_key


def verify_time_key_hash(time_key: bytes, expected_hash: bytes) -> bool:
    """
    Verify that time_key matches expected hash.
    Prevents fake servers from returning wrong time_key.
    
    Args:
        time_key: 32-byte time key from server
        expected_hash: 32-byte SHA-256 hash stored in metadata
    
    Returns:
        True if hash matches, False otherwise
    """
    if len(time_key) != 32:
        raise ValueError("time_key must be 32 bytes")
    if len(expected_hash) != 32:
        raise ValueError("expected_hash must be 32 bytes (SHA-256)")
    
    actual_hash = hashlib.sha256(time_key).digest()
    return secrets.compare_digest(actual_hash, expected_hash)
