"""
Payload key wrapping for rekey-capable Avikal archives.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PAYLOAD_KEY_WRAP_ALGORITHM = "aes256gcm-dek-wrap-v1"
PAYLOAD_KEY_BYTES = 32
WRAP_NONCE_BYTES = 12
WRAP_TAG_BYTES = 16


def generate_payload_key() -> bytes:
    """Generate a random 256-bit data-encryption key for payload.enc."""
    return secrets.token_bytes(PAYLOAD_KEY_BYTES)


def wrap_payload_key(payload_key: bytes, wrapping_key: bytes, aad: bytes) -> bytes:
    """
    Wrap the random payload key with the derived archive access key.

    Returns bytes in the form: [12-byte nonce][ciphertext+GCM tag].
    """
    _validate_key("payload_key", payload_key)
    _validate_key("wrapping_key", wrapping_key)
    if not isinstance(aad, (bytes, bytearray)):
        raise ValueError("AAD must be bytes")

    nonce = secrets.token_bytes(WRAP_NONCE_BYTES)
    encrypted_key = AESGCM(wrapping_key).encrypt(nonce, payload_key, bytes(aad))
    return nonce + encrypted_key


def unwrap_payload_key(wrapped_payload_key: bytes, wrapping_key: bytes, aad: bytes) -> bytes:
    """Unwrap and authenticate a payload key stored in metadata."""
    _validate_key("wrapping_key", wrapping_key)
    if not isinstance(wrapped_payload_key, (bytes, bytearray)):
        raise ValueError("Wrapped payload key must be bytes")
    wrapped_payload_key = bytes(wrapped_payload_key)
    min_length = WRAP_NONCE_BYTES + PAYLOAD_KEY_BYTES + WRAP_TAG_BYTES
    if len(wrapped_payload_key) < min_length:
        raise ValueError("Wrapped payload key is too short")
    if not isinstance(aad, (bytes, bytearray)):
        raise ValueError("AAD must be bytes")

    nonce = wrapped_payload_key[:WRAP_NONCE_BYTES]
    ciphertext = wrapped_payload_key[WRAP_NONCE_BYTES:]
    try:
        payload_key = AESGCM(wrapping_key).decrypt(nonce, ciphertext, bytes(aad))
    except Exception as exc:
        raise ValueError("Wrapped payload key could not be unlocked") from exc

    _validate_key("payload_key", payload_key)
    return payload_key


def _validate_key(name: str, value: bytes) -> None:
    if not isinstance(value, (bytes, bytearray)) or len(value) != PAYLOAD_KEY_BYTES:
        raise ValueError(f"{name} must be {PAYLOAD_KEY_BYTES} bytes")
