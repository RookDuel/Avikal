"""
Regression tests for the Rust-backed native cryptography bridge.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from avikal_backend.archive.security import native_bridge
from avikal_backend.archive.security.crypto import (
    ARGON2_ITERATIONS,
    ARGON2_LANES,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_OUTPUT_BYTES,
)
from avikal_backend.archive.security.key_wrap import PAYLOAD_KEY_BYTES, wrap_payload_key, unwrap_payload_key


def test_native_extension_is_available() -> None:
    assert native_bridge.native_available(), "Expected compiled avikal_backend._native module to be available"


def test_argon2id_matches_python_reference() -> None:
    secret = b"avikal|native|bridge"
    salt = bytes(range(32))

    expected = Argon2id(
        salt=salt,
        length=ARGON2_OUTPUT_BYTES,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST_KIB,
    ).derive(secret)

    actual = native_bridge.derive_argon2id_key(
        secret,
        salt,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost_kib=ARGON2_MEMORY_COST_KIB,
        length=ARGON2_OUTPUT_BYTES,
    )

    assert actual == expected


def test_hkdf_sha256_matches_python_reference() -> None:
    ikm = b"payload-key-material"
    salt = b"\x05" * 32
    info = b"avikal_payload_v1"
    expected = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)
    actual = native_bridge.hkdf_sha256(ikm, salt, info, length=32)
    assert actual == expected


def test_hkdf_sha256_matches_rfc5869_known_answer() -> None:
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    assert native_bridge.hkdf_sha256(ikm, salt, info, length=42) == expected


def test_aes256gcm_matches_python_reference() -> None:
    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"avikal-header"
    plaintext = b"metadata payload to protect"

    expected = AESGCM(key).encrypt(nonce, plaintext, associated_data=aad)
    actual = native_bridge.aes256gcm_encrypt(key, nonce, plaintext, aad)
    assert actual == expected
    assert native_bridge.aes256gcm_decrypt(key, nonce, actual, aad) == plaintext


def test_aes256gcm_matches_nist_empty_plaintext_vector() -> None:
    key = bytes(32)
    nonce = bytes(12)
    expected_tag = bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b")

    ciphertext = native_bridge.aes256gcm_encrypt(key, nonce, b"", b"")

    assert ciphertext == expected_tag
    assert native_bridge.aes256gcm_decrypt(key, nonce, ciphertext, b"") == b""


def test_native_memory_lock_self_test_is_reportable() -> None:
    assert isinstance(native_bridge.native_memory_lock_self_test(), bool)


def test_key_wrap_roundtrip_uses_native_bridge() -> None:
    payload_key = bytes([0xAB]) * PAYLOAD_KEY_BYTES
    wrapping_key = bytes([0xCD]) * PAYLOAD_KEY_BYTES
    aad = b"avikal-wrap-aad"

    wrapped = wrap_payload_key(payload_key, wrapping_key, aad)
    assert wrapped[:12] != b"\x00" * 12
    assert unwrap_payload_key(wrapped, wrapping_key, aad) == payload_key
