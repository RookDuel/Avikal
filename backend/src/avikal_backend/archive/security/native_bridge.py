"""Native-backed cryptographic primitives for Avikal.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import logging
from typing import Final


log = logging.getLogger("avikal.native")

NATIVE_IMPORT_ERROR: Exception | None = None

try:
    from ... import _native as native_module
except Exception as exc:  # pragma: no cover - exercised indirectly in tests
    native_module = None
    NATIVE_IMPORT_ERROR = exc


ARGON2_OUTPUT_BYTES: Final[int] = 32
PAYLOAD_STREAM_TAG_BYTES: Final[int] = 16
PAYLOAD_STREAM_NONCE_BYTES: Final[int] = 12


def native_available() -> bool:
    return native_module is not None


def require_native_available() -> None:
    if native_module is None:
        raise RuntimeError(
            "Avikal native cryptography module is not available. "
            "Install a native-backed Avikal build or rebuild the backend extension with "
            "`python backend/scripts/build_native_extension.py`."
        ) from NATIVE_IMPORT_ERROR


def _require_bytes(name: str, value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(f"{name} must be bytes")
    return bytes(value)


def random_bytes(length: int) -> bytes:
    require_native_available()
    if length <= 0:
        raise ValueError("Requested random byte length must be greater than zero")
    return bytes(native_module.random_bytes(length))


def derive_argon2id_key(
    secret: bytes | bytearray | memoryview,
    salt: bytes,
    *,
    iterations: int,
    lanes: int,
    memory_cost_kib: int,
    length: int = ARGON2_OUTPUT_BYTES,
) -> bytes:
    require_native_available()
    salt_bytes = _require_bytes("salt", salt)
    secret_bytes = _require_bytes("secret", secret)
    if not salt_bytes:
        raise ValueError("salt must not be empty")
    if not secret_bytes:
        raise ValueError("secret must not be empty")
    if length <= 0:
        raise ValueError("Requested Argon2id output length must be greater than zero")
    return bytes(
        native_module.derive_argon2id_key(
            secret_bytes,
            salt_bytes,
            length=length,
            iterations=iterations,
            lanes=lanes,
            memory_cost_kib=memory_cost_kib,
        )
    )


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, *, length: int = 32) -> bytes:
    require_native_available()
    return bytes(
        native_module.hkdf_sha256(
            _require_bytes("ikm", ikm),
            _require_bytes("salt", salt),
            _require_bytes("info", info),
            length=length,
        )
    )


def hkdf_sha3_256(ikm: bytes, salt: bytes | None, info: bytes, *, length: int = 32) -> bytes:
    require_native_available()
    normalized_salt = None if salt is None else _require_bytes("salt", salt)
    return bytes(
        native_module.hkdf_sha3_256(
            _require_bytes("ikm", ikm),
            normalized_salt,
            _require_bytes("info", info),
            length=length,
        )
    )


def aes256gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    require_native_available()
    return bytes(
        native_module.aes256gcm_encrypt(
            _require_bytes("key", key),
            _require_bytes("nonce", nonce),
            _require_bytes("plaintext", plaintext),
            _require_bytes("aad", aad),
        )
    )


def aes256gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    require_native_available()
    return bytes(
        native_module.aes256gcm_decrypt(
            _require_bytes("key", key),
            _require_bytes("nonce", nonce),
            _require_bytes("ciphertext", ciphertext),
            _require_bytes("aad", aad),
        )
    )


def avp_encode_chunk(
    key: bytes | None,
    base_nonce: bytes,
    archive_aad: bytes,
    payload_header: bytes,
    chunk_index: int,
    plaintext: bytes,
    compress_payload: bool,
) -> tuple[bytes, int]:
    require_native_available()
    encoded, stored_len = native_module.avp_encode_chunk(
        None if key is None else _require_bytes("key", key),
        _require_bytes("base_nonce", base_nonce),
        _require_bytes("archive_aad", archive_aad),
        _require_bytes("payload_header", payload_header),
        chunk_index,
        _require_bytes("plaintext", plaintext),
        bool(compress_payload),
    )
    return bytes(encoded), int(stored_len)


def avp_decode_chunk(
    key: bytes | None,
    base_nonce: bytes,
    archive_aad: bytes,
    payload_header: bytes,
    chunk_header: bytes,
    data: bytes,
    compressed: bool,
) -> bytes:
    require_native_available()
    return bytes(
        native_module.avp_decode_chunk(
            None if key is None else _require_bytes("key", key),
            _require_bytes("base_nonce", base_nonce),
            _require_bytes("archive_aad", archive_aad),
            _require_bytes("payload_header", payload_header),
            _require_bytes("chunk_header", chunk_header),
            _require_bytes("data", data),
            bool(compressed),
        )
    )


def sha256_digest(data: bytes) -> bytes:
    require_native_available()
    return bytes(native_module.sha256_digest(_require_bytes("data", data)))


PayloadStreamEncoder = None
PayloadCipherVerifier = None
PayloadStreamDecoder = None

if native_module is not None:
    PayloadStreamEncoder = native_module.PayloadStreamEncoder
    PayloadCipherVerifier = native_module.PayloadCipherVerifier
    PayloadStreamDecoder = native_module.PayloadStreamDecoder
