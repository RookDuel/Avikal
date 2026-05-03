"""
Streaming payload processing for Avk archives.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
import tempfile
import zlib
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

log = logging.getLogger("avikal.payload_streaming")


PAYLOAD_MAGIC = b"AVP2"
PAYLOAD_VERSION = 0x01
FLAG_COMPRESSED_ZLIB = 0x01
FLAG_ENCRYPTED_AESGCM = 0x02
PAYLOAD_HEADER_STRUCT = struct.Struct(">4sBBH12s16s")
PAYLOAD_HEADER_SIZE = PAYLOAD_HEADER_STRUCT.size
DEFAULT_STREAM_CHUNK_SIZE = 10 * 1024 * 1024
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024 * 1024 * 1024


def _validate_key(key: bytes | None) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("Payload encryption key must be 32 bytes")
    return bytes(key)


def _write_initial_header(handle: BinaryIO, *, flags: int, nonce: bytes) -> None:
    handle.write(
        PAYLOAD_HEADER_STRUCT.pack(
            PAYLOAD_MAGIC,
            PAYLOAD_VERSION,
            flags,
            0,
            nonce,
            b"\x00" * GCM_TAG_BYTES,
        )
    )


def _rewrite_tag(handle: BinaryIO, *, flags: int, nonce: bytes, tag: bytes) -> None:
    handle.seek(0)
    handle.write(
        PAYLOAD_HEADER_STRUCT.pack(
            PAYLOAD_MAGIC,
            PAYLOAD_VERSION,
            flags,
            0,
            nonce,
            tag,
        )
    )
    handle.flush()


def stream_file_to_payload(
    *,
    input_path: str,
    payload_path: str,
    aad: bytes,
    encrypt_key: bytes | None,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    progress_callback=None,
) -> dict:
    """Compress a file with zlib and optionally encrypt it with streaming AES-256-GCM."""
    flags = FLAG_COMPRESSED_ZLIB
    nonce = b"\x00" * GCM_NONCE_BYTES
    encryptor = None

    if encrypt_key is not None:
        flags |= FLAG_ENCRYPTED_AESGCM
        nonce = os.urandom(GCM_NONCE_BYTES)
        encryptor = Cipher(algorithms.AES(_validate_key(encrypt_key)), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(aad)

    compressor = zlib.compressobj(level=6, wbits=zlib.MAX_WBITS)
    checksum = hashlib.sha256()
    original_size = 0
    compressed_size = 0
    ciphertext_size = 0

    with open(input_path, "rb") as source, open(payload_path, "w+b") as target:
        _write_initial_header(target, flags=flags, nonce=nonce)

        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            original_size += len(chunk)
            checksum.update(chunk)
            compressed_chunk = compressor.compress(chunk)
            if not compressed_chunk:
                continue
            compressed_size += len(compressed_chunk)
            output_chunk = encryptor.update(compressed_chunk) if encryptor else compressed_chunk
            target.write(output_chunk)
            ciphertext_size += len(output_chunk)
            if progress_callback:
                progress_callback(original_size, None)

        final_compressed = compressor.flush()
        compressed_size += len(final_compressed)
        if final_compressed:
            output_chunk = encryptor.update(final_compressed) if encryptor else final_compressed
            target.write(output_chunk)
            ciphertext_size += len(output_chunk)
        if progress_callback:
            progress_callback(original_size, None)

        if encryptor:
            trailing = encryptor.finalize()
            if trailing:
                target.write(trailing)
                ciphertext_size += len(trailing)
            _rewrite_tag(target, flags=flags, nonce=nonce, tag=encryptor.tag)
        else:
            target.flush()

    return {
        "flags": flags,
        "original_size": original_size,
        "compressed_size": compressed_size,
        "payload_size": PAYLOAD_HEADER_SIZE + ciphertext_size,
        "checksum": checksum.digest(),
    }


def parse_payload_header(header_bytes: bytes) -> dict:
    if len(header_bytes) != PAYLOAD_HEADER_SIZE:
        raise ValueError("Payload header is truncated")

    magic, version, flags, _reserved, nonce, tag = PAYLOAD_HEADER_STRUCT.unpack(header_bytes)
    if magic != PAYLOAD_MAGIC:
        raise ValueError("Unsupported payload format")
    if version != PAYLOAD_VERSION:
        raise ValueError("Unsupported payload version")
    if not (flags & FLAG_COMPRESSED_ZLIB):
        raise ValueError("Payload compression flag is missing")

    encrypted = bool(flags & FLAG_ENCRYPTED_AESGCM)
    if encrypted and nonce == b"\x00" * GCM_NONCE_BYTES:
        raise ValueError("Encrypted payload nonce is invalid")
    if not encrypted and tag != b"\x00" * GCM_TAG_BYTES:
        raise ValueError("Plaintext payload tag is invalid")

    return {
        "flags": flags,
        "encrypted": encrypted,
        "nonce": nonce,
        "tag": tag,
    }


def stream_payload_to_file(
    *,
    payload_stream: BinaryIO,
    output_path: str,
    aad: bytes,
    decrypt_key: bytes | None,
    expected_checksum: bytes,
    expected_output_size: int | None = None,
    max_output_size: int = DEFAULT_MAX_OUTPUT_BYTES,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    progress_callback=None,
) -> dict:
    """Decrypt/decompress a streamed payload into a temp file and atomically commit it."""
    if expected_output_size is not None and expected_output_size < 0:
        raise ValueError("Expected output size must be non-negative")
    if max_output_size <= 0:
        raise ValueError("Maximum output size must be positive")

    header_bytes = payload_stream.read(PAYLOAD_HEADER_SIZE)
    header = parse_payload_header(header_bytes)
    total_payload_size = getattr(payload_stream, "avikal_file_size", None)
    processed_bytes = len(header_bytes)

    if header["encrypted"]:
        decryptor = Cipher(
            algorithms.AES(_validate_key(decrypt_key)),
            modes.GCM(header["nonce"], header["tag"]),
        ).decryptor()
        decryptor.authenticate_additional_data(aad)
    else:
        if decrypt_key is not None:
            # Plaintext archives intentionally ignore any supplied key.
            decrypt_key = None
        decryptor = None

    decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS)
    checksum = hashlib.sha256()
    original_size = 0
    temp_handle = None
    temp_path = None

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        temp_handle = tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            dir=os.path.dirname(output_path),
            prefix=".avikal-dec-",
            suffix=".tmp",
        )
        temp_path = temp_handle.name

        while True:
            chunk = payload_stream.read(chunk_size)
            if not chunk:
                break
            processed_bytes += len(chunk)

            plaintext_chunk = decryptor.update(chunk) if decryptor else chunk
            decompressed_chunk = decompressor.decompress(plaintext_chunk)
            if decompressed_chunk:
                next_size = original_size + len(decompressed_chunk)
                output_limit = expected_output_size if expected_output_size is not None else max_output_size
                if next_size > output_limit:
                    raise ValueError("Payload expands beyond the allowed output size.")
                temp_handle.write(decompressed_chunk)
                checksum.update(decompressed_chunk)
                original_size = next_size
            if progress_callback:
                progress_callback(processed_bytes, total_payload_size)

        if decryptor:
            try:
                final_plaintext = decryptor.finalize()
            except Exception as exc:
                raise ValueError("Payload authentication failed. The archive may be corrupted or the key is incorrect.") from exc
            if final_plaintext:
                decompressed_chunk = decompressor.decompress(final_plaintext)
                if decompressed_chunk:
                    next_size = original_size + len(decompressed_chunk)
                    output_limit = expected_output_size if expected_output_size is not None else max_output_size
                    if next_size > output_limit:
                        raise ValueError("Payload expands beyond the allowed output size.")
                    temp_handle.write(decompressed_chunk)
                    checksum.update(decompressed_chunk)
                    original_size = next_size
            if progress_callback:
                progress_callback(processed_bytes, total_payload_size)

        tail = decompressor.flush()
        if tail:
            next_size = original_size + len(tail)
            output_limit = expected_output_size if expected_output_size is not None else max_output_size
            if next_size > output_limit:
                raise ValueError("Payload expands beyond the allowed output size.")
            temp_handle.write(tail)
            checksum.update(tail)
            original_size = next_size

        temp_handle.flush()
        temp_handle.close()
        temp_handle = None

        if expected_output_size is not None and original_size != expected_output_size:
            raise ValueError("Payload size verification failed. The archive may be corrupted.")
        if checksum.digest() != expected_checksum:
            raise ValueError("Payload checksum verification failed. The archive may be corrupted.")

        os.replace(temp_path, output_path)
        temp_path = None
        return {"output_path": output_path, "size": original_size}
    finally:
        if temp_handle is not None:
            try:
                temp_handle.close()
            except OSError as exc:
                log.debug("Failed to close payload temp file handle for %s: %s", output_path, exc)
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError as exc:
                log.debug("Failed to remove payload temp file %s: %s", temp_path, exc)
