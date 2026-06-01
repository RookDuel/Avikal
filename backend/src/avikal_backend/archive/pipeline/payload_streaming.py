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
from itertools import chain
from typing import BinaryIO, Iterable

from avikal_backend.core.temp_janitor import register_temp_artifact, unregister_temp_artifact

from ..security.native_bridge import (
    PayloadCipherVerifier,
    PayloadStreamDecoder,
    PayloadStreamEncoder,
    avp_decode_chunk,
    avp_encode_chunk,
)

log = logging.getLogger("avikal.payload_streaming")


PAYLOAD_MAGIC_LEGACY = b"AVP2"
PAYLOAD_MAGIC = b"AVP\x00"
PAYLOAD_VERSION = 0x01
FLAG_COMPRESSED_ZLIB = 0x01
FLAG_ENCRYPTED_AESGCM = 0x02
PAYLOAD_HEADER_STRUCT = struct.Struct(">4sBBH12s16s")
PAYLOAD_HEADER_SIZE = PAYLOAD_HEADER_STRUCT.size
PAYLOAD_CHUNKED_HEADER_STRUCT = PAYLOAD_HEADER_STRUCT
PAYLOAD_CHUNK_STRUCT = struct.Struct(">QII")
DEFAULT_STREAM_CHUNK_SIZE = 10 * 1024 * 1024
MAX_AVP_CHUNK_BYTES = 64 * 1024 * 1024
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024 * 1024 * 1024
ADAPTIVE_COMPRESSION_SAMPLE_BYTES = 4 * 1024 * 1024
ADAPTIVE_COMPRESSION_MIN_BYTES = 64 * 1024 * 1024
ADAPTIVE_COMPRESSION_MIN_SAVINGS_RATIO = 0.03
_CHUNKED_HEADER_RESERVED = b"\x00" * GCM_TAG_BYTES
_COMPRESSED_EXTENSIONS = {
    ".7z",
    ".apk",
    ".avif",
    ".br",
    ".bz2",
    ".cab",
    ".deb",
    ".docx",
    ".dll",
    ".dmg",
    ".exe",
    ".gz",
    ".heic",
    ".heif",
    ".img",
    ".iso",
    ".jpeg",
    ".jpg",
    ".m4a",
    ".m4v",
    ".mov",
    ".mp3",
    ".mp4",
    ".msi",
    ".msix",
    ".msixbundle",
    ".ogg",
    ".pdf",
    ".pkg",
    ".png",
    ".rar",
    ".rpm",
    ".vhd",
    ".vhdx",
    ".webm",
    ".webp",
    ".xlsx",
    ".xz",
    ".zip",
    ".zst",
}


class LegacyPayloadStreamingRequired(ValueError):
    """Raised when a legacy payload must use the materialized compatibility path."""


def _validate_key(key: bytes | None) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("Payload encryption key must be 32 bytes")
    return bytes(key)


def _write_initial_header(handle: BinaryIO, *, flags: int, nonce: bytes) -> None:
    handle.write(
        PAYLOAD_HEADER_STRUCT.pack(
            PAYLOAD_MAGIC_LEGACY,
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
            PAYLOAD_MAGIC_LEGACY,
            PAYLOAD_VERSION,
            flags,
            0,
            nonce,
            tag,
        )
    )
    handle.flush()


def _should_compress_payload(input_path: str) -> bool:
    extension = os.path.splitext(input_path)[1].lower()
    return extension not in _COMPRESSED_EXTENSIONS


def choose_payload_compression(
    *,
    input_path: str | None = None,
    total_input_size: int | None = None,
    sample_bytes: bytes | None = None,
    force_compress: bool | None = None,
) -> dict:
    """Choose whether the primary AVP stream should zlib-compress plaintext chunks."""
    if total_input_size is not None and total_input_size < 0:
        raise ValueError("Payload input size must be non-negative")
    if force_compress is not None:
        return {
            "enabled": bool(force_compress),
            "reason": "forced",
            "sample_ratio": None,
        }

    extension = os.path.splitext(input_path or "")[1].lower()
    if extension in _COMPRESSED_EXTENSIONS:
        return {
            "enabled": False,
            "reason": "extension",
            "sample_ratio": None,
        }

    if total_input_size is not None and total_input_size < ADAPTIVE_COMPRESSION_MIN_BYTES:
        return {
            "enabled": True,
            "reason": "small_input",
            "sample_ratio": None,
        }

    if sample_bytes:
        compressed = zlib.compress(sample_bytes, level=1)
        ratio = len(compressed) / len(sample_bytes)
        return {
            "enabled": (1.0 - ratio) >= ADAPTIVE_COMPRESSION_MIN_SAVINGS_RATIO,
            "reason": "sample",
            "sample_ratio": ratio,
        }

    return {
        "enabled": True,
        "reason": "default",
        "sample_ratio": None,
    }


def _stream_file_to_payload_v2(
    *,
    input_path: str,
    payload_path: str,
    aad: bytes,
    encrypt_key: bytes | None,
    chunk_size: int,
    progress_callback=None,
) -> dict:
    """Write the legacy AVP2 payload format. New archives use the primary AVP format."""
    flags = FLAG_COMPRESSED_ZLIB
    nonce = b"\x00" * GCM_NONCE_BYTES

    if encrypt_key is not None:
        flags |= FLAG_ENCRYPTED_AESGCM
        nonce = os.urandom(GCM_NONCE_BYTES)
    encoder = PayloadStreamEncoder(
        _validate_key(encrypt_key) if encrypt_key is not None else None,
        nonce if encrypt_key is not None else None,
        bytes(aad),
        compression_level=6,
    )
    payload_bytes_written = 0

    with open(input_path, "rb") as source, open(payload_path, "w+b") as target:
        _write_initial_header(target, flags=flags, nonce=nonce)
        processed_input_bytes = 0

        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            processed_input_bytes += len(chunk)
            output_chunk = encoder.update(chunk)
            if output_chunk:
                target.write(output_chunk)
                payload_bytes_written += len(output_chunk)
            if progress_callback:
                progress_callback(processed_input_bytes, None)

        final_output, tag, checksum, original_size, compressed_size = encoder.finalize()
        if final_output:
            target.write(final_output)
            payload_bytes_written += len(final_output)
        if progress_callback:
            progress_callback(processed_input_bytes, None)

        if tag is not None:
            _rewrite_tag(target, flags=flags, nonce=nonce, tag=tag)
        else:
            target.flush()

    return {
        "format": "AVP2",
        "flags": flags,
        "original_size": original_size,
        "compressed_size": compressed_size,
        "payload_size": PAYLOAD_HEADER_SIZE + payload_bytes_written,
        "checksum": checksum,
    }


def _write_chunked_payload_to_writer(
    *,
    chunks: Iterable[bytes],
    total_input_size: int,
    target: BinaryIO,
    aad: bytes,
    encrypt_key: bytes | None,
    compression_decision: dict,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    progress_callback=None,
) -> dict:
    """Write primary AVP chunks into an already-open binary writer."""
    if chunk_size <= 0:
        raise ValueError("Payload chunk size must be positive")
    if total_input_size < 0:
        raise ValueError("Payload input size must be non-negative")

    compress_payload = bool(compression_decision.get("enabled"))
    flags = FLAG_COMPRESSED_ZLIB if compress_payload else 0
    base_nonce = b"\x00" * GCM_NONCE_BYTES
    key = None
    if encrypt_key is not None:
        flags |= FLAG_ENCRYPTED_AESGCM
        base_nonce = os.urandom(GCM_NONCE_BYTES)
        key = _validate_key(encrypt_key)

    header_bytes = PAYLOAD_CHUNKED_HEADER_STRUCT.pack(
        PAYLOAD_MAGIC,
        PAYLOAD_VERSION,
        flags,
        PAYLOAD_HEADER_SIZE,
        base_nonce,
        _CHUNKED_HEADER_RESERVED,
    )
    checksum = hashlib.sha256()
    pending = bytearray()
    payload_bytes_written = 0
    processed_input_bytes = 0
    stored_size = 0
    chunk_index = 0

    def write_one_chunk(target: BinaryIO, plaintext_chunk: bytes) -> None:
        nonlocal payload_bytes_written, stored_size, chunk_index
        checksum.update(plaintext_chunk)
        encoded_chunk, stored_len = avp_encode_chunk(
            key,
            base_nonce,
            bytes(aad),
            header_bytes,
            chunk_index,
            plaintext_chunk,
            compress_payload,
        )
        target.write(encoded_chunk)
        payload_bytes_written += len(encoded_chunk)
        stored_size += stored_len
        chunk_index += 1

    target.write(header_bytes)
    payload_bytes_written += len(header_bytes)

    for raw_chunk in chunks:
        if not raw_chunk:
            continue
        pending.extend(bytes(raw_chunk))
        while len(pending) >= chunk_size:
            plaintext_chunk = bytes(pending[:chunk_size])
            del pending[:chunk_size]
            processed_input_bytes += len(plaintext_chunk)
            write_one_chunk(target, plaintext_chunk)
            if progress_callback:
                progress_callback(processed_input_bytes, total_input_size)

    if pending:
        plaintext_chunk = bytes(pending)
        pending.clear()
        processed_input_bytes += len(plaintext_chunk)
        write_one_chunk(target, plaintext_chunk)

    if processed_input_bytes != total_input_size:
        raise ValueError("Payload input size changed during streaming")
    if progress_callback:
        progress_callback(processed_input_bytes, total_input_size)
    if hasattr(target, "flush"):
        target.flush()

    return {
        "format": "AVP",
        "flags": flags,
        "original_size": processed_input_bytes,
        "compressed_size": stored_size,
        "payload_size": payload_bytes_written,
        "checksum": checksum.digest(),
        "compression_enabled": compress_payload,
        "compression_reason": compression_decision.get("reason"),
        "compression_sample_ratio": compression_decision.get("sample_ratio"),
        "source_bytes_read": processed_input_bytes,
        "payload_bytes_written": payload_bytes_written,
    }


def _sample_chunks(
    chunks: Iterable[bytes],
    *,
    sample_size: int = ADAPTIVE_COMPRESSION_SAMPLE_BYTES,
) -> tuple[bytes, Iterable[bytes]]:
    iterator = iter(chunks)
    buffered: list[bytes] = []
    sample = bytearray()
    for raw_chunk in iterator:
        if not raw_chunk:
            continue
        chunk = bytes(raw_chunk)
        buffered.append(chunk)
        if len(sample) < sample_size:
            sample.extend(chunk[: sample_size - len(sample)])
        if len(sample) >= sample_size:
            break
    return bytes(sample), chain(buffered, iterator)


def stream_chunks_to_payload_writer(
    *,
    chunks: Iterable[bytes],
    total_input_size: int,
    target: BinaryIO,
    aad: bytes,
    encrypt_key: bytes | None,
    compress_payload: bool | None = True,
    compression_decision: dict | None = None,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    progress_callback=None,
) -> dict:
    """Write caller-provided plaintext chunks into an already-open AVP writer."""
    chunks_to_write = chunks
    if compression_decision is None:
        if compress_payload is None:
            sample, chunks_to_write = _sample_chunks(chunks)
            compression_decision = choose_payload_compression(
                total_input_size=total_input_size,
                sample_bytes=sample,
            )
        else:
            compression_decision = choose_payload_compression(
                total_input_size=total_input_size,
                force_compress=compress_payload,
            )
    return _write_chunked_payload_to_writer(
        chunks=chunks_to_write,
        total_input_size=total_input_size,
        target=target,
        aad=aad,
        encrypt_key=encrypt_key,
        compression_decision=compression_decision,
        chunk_size=chunk_size,
        progress_callback=progress_callback,
    )


def stream_chunks_to_payload(
    *,
    chunks,
    total_input_size: int,
    payload_path: str,
    aad: bytes,
    encrypt_key: bytes | None,
    compress_payload: bool | None = True,
    compression_decision: dict | None = None,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    progress_callback=None,
) -> dict:
    """Write caller-provided plaintext chunks into the primary AVP chunked payload."""
    with open(payload_path, "w+b") as target:
        return stream_chunks_to_payload_writer(
            chunks=chunks,
            total_input_size=total_input_size,
            target=target,
            aad=aad,
            encrypt_key=encrypt_key,
            compress_payload=compress_payload,
            compression_decision=compression_decision,
            chunk_size=chunk_size,
            progress_callback=progress_callback,
        )


def _file_chunks(source: BinaryIO, first_chunk: bytes, chunk_size: int) -> Iterable[bytes]:
    if first_chunk:
        yield first_chunk
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            break
        yield chunk


def stream_file_to_payload_writer(
    *,
    input_path: str,
    target: BinaryIO,
    aad: bytes,
    encrypt_key: bytes | None,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    progress_callback=None,
    payload_format: str = "AVP",
) -> dict:
    """Write the primary AVP chunked payload into an already-open binary writer."""
    if chunk_size <= 0:
        raise ValueError("Payload chunk size must be positive")
    normalized_format = (payload_format or "AVP").upper()
    if normalized_format != "AVP":
        raise ValueError("Unsupported payload format")

    source_size = os.path.getsize(input_path)
    compression_decision = choose_payload_compression(
        input_path=input_path,
        total_input_size=source_size,
    )
    first_chunk = b""
    with open(input_path, "rb") as source:
        if (
            compression_decision["enabled"]
            and compression_decision["reason"] == "default"
            and source_size >= ADAPTIVE_COMPRESSION_MIN_BYTES
        ):
            first_chunk = source.read(ADAPTIVE_COMPRESSION_SAMPLE_BYTES)
            compression_decision = choose_payload_compression(
                input_path=input_path,
                total_input_size=source_size,
                sample_bytes=first_chunk,
            )
        return _write_chunked_payload_to_writer(
            chunks=_file_chunks(source, first_chunk, chunk_size),
            total_input_size=source_size,
            target=target,
            aad=aad,
            encrypt_key=encrypt_key,
            compression_decision=compression_decision,
            chunk_size=chunk_size,
            progress_callback=progress_callback,
        )


def stream_file_to_payload(
    *,
    input_path: str,
    payload_path: str,
    aad: bytes,
    encrypt_key: bytes | None,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
    progress_callback=None,
    payload_format: str = "AVP",
) -> dict:
    """Write the primary AVP chunked payload by default, with AVP2 available for legacy tests."""
    normalized_format = (payload_format or "AVP").upper()
    if normalized_format == "AVP2":
        return _stream_file_to_payload_v2(
            input_path=input_path,
            payload_path=payload_path,
            aad=aad,
            encrypt_key=encrypt_key,
            chunk_size=chunk_size,
            progress_callback=progress_callback,
        )
    with open(payload_path, "w+b") as target:
        return stream_file_to_payload_writer(
            input_path=input_path,
            target=target,
            aad=aad,
            encrypt_key=encrypt_key,
            chunk_size=chunk_size,
            progress_callback=progress_callback,
            payload_format=normalized_format,
        )


def parse_payload_header(header_bytes: bytes) -> dict:
    if len(header_bytes) != PAYLOAD_HEADER_SIZE:
        raise ValueError("Payload header is truncated")

    magic, version, flags, _reserved, nonce, tag = PAYLOAD_HEADER_STRUCT.unpack(header_bytes)
    if magic not in {PAYLOAD_MAGIC_LEGACY, PAYLOAD_MAGIC}:
        raise ValueError("Unsupported payload format")
    if version != PAYLOAD_VERSION:
        raise ValueError("Unsupported payload version")
    is_primary_avp = magic == PAYLOAD_MAGIC
    if not is_primary_avp and not (flags & FLAG_COMPRESSED_ZLIB):
        raise ValueError("Payload compression flag is missing")

    encrypted = bool(flags & FLAG_ENCRYPTED_AESGCM)
    if encrypted and nonce == b"\x00" * GCM_NONCE_BYTES:
        raise ValueError("Encrypted payload nonce is invalid")
    if not encrypted and not is_primary_avp and tag != b"\x00" * GCM_TAG_BYTES:
        raise ValueError("Plaintext payload tag is invalid")

    return {
        "format": "AVP" if is_primary_avp else "AVP2",
        "flags": flags,
        "compressed": bool(flags & FLAG_COMPRESSED_ZLIB),
        "encrypted": encrypted,
        "nonce": nonce,
        "tag": tag,
    }


def _open_temp_file(output_path: str, *, prefix: str, suffix: str) -> tuple[BinaryIO, str]:
    handle = tempfile.NamedTemporaryFile(
        mode="w+b",
        delete=False,
        dir=os.path.dirname(output_path),
        prefix=prefix,
        suffix=suffix,
    )
    register_temp_artifact(handle.name)
    return handle, handle.name


def _decompress_stream_to_output_v2(
    *,
    source_stream: BinaryIO,
    output_path: str,
    decoder: PayloadStreamDecoder,
    expected_checksum: bytes,
    expected_output_size: int | None,
    max_output_size: int,
    total_payload_size: int | None,
    processed_bytes: int,
    chunk_size: int,
    progress_callback,
) -> dict:
    temp_handle = None
    temp_path = None

    try:
        temp_handle, temp_path = _open_temp_file(
            output_path,
            prefix=".avikal-dec-",
            suffix=".tmp",
        )

        while True:
            chunk = source_stream.read(chunk_size)
            if not chunk:
                break
            processed_bytes += len(chunk)
            decompressed_chunk = decoder.update(chunk)
            if decompressed_chunk:
                temp_handle.write(decompressed_chunk)
            if progress_callback:
                progress_callback(processed_bytes, total_payload_size)

        tail, checksum, original_size = decoder.finalize()
        if tail:
            temp_handle.write(tail)

        temp_handle.flush()
        temp_handle.close()
        temp_handle = None

        if expected_output_size is not None and original_size != expected_output_size:
            raise ValueError("Payload size verification failed. The archive may be corrupted.")
        if checksum != expected_checksum:
            raise ValueError("Payload checksum verification failed. The archive may be corrupted.")

        os.replace(temp_path, output_path)
        unregister_temp_artifact(temp_path)
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
                unregister_temp_artifact(temp_path)
            except OSError as exc:
                log.debug("Failed to remove payload temp file %s: %s", temp_path, exc)


def _stream_payload_chunked_to_file(
    *,
    payload_stream: BinaryIO,
    header_bytes: bytes,
    header: dict,
    output_path: str,
    aad: bytes,
    decrypt_key: bytes | None,
    expected_checksum: bytes,
    expected_output_size: int | None,
    max_output_size: int,
    chunk_size: int,
    progress_callback,
) -> dict:
    temp_handle = None
    temp_path = None
    checksum = hashlib.sha256()
    output_size = 0
    processed_bytes = PAYLOAD_HEADER_SIZE
    total_payload_size = getattr(payload_stream, "avikal_file_size", None)
    key = _validate_key(decrypt_key) if header["encrypted"] else None

    try:
        temp_handle, temp_path = _open_temp_file(
            output_path,
            prefix=".avikal-dec-",
            suffix=".tmp",
        )
        expected_index = 0
        while True:
            chunk_header = payload_stream.read(PAYLOAD_CHUNK_STRUCT.size)
            if chunk_header == b"":
                break
            if len(chunk_header) != PAYLOAD_CHUNK_STRUCT.size:
                raise ValueError("Payload chunk header is truncated")
            processed_bytes += len(chunk_header)
            chunk_index, original_len, data_len = PAYLOAD_CHUNK_STRUCT.unpack(chunk_header)
            if chunk_index != expected_index:
                raise ValueError("Payload chunk sequence is invalid")
            if original_len > MAX_AVP_CHUNK_BYTES:
                raise ValueError("Payload chunk size is out of bounds")
            if data_len <= 0 or data_len > MAX_AVP_CHUNK_BYTES + 1024 + GCM_TAG_BYTES:
                raise ValueError("Payload chunk data size is out of bounds")
            data = payload_stream.read(data_len)
            if len(data) != data_len:
                raise ValueError("Payload chunk data is truncated")
            processed_bytes += len(data)

            try:
                plaintext = avp_decode_chunk(
                    key,
                    header["nonce"],
                    bytes(aad),
                    header_bytes,
                    chunk_header,
                    data,
                    header["compressed"],
                )
            except Exception as exc:
                if "decompression" in str(exc).lower():
                    raise ValueError("Payload decompression failed. The archive may be corrupted.") from exc
                if key is not None:
                    raise ValueError(
                        "Payload authentication failed. The archive may be corrupted or the key is incorrect."
                    ) from exc
                raise ValueError("Payload chunk processing failed. The archive may be corrupted.") from exc
            if len(plaintext) != original_len:
                raise ValueError("Payload chunk size verification failed. The archive may be corrupted.")

            output_size += len(plaintext)
            if output_size > max_output_size:
                raise ValueError("Payload output size exceeds the safety limit")
            checksum.update(plaintext)
            if plaintext:
                temp_handle.write(plaintext)
            expected_index += 1
            if progress_callback:
                progress_callback(processed_bytes, total_payload_size)

        temp_handle.flush()
        temp_handle.close()
        temp_handle = None

        if expected_output_size is not None and output_size != expected_output_size:
            raise ValueError("Payload size verification failed. The archive may be corrupted.")
        if checksum.digest() != expected_checksum:
            raise ValueError("Payload checksum verification failed. The archive may be corrupted.")

        os.replace(temp_path, output_path)
        unregister_temp_artifact(temp_path)
        temp_path = None
        return {"output_path": output_path, "size": output_size}
    finally:
        if temp_handle is not None:
            try:
                temp_handle.close()
            except OSError as exc:
                log.debug("Failed to close AVP temp file handle for %s: %s", output_path, exc)
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                unregister_temp_artifact(temp_path)
            except OSError as exc:
                log.debug("Failed to remove AVP temp file %s: %s", temp_path, exc)


def iter_payload_plaintext_chunks(
    *,
    payload_stream: BinaryIO,
    aad: bytes,
    decrypt_key: bytes | None,
    expected_checksum: bytes,
    expected_output_size: int | None = None,
    max_output_size: int = DEFAULT_MAX_OUTPUT_BYTES,
    progress_callback=None,
) -> Iterable[bytes]:
    """Yield authenticated plaintext chunks from the primary AVP payload format."""
    if expected_output_size is not None and expected_output_size < 0:
        raise ValueError("Expected output size must be non-negative")
    if max_output_size <= 0:
        raise ValueError("Maximum output size must be positive")

    header_bytes = payload_stream.read(PAYLOAD_HEADER_SIZE)
    header = parse_payload_header(header_bytes)
    if header["format"] != "AVP":
        raise LegacyPayloadStreamingRequired("Legacy AVP2 payload requires materialized decode")
    if not header["encrypted"] and decrypt_key is not None:
        decrypt_key = None

    checksum = hashlib.sha256()
    output_size = 0
    processed_bytes = PAYLOAD_HEADER_SIZE
    total_payload_size = getattr(payload_stream, "avikal_file_size", None)
    key = _validate_key(decrypt_key) if header["encrypted"] else None
    expected_index = 0

    while True:
        chunk_header = payload_stream.read(PAYLOAD_CHUNK_STRUCT.size)
        if chunk_header == b"":
            break
        if len(chunk_header) != PAYLOAD_CHUNK_STRUCT.size:
            raise ValueError("Payload chunk header is truncated")
        processed_bytes += len(chunk_header)
        chunk_index, original_len, data_len = PAYLOAD_CHUNK_STRUCT.unpack(chunk_header)
        if chunk_index != expected_index:
            raise ValueError("Payload chunk sequence is invalid")
        if original_len > MAX_AVP_CHUNK_BYTES:
            raise ValueError("Payload chunk size is out of bounds")
        if data_len <= 0 or data_len > MAX_AVP_CHUNK_BYTES + 1024 + GCM_TAG_BYTES:
            raise ValueError("Payload chunk data size is out of bounds")
        data = payload_stream.read(data_len)
        if len(data) != data_len:
            raise ValueError("Payload chunk data is truncated")
        processed_bytes += len(data)

        try:
            plaintext = avp_decode_chunk(
                key,
                header["nonce"],
                bytes(aad),
                header_bytes,
                chunk_header,
                data,
                header["compressed"],
            )
        except Exception as exc:
            if "decompression" in str(exc).lower():
                raise ValueError("Payload decompression failed. The archive may be corrupted.") from exc
            if key is not None:
                raise ValueError(
                    "Payload authentication failed. The archive may be corrupted or the key is incorrect."
                ) from exc
            raise ValueError("Payload chunk processing failed. The archive may be corrupted.") from exc
        if len(plaintext) != original_len:
            raise ValueError("Payload chunk size verification failed. The archive may be corrupted.")

        output_size += len(plaintext)
        if output_size > max_output_size:
            raise ValueError("Payload output size exceeds the safety limit")
        checksum.update(plaintext)
        expected_index += 1
        if progress_callback:
            progress_callback(processed_bytes, total_payload_size)
        if plaintext:
            yield plaintext

    if expected_output_size is not None and output_size != expected_output_size:
        raise ValueError("Payload size verification failed. The archive may be corrupted.")
    if checksum.digest() != expected_checksum:
        raise ValueError("Payload checksum verification failed. The archive may be corrupted.")


def _stream_payload_v2_to_file(
    *,
    payload_stream: BinaryIO,
    header: dict,
    output_path: str,
    aad: bytes,
    decrypt_key: bytes | None,
    expected_checksum: bytes,
    expected_output_size: int | None,
    max_output_size: int,
    chunk_size: int,
    progress_callback,
) -> dict:
    total_payload_size = getattr(payload_stream, "avikal_file_size", None)
    processed_bytes = PAYLOAD_HEADER_SIZE

    if header["encrypted"]:
        ciphertext_handle, ciphertext_path = _open_temp_file(
            output_path,
            prefix=".avikal-cipher-",
            suffix=".enc",
        )
        try:
            progress_total = (total_payload_size * 2) if total_payload_size else None
            auth_verifier = PayloadCipherVerifier(
                _validate_key(decrypt_key),
                header["nonce"],
                header["tag"],
                bytes(aad),
            )
            while True:
                chunk = payload_stream.read(chunk_size)
                if not chunk:
                    break
                processed_bytes += len(chunk)
                ciphertext_handle.write(chunk)
                auth_verifier.update(chunk)
                if progress_callback:
                    progress_callback(processed_bytes, progress_total)

            try:
                auth_verifier.finalize()
            except Exception as exc:
                raise ValueError(
                    "Payload authentication failed. The archive may be corrupted or the key is incorrect."
                ) from exc

            ciphertext_handle.flush()
            ciphertext_handle.seek(0)
            decoder = PayloadStreamDecoder(
                _validate_key(decrypt_key),
                header["nonce"],
                header["tag"],
                bytes(aad),
                max_output_size=max_output_size,
            )

            return _decompress_stream_to_output_v2(
                source_stream=ciphertext_handle,
                output_path=output_path,
                decoder=decoder,
                expected_checksum=expected_checksum,
                expected_output_size=expected_output_size,
                max_output_size=max_output_size,
                total_payload_size=progress_total,
                processed_bytes=total_payload_size or PAYLOAD_HEADER_SIZE,
                chunk_size=chunk_size,
                progress_callback=progress_callback,
            )
        finally:
            if ciphertext_handle is not None:
                try:
                    ciphertext_handle.close()
                except OSError as exc:
                    log.debug("Failed to close encrypted payload buffer for %s: %s", output_path, exc)
            if os.path.exists(ciphertext_path):
                try:
                    os.remove(ciphertext_path)
                    unregister_temp_artifact(ciphertext_path)
                except OSError as exc:
                    log.debug("Failed to remove encrypted payload buffer %s: %s", ciphertext_path, exc)

    return _decompress_stream_to_output_v2(
        source_stream=payload_stream,
        output_path=output_path,
        decoder=PayloadStreamDecoder(
            None,
            None,
            None,
            b"",
            max_output_size=max_output_size,
        ),
        expected_checksum=expected_checksum,
        expected_output_size=expected_output_size,
        max_output_size=max_output_size,
        total_payload_size=total_payload_size,
        processed_bytes=processed_bytes,
        chunk_size=chunk_size,
        progress_callback=progress_callback,
    )


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
    """Decrypt/decompress a payload into a temp file and atomically commit it."""
    if expected_output_size is not None and expected_output_size < 0:
        raise ValueError("Expected output size must be non-negative")
    if max_output_size <= 0:
        raise ValueError("Maximum output size must be positive")

    header_bytes = payload_stream.read(PAYLOAD_HEADER_SIZE)
    header = parse_payload_header(header_bytes)
    total_payload_size = getattr(payload_stream, "avikal_file_size", None)
    processed_bytes = len(header_bytes)

    if not header["encrypted"]:
        if decrypt_key is not None:
            # Plaintext archives intentionally ignore any supplied key.
            decrypt_key = None

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if header["format"] == "AVP":
        return _stream_payload_chunked_to_file(
            payload_stream=payload_stream,
            header_bytes=header_bytes,
            header=header,
            output_path=output_path,
            aad=aad,
            decrypt_key=decrypt_key,
            expected_checksum=expected_checksum,
            expected_output_size=expected_output_size,
            max_output_size=max_output_size,
            chunk_size=chunk_size,
            progress_callback=progress_callback,
        )

    return _stream_payload_v2_to_file(
        payload_stream=payload_stream,
        header=header,
        output_path=output_path,
        aad=aad,
        decrypt_key=decrypt_key,
        expected_checksum=expected_checksum,
        expected_output_size=expected_output_size,
        max_output_size=max_output_size,
        chunk_size=chunk_size,
        progress_callback=progress_callback,
    )
