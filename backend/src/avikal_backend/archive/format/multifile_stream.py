"""Streaming multi-file payload container for primary AVP archives.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import BinaryIO, Iterable

from .manifest import build_archive_manifest, serialize_archive_manifest
from ..path_safety import normalize_multi_archive_relative_path, resolve_safe_relative_output_path


MULTIFILE_STREAM_MAGIC = b"AVM3"
_HEADER_STRUCT = struct.Struct(">4sI")
_ENTRY_STRUCT = struct.Struct(">HQ")
_IO_CHUNK_SIZE = 1024 * 1024


def scan_multifile_entries(entries: list[tuple[str, str]]) -> tuple[list[dict], int]:
    file_info: list[dict] = []
    total_original_size = 0
    for abs_path, arcname in entries:
        digest = hashlib.sha256()
        file_size = 0
        with open(abs_path, "rb") as handle:
            while True:
                chunk = handle.read(_IO_CHUNK_SIZE)
                if not chunk:
                    break
                file_size += len(chunk)
                digest.update(chunk)
        file_info.append(
            {
                "filename": arcname,
                "size": file_size,
                "checksum": digest.hexdigest(),
            }
        )
        total_original_size += file_size
    return file_info, total_original_size


def build_multifile_stream_manifest(file_info: list[dict], total_original_size: int) -> tuple[dict, bytes]:
    manifest = build_archive_manifest(file_info, total_original_size)
    return manifest, serialize_archive_manifest(manifest)


def multifile_stream_size(manifest_bytes: bytes, manifest: dict) -> int:
    size = _HEADER_STRUCT.size + len(manifest_bytes)
    for entry in manifest["files"]:
        path_bytes = entry["filename"].encode("utf-8")
        if len(path_bytes) > 0xFFFF:
            raise ValueError("Archive entry path is too long")
        size += _ENTRY_STRUCT.size + len(path_bytes) + int(entry["size"])
    return size


def iter_multifile_stream_chunks(
    entries: list[tuple[str, str]],
    manifest_bytes: bytes,
    *,
    read_chunk_size: int = _IO_CHUNK_SIZE,
) -> Iterable[bytes]:
    entry_by_name = {arcname: abs_path for abs_path, arcname in entries}
    parsed = json.loads(manifest_bytes.decode("utf-8"))
    manifest = build_archive_manifest(parsed["files"], parsed["total_original_size"])
    yield _HEADER_STRUCT.pack(MULTIFILE_STREAM_MAGIC, len(manifest_bytes))
    yield manifest_bytes
    for entry in manifest["files"]:
        arcname = entry["filename"]
        path_bytes = arcname.encode("utf-8")
        abs_path = entry_by_name.get(arcname)
        if abs_path is None:
            raise ValueError(f"Archive entry source is missing: {arcname}")
        yield _ENTRY_STRUCT.pack(len(path_bytes), int(entry["size"]))
        yield path_bytes
        with open(abs_path, "rb") as handle:
            while True:
                chunk = handle.read(read_chunk_size)
                if not chunk:
                    break
                yield chunk


def is_multifile_stream_container(handle: BinaryIO) -> bool:
    current = handle.tell()
    try:
        return handle.read(4) == MULTIFILE_STREAM_MAGIC
    finally:
        handle.seek(current)


def read_multifile_stream_manifest(handle: BinaryIO) -> tuple[dict, bytes]:
    header = handle.read(_HEADER_STRUCT.size)
    if len(header) != _HEADER_STRUCT.size:
        raise ValueError("Multi-file payload stream header is truncated")
    magic, manifest_len = _HEADER_STRUCT.unpack(header)
    if magic != MULTIFILE_STREAM_MAGIC:
        raise ValueError("Unsupported multi-file payload stream")
    if manifest_len <= 0 or manifest_len > 32 * 1024 * 1024:
        raise ValueError("Multi-file payload manifest size is out of bounds")
    manifest_bytes = handle.read(manifest_len)
    if len(manifest_bytes) != manifest_len:
        raise ValueError("Multi-file payload manifest is truncated")
    parsed = json.loads(manifest_bytes.decode("utf-8"))
    manifest = build_archive_manifest(parsed["files"], parsed["total_original_size"])
    return manifest, manifest_bytes


class _ChunkReader:
    def __init__(self, chunks: Iterable[bytes]):
        self._chunks = iter(chunks)
        self._buffer = bytearray()

    def _fill(self, minimum: int) -> None:
        while len(self._buffer) < minimum:
            try:
                chunk = next(self._chunks)
            except StopIteration:
                break
            if chunk:
                self._buffer.extend(chunk)

    def read_exact(self, size: int) -> bytes:
        if size < 0:
            raise ValueError("Read size must be non-negative")
        self._fill(size)
        if len(self._buffer) < size:
            raise ValueError("Multi-file payload stream is truncated")
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def read_at_most(self, size: int) -> bytes:
        if size <= 0:
            return b""
        self._fill(1)
        if not self._buffer:
            return b""
        take = min(size, len(self._buffer))
        data = bytes(self._buffer[:take])
        del self._buffer[:take]
        return data


def extract_multifile_stream_from_plaintext_chunks(
    chunks: Iterable[bytes],
    output_root: str,
    *,
    expected_manifest_hash: bytes,
    expected_entry_count: int,
    expected_total_size: int,
    progress_callback=None,
) -> list[dict]:
    """Extract AVM3 directly from authenticated payload plaintext chunks."""
    if not isinstance(expected_manifest_hash, (bytes, bytearray)) or len(expected_manifest_hash) != 32:
        raise ValueError("Archive metadata is missing a valid manifest hash")
    reader = _ChunkReader(chunks)
    header = reader.read_exact(_HEADER_STRUCT.size)
    magic, manifest_len = _HEADER_STRUCT.unpack(header)
    if magic != MULTIFILE_STREAM_MAGIC:
        raise ValueError("Unsupported multi-file payload stream")
    if manifest_len <= 0 or manifest_len > 32 * 1024 * 1024:
        raise ValueError("Multi-file payload manifest size is out of bounds")

    manifest_bytes = reader.read_exact(manifest_len)
    if hashlib.sha256(manifest_bytes).digest() != bytes(expected_manifest_hash):
        raise ValueError("Payload manifest verification failed. keychain.pgn does not match payload.enc.")
    parsed = json.loads(manifest_bytes.decode("utf-8"))
    manifest = build_archive_manifest(parsed["files"], parsed["total_original_size"])
    if manifest["file_count"] != expected_entry_count:
        raise ValueError("Payload manifest file count does not match keychain metadata")
    if manifest["total_original_size"] != expected_total_size:
        raise ValueError("Payload manifest size summary does not match keychain metadata")

    expected_by_name = {entry["filename"]: entry for entry in manifest["files"]}
    extracted_files: list[dict] = []
    total_verified_size = 0

    for index in range(manifest["file_count"]):
        if progress_callback:
            progress_callback(index, manifest["file_count"])
        entry_header = reader.read_exact(_ENTRY_STRUCT.size)
        path_len, file_size = _ENTRY_STRUCT.unpack(entry_header)
        if path_len <= 0:
            raise ValueError("Multi-file payload entry path is invalid")
        raw_path = reader.read_exact(path_len)
        arcname = raw_path.decode("utf-8")
        expected = expected_by_name.get(arcname)
        if expected is None:
            raise ValueError("Unexpected multi-file payload entry")
        if file_size != int(expected["size"]):
            raise ValueError(f"Manifest size mismatch for {arcname}")

        safe_relpath = normalize_multi_archive_relative_path(arcname)
        output_path = resolve_safe_relative_output_path(output_root, safe_relpath)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        remaining = file_size
        with open(output_path, "wb") as output:
            while remaining:
                chunk = reader.read_at_most(min(_IO_CHUNK_SIZE, remaining))
                if not chunk:
                    raise ValueError(f"Multi-file payload entry is truncated: {arcname}")
                remaining -= len(chunk)
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != expected["checksum"]:
            raise ValueError(f"Manifest checksum mismatch for {arcname}")
        total_verified_size += file_size
        extracted_files.append(
            {
                "filename": safe_relpath.replace("/", os.sep),
                "path": output_path,
                "size": file_size,
            }
        )

    if reader.read_at_most(1) != b"":
        raise ValueError("Multi-file payload stream contains trailing data")
    if total_verified_size != int(manifest["total_original_size"]):
        raise ValueError("Payload manifest total size verification failed")
    if progress_callback:
        progress_callback(manifest["file_count"], manifest["file_count"])
    return extracted_files


def extract_multifile_stream_container(
    container_path: str,
    output_root: str,
    manifest: dict,
) -> list[dict]:
    expected_by_name = {entry["filename"]: entry for entry in manifest["files"]}
    extracted_files: list[dict] = []
    total_verified_size = 0

    with open(container_path, "rb") as handle:
        parsed_manifest, _manifest_bytes = read_multifile_stream_manifest(handle)
        if parsed_manifest != manifest:
            raise ValueError("Payload stream manifest does not match metadata")

        for _ in range(manifest["file_count"]):
            entry_header = handle.read(_ENTRY_STRUCT.size)
            if len(entry_header) != _ENTRY_STRUCT.size:
                raise ValueError("Multi-file payload entry header is truncated")
            path_len, file_size = _ENTRY_STRUCT.unpack(entry_header)
            if path_len <= 0:
                raise ValueError("Multi-file payload entry path is invalid")
            raw_path = handle.read(path_len)
            if len(raw_path) != path_len:
                raise ValueError("Multi-file payload entry path is truncated")
            arcname = raw_path.decode("utf-8")
            expected = expected_by_name.get(arcname)
            if expected is None:
                raise ValueError("Unexpected multi-file payload entry")
            if file_size != int(expected["size"]):
                raise ValueError(f"Manifest size mismatch for {arcname}")

            safe_relpath = normalize_multi_archive_relative_path(arcname)
            output_path = resolve_safe_relative_output_path(output_root, safe_relpath)
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            remaining = file_size
            with open(output_path, "wb") as output:
                while remaining:
                    chunk = handle.read(min(_IO_CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError(f"Multi-file payload entry is truncated: {arcname}")
                    remaining -= len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != expected["checksum"]:
                raise ValueError(f"Manifest checksum mismatch for {arcname}")
            total_verified_size += file_size
            extracted_files.append(
                {
                    "filename": safe_relpath.replace("/", os.sep),
                    "path": output_path,
                    "size": file_size,
                }
            )

        if handle.read(1) != b"":
            raise ValueError("Multi-file payload stream contains trailing data")

    if total_verified_size != int(manifest["total_original_size"]):
        raise ValueError("Payload manifest total size verification failed")
    return extracted_files
