"""Authenticated random-access payload format for Avikal multi-file archives."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import struct
import tempfile
import time
import zlib
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

from avikal_backend.core.secure_delete import secure_remove_file

from ..compression_policy import (
    ADAPTIVE_COMPRESSION_MIN_BYTES,
    ADAPTIVE_COMPRESSION_SAMPLE_BYTES,
    choose_payload_compression,
)
from ..path_safety import normalize_multi_archive_relative_path, resolve_safe_relative_output_path
from ..security.native_bridge import aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256
from ..input_safety import assert_safe_input_file


INDEXED_PAYLOAD_MAGIC = b"AVI1"
INDEXED_PAYLOAD_VERSION = 1
INDEX_TRAILER_MAGIC = b"AVIX"
CHUNK_MAGIC = b"AVC1"
FLAG_ENCRYPTED = 0x01
FLAG_INDEX_ENCRYPTED = 0x01
FLAG_CHUNK_COMPRESSED = 0x01
HEADER_STRUCT = struct.Struct(">4sBBH16s")
CHUNK_STRUCT = struct.Struct(">4s16sQBII12s")
TRAILER_STRUCT = struct.Struct(">4sQIB3x12s32s32sQ")
DEFAULT_CHUNK_SIZE = 10 * 1024 * 1024
MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_ENTRY_COUNT = 2_000_000
MAX_DIRECTORY_DEPTH = 128
_HEX_32_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: dict) -> bytes:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not encoded or len(encoded) > MAX_INDEX_BYTES:
        raise ValueError("Authenticated content index size is out of bounds")
    return encoded


def _derive_keys(payload_key: bytes, archive_id: bytes) -> tuple[bytes, bytes]:
    if not isinstance(payload_key, (bytes, bytearray)) or len(payload_key) != 32:
        raise ValueError("Indexed payload encryption key must be 32 bytes")
    key = bytes(payload_key)
    return (
        hkdf_sha256(key, archive_id, b"avikal_indexed_payload_index_v1", length=32),
        hkdf_sha256(key, archive_id, b"avikal_indexed_payload_chunk_v1", length=32),
    )


def _merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"avikal-empty-payload-v1").digest()
    level = [hashlib.sha256(b"\x00" + bytes(leaf)).digest() for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"\x01" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0]


class _CountingWriter:
    def __init__(self, target: BinaryIO):
        self.target = target
        self.offset = 0
        self.digest = hashlib.sha256()

    def write(self, value: bytes) -> None:
        data = bytes(value)
        written = self.target.write(data)
        if written is not None and written != len(data):
            raise OSError("Short write while creating indexed payload")
        self.digest.update(data)
        self.offset += len(data)


@dataclass(frozen=True)
class _SourceSnapshot:
    size: int
    modified_ns: int
    device: int
    inode: int


@dataclass(frozen=True)
class _EncodedChunk:
    index: int
    original_length: int
    stored_plaintext_length: int
    compressed: bool
    record: bytes
    leaf: bytes
    compression_ms: float
    encryption_ms: float


def _snapshot_source(path: str) -> _SourceSnapshot:
    stat = assert_safe_input_file(path)
    return _SourceSnapshot(
        size=int(stat.st_size),
        modified_ns=int(stat.st_mtime_ns),
        device=int(stat.st_dev),
        inode=int(stat.st_ino),
    )


def _assert_source_unchanged(path: str, expected: _SourceSnapshot, archive_path: str) -> None:
    current = _snapshot_source(path)
    if current != expected:
        raise ValueError(f"Input file changed during archive creation: {archive_path}")


def _source_storage_profile(paths: Iterable[str]) -> str:
    resolved = [os.path.abspath(path) for path in paths]
    if not resolved:
        return "unknown"
    if os.name == "nt":
        try:
            import ctypes

            get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
            get_drive_type.argtypes = [ctypes.c_wchar_p]
            get_drive_type.restype = ctypes.c_uint
            drive_types = set()
            for path in resolved:
                drive, _tail = os.path.splitdrive(path)
                if drive:
                    drive_types.add(int(get_drive_type(drive + "\\")))
            if 4 in drive_types:
                return "remote"
            if 2 in drive_types:
                return "removable"
            if 5 in drive_types:
                return "optical"
            if drive_types == {3}:
                return "local_fixed"
        except (AttributeError, OSError, ValueError):
            return "unknown"
        return "unknown"

    mounts_path = Path("/proc/mounts")
    if mounts_path.is_file():
        try:
            network_types = {"9p", "cifs", "fuse.sshfs", "nfs", "nfs4", "smbfs", "sshfs"}
            mounts: list[tuple[str, str]] = []
            for line in mounts_path.read_text(encoding="utf-8", errors="replace").splitlines():
                fields = line.split()
                if len(fields) >= 3:
                    mounts.append((fields[1].replace("\\040", " "), fields[2]))
            for path in resolved:
                matching = [item for item in mounts if path == item[0] or path.startswith(item[0].rstrip("/") + "/")]
                if matching and max(matching, key=lambda item: len(item[0]))[1] in network_types:
                    return "remote"
            return "local_or_unknown"
        except OSError:
            pass
    return "unknown"


def _payload_worker_count(storage_profile: str) -> int:
    configured = os.getenv("AVIKAL_PAYLOAD_WORKERS")
    if configured:
        try:
            return max(1, min(4, int(configured)))
        except ValueError as exc:
            raise ValueError("AVIKAL_PAYLOAD_WORKERS must be an integer between 1 and 4") from exc

    if storage_profile in {"remote", "removable", "optical"}:
        return 1

    cpu_count = os.cpu_count() or 1
    workers = 1 if cpu_count <= 2 else min(3, max(1, cpu_count // 2))
    try:
        import psutil

        available = int(psutil.virtual_memory().available)
        if available < 1024 * 1024 * 1024:
            return 1
        if available < 2 * 1024 * 1024 * 1024:
            workers = min(workers, 2)
    except Exception:
        pass
    return workers


def _iter_source_chunks(source: BinaryIO, prefix: bytes, chunk_size: int) -> Iterable[bytes]:
    pending = bytearray(prefix)
    reached_eof = False
    while True:
        while len(pending) < chunk_size:
            part = source.read(chunk_size - len(pending))
            if not part:
                reached_eof = True
                break
            pending.extend(part)
        if pending:
            yield bytes(pending)
            pending.clear()
        if reached_eof:
            break


def _encode_payload_chunk(
    *,
    plaintext: bytes,
    chunk_index: int,
    file_id: bytes,
    encrypted: bool,
    data_key: bytes | None,
    archive_aad: bytes,
    payload_header: bytes,
    compression_allowed: bool,
) -> _EncodedChunk:
    compression_started = time.perf_counter()
    stored_plaintext = plaintext
    compressed = False
    if compression_allowed:
        candidate = zlib.compress(plaintext, level=1)
        if len(candidate) <= int(len(plaintext) * 0.97):
            stored_plaintext = candidate
            compressed = True
    compression_ms = (time.perf_counter() - compression_started) * 1000

    nonce = secrets.token_bytes(12) if encrypted else b"\x00" * 12
    data_len = len(stored_plaintext) + (16 if encrypted else 0)
    chunk_header = CHUNK_STRUCT.pack(
        CHUNK_MAGIC,
        file_id,
        chunk_index,
        FLAG_CHUNK_COMPRESSED if compressed else 0,
        len(plaintext),
        data_len,
        nonce,
    )
    encryption_started = time.perf_counter()
    ciphertext = (
        aes256gcm_encrypt(data_key, nonce, stored_plaintext, archive_aad + payload_header + chunk_header)
        if encrypted
        else stored_plaintext
    )
    encryption_ms = (time.perf_counter() - encryption_started) * 1000
    if len(ciphertext) != data_len:
        raise ValueError("Indexed payload chunk length is inconsistent")
    record = chunk_header + ciphertext
    return _EncodedChunk(
        index=chunk_index,
        original_length=len(plaintext),
        stored_plaintext_length=len(stored_plaintext),
        compressed=compressed,
        record=record,
        leaf=hashlib.sha256(record).digest(),
        compression_ms=compression_ms,
        encryption_ms=encryption_ms,
    )


def _directory_records(paths: Iterable[str]) -> list[dict]:
    directories: set[str] = set()
    for raw_path in paths:
        normalized = normalize_multi_archive_relative_path(raw_path)
        parts = normalized.split("/")
        if len(parts) > MAX_DIRECTORY_DEPTH:
            raise ValueError("Archive directory depth exceeds the supported limit")
        for end in range(1, len(parts) + 1):
            directories.add("/".join(parts[:end]))
    return [
        {
            "id": hashlib.sha256(b"dir\x00" + path.encode("utf-8")).hexdigest()[:32],
            "path": path,
            "type": "directory",
        }
        for path in sorted(directories)
    ]


def write_indexed_multifile_payload(
    *,
    entries: list[tuple[str, str]],
    explicit_directories: list[str],
    target: BinaryIO,
    payload_key: bytes | None,
    archive_id: bytes,
    header_aad: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback=None,
) -> dict:
    """Stream independently authenticated file chunks followed by an encrypted index."""
    if not isinstance(archive_id, (bytes, bytearray)) or len(archive_id) != 16:
        raise ValueError("Indexed payload archive ID must be 16 bytes")
    if chunk_size <= 0 or chunk_size > 64 * 1024 * 1024:
        raise ValueError("Indexed payload chunk size is invalid")
    if len(entries) > MAX_ENTRY_COUNT:
        raise ValueError("Archive contains too many entries")

    encrypted = payload_key is not None
    index_key = data_key = None
    if encrypted:
        index_key, data_key = _derive_keys(bytes(payload_key), bytes(archive_id))
    header = HEADER_STRUCT.pack(
        INDEXED_PAYLOAD_MAGIC,
        INDEXED_PAYLOAD_VERSION,
        FLAG_ENCRYPTED if encrypted else 0,
        HEADER_STRUCT.size,
        bytes(archive_id),
    )
    snapshots = {path: _snapshot_source(path) for path, _ in entries}
    total_source_size = sum(snapshots[path].size for path, _archive_path in entries)
    writer = _CountingWriter(target)
    writer.write(header)
    processed = 0
    global_chunk_index = 0
    leaves: list[bytes] = []
    files: list[dict] = []
    storage_profile = _source_storage_profile(path for path, _archive_path in entries)
    worker_count = _payload_worker_count(storage_profile)
    queue_depth = worker_count + 1
    compression_ms = 0.0
    encryption_ms = 0.0
    stored_plaintext_bytes = 0
    compressed_chunk_count = 0
    compression_decisions: list[dict] = []

    from ..pipeline.progress import check_cancelled

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="avikal-payload") as executor:
        for source_path, raw_archive_path in entries:
            check_cancelled()
            archive_path = normalize_multi_archive_relative_path(raw_archive_path)
            file_id = hashlib.sha256(b"file\x00" + archive_path.encode("utf-8")).digest()[:16]
            snapshot = snapshots[source_path]
            file_digest = hashlib.sha256()
            file_size = 0
            chunks: list[dict] = []
            pending: deque[Future[_EncodedChunk]] = deque()

            def commit_next() -> None:
                nonlocal processed, compression_ms, encryption_ms, stored_plaintext_bytes, compressed_chunk_count
                check_cancelled()
                encoded = pending.popleft().result()
                record_offset = writer.offset
                writer.write(encoded.record)
                leaves.append(encoded.leaf)
                chunks.append(
                    {
                        "index": encoded.index,
                        "offset": record_offset,
                        "record_length": len(encoded.record),
                        "original_length": encoded.original_length,
                        "leaf_sha256": encoded.leaf.hex(),
                    }
                )
                processed += encoded.original_length
                compression_ms += encoded.compression_ms
                encryption_ms += encoded.encryption_ms
                stored_plaintext_bytes += encoded.stored_plaintext_length
                compressed_chunk_count += int(encoded.compressed)
                if progress_callback:
                    progress_callback(processed, total_source_size)

            with open(source_path, "rb") as source:
                initial_decision = choose_payload_compression(
                    input_path=source_path,
                    total_input_size=snapshot.size,
                    minimum_input_bytes=ADAPTIVE_COMPRESSION_MIN_BYTES,
                )
                prefix = b""
                if initial_decision["reason"] == "default" and snapshot.size >= ADAPTIVE_COMPRESSION_MIN_BYTES:
                    prefix = source.read(min(ADAPTIVE_COMPRESSION_SAMPLE_BYTES, snapshot.size))
                    decision = choose_payload_compression(
                        input_path=source_path,
                        total_input_size=snapshot.size,
                        sample_bytes=prefix,
                        minimum_input_bytes=ADAPTIVE_COMPRESSION_MIN_BYTES,
                    )
                else:
                    decision = initial_decision
                compression_decisions.append({"path": archive_path, **decision})

                for plaintext in _iter_source_chunks(source, prefix, chunk_size):
                    check_cancelled()
                    file_digest.update(plaintext)
                    file_size += len(plaintext)
                    pending.append(
                        executor.submit(
                            _encode_payload_chunk,
                            plaintext=plaintext,
                            chunk_index=global_chunk_index,
                            file_id=file_id,
                            encrypted=encrypted,
                            data_key=data_key,
                            archive_aad=bytes(header_aad),
                            payload_header=header,
                            compression_allowed=bool(decision["enabled"]),
                        )
                    )
                    global_chunk_index += 1
                    if len(pending) >= queue_depth:
                        commit_next()
                while pending:
                    commit_next()

            if file_size != snapshot.size:
                raise ValueError(f"Input file changed during archive creation: {archive_path}")
            _assert_source_unchanged(source_path, snapshot, archive_path)
            files.append(
                {
                    "id": file_id.hex(),
                    "path": archive_path,
                    "type": "file",
                    "size": file_size,
                    "sha256": file_digest.hexdigest(),
                    "chunks": chunks,
                }
            )

    directory_paths = set(explicit_directories)
    for file_entry in files:
        parts = file_entry["path"].split("/")[:-1]
        for end in range(1, len(parts) + 1):
            directory_paths.add("/".join(parts[:end]))
    directories = _directory_records(directory_paths)
    index_document = {
        "archive_id": bytes(archive_id).hex(),
        "directories": directories,
        "file_count": len(files),
        "files": files,
        "folder_count": len(directories),
        "format": "avikal-indexed-payload",
        "total_original_size": sum(item["size"] for item in files),
        "version": INDEXED_PAYLOAD_VERSION,
    }
    index_plaintext = _canonical_json(index_document)
    index_nonce = secrets.token_bytes(12) if encrypted else b"\x00" * 12
    index_aad = bytes(header_aad) + header + b"avikal-index-v1"
    index_ciphertext = (
        aes256gcm_encrypt(index_key, index_nonce, index_plaintext, index_aad)
        if encrypted
        else index_plaintext
    )
    index_offset = writer.offset
    writer.write(index_ciphertext)
    index_hash = hashlib.sha256(index_ciphertext).digest()
    merkle_root = _merkle_root(leaves)
    trailer = TRAILER_STRUCT.pack(
        INDEX_TRAILER_MAGIC,
        index_offset,
        len(index_ciphertext),
        FLAG_INDEX_ENCRYPTED if encrypted else 0,
        index_nonce,
        index_hash,
        merkle_root,
        global_chunk_index,
    )
    writer.write(trailer)
    if progress_callback:
        progress_callback(total_source_size, total_source_size)
    decision_reasons = sorted({str(item["reason"]) for item in compression_decisions})
    sample_ratios = [float(item["sample_ratio"]) for item in compression_decisions if item.get("sample_ratio") is not None]
    return {
        "format": "AVI1",
        "archive_id": bytes(archive_id),
        "payload_size": writer.offset,
        "payload_sha256": writer.digest.hexdigest(),
        "index_hash": index_hash,
        "manifest_hash": hashlib.sha256(index_plaintext).digest(),
        "merkle_root": merkle_root,
        "file_count": len(files),
        "folder_count": len(directories),
        "total_original_size": total_source_size,
        "chunk_count": global_chunk_index,
        "index_bytes": len(index_ciphertext),
        "files": files,
        "directories": directories,
        "source_bytes_read": total_source_size,
        "payload_bytes_written": writer.offset,
        "stored_plaintext_bytes": stored_plaintext_bytes,
        "compression_enabled": compressed_chunk_count > 0,
        "compression_reason": decision_reasons[0] if len(decision_reasons) == 1 else "mixed",
        "compression_decisions": compression_decisions,
        "compression_sample_ratio": (sum(sample_ratios) / len(sample_ratios)) if sample_ratios else None,
        "compressed_chunk_count": compressed_chunk_count,
        "compression_ms": compression_ms,
        "encryption_ms": encryption_ms,
        "worker_count": worker_count,
        "queue_depth": queue_depth,
        "source_storage_profile": storage_profile,
        "chunk_size": chunk_size,
        "compressed_size": writer.offset,
        "checksum": hashlib.sha256(index_plaintext).digest(),
    }


def is_indexed_payload(handle: BinaryIO) -> bool:
    current = handle.tell()
    try:
        handle.seek(0)
        return handle.read(4) == INDEXED_PAYLOAD_MAGIC
    finally:
        handle.seek(current)


def read_indexed_payload_index(
    handle: BinaryIO,
    *,
    payload_key: bytes | None,
    header_aad: bytes,
    expected_index_hash: bytes | None = None,
    expected_merkle_root: bytes | None = None,
) -> tuple[dict, dict]:
    """Authenticate and decode only the trailing content index."""
    handle.seek(0)
    header = handle.read(HEADER_STRUCT.size)
    if len(header) != HEADER_STRUCT.size:
        raise ValueError("Indexed payload header is truncated")
    magic, version, flags, header_size, archive_id = HEADER_STRUCT.unpack(header)
    if magic != INDEXED_PAYLOAD_MAGIC or version != INDEXED_PAYLOAD_VERSION or header_size != HEADER_STRUCT.size:
        raise ValueError("Unsupported indexed payload format")
    if flags & ~FLAG_ENCRYPTED:
        raise ValueError("Indexed payload header contains unsupported flags")
    handle.seek(0, os.SEEK_END)
    payload_size = handle.tell()
    if payload_size < HEADER_STRUCT.size + TRAILER_STRUCT.size:
        raise ValueError("Indexed payload is truncated")
    handle.seek(payload_size - TRAILER_STRUCT.size)
    trailer_bytes = handle.read(TRAILER_STRUCT.size)
    trailer = TRAILER_STRUCT.unpack(trailer_bytes)
    trailer_magic, index_offset, index_length, index_flags, index_nonce, index_hash, merkle_root, chunk_count = trailer
    if trailer_magic != INDEX_TRAILER_MAGIC:
        raise ValueError("Indexed payload trailer is missing")
    if index_flags & ~FLAG_INDEX_ENCRYPTED:
        raise ValueError("Indexed payload index contains unsupported flags")
    if index_length <= 0 or index_length > MAX_INDEX_BYTES + 16:
        raise ValueError("Indexed payload index size is out of bounds")
    if index_offset < HEADER_STRUCT.size or index_offset + index_length != payload_size - TRAILER_STRUCT.size:
        raise ValueError("Indexed payload index offset is invalid")
    if expected_index_hash is not None and bytes(expected_index_hash) != index_hash:
        raise ValueError("Indexed payload does not match keychain metadata")
    if expected_merkle_root is not None and bytes(expected_merkle_root) != merkle_root:
        raise ValueError("Payload Merkle root does not match keychain metadata")
    handle.seek(index_offset)
    index_ciphertext = handle.read(index_length)
    if len(index_ciphertext) != index_length or hashlib.sha256(index_ciphertext).digest() != index_hash:
        raise ValueError("Indexed payload index integrity verification failed")
    encrypted = bool(index_flags & FLAG_INDEX_ENCRYPTED)
    if encrypted != bool(flags & FLAG_ENCRYPTED):
        raise ValueError("Indexed payload encryption flags are inconsistent")
    if encrypted:
        index_key, _data_key = _derive_keys(payload_key, archive_id)
        index_plaintext = aes256gcm_decrypt(
            index_key,
            index_nonce,
            index_ciphertext,
            bytes(header_aad) + header + b"avikal-index-v1",
        )
    else:
        index_plaintext = index_ciphertext
    try:
        document = json.loads(index_plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Authenticated content index is malformed") from exc
    if _canonical_json(document) != index_plaintext:
        raise ValueError("Authenticated content index is not canonical")
    _validate_index(document, payload_size, index_offset, chunk_count, merkle_root, archive_id)
    return document, {
        "payload_size": payload_size,
        "index_bytes": index_length,
        "index_hash": index_hash,
        "manifest_hash": hashlib.sha256(index_plaintext).digest(),
        "merkle_root": merkle_root,
        "chunk_count": chunk_count,
        "archive_id": archive_id,
        "encrypted": encrypted,
    }


def _validate_index(
    document: dict,
    payload_size: int,
    index_offset: int,
    chunk_count: int,
    merkle_root: bytes,
    archive_id: bytes,
) -> None:
    if not isinstance(document, dict) or document.get("format") != "avikal-indexed-payload" or document.get("version") != 1:
        raise ValueError("Unsupported authenticated content index")
    files = document.get("files")
    directories = document.get("directories")
    if not isinstance(files, list) or not isinstance(directories, list):
        raise ValueError("Authenticated content index entries are invalid")
    if len(files) != document.get("file_count") or len(directories) != document.get("folder_count"):
        raise ValueError("Authenticated content index counts are inconsistent")
    if len(files) + len(directories) > MAX_ENTRY_COUNT:
        raise ValueError("Authenticated content index contains too many entries")
    if document.get("archive_id") != archive_id.hex():
        raise ValueError("Authenticated content index archive identifier is invalid")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    leaves: list[bytes] = []
    total_size = 0
    expected_chunk_index = 0
    expected_record_offset = HEADER_STRUCT.size
    for directory in directories:
        _validate_entry_identity(directory, "directory", seen_ids, seen_paths)
    for file_entry in files:
        _validate_entry_identity(file_entry, "file", seen_ids, seen_paths)
        size = file_entry.get("size")
        digest = file_entry.get("sha256")
        chunks = file_entry.get("chunks")
        if not isinstance(size, int) or size < 0 or not isinstance(digest, str) or _HEX_64_PATTERN.fullmatch(digest) is None:
            raise ValueError("Authenticated file entry is invalid")
        if not isinstance(chunks, list):
            raise ValueError("Authenticated file chunks are invalid")
        chunk_total = 0
        for chunk in chunks:
            if chunk.get("index") != expected_chunk_index:
                raise ValueError("Authenticated chunk ordering is invalid")
            offset = chunk.get("offset")
            record_length = chunk.get("record_length")
            original_length = chunk.get("original_length")
            leaf_hex = chunk.get("leaf_sha256")
            if not all(isinstance(value, int) for value in (offset, record_length, original_length)):
                raise ValueError("Authenticated chunk bounds are invalid")
            if offset != expected_record_offset or record_length <= CHUNK_STRUCT.size or offset + record_length > index_offset:
                raise ValueError("Authenticated chunk escapes the payload data region")
            if not isinstance(original_length, int) or original_length <= 0 or original_length > 64 * 1024 * 1024:
                raise ValueError("Authenticated chunk plaintext size is invalid")
            if not isinstance(leaf_hex, str) or _HEX_64_PATTERN.fullmatch(leaf_hex) is None:
                raise ValueError("Authenticated chunk digest is invalid")
            leaves.append(bytes.fromhex(leaf_hex))
            chunk_total += original_length
            expected_record_offset += record_length
            expected_chunk_index += 1
        if chunk_total != size:
            raise ValueError("Authenticated file size does not match its chunks")
        total_size += size
    if expected_record_offset != index_offset:
        raise ValueError("Authenticated chunk records do not cover the payload data region")
    if expected_chunk_index != chunk_count or _merkle_root(leaves) != merkle_root:
        raise ValueError("Authenticated payload Merkle verification failed")
    if total_size != document.get("total_original_size"):
        raise ValueError("Authenticated content index total size is invalid")


def _validate_entry_identity(entry: dict, expected_type: str, seen_ids: set[str], seen_paths: set[str]) -> None:
    if not isinstance(entry, dict) or entry.get("type") != expected_type:
        raise ValueError("Authenticated content index entry type is invalid")
    entry_id = entry.get("id")
    path = normalize_multi_archive_relative_path(entry.get("path", ""))
    if not isinstance(entry_id, str) or _HEX_32_PATTERN.fullmatch(entry_id) is None or entry_id in seen_ids or path in seen_paths:
        raise ValueError("Authenticated content index contains duplicate entries")
    seen_ids.add(entry_id)
    seen_paths.add(path)


def extract_indexed_selection(
    handle: BinaryIO,
    *,
    index: dict,
    selected_entry_ids: list[str],
    output_root: str,
    payload_key: bytes | None,
    header_aad: bytes,
    verify_only: bool = False,
    progress_callback=None,
) -> list[dict]:
    """Seek directly to authenticated chunks for selected files and folders."""
    from ..pipeline.progress import check_cancelled

    check_cancelled()
    selected = list(dict.fromkeys(selected_entry_ids))
    if not selected:
        raise ValueError("At least one archive entry must be selected")
    files_by_id = {item["id"]: item for item in index["files"]}
    directories_by_id = {item["id"]: item for item in index["directories"]}
    known_ids = set(files_by_id) | set(directories_by_id)
    if any(entry_id not in known_ids for entry_id in selected):
        raise ValueError("Selected archive entry is not present in the authenticated index")
    selected_files: dict[str, dict] = {}
    selected_directory_paths = [directories_by_id[item]["path"] for item in selected if item in directories_by_id]
    for entry_id in selected:
        if entry_id in files_by_id:
            path = files_by_id[entry_id]["path"]
            if any(path.startswith(directory + "/") for directory in selected_directory_paths):
                raise ValueError("Selection contains both a folder and one of its descendants")
            selected_files[entry_id] = files_by_id[entry_id]
    for directory in selected_directory_paths:
        for entry_id, file_entry in files_by_id.items():
            if file_entry["path"].startswith(directory + "/"):
                selected_files[entry_id] = file_entry

    handle.seek(0)
    header = handle.read(HEADER_STRUCT.size)
    _magic, _version, flags, _header_size, archive_id = HEADER_STRUCT.unpack(header)
    encrypted = bool(flags & FLAG_ENCRYPTED)
    data_key = None
    if encrypted:
        _index_key, data_key = _derive_keys(payload_key, archive_id)
    output_path_root = Path(output_root).resolve()
    output_path_root.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    total_files = len(selected_files)

    for file_number, file_entry in enumerate(sorted(selected_files.values(), key=lambda item: item["path"])):
        check_cancelled()
        safe_path = normalize_multi_archive_relative_path(file_entry["path"])
        output_path = resolve_safe_relative_output_path(str(output_path_root), safe_path)
        temporary_path = None
        digest = hashlib.sha256()
        written = 0
        output = None
        try:
            if not verify_only:
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                descriptor, temporary_path = tempfile.mkstemp(prefix=".avikal-selected-", dir=str(Path(output_path).parent))
                output = os.fdopen(descriptor, "wb")
            for chunk in file_entry["chunks"]:
                check_cancelled()
                handle.seek(chunk["offset"])
                record = handle.read(chunk["record_length"])
                if len(record) != chunk["record_length"] or hashlib.sha256(record).hexdigest() != chunk["leaf_sha256"]:
                    raise ValueError(f"Authenticated chunk verification failed for {safe_path}")
                chunk_header = record[:CHUNK_STRUCT.size]
                ciphertext = record[CHUNK_STRUCT.size:]
                magic, file_id, chunk_index, chunk_flags, original_len, data_len, nonce = CHUNK_STRUCT.unpack(chunk_header)
                if magic != CHUNK_MAGIC or file_id.hex() != file_entry["id"] or chunk_index != chunk["index"] or data_len != len(ciphertext):
                    raise ValueError(f"Authenticated chunk metadata is invalid for {safe_path}")
                if chunk_flags & ~FLAG_CHUNK_COMPRESSED:
                    raise ValueError(f"Authenticated chunk flags are invalid for {safe_path}")
                if original_len != chunk["original_length"] or original_len <= 0 or original_len > 64 * 1024 * 1024:
                    raise ValueError(f"Authenticated chunk size is invalid for {safe_path}")
                stored = (
                    aes256gcm_decrypt(data_key, nonce, ciphertext, bytes(header_aad) + header + chunk_header)
                    if encrypted
                    else ciphertext
                )
                plaintext = _bounded_decompress(stored, original_len) if chunk_flags & FLAG_CHUNK_COMPRESSED else stored
                if len(plaintext) != original_len:
                    raise ValueError(f"Authenticated chunk size is invalid for {safe_path}")
                digest.update(plaintext)
                written += len(plaintext)
                if output is not None:
                    output.write(plaintext)
            if output is not None:
                output.flush()
                os.fsync(output.fileno())
                output.close()
                output = None
            if written != file_entry["size"] or digest.hexdigest() != file_entry["sha256"]:
                raise ValueError(f"Selected file verification failed for {safe_path}")
            if temporary_path is not None:
                if os.path.exists(output_path):
                    raise ValueError(f"Refusing to overwrite existing preview file: {safe_path}")
                os.replace(temporary_path, output_path)
                temporary_path = None
            results.append({
                "id": file_entry["id"],
                "type": "file",
                "filename": safe_path.replace("/", os.sep),
                "path": output_path if not verify_only else None,
                "size": written,
                "sha256": digest.hexdigest(),
                "chunks_verified": len(file_entry["chunks"]),
                "verification": "verified",
            })
            if progress_callback:
                progress_callback(file_number + 1, total_files)
        finally:
            if output is not None:
                output.close()
            if temporary_path and os.path.exists(temporary_path):
                secure_remove_file(temporary_path)

    if not verify_only:
        selected_directories = [
            item
            for item in index["directories"]
            if any(item["path"] == selected or item["path"].startswith(selected + "/") for selected in selected_directory_paths)
        ]
        for directory in sorted(selected_directories, key=lambda item: item["path"]):
            output_path = resolve_safe_relative_output_path(str(output_path_root), directory["path"])
            Path(output_path).mkdir(parents=True, exist_ok=True)
            results.append({
                "id": directory["id"],
                "type": "directory",
                "filename": directory["path"].replace("/", os.sep),
                "path": output_path,
                "size": 0,
                "verification": "authenticated_index",
            })
    return results


def _bounded_decompress(value: bytes, expected_length: int) -> bytes:
    decoder = zlib.decompressobj()
    plaintext = decoder.decompress(value, expected_length + 1)
    if len(plaintext) > expected_length or decoder.unconsumed_tail:
        raise ValueError("Authenticated chunk decompression limit exceeded")
    plaintext += decoder.flush()
    if len(plaintext) != expected_length or not decoder.eof or decoder.unused_data:
        raise ValueError("Authenticated chunk compression stream is invalid")
    return plaintext
