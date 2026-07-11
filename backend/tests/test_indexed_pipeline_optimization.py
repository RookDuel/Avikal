"""Focused regression tests for the bounded single-pass AVI1 writer."""

from __future__ import annotations

import builtins
import io
import os
from pathlib import Path

import pytest

from avikal_backend.archive.format import indexed_payload


class _CountingReader:
    def __init__(self, handle, counter: dict[str, int]):
        self._handle = handle
        self._counter = counter

    def read(self, size=-1):
        value = self._handle.read(size)
        self._counter["bytes"] += len(value)
        return value

    def __enter__(self):
        self._handle.__enter__()
        return self

    def __exit__(self, *args):
        return self._handle.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self._handle, name)


def _write(source: Path, *, chunk_size: int = 1024, progress_callback=None) -> dict:
    return indexed_payload.write_indexed_multifile_payload(
        entries=[(str(source), source.name)],
        explicit_directories=[],
        target=io.BytesIO(),
        payload_key=bytes(range(32)),
        archive_id=bytes(range(16)),
        header_aad=b"avikal-indexed-test",
        chunk_size=chunk_size,
        progress_callback=progress_callback,
    )


def test_indexed_writer_reads_sampled_source_exactly_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "random.dat"
    source.write_bytes(os.urandom(32 * 1024))
    monkeypatch.setattr(indexed_payload, "ADAPTIVE_COMPRESSION_MIN_BYTES", 4096)
    monkeypatch.setattr(indexed_payload, "ADAPTIVE_COMPRESSION_SAMPLE_BYTES", 2048)
    counter = {"bytes": 0}
    original_open = builtins.open

    def counting_open(path, mode="r", *args, **kwargs):
        handle = original_open(path, mode, *args, **kwargs)
        return _CountingReader(handle, counter) if os.fspath(path) == str(source) and mode == "rb" else handle

    monkeypatch.setattr(indexed_payload, "open", counting_open, raising=False)
    result = _write(source)

    assert counter["bytes"] == source.stat().st_size
    assert result["source_bytes_read"] == source.stat().st_size
    assert result["compression_reason"] == "sample"
    assert result["compression_enabled"] is False
    assert 1 <= result["worker_count"] <= 4
    assert result["queue_depth"] == result["worker_count"] + 1


def test_indexed_writer_skips_known_compressed_extension(tmp_path: Path):
    source = tmp_path / "already-compressed.zip"
    source.write_bytes(b"A" * 8192)
    result = _write(source)

    assert result["compression_reason"] == "extension"
    assert result["compression_enabled"] is False
    assert result["compressed_chunk_count"] == 0
    assert result["stored_plaintext_bytes"] == source.stat().st_size


def test_indexed_writer_rejects_source_metadata_change(tmp_path: Path):
    source = tmp_path / "moving.bin"
    source.write_bytes(os.urandom(64 * 1024))
    changed = False

    def progress(_processed: int, _total: int) -> None:
        nonlocal changed
        if not changed:
            changed = True
            current = source.stat()
            os.utime(source, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000_000))

    with pytest.raises(ValueError, match="changed during archive creation"):
        _write(source, chunk_size=4096, progress_callback=progress)


def test_payload_workers_throttle_slow_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AVIKAL_PAYLOAD_WORKERS", raising=False)
    assert indexed_payload._payload_worker_count("remote") == 1
    assert indexed_payload._payload_worker_count("removable") == 1
    assert indexed_payload._payload_worker_count("optical") == 1
