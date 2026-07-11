"""
Regression tests for the native-backed payload streaming path.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from avikal_backend.archive.pipeline import encoder as encoder_module
from avikal_backend.archive.pipeline import payload_streaming as payload_streaming_module
from avikal_backend.archive.pipeline.payload_streaming import (
    PAYLOAD_HEADER_SIZE,
    parse_payload_header,
    stream_file_to_payload,
    stream_payload_to_file,
)
from avikal_backend.archive.security.native_bridge import sha256_digest


def _write_sample_file(path: Path) -> bytes:
    data = (b"Avikal payload streaming regression data.\n" * 4096) + bytes(range(256)) * 32
    path.write_bytes(data)
    return data


def test_payload_streaming_roundtrip_encrypted(tmp_path: Path) -> None:
    source_path = tmp_path / "source.bin"
    payload_path = tmp_path / "payload.enc"
    output_path = tmp_path / "output.bin"
    expected = _write_sample_file(source_path)
    key = bytes(range(32))
    aad = b"avikal-native-payload"

    details = stream_file_to_payload(
        input_path=str(source_path),
        payload_path=str(payload_path),
        aad=aad,
        encrypt_key=key,
        chunk_size=137,
    )

    with payload_path.open("rb") as handle:
        header = parse_payload_header(handle.read(PAYLOAD_HEADER_SIZE))
        assert header["format"] == "AVP"
        assert header["encrypted"] is True
        handle.seek(0)
        stream_payload_to_file(
            payload_stream=handle,
            output_path=str(output_path),
            aad=aad,
            decrypt_key=key,
            expected_checksum=details["checksum"],
            expected_output_size=len(expected),
            chunk_size=113,
        )

    assert output_path.read_bytes() == expected


def test_payload_streaming_roundtrip_plaintext(tmp_path: Path) -> None:
    source_path = tmp_path / "source.bin"
    payload_path = tmp_path / "payload.enc"
    output_path = tmp_path / "output.bin"
    expected = _write_sample_file(source_path)

    details = stream_file_to_payload(
        input_path=str(source_path),
        payload_path=str(payload_path),
        aad=b"avikal-native-payload",
        encrypt_key=None,
        chunk_size=257,
    )

    with payload_path.open("rb") as handle:
        header = parse_payload_header(handle.read(PAYLOAD_HEADER_SIZE))
        assert header["format"] == "AVP"
        assert header["encrypted"] is False
        handle.seek(0)
        stream_payload_to_file(
            payload_stream=handle,
            output_path=str(output_path),
            aad=b"ignored-for-plaintext",
            decrypt_key=None,
            expected_checksum=details["checksum"],
            expected_output_size=len(expected),
            chunk_size=89,
        )

    assert output_path.read_bytes() == expected


def test_adaptive_compression_skips_known_compressed_extension(tmp_path: Path) -> None:
    source_path = tmp_path / "installer.exe"
    payload_path = tmp_path / "payload.enc"
    source_path.write_bytes(b"A" * 8192)

    details = stream_file_to_payload(
        input_path=str(source_path),
        payload_path=str(payload_path),
        aad=b"avikal-native-payload",
        encrypt_key=None,
        chunk_size=1024,
    )

    assert details["compression_enabled"] is False
    assert details["compression_reason"] == "extension"


def test_adaptive_compression_samples_large_incompressible_payload(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(payload_streaming_module, "ADAPTIVE_COMPRESSION_MIN_BYTES", 1024)
    monkeypatch.setattr(payload_streaming_module, "ADAPTIVE_COMPRESSION_SAMPLE_BYTES", 2048)
    source_path = tmp_path / "random.dat"
    payload_path = tmp_path / "payload.enc"
    source_path.write_bytes(os.urandom(8192))

    details = stream_file_to_payload(
        input_path=str(source_path),
        payload_path=str(payload_path),
        aad=b"avikal-native-payload",
        encrypt_key=None,
        chunk_size=1024,
    )

    assert details["compression_enabled"] is False
    assert details["compression_reason"] == "sample"
    assert details["compression_sample_ratio"] is not None


def test_adaptive_compression_keeps_large_compressible_payload(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(payload_streaming_module, "ADAPTIVE_COMPRESSION_MIN_BYTES", 1024)
    monkeypatch.setattr(payload_streaming_module, "ADAPTIVE_COMPRESSION_SAMPLE_BYTES", 2048)
    source_path = tmp_path / "notes.dat"
    payload_path = tmp_path / "payload.enc"
    source_path.write_bytes(b"A" * 8192)

    details = stream_file_to_payload(
        input_path=str(source_path),
        payload_path=str(payload_path),
        aad=b"avikal-native-payload",
        encrypt_key=None,
        chunk_size=1024,
    )

    assert details["compression_enabled"] is True
    assert details["compression_reason"] == "sample"
    assert details["compression_sample_ratio"] < 0.97


def test_direct_archive_streaming_failure_leaves_no_output_or_payload_temp(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_path = tmp_path / "source.txt"
    output_path = tmp_path / "out.avk"
    source_path.write_text("payload", encoding="utf-8")

    def fail_stream(*_args, **_kwargs):
        raise RuntimeError("simulated payload failure")

    monkeypatch.setattr(
        "avikal_backend.archive.pipeline.multi_file_encoder.write_indexed_multifile_payload",
        fail_stream,
    )

    with pytest.raises(RuntimeError, match="simulated payload failure"):
        encoder_module.create_avk_file_enhanced(
            input_filepath=str(source_path),
            output_filepath=str(output_path),
        )

    assert not output_path.exists()
    assert not list(tmp_path.glob(".avikal-archive-*"))
    assert not list(tmp_path.glob(".avikal-payload-*"))


def test_payload_streaming_tamper_fails_before_output_commit(tmp_path: Path) -> None:
    source_path = tmp_path / "source.bin"
    payload_path = tmp_path / "payload.enc"
    output_path = tmp_path / "output.bin"
    expected = _write_sample_file(source_path)
    key = bytes(range(32))
    aad = b"avikal-native-payload"

    details = stream_file_to_payload(
        input_path=str(source_path),
        payload_path=str(payload_path),
        aad=aad,
        encrypt_key=key,
        chunk_size=211,
    )

    payload_bytes = bytearray(payload_path.read_bytes())
    payload_bytes[PAYLOAD_HEADER_SIZE + 17] ^= 0x5A
    payload_path.write_bytes(payload_bytes)

    with payload_path.open("rb") as handle:
        with pytest.raises(ValueError, match="Payload authentication failed"):
            stream_payload_to_file(
                payload_stream=handle,
                output_path=str(output_path),
                aad=aad,
                decrypt_key=key,
                expected_checksum=details["checksum"],
                expected_output_size=len(expected),
                chunk_size=97,
            )

    assert not output_path.exists()


def test_native_checksum_matches_payload_digest_reference(tmp_path: Path) -> None:
    source_path = tmp_path / "source.bin"
    payload_path = tmp_path / "payload.enc"
    expected = _write_sample_file(source_path)

    details = stream_file_to_payload(
        input_path=str(source_path),
        payload_path=str(payload_path),
        aad=b"avikal-native-payload",
        encrypt_key=None,
        chunk_size=149,
    )

    assert details["checksum"] == sha256_digest(expected)


def test_payload_streaming_does_not_expose_legacy_generation(tmp_path: Path) -> None:
    source_path = tmp_path / "source.bin"
    payload_path = tmp_path / "payload.enc"
    _write_sample_file(source_path)

    with pytest.raises(TypeError, match="payload_format"):
        stream_file_to_payload(
            input_path=str(source_path),
            payload_path=str(payload_path),
            aad=b"avikal-current-payload",
            encrypt_key=bytes(range(32)),
            payload_format="AVP2",
        )
