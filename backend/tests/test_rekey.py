"""
Rekey architecture tests.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import uuid

import pytest

from avikal_backend.archive.chess_metadata import decode_chess_to_metadata_enhanced
from avikal_backend.archive.format.container import read_avk_container
from avikal_backend.archive.pipeline.decoder import extract_avk_file
from avikal_backend.archive.pipeline.encoder import create_avk_file
from avikal_backend.archive.pipeline.rekey import rekey_avk_archive
from avikal_backend.archive.security.key_wrap import PAYLOAD_KEY_WRAP_ALGORITHM


def _workspace_tempdir() -> Path:
    root = Path(__file__).resolve().parents[1] / ".tmp_rekey_tests"
    root.mkdir(exist_ok=True)
    path = root / uuid.uuid4().hex
    path.mkdir()
    return path


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("avikal_backend.archive.security.crypto.ARGON2_MEMORY_COST_KIB", 8192)
    monkeypatch.setattr("avikal_backend.archive.security.crypto.ARGON2_ITERATIONS", 1)
    monkeypatch.setattr("avikal_backend.archive.security.crypto.ARGON2_LANES", 1)


def test_rekey_rotates_password_without_rewriting_payload():
    temp_path = _workspace_tempdir()
    try:
        source = temp_path / "secret.txt"
        archive = temp_path / "secret.avk"
        output_dir = temp_path / "out"
        output_dir.mkdir()
        source.write_text("Avikal rekey architecture proof\n", encoding="utf-8")

        create_avk_file(
            str(source),
            str(archive),
            password="OldPass#123",
            use_timecapsule=False,
        )
        header_before, keychain_before, payload_before = read_avk_container(str(archive))
        metadata_before = decode_chess_to_metadata_enhanced(
            keychain_before,
            password="OldPass#123",
            aad=header_before,
        )

        assert metadata_before["version"] == 0x01
        assert metadata_before["payload_key_wrap_algorithm"] == PAYLOAD_KEY_WRAP_ALGORITHM
        assert metadata_before["wrapped_payload_key"]

        result = rekey_avk_archive(
            str(archive),
            old_password="OldPass#123",
            new_password="NewPass#456",
        )

        assert result["ok"] is True
        assert result["payload_rewritten"] is False

        header_after, keychain_after, payload_after = read_avk_container(str(archive))
        metadata_after = decode_chess_to_metadata_enhanced(
            keychain_after,
            password="NewPass#456",
            aad=header_after,
        )

        assert header_after == header_before
        assert payload_after == payload_before
        assert keychain_after != keychain_before
        assert metadata_after["version"] == 0x01
        assert metadata_after["salt"] != metadata_before["salt"]
        assert metadata_after["wrapped_payload_key"] != metadata_before["wrapped_payload_key"]

        with pytest.raises(ValueError, match="Incorrect password|Chess decoding failed"):
            extract_avk_file(str(archive), str(output_dir), password="OldPass#123")

        extracted = Path(extract_avk_file(str(archive), str(output_dir), password="NewPass#456"))
        assert extracted.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


def test_rekey_requires_archive_binding_for_wrapped_payload_key_metadata():
    from avikal_backend.archive.format.metadata import pack_cascade_metadata

    with pytest.raises(ValueError, match="archive_type"):
        pack_cascade_metadata(
            b"\x01" * 32,
            b"",
            None,
            1_900_000_000,
            "unbound.txt",
            b"\x02" * 32,
            "aes256gcm_stream",
            False,
            payload_key_wrap_algorithm=PAYLOAD_KEY_WRAP_ALGORITHM,
            wrapped_payload_key=b"\x03" * 60,
        )
