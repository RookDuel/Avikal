"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import shutil
import uuid
import zipfile

import pytest

from avikal_backend.archive.format.container import read_avk_container
from avikal_backend.archive.format.header import attach_header_to_keychain_pgn
from avikal_backend.archive.chess_metadata import (
    decode_chess_to_metadata_enhanced,
    encode_metadata_to_chess_enhanced,
)
from avikal_backend.archive.format.manifest import normalize_user_archive_path
from avikal_backend.archive.format.metadata import pack_cascade_metadata, unpack_cascade_metadata
from avikal_backend.archive.pipeline.decoder import extract_avk_file_enhanced
from avikal_backend.archive.pipeline.encoder import create_avk_file_enhanced
from avikal_backend.archive.path_safety import resolve_safe_output_path, resolve_safe_relative_output_path


PASSWORD = "AvikalStrongPass!9Zeta"


@contextmanager
def _workspace_tempdir():
    base = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    base.mkdir(exist_ok=True)
    temp_path = base / f"security_{uuid.uuid4().hex}"
    temp_path.mkdir()
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


def _rewrite_archive(archive_path: Path, *, keychain_pgn: str, payload_bytes: bytes) -> None:
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("keychain.pgn", keychain_pgn)
        zf.writestr("payload.enc", payload_bytes, compress_type=zipfile.ZIP_STORED)


def test_resolve_safe_output_path_rejects_traversal():
    with _workspace_tempdir() as temp_dir:
        with pytest.raises(ValueError, match="path separators|escapes"):
            resolve_safe_output_path(str(temp_dir), "../escaped.txt")


def test_resolve_safe_relative_output_path_rejects_traversal():
    with _workspace_tempdir() as temp_dir:
        with pytest.raises(ValueError, match="invalid|escapes"):
            resolve_safe_relative_output_path(str(temp_dir), "../escaped.txt")


@pytest.mark.parametrize(
    ("arcname", "message"),
    [
        ("CON.txt", "reserved device name"),
        ("folder/bad:.txt", "invalid Windows filename characters"),
        ("folder/trailing. ", "leading or trailing whitespace|must not end with spaces or periods"),
        ("folder/ques?.txt", "invalid Windows filename characters"),
        (" folder/name.txt", "leading or trailing whitespace"),
    ],
)
def test_multi_file_manifest_rejects_windows_unsafe_names(arcname: str, message: str):
    with pytest.raises(ValueError, match=message):
        normalize_user_archive_path(arcname)


def test_tampered_protected_archive_header_is_rejected_before_write():
    with _workspace_tempdir() as temp_dir:
        payload = temp_dir / "payload.txt"
        archive = temp_dir / "protected.avk"
        tampered_archive = temp_dir / "protected_tampered.avk"
        output_dir = temp_dir / "out"
        output_dir.mkdir()
        payload.write_bytes(b"protected payload\n" * 16)

        create_avk_file_enhanced(
            str(payload),
            str(archive),
            password=PASSWORD,
            use_timecapsule=False,
        )

        header_bytes, keychain_pgn, payload_bytes = read_avk_container(str(archive))
        tampered_header = bytearray(header_bytes)
        tampered_header[-1] = 0x02
        tampered_keychain = attach_header_to_keychain_pgn(keychain_pgn, bytes(tampered_header))
        _rewrite_archive(tampered_archive, keychain_pgn=tampered_keychain, payload_bytes=payload_bytes)

        with pytest.raises(ValueError, match="Failed to open|decryption failed"):
            extract_avk_file_enhanced(
                str(tampered_archive),
                str(output_dir),
                password=PASSWORD,
            )

        assert list(output_dir.iterdir()) == []


def test_plaintext_archive_tampered_filename_cannot_escape_output_directory():
    with _workspace_tempdir() as temp_dir:
        payload = temp_dir / "safe_name.bin"
        archive = temp_dir / "plain.avk"
        tampered_archive = temp_dir / "plain_tampered.avk"
        output_dir = temp_dir / "out"
        outside_target = temp_dir / "escaped.txt"
        output_dir.mkdir()
        payload.write_bytes(b"plaintext payload\n" * 8)

        create_avk_file_enhanced(
            str(payload),
            str(archive),
            password=None,
            keyphrase=None,
            use_timecapsule=False,
        )

        header_bytes, keychain_pgn, payload_bytes = read_avk_container(str(archive))
        metadata = decode_chess_to_metadata_enhanced(
            keychain_pgn,
            password=None,
            keyphrase=None,
            aad=header_bytes,
        )
        rebuilt_metadata = pack_cascade_metadata(
            metadata["salt"],
            metadata.get("pqc_ciphertext"),
            metadata.get("pqc_private_key"),
            metadata["unlock_timestamp"],
            "safe_name.bin",
            metadata["checksum"],
            metadata["encryption_method"],
            metadata.get("keyphrase_protected", False),
            chess_salt=metadata.get("chess_salt"),
            timelock_mode=metadata.get("timelock_mode", "convenience"),
            file_id=metadata.get("file_id"),
            server_url=metadata.get("server_url"),
            time_key_hash=metadata.get("time_key_hash"),
            timecapsule_provider=metadata.get("timecapsule_provider"),
            drand_round=metadata.get("drand_round"),
            drand_chain_hash=metadata.get("drand_chain_hash"),
            drand_chain_url=metadata.get("drand_chain_url"),
            drand_ciphertext=metadata.get("drand_ciphertext"),
            drand_beacon_id=metadata.get("drand_beacon_id"),
            pqc_required=metadata.get("pqc_required", False),
            pqc_algorithm=metadata.get("pqc_algorithm"),
            pqc_key_id=metadata.get("pqc_key_id"),
            keyphrase_format_version=metadata.get("keyphrase_format_version"),
            keyphrase_wordlist_id=metadata.get("keyphrase_wordlist_id"),
            archive_type=metadata.get("archive_type"),
            entry_count=metadata.get("entry_count"),
            total_original_size=metadata.get("total_original_size"),
            manifest_hash=metadata.get("manifest_hash"),
            payload_key_wrap_algorithm=metadata.get("payload_key_wrap_algorithm"),
            wrapped_payload_key=metadata.get("wrapped_payload_key"),
        )
        tampered_metadata = rebuilt_metadata.replace(b"safe_name.bin", b"../escape.txt", 1)
        tampered_keychain = encode_metadata_to_chess_enhanced(
            tampered_metadata,
            password=None,
            keyphrase=None,
            aad=header_bytes,
        )
        _rewrite_archive(tampered_archive, keychain_pgn=tampered_keychain, payload_bytes=payload_bytes)

        with pytest.raises(ValueError, match="unsafe filename|Failed to open"):
            extract_avk_file_enhanced(
                str(tampered_archive),
                str(output_dir),
            )

        assert not outside_target.exists()
        assert list(output_dir.iterdir()) == []


def test_aavrit_metadata_supports_single_file_without_keyphrase():
    metadata_bytes = pack_cascade_metadata(
        b"\x01" * 32,
        b"",
        None,
        1_900_000_100,
        "payload.txt",
        b"\x02" * 32,
        "aes256gcm_stream_timekey",
        False,
        chess_salt=None,
        timelock_mode="convenience",
        file_id="8ab90ae8-3ffd-42af-8f10-9ba94fbe5ea6",
        server_url="https://aavrit.example.com",
        time_key_hash=b"\x03" * 32,
        timecapsule_provider="aavrit",
        aavrit_data_hash="data-hash",
        aavrit_commit_hash="commit-hash",
        aavrit_server_key_id="server-key",
        aavrit_commit_signature="commit-signature",
        archive_type="single_file",
        entry_count=1,
        total_original_size=1234,
        manifest_hash=b"\x04" * 32,
    )

    unpacked = unpack_cascade_metadata(metadata_bytes)

    assert unpacked["timecapsule_provider"] == "aavrit"
    assert unpacked["archive_type"] == "single_file"
    assert unpacked["entry_count"] == 1
    assert unpacked["keyphrase_format_version"] == 0
    assert unpacked["keyphrase_wordlist_id"] is None


def test_aavrit_metadata_supports_keyphrase_in_current_format():
    metadata_bytes = pack_cascade_metadata(
        b"\x05" * 32,
        b"",
        None,
        1_900_000_100,
        "payload.txt",
        b"\x06" * 32,
        "aes256gcm_stream",
        True,
        chess_salt=None,
        timelock_mode="convenience",
        file_id="8ab90ae8-3ffd-42af-8f10-9ba94fbe5ea6",
        server_url="https://aavrit.example.com",
        time_key_hash=b"\x07" * 32,
        timecapsule_provider="aavrit",
        aavrit_data_hash="data-hash",
        aavrit_commit_hash="commit-hash",
        aavrit_server_key_id="server-key",
        aavrit_commit_signature="commit-signature",
        keyphrase_format_version=1,
        keyphrase_wordlist_id="avikal-hi-2048-v1",
        archive_type="single_file",
        entry_count=1,
        total_original_size=4321,
        manifest_hash=b"\x08" * 32,
    )

    unpacked = unpack_cascade_metadata(metadata_bytes)

    assert unpacked["timecapsule_provider"] == "aavrit"
    assert unpacked["keyphrase_format_version"] == 1
    assert unpacked["keyphrase_wordlist_id"] == "avikal-hi-2048-v1"


def test_chess_decoder_accepts_aavrit_metadata_current_format():
    metadata_bytes = pack_cascade_metadata(
        b"\x09" * 32,
        b"",
        None,
        1_900_000_100,
        "payload.txt",
        b"\x0A" * 32,
        "aes256gcm_stream_timekey",
        False,
        chess_salt=b"\x0B" * 32,
        timelock_mode="convenience",
        file_id="8ab90ae8-3ffd-42af-8f10-9ba94fbe5ea6",
        server_url="https://aavrit.example.com",
        time_key_hash=b"\x0C" * 32,
        timecapsule_provider="aavrit",
        aavrit_data_hash="data-hash",
        aavrit_commit_hash="commit-hash",
        aavrit_server_key_id="server-key",
        aavrit_commit_signature="commit-signature",
        archive_type="single_file",
        entry_count=1,
        total_original_size=2048,
        manifest_hash=b"\x0D" * 32,
    )
    aad = b"AVKL\x01\x01\x02\x01"
    encoded = encode_metadata_to_chess_enhanced(
        metadata_bytes,
        password=None,
        keyphrase=None,
        use_timecapsule=True,
        aad=aad,
    )

    decoded = decode_chess_to_metadata_enhanced(
        encoded,
        password=None,
        keyphrase=None,
        skip_timelock=True,
        aad=aad,
    )

    assert decoded["version"] == 0x01
    assert decoded["timecapsule_provider"] == "aavrit"
    assert decoded["archive_type"] == "single_file"
