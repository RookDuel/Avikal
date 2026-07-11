"""Regression tests for assured metadata, indexed recovery, and mandatory signatures."""

from __future__ import annotations

import io
import copy
import shutil
import uuid
import zipfile
from pathlib import Path

import pytest

from avikal_backend.archive.format.indexed_payload import (
    extract_indexed_selection,
    read_indexed_payload_index,
    write_indexed_multifile_payload,
)
from avikal_backend.archive.format.metadata_pack import normalize_sender_message
from avikal_backend.archive.pipeline.encoder import create_avk_file
from avikal_backend.archive.pipeline.keychain_security import read_archive_keychain_metadata
from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
from avikal_backend.archive.reporting import verify_assurance_report
from avikal_backend.archive.security.pqc_provider import provider_status
from avikal_backend.core.archive_sessions import ArchiveSessionStore


def _workspace_tempdir() -> Path:
    root = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    root.mkdir(exist_ok=True)
    path = root / f"assured-{uuid.uuid4().hex}"
    path.mkdir()
    return path


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("avikal_backend.archive.security.crypto.ARGON2_MEMORY_COST_KIB", 8192)
    monkeypatch.setattr("avikal_backend.archive.security.crypto.ARGON2_ITERATIONS", 1)
    monkeypatch.setattr("avikal_backend.archive.security.crypto.ARGON2_LANES", 1)


def test_sender_message_normalization_and_rejection():
    assert normalize_sender_message("  नमस्ते\r\nविश्व  ") == "नमस्ते\nविश्व"
    with pytest.raises(ValueError, match="100 words"):
        normalize_sender_message(" ".join(["word"] * 101))
    with pytest.raises(ValueError, match="1024 UTF-8 bytes"):
        normalize_sender_message("अ" * 400)
    with pytest.raises(ValueError, match="directional controls"):
        normalize_sender_message("safe\u202eevil")
    with pytest.raises(ValueError, match="control characters"):
        normalize_sender_message("tab\tseparated")


def test_unprotected_archive_rejects_sender_message_before_creation():
    root = _workspace_tempdir()
    try:
        source = root / "plain.txt"
        source.write_text("plain", encoding="utf-8")
        with pytest.raises(ValueError, match="Sender messages require"):
            create_avk_file(str(source), str(root / "plain.avk"), sender_message="private note")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_indexed_payload_random_access_and_tamper_rejection():
    root = _workspace_tempdir()
    try:
        alpha = root / "alpha.txt"
        beta = root / "beta.bin"
        alpha.write_text("alpha" * 20, encoding="utf-8")
        beta.write_bytes(bytes(range(64)))
        payload_key = bytes(range(32))
        archive_id = bytes(range(16))
        header_aad = b"AVK2\x01\x01\x00\x00"
        target = io.BytesIO()
        written = write_indexed_multifile_payload(
            entries=[(str(alpha), "root/alpha.txt"), (str(beta), "root/nested/beta.bin")],
            explicit_directories=["root/empty"],
            target=target,
            payload_key=payload_key,
            archive_id=archive_id,
            header_aad=header_aad,
            chunk_size=17,
        )
        target.seek(0)
        index, index_meta = read_indexed_payload_index(
            target,
            payload_key=payload_key,
            header_aad=header_aad,
            expected_index_hash=written["index_hash"],
            expected_merkle_root=written["merkle_root"],
        )
        root_id = next(item["id"] for item in index["directories"] if item["path"] == "root")
        output = root / "output"
        target.seek(0)
        files = extract_indexed_selection(
            target,
            index=index,
            selected_entry_ids=[root_id],
            output_root=str(output),
            payload_key=payload_key,
            header_aad=header_aad,
        )
        assert len([item for item in files if item["type"] == "file"]) == 2
        assert any(item["type"] == "directory" and item["filename"].replace("\\", "/") == "root/empty" for item in files)
        assert (output / "root" / "alpha.txt").read_text(encoding="utf-8") == "alpha" * 20
        assert (output / "root" / "nested" / "beta.bin").read_bytes() == bytes(range(64))
        assert (output / "root" / "empty").is_dir()
        assert index_meta["manifest_hash"] == written["manifest_hash"]

        damaged = bytearray(target.getvalue())
        first_chunk = index["files"][0]["chunks"][0]
        damaged[first_chunk["offset"] + first_chunk["record_length"] - 1] ^= 0x01
        with pytest.raises(ValueError, match="chunk verification"):
            extract_indexed_selection(
                io.BytesIO(damaged),
                index=index,
                selected_entry_ids=[index["files"][0]["id"]],
                output_root=str(root / "tampered"),
                payload_key=payload_key,
                header_aad=header_aad,
            )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_non_pqc_archive_requires_its_dual_signature():
    status = provider_status()
    if not status["available"]:
        pytest.skip(status["reason"])
    root = _workspace_tempdir()
    try:
        source = root / "signed.txt"
        archive = root / "signed.avk"
        damaged = root / "unsigned-copy.avk"
        source.write_text("signed payload", encoding="utf-8")
        create_avk_file(str(source), str(archive), password="StrongPass#123")
        with zipfile.ZipFile(archive, "r") as archive_zip:
            assert archive_zip.read("payload.enc")[:4] == b"AVI1"
        verified = read_archive_keychain_metadata(
            str(archive),
            password="StrongPass#123",
            keyphrase=None,
        )
        assert verified.archive_signature_verified is True

        with zipfile.ZipFile(archive, "r") as source_zip:
            keychain = source_zip.read("keychain.pgn").decode("utf-8")
            payload = source_zip.read("payload.enc")
        keychain = "\n".join(
            line for line in keychain.splitlines() if not line.startswith("[AvikalArchiveMLDSA ")
        ) + "\n"
        with zipfile.ZipFile(damaged, "w") as output_zip:
            output_zip.writestr("payload.enc", payload, compress_type=zipfile.ZIP_STORED)
            output_zip.writestr("keychain.pgn", keychain, compress_type=zipfile.ZIP_DEFLATED)
        with pytest.raises(ValueError, match="signature envelope is incomplete"):
            read_archive_keychain_metadata(
                str(damaged),
                password="StrongPass#123",
                keyphrase=None,
            )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_signed_indexed_session_supports_selective_and_complete_verification():
    status = provider_status()
    if not status["available"]:
        pytest.skip(status["reason"])
    root = _workspace_tempdir()
    store = ArchiveSessionStore()
    try:
        source = root / "source"
        (source / "nested" / "empty").mkdir(parents=True)
        (source / "first.txt").write_text("first", encoding="utf-8")
        (source / "nested" / "second.txt").write_text("second", encoding="utf-8")
        archive = root / "indexed.avk"
        created = create_multi_file_avk(
            [str(source)],
            str(archive),
            password="StrongPass#123",
            sender_message="प्रमाणित संदेश",
        )
        creation_report = created["creation_report"]
        verified_report = verify_assurance_report(creation_report)
        assert verified_report["valid"] is True
        damaged_report = copy.deepcopy(creation_report)
        damaged_report["archive"]["file_count"] = 999
        with pytest.raises(ValueError, match="digest verification failed"):
            verify_assurance_report(damaged_report)
        session = store.open(
            str(archive),
            password="StrongPass#123",
            keyphrase=None,
            time_key=None,
            pqc_keyfile_path=None,
            pqc_keyfile_password=None,
        )
        selected = next(item for item in session.index["files"] if item["path"].endswith("second.txt"))
        extracted = store.extract(session.session_id, [selected["id"]], str(root / "preview"))
        assert len(extracted) == 1
        assert Path(extracted[0]["path"]).read_text(encoding="utf-8") == "second"
        assert not (root / "preview" / "source" / "first.txt").exists()
        commitment = store.verify_payload_commitment(session.session_id)
        assert commitment["payload_sha256"] == session.metadata["archive_integrity"]["payload_sha256"]
        assert session.metadata["sender_message"] == "प्रमाणित संदेश"
    finally:
        store.close_all()
        shutil.rmtree(root, ignore_errors=True)
