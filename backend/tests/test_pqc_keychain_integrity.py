"""PQC-gated keychain and archive signature regression tests.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from avikal_backend.archive.format import multipart
from avikal_backend.archive.chess_metadata import (
    CHESS_ENVELOPE_PQC_PROTECTED,
    inspect_chess_keychain_envelope,
)
from avikal_backend.archive.pipeline.decoder import extract_avk_file_enhanced
from avikal_backend.archive.pipeline.encoder import create_avk_file_enhanced
from avikal_backend.archive.pipeline.keychain_security import read_archive_keychain_metadata
from avikal_backend.archive.security.archive_signature import (
    TAG_SIGNATURE_ML_DSA,
    extract_archive_signature,
    strip_archive_signature_tags,
)
from avikal_backend.archive.security.pqc_keyfile import PQC_STORAGE_MODE_EMBEDDED
from avikal_backend.archive.security.pqc_provider import provider_status


PASSWORD = "AvikalStrongPass!9Zeta"


@pytest.fixture(scope="module")
def signed_embedded_archive(tmp_path_factory):
    status = provider_status()
    if not status["available"]:
        pytest.skip(status["reason"])
    root = tmp_path_factory.mktemp("signed-pqc-keychain")
    source = root / "source.txt"
    source.write_bytes(b"signed PQC-gated Avikal keychain\n" * 32)
    archive = root / "signed.avk"
    create_avk_file_enhanced(
        str(source),
        str(archive),
        password=PASSWORD,
        pqc_enabled=True,
        pqc_storage_mode=PQC_STORAGE_MODE_EMBEDDED,
    )
    return root, source, archive


def test_pqc_keychain_is_gated_and_dual_signed(signed_embedded_archive):
    _root, _source, archive = signed_embedded_archive
    with zipfile.ZipFile(archive, "r") as zf:
        keychain = zf.read("keychain.pgn").decode("utf-8")

    envelope = inspect_chess_keychain_envelope(keychain)
    signature = extract_archive_signature(keychain, required=True)
    verified = read_archive_keychain_metadata(
        str(archive),
        password=PASSWORD,
        keyphrase=None,
    )

    assert envelope["version"] == CHESS_ENVELOPE_PQC_PROTECTED
    assert envelope["pqc_bootstrap"]["signature_required"] is True
    assert signature["signatures"]["ml_dsa"]
    assert signature["signatures"]["slh_dsa"]
    assert verified.pqc_resolved is True
    assert verified.archive_signature_verified is True


def test_signed_archive_multipart_roundtrip_preserves_verifiable_bytes(
    signed_embedded_archive,
    monkeypatch,
):
    root, _source, archive = signed_embedded_archive
    output_root = root / "multipart-output"
    output_root.mkdir(exist_ok=True)
    restored = root / "multipart-restored.avk"
    monkeypatch.setattr(multipart, "MIN_VOLUME_SIZE", 64 * 1024)

    split = multipart.split_archive_to_volumes(
        str(archive),
        output_dir=str(output_root),
        volume_size=64 * 1024,
    )
    joined = multipart.join_archive_volumes(
        split["path"],
        output_archive=str(restored),
    )

    assert restored.read_bytes() == archive.read_bytes()
    assert joined["archive_sha256"] == split["archive_sha256"]
    verified = read_archive_keychain_metadata(
        str(restored),
        password=PASSWORD,
        keyphrase=None,
    )
    assert verified.archive_signature_verified is True
    assert len(verified.expected_payload_sha256) == 32


def test_signature_stripping_is_rejected(signed_embedded_archive):
    root, _source, archive = signed_embedded_archive
    stripped_archive = root / "stripped.avk"
    with zipfile.ZipFile(archive, "r") as source_zip, zipfile.ZipFile(stripped_archive, "w") as output_zip:
        for info in source_zip.infolist():
            value = source_zip.read(info.filename)
            if info.filename == "keychain.pgn":
                value = strip_archive_signature_tags(value.decode("utf-8")).encode("utf-8")
            output_zip.writestr(info.filename, value, compress_type=info.compress_type)

    output = root / "stripped-output"
    output.mkdir()
    with pytest.raises(ValueError, match="signature is required but missing"):
        extract_avk_file_enhanced(str(stripped_archive), str(output), password=PASSWORD)
    assert list(output.iterdir()) == []


def test_modified_archive_signature_is_rejected(signed_embedded_archive):
    root, _source, archive = signed_embedded_archive
    modified_archive = root / "modified-signature.avk"
    with zipfile.ZipFile(archive, "r") as source_zip, zipfile.ZipFile(modified_archive, "w") as output_zip:
        for info in source_zip.infolist():
            value = source_zip.read(info.filename)
            if info.filename == "keychain.pgn":
                keychain = value.decode("utf-8")
                marker = f'[{TAG_SIGNATURE_ML_DSA} "'
                start = keychain.index(marker) + len(marker)
                replacement = "A" if keychain[start] != "A" else "B"
                keychain = keychain[:start] + replacement + keychain[start + 1:]
                value = keychain.encode("utf-8")
            output_zip.writestr(info.filename, value, compress_type=info.compress_type)

    output = root / "modified-signature-output"
    output.mkdir()
    with pytest.raises(ValueError, match="signature verification failed"):
        extract_avk_file_enhanced(str(modified_archive), str(output), password=PASSWORD)
    assert list(output.iterdir()) == []


def test_modified_payload_is_never_committed(signed_embedded_archive):
    root, _source, archive = signed_embedded_archive
    modified_archive = root / "modified-payload.avk"
    with zipfile.ZipFile(archive, "r") as source_zip, zipfile.ZipFile(modified_archive, "w") as output_zip:
        for info in source_zip.infolist():
            value = bytearray(source_zip.read(info.filename))
            if info.filename == "payload.enc":
                value[-1] ^= 0x01
            output_zip.writestr(info.filename, bytes(value), compress_type=info.compress_type)

    output = root / "modified-payload-output"
    output.mkdir()
    with pytest.raises(ValueError, match="authentication failed|signature payload binding failed|Merkle verification failed"):
        extract_avk_file_enhanced(str(modified_archive), str(output), password=PASSWORD)
    assert list(output.iterdir()) == []


def test_external_pqc_keychain_roundtrip(tmp_path):
    status = provider_status()
    if not status["available"]:
        pytest.skip(status["reason"])
    source = tmp_path / "external.txt"
    source.write_bytes(b"external signed keychain" * 20)
    archive = tmp_path / "external.avk"
    keyfile = tmp_path / "external.avkkey"
    output = tmp_path / "output"
    output.mkdir()

    create_avk_file_enhanced(
        str(source),
        str(archive),
        password=PASSWORD,
        pqc_enabled=True,
        pqc_keyfile_output=str(keyfile),
    )
    target = extract_avk_file_enhanced(
        str(archive),
        str(output),
        password=PASSWORD,
        pqc_keyfile_path=str(keyfile),
    )
    assert Path(target).read_bytes() == source.read_bytes()
