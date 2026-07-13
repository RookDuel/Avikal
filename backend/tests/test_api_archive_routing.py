"""Archive public-route inspection regression tests."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from avikal_backend.archive.format.header import (
    ARCHIVE_MODE_MULTI,
    HEADER_MAGIC,
    PROVIDER_ID_NONE,
    attach_header_to_keychain_pgn,
    attach_public_route_tags_to_keychain_pgn,
    build_header_bytes,
    extract_public_route_tags_from_keychain_pgn,
    parse_header_bytes,
)
from avikal_backend.core.services import _read_avk_public_route


def test_public_route_tags_are_parsed_without_payload_decryption() -> None:
    keychain = attach_public_route_tags_to_keychain_pgn(
        '[Event "Avikal"]\n',
        requires_password=True,
        requires_keyphrase=False,
        requires_pqc=True,
        pqc_storage_mode="embedded",
    )

    route = extract_public_route_tags_from_keychain_pgn(keychain)

    assert route["available"] is True
    assert route["requires_password"] is True
    assert route["requires_keyphrase"] is False
    assert route["requires_pqc"] is True
    assert route["pqc_storage_mode"] == "embedded"


def test_read_avk_public_route_rejects_malformed_container(tmp_path: Path) -> None:
    archive = tmp_path / "malformed.avk"
    with zipfile.ZipFile(archive, "w") as archive_zip:
        archive_zip.writestr("keychain.pgn", b"not-a-valid-header")
        archive_zip.writestr("payload.enc", b"x", compress_type=zipfile.ZIP_STORED)

    with pytest.raises(ValueError, match="header"):
        _read_avk_public_route(str(archive))


def test_read_avk_public_route_uses_header_and_route_tags(tmp_path: Path) -> None:
    archive = tmp_path / "route.avk"
    header = build_header_bytes(archive_mode=ARCHIVE_MODE_MULTI, provider_id=PROVIDER_ID_NONE)
    keychain = attach_header_to_keychain_pgn('[Event "Avikal"]\n', header)
    keychain = attach_public_route_tags_to_keychain_pgn(
        keychain,
        requires_password=True,
        requires_keyphrase=False,
        requires_pqc=False,
    )
    with zipfile.ZipFile(archive, "w") as archive_zip:
        archive_zip.writestr("keychain.pgn", keychain)
        archive_zip.writestr("payload.enc", b"opaque-payload", compress_type=zipfile.ZIP_STORED)

    header_info, route = _read_avk_public_route(str(archive))

    assert header_info["archive_mode"] == ARCHIVE_MODE_MULTI
    assert route["archive_type"] == "multi_file"
    assert route["provider"] is None
    assert route["requires_password"] is True
    assert route["requires_keyphrase"] is False


def test_header_public_route_shape_matches_multi_file_archives() -> None:
    header = build_header_bytes(archive_mode=ARCHIVE_MODE_MULTI, provider_id=PROVIDER_ID_NONE)
    parsed = parse_header_bytes(header)

    assert header.startswith(HEADER_MAGIC)
    assert parsed["archive_mode"] == ARCHIVE_MODE_MULTI
    assert parsed["aad"] == header
