"""
Deterministic malformed-archive smoke tests.

These are cheap parser abuse checks meant to run in CI on every change.
"""

from __future__ import annotations

import os
import shutil
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from avikal_backend.archive.format.container import (
    open_avk_payload_stream,
    read_avk_container,
    read_avk_embedded_pqc_member,
    read_avk_header_and_keychain,
)
from avikal_backend.archive.security.pqc_keyfile import PQC_EMBEDDED_MEMBER_NAME
from avikal_backend.core.services import _read_avk_public_route


@contextmanager
def _workspace_tempdir():
    base = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    base.mkdir(exist_ok=True)
    temp_path = base / f"fuzz_{uuid.uuid4().hex}"
    temp_path.mkdir()
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


def _write_bytes(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    return path


def _write_zip(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_zip:
        for name, content in members:
            archive_zip.writestr(name, content)
    return path


@pytest.mark.parametrize(
    ("builder", "match"),
    [
        (lambda path: _write_bytes(path, os.urandom(96)), "valid ZIP archive"),
        (lambda path: _write_zip(path, [("keychain.pgn", b"not-a-valid-header"), ("payload.enc", b"x")]), "header"),
        (lambda path: _write_zip(path, [("keychain.pgn", b""), ("payload.enc", b"x")]), "size is out of bounds"),
        (lambda path: _write_zip(path, [("payload.enc", b"x")]), "required members are missing"),
        (
            lambda path: _write_zip(
                path,
                [("keychain.pgn", b"hello"), ("payload.enc", b"x"), (PQC_EMBEDDED_MEMBER_NAME, b"")],
            ),
            f"{PQC_EMBEDDED_MEMBER_NAME} is empty",
        ),
    ],
)
def test_malformed_archives_fail_closed(builder, match: str):
    with _workspace_tempdir() as temp_dir:
        archive_path = builder(temp_dir / "sample.avk")

        with pytest.raises(ValueError, match=match):
            read_avk_container(str(archive_path))
        with pytest.raises(ValueError, match=match):
            read_avk_header_and_keychain(str(archive_path))
        if match != "header":
            with pytest.raises(ValueError, match=match):
                read_avk_embedded_pqc_member(str(archive_path))
        with pytest.raises(ValueError, match=match):
            _read_avk_public_route(str(archive_path))
        with pytest.raises(ValueError, match=match):
            with open_avk_payload_stream(str(archive_path)):
                pass


def test_duplicate_members_are_rejected():
    with _workspace_tempdir() as temp_dir:
        archive_path = temp_dir / "duplicate.avk"
        with zipfile.ZipFile(archive_path, "w") as archive_zip:
            archive_zip.writestr("keychain.pgn", "one")
            archive_zip.writestr("keychain.pgn", "two")
            archive_zip.writestr("payload.enc", b"x")

        with pytest.raises(ValueError, match="duplicate archive members"):
            read_avk_container(str(archive_path))
