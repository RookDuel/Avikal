"""
Strict AVK container validation and reading helpers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
import zipfile
from contextlib import contextmanager

from .header import HEADER_FILENAME, HEADER_SIZE, parse_header_bytes

REQUIRED_AVK_MEMBERS = {HEADER_FILENAME, "keychain.pgn", "payload.enc"}
# keychain.pgn only carries the encrypted control plane, not bulk payload bytes.
MAX_KEYCHAIN_BYTES = 256 * 1024


def _validate_avk_zip(zf: zipfile.ZipFile) -> tuple[zipfile.ZipInfo, zipfile.ZipInfo, zipfile.ZipInfo]:
    infos = zf.infolist()
    names = [info.filename for info in infos]
    unique_names = set(names)

    if len(names) != len(unique_names):
        raise ValueError("Invalid .avk container: duplicate archive members are not allowed")

    missing = REQUIRED_AVK_MEMBERS - unique_names
    extras = unique_names - REQUIRED_AVK_MEMBERS
    if missing:
        raise ValueError("Invalid .avk container: required members are missing")
    if extras:
        raise ValueError("Invalid .avk container: unexpected archive members are present")

    header_info = zf.getinfo(HEADER_FILENAME)
    keychain_info = zf.getinfo("keychain.pgn")
    payload_info = zf.getinfo("payload.enc")

    if header_info.is_dir() or keychain_info.is_dir() or payload_info.is_dir():
        raise ValueError("Invalid .avk container: archive members must be files")
    if header_info.file_size != HEADER_SIZE:
        raise ValueError("Invalid .avk container: header.bin size is out of bounds")
    if keychain_info.file_size <= 0 or keychain_info.file_size > MAX_KEYCHAIN_BYTES:
        raise ValueError("Invalid .avk container: keychain.pgn size is out of bounds")
    if payload_info.file_size <= 0:
        raise ValueError("Invalid .avk container: payload.enc is empty")

    return header_info, keychain_info, payload_info


def read_avk_container(avk_filepath: str) -> tuple[bytes, str, bytes]:
    """
    Read an AVK container after strict structural validation.

    Rules:
    - file must exist and be a valid ZIP
    - exactly `header.bin`, `keychain.pgn`, and `payload.enc` must be present
    - duplicate members are rejected
    - `header.bin` must be 8 bytes and pass Avk header validation
    - `keychain.pgn` must be valid UTF-8 and size-bounded
    - `payload.enc` must be non-empty
    """
    if not os.path.exists(avk_filepath):
        raise ValueError("File not found")

    try:
        with zipfile.ZipFile(avk_filepath, "r") as zf:
            _validate_avk_zip(zf)

            try:
                header_bytes = zf.read(HEADER_FILENAME)
                parse_header_bytes(header_bytes)
                keychain_pgn = zf.read("keychain.pgn").decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("Invalid .avk container: keychain.pgn is not valid UTF-8") from exc
            encrypted_payload = zf.read("payload.enc")
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid .avk container: file is not a valid ZIP archive") from exc
    except OSError as exc:
        raise ValueError("Invalid .avk container: unable to read archive") from exc

    return header_bytes, keychain_pgn, encrypted_payload


@contextmanager
def open_avk_payload_stream(avk_filepath: str):
    """Yield `(header_bytes, keychain_pgn, payload_stream)` for streamed payload processing."""
    if not os.path.exists(avk_filepath):
        raise ValueError("File not found")

    try:
        with zipfile.ZipFile(avk_filepath, "r") as zf:
            _header_info, _keychain_info, payload_info = _validate_avk_zip(zf)
            try:
                header_bytes = zf.read(HEADER_FILENAME)
                parse_header_bytes(header_bytes)
                keychain_pgn = zf.read("keychain.pgn").decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("Invalid .avk container: keychain.pgn is not valid UTF-8") from exc

            with zf.open("payload.enc", "r") as payload_stream:
                setattr(payload_stream, "avikal_file_size", payload_info.file_size)
                yield header_bytes, keychain_pgn, payload_stream
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid .avk container: file is not a valid ZIP archive") from exc
    except OSError as exc:
        raise ValueError("Invalid .avk container: unable to read archive") from exc
