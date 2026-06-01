"""
Strict AVK container validation and reading helpers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
import zipfile
from contextlib import contextmanager

from .header import extract_header_from_keychain_pgn, parse_header_bytes
from ..security.pqc_keyfile import PQC_EMBEDDED_MEMBER_NAME

REQUIRED_AVK_MEMBERS = {"keychain.pgn", "payload.enc"}
OPTIONAL_AVK_MEMBERS = {PQC_EMBEDDED_MEMBER_NAME}
# keychain.pgn only carries the encrypted control plane, not bulk payload bytes.
MAX_KEYCHAIN_BYTES = 256 * 1024


def _validate_avk_zip(zf: zipfile.ZipFile) -> tuple[zipfile.ZipInfo, zipfile.ZipInfo, zipfile.ZipInfo | None]:
    infos = zf.infolist()
    names = [info.filename for info in infos]
    unique_names = set(names)

    if len(names) != len(unique_names):
        raise ValueError("Invalid .avk container: duplicate archive members are not allowed")

    missing = REQUIRED_AVK_MEMBERS - unique_names
    extras = unique_names - REQUIRED_AVK_MEMBERS - OPTIONAL_AVK_MEMBERS
    if missing:
        raise ValueError("Invalid .avk container: required members are missing")
    if extras:
        raise ValueError("Invalid .avk container: unexpected archive members are present")

    keychain_info = zf.getinfo("keychain.pgn")
    payload_info = zf.getinfo("payload.enc")
    embedded_pqc_info = zf.getinfo(PQC_EMBEDDED_MEMBER_NAME) if PQC_EMBEDDED_MEMBER_NAME in unique_names else None

    if keychain_info.is_dir() or payload_info.is_dir():
        raise ValueError("Invalid .avk container: archive members must be files")
    if embedded_pqc_info and embedded_pqc_info.is_dir():
        raise ValueError("Invalid .avk container: archive members must be files")
    if keychain_info.file_size <= 0 or keychain_info.file_size > MAX_KEYCHAIN_BYTES:
        raise ValueError("Invalid .avk container: keychain.pgn size is out of bounds")
    if payload_info.file_size <= 0:
        raise ValueError("Invalid .avk container: payload.enc is empty")
    if embedded_pqc_info and embedded_pqc_info.file_size <= 0:
        raise ValueError(f"Invalid .avk container: {PQC_EMBEDDED_MEMBER_NAME} is empty")

    return keychain_info, payload_info, embedded_pqc_info


def _read_header_bytes(keychain_pgn: str) -> bytes:
    header_bytes = extract_header_from_keychain_pgn(keychain_pgn)
    parse_header_bytes(header_bytes)
    return header_bytes


def KEYCHAIN_HAS_HEADER(keychain_pgn: str) -> bool:
    try:
        extract_header_from_keychain_pgn(keychain_pgn)
        return True
    except ValueError:
        return False


def read_avk_container(avk_filepath: str) -> tuple[bytes, str, bytes]:
    """Read an AVK container after strict structural validation."""
    if not os.path.exists(avk_filepath):
        raise ValueError("File not found")

    try:
        with zipfile.ZipFile(avk_filepath, "r") as zf:
            _keychain_info, _payload_info, _embedded_pqc_info = _validate_avk_zip(zf)

            try:
                keychain_pgn = zf.read("keychain.pgn").decode("utf-8")
                header_bytes = _read_header_bytes(keychain_pgn)
            except UnicodeDecodeError as exc:
                raise ValueError("Invalid .avk container: keychain.pgn is not valid UTF-8") from exc
            encrypted_payload = zf.read("payload.enc")
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid .avk container: file is not a valid ZIP archive") from exc
    except OSError as exc:
        raise ValueError("Invalid .avk container: unable to read archive") from exc

    return header_bytes, keychain_pgn, encrypted_payload


def read_avk_header_and_keychain(avk_filepath: str) -> tuple[bytes, str]:
    """
    Read only the validated public header and PGN control plane.

    This avoids materializing `payload.enc` for metadata inspection flows.
    """
    if not os.path.exists(avk_filepath):
        raise ValueError("File not found")

    try:
        with zipfile.ZipFile(avk_filepath, "r") as zf:
            _validate_avk_zip(zf)
            try:
                keychain_pgn = zf.read("keychain.pgn").decode("utf-8")
                header_bytes = _read_header_bytes(keychain_pgn)
            except UnicodeDecodeError as exc:
                raise ValueError("Invalid .avk container: keychain.pgn is not valid UTF-8") from exc
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid .avk container: file is not a valid ZIP archive") from exc
    except OSError as exc:
        raise ValueError("Invalid .avk container: unable to read archive") from exc

    return header_bytes, keychain_pgn


def read_avk_embedded_pqc_member(avk_filepath: str) -> bytes | None:
    """Read only the optional embedded PQC archive member after validation."""
    if not os.path.exists(avk_filepath):
        raise ValueError("File not found")

    try:
        with zipfile.ZipFile(avk_filepath, "r") as zf:
            _keychain_info, _payload_info, embedded_pqc_info = _validate_avk_zip(zf)
            if not embedded_pqc_info:
                return None
            return zf.read(PQC_EMBEDDED_MEMBER_NAME)
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid .avk container: file is not a valid ZIP archive") from exc
    except OSError as exc:
        raise ValueError("Invalid .avk container: unable to read archive") from exc


@contextmanager
def open_avk_payload_stream(avk_filepath: str):
    """Yield `(header_bytes, keychain_pgn, payload_stream, embedded_pqc)` for streamed payload processing."""
    if not os.path.exists(avk_filepath):
        raise ValueError("File not found")

    try:
        with zipfile.ZipFile(avk_filepath, "r") as zf:
            _keychain_info, payload_info, embedded_pqc_info = _validate_avk_zip(zf)
            try:
                keychain_pgn = zf.read("keychain.pgn").decode("utf-8")
                header_bytes = _read_header_bytes(keychain_pgn)
            except UnicodeDecodeError as exc:
                raise ValueError("Invalid .avk container: keychain.pgn is not valid UTF-8") from exc
            embedded_pqc = zf.read(PQC_EMBEDDED_MEMBER_NAME) if embedded_pqc_info else None

            with zf.open("payload.enc", "r") as payload_stream:
                setattr(payload_stream, "avikal_file_size", payload_info.file_size)
                yield header_bytes, keychain_pgn, payload_stream, embedded_pqc
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid .avk container: file is not a valid ZIP archive") from exc
    except OSError as exc:
        raise ValueError("Invalid .avk container: unable to read archive") from exc
