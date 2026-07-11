"""
Avk archive header handling.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import base64
import json
import re
import struct

from ..security.pqc_keyfile import PQC_STORAGE_MODE_EMBEDDED, PQC_STORAGE_MODE_EXTERNAL, PQC_STORAGE_MODES

HEADER_MAGIC = b"AVK2"
HEADER_FORMAT_VERSION = 0x01
HEADER_STRUCTURE_ID = 0x01
HEADER_SIZE = 8
KEYCHAIN_HEADER_TAG = "AvikalHeader"
KEYCHAIN_ROUTE_VERSION_TAG = "AvikalRouteVersion"
KEYCHAIN_REQUIRE_PASSWORD_TAG = "AvikalRequirePassword"
KEYCHAIN_REQUIRE_KEYPHRASE_TAG = "AvikalRequireKeyphrase"
KEYCHAIN_REQUIRE_PQC_TAG = "AvikalRequirePQC"
KEYCHAIN_PQC_STORAGE_MODE_TAG = "AvikalPQCStorageMode"
KEYCHAIN_UNLOCK_TIMESTAMP_TAG = "AvikalUnlockTimestamp"
KEYCHAIN_DRAND_ROUND_TAG = "AvikalDrandRound"
KEYCHAIN_KEYPHRASE_WORDLIST_TAG = "AvikalKeyphraseWordlist"
KEYCHAIN_AAVRIT_ROUTE_TAG = "AvikalAavritRoute"
KEYCHAIN_TIME_GATED_TAG = "AvikalTimeGatedKeychain"
PUBLIC_ROUTE_FORMAT_VERSION_V1 = "1"
PUBLIC_ROUTE_FORMAT_VERSION_V2 = "2"
PUBLIC_ROUTE_FORMAT_VERSION_V3 = "3"
MAX_AAVRIT_ROUTE_BYTES = 32_768

ARCHIVE_MODE_SINGLE = 0x01
ARCHIVE_MODE_MULTI = 0x02

PROVIDER_ID_NONE = 0x00
PROVIDER_ID_DRAND = 0x02
PROVIDER_ID_AAVRIT = 0x03

_VALID_ARCHIVE_MODES = {ARCHIVE_MODE_SINGLE, ARCHIVE_MODE_MULTI}
_VALID_PROVIDER_IDS = {PROVIDER_ID_NONE, PROVIDER_ID_DRAND, PROVIDER_ID_AAVRIT}


def provider_name_to_id(provider: str | None) -> int:
    normalized = (provider or "").strip().lower()
    if not normalized:
        return PROVIDER_ID_NONE
    if normalized == "drand":
        return PROVIDER_ID_DRAND
    if normalized == "aavrit":
        return PROVIDER_ID_AAVRIT
    raise ValueError(f"Unsupported time-capsule provider: {provider}")


def provider_id_to_name(provider_id: int) -> str | None:
    if provider_id == PROVIDER_ID_NONE:
        return None
    if provider_id == PROVIDER_ID_DRAND:
        return "drand"
    if provider_id == PROVIDER_ID_AAVRIT:
        return "aavrit"
    raise ValueError(f"Unsupported provider_id: {provider_id}")


def build_header_bytes(*, archive_mode: int, provider_id: int) -> bytes:
    if archive_mode not in _VALID_ARCHIVE_MODES:
        raise ValueError(f"Invalid archive_mode: {archive_mode}")
    if provider_id not in _VALID_PROVIDER_IDS:
        raise ValueError(f"Invalid provider_id: {provider_id}")

    return struct.pack(
        ">4sBBBB",
        HEADER_MAGIC,
        HEADER_FORMAT_VERSION,
        archive_mode,
        HEADER_STRUCTURE_ID,
        provider_id,
    )


def parse_header_bytes(header_bytes: bytes) -> dict:
    if not isinstance(header_bytes, (bytes, bytearray)):
        raise ValueError("Invalid Avk header: header must be bytes")
    if len(header_bytes) != HEADER_SIZE:
        raise ValueError("Invalid Avk header: header size is out of bounds")

    magic, format_version, archive_mode, structure_id, provider_id = struct.unpack(
        ">4sBBBB",
        bytes(header_bytes),
    )

    if magic != HEADER_MAGIC:
        raise ValueError("Invalid Avk header: magic mismatch")
    if format_version != HEADER_FORMAT_VERSION:
        raise ValueError("Invalid Avk header: unsupported format version")
    if archive_mode not in _VALID_ARCHIVE_MODES:
        raise ValueError("Invalid Avk header: archive mode is invalid")
    if structure_id != HEADER_STRUCTURE_ID:
        raise ValueError("Invalid Avk header: structure identifier is invalid")
    if provider_id not in _VALID_PROVIDER_IDS:
        raise ValueError("Invalid Avk header: provider identifier is invalid")

    return {
        "magic": magic.decode("ascii"),
        "format_version": format_version,
        "archive_mode": archive_mode,
        "structure_id": structure_id,
        "provider_id": provider_id,
        "provider": provider_id_to_name(provider_id),
        "aad": bytes(header_bytes),
    }


def encode_header_tag_value(header_bytes: bytes) -> str:
    """Encode the fixed archive header for storage in keychain.pgn tags."""
    parse_header_bytes(header_bytes)
    return base64.b64encode(bytes(header_bytes)).decode("ascii")


def decode_header_tag_value(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("Invalid Avk keychain header: missing header tag")
    try:
        header_bytes = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("Invalid Avk keychain header: malformed header tag") from exc
    parse_header_bytes(header_bytes)
    return header_bytes


def _replace_or_insert_tag(keychain_pgn: str, tag_name: str, value: str) -> str:
    tag_line = f'[{tag_name} "{value}"]'
    lines = keychain_pgn.splitlines()
    replaced = False
    output: list[str] = []
    pattern = rf'^\[{re.escape(tag_name)}\s+"[^"]*"\]$'
    for line in lines:
        if re.match(pattern, line.strip()):
            output.append(tag_line)
            replaced = True
        else:
            output.append(line)
    if replaced:
        return "\n".join(output) + ("\n" if keychain_pgn.endswith("\n") else "")

    insert_at = 0
    while insert_at < len(output) and output[insert_at].startswith("["):
        insert_at += 1
    output.insert(insert_at, tag_line)
    return "\n".join(output) + ("\n" if keychain_pgn.endswith("\n") else "")


def _extract_tag_value(keychain_pgn: str, tag_name: str) -> str | None:
    pattern = rf'^\[{re.escape(tag_name)}\s+"([^"]+)"\]$'
    for line in keychain_pgn.splitlines():
        match = re.match(pattern, line.strip())
        if match:
            return match.group(1)
    return None


def _encode_route_bool(value: bool) -> str:
    return "1" if value else "0"


def _decode_route_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    if value == "1":
        return True
    if value == "0":
        return False
    raise ValueError("Invalid Avk route hint boolean")


def attach_public_route_tags_to_keychain_pgn(
    keychain_pgn: str,
    *,
    requires_password: bool,
    requires_keyphrase: bool,
    requires_pqc: bool,
    pqc_storage_mode: str | None = None,
    unlock_timestamp: int | None = None,
    drand_round: int | None = None,
    keyphrase_wordlist_id: str | None = None,
    aavrit_route: dict | None = None,
    time_key_gated: bool = False,
) -> str:
    """Attach public non-secret routing hints to keychain.pgn."""
    if pqc_storage_mode is not None and pqc_storage_mode not in PQC_STORAGE_MODES:
        raise ValueError("Invalid PQC storage mode route hint")
    if pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED and not requires_pqc:
        raise ValueError("Embedded PQC storage mode requires PQC to be enabled")
    route_version = PUBLIC_ROUTE_FORMAT_VERSION_V3 if aavrit_route else (
        PUBLIC_ROUTE_FORMAT_VERSION_V2 if pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED else PUBLIC_ROUTE_FORMAT_VERSION_V1
    )
    output = keychain_pgn
    output = _replace_or_insert_tag(output, KEYCHAIN_ROUTE_VERSION_TAG, route_version)
    output = _replace_or_insert_tag(output, KEYCHAIN_REQUIRE_PASSWORD_TAG, _encode_route_bool(requires_password))
    output = _replace_or_insert_tag(output, KEYCHAIN_REQUIRE_KEYPHRASE_TAG, _encode_route_bool(requires_keyphrase))
    output = _replace_or_insert_tag(output, KEYCHAIN_REQUIRE_PQC_TAG, _encode_route_bool(requires_pqc))
    if pqc_storage_mode == PQC_STORAGE_MODE_EMBEDDED or (route_version == PUBLIC_ROUTE_FORMAT_VERSION_V3 and requires_pqc):
        output = _replace_or_insert_tag(output, KEYCHAIN_PQC_STORAGE_MODE_TAG, pqc_storage_mode)
    if unlock_timestamp is not None:
        output = _replace_or_insert_tag(output, KEYCHAIN_UNLOCK_TIMESTAMP_TAG, str(int(unlock_timestamp)))
    if drand_round is not None:
        output = _replace_or_insert_tag(output, KEYCHAIN_DRAND_ROUND_TAG, str(int(drand_round)))
    if keyphrase_wordlist_id:
        output = _replace_or_insert_tag(output, KEYCHAIN_KEYPHRASE_WORDLIST_TAG, keyphrase_wordlist_id)
    if aavrit_route is not None:
        required = {"protocol", "server_url", "escrow_id", "capability", "authority"}
        if not isinstance(aavrit_route, dict) or set(aavrit_route) != required:
            raise ValueError("Invalid Aavrit public route")
        encoded_route = json.dumps(aavrit_route, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded_route) > MAX_AAVRIT_ROUTE_BYTES:
            raise ValueError("Aavrit public route is oversized")
        output = _replace_or_insert_tag(
            output,
            KEYCHAIN_AAVRIT_ROUTE_TAG,
            base64.urlsafe_b64encode(encoded_route).rstrip(b"=").decode("ascii"),
        )
    if time_key_gated:
        if aavrit_route is None:
            raise ValueError("Time-gated keychain route requires Aavrit routing material")
        output = _replace_or_insert_tag(output, KEYCHAIN_TIME_GATED_TAG, "1")
    return output


def extract_public_route_tags_from_keychain_pgn(keychain_pgn: str) -> dict:
    """Read public non-secret routing hints from keychain.pgn."""
    route_version = _extract_tag_value(keychain_pgn, KEYCHAIN_ROUTE_VERSION_TAG)
    if route_version is None:
        return {
            "available": False,
            "format_version": None,
            "requires_password": None,
            "requires_keyphrase": None,
            "requires_pqc": None,
            "pqc_storage_mode": None,
            "unlock_timestamp": None,
            "drand_round": None,
            "keyphrase_wordlist_id": None,
            "aavrit_route": None,
            "time_key_gated": False,
        }
    if route_version not in {PUBLIC_ROUTE_FORMAT_VERSION_V1, PUBLIC_ROUTE_FORMAT_VERSION_V2, PUBLIC_ROUTE_FORMAT_VERSION_V3}:
        raise ValueError("Unsupported Avk public route hint version")

    unlock_timestamp_raw = _extract_tag_value(keychain_pgn, KEYCHAIN_UNLOCK_TIMESTAMP_TAG)
    drand_round_raw = _extract_tag_value(keychain_pgn, KEYCHAIN_DRAND_ROUND_TAG)
    requires_pqc = _decode_route_bool(_extract_tag_value(keychain_pgn, KEYCHAIN_REQUIRE_PQC_TAG))
    pqc_storage_mode = None
    if route_version in {PUBLIC_ROUTE_FORMAT_VERSION_V2, PUBLIC_ROUTE_FORMAT_VERSION_V3}:
        if requires_pqc:
            pqc_storage_mode = _extract_tag_value(keychain_pgn, KEYCHAIN_PQC_STORAGE_MODE_TAG)
            if pqc_storage_mode not in PQC_STORAGE_MODES:
                raise ValueError("Invalid Avk PQC storage mode route hint")
    elif requires_pqc:
        pqc_storage_mode = PQC_STORAGE_MODE_EXTERNAL

    aavrit_route = None
    if route_version == PUBLIC_ROUTE_FORMAT_VERSION_V3:
        encoded_route = _extract_tag_value(keychain_pgn, KEYCHAIN_AAVRIT_ROUTE_TAG)
        if not encoded_route:
            raise ValueError("Aavrit public route is missing")
        try:
            raw_route = base64.urlsafe_b64decode(encoded_route + "=" * (-len(encoded_route) % 4))
            if len(raw_route) > MAX_AAVRIT_ROUTE_BYTES:
                raise ValueError("Aavrit public route is oversized")
            aavrit_route = json.loads(raw_route.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Aavrit public route is malformed") from exc
        required = {"protocol", "server_url", "escrow_id", "capability", "authority"}
        if not isinstance(aavrit_route, dict) or set(aavrit_route) != required:
            raise ValueError("Aavrit public route is invalid")
    time_key_gated = _decode_route_bool(_extract_tag_value(keychain_pgn, KEYCHAIN_TIME_GATED_TAG)) or False
    if time_key_gated and aavrit_route is None:
        raise ValueError("Time-gated keychain is missing Aavrit routing material")

    return {
        "available": True,
        "format_version": route_version,
        "requires_password": _decode_route_bool(_extract_tag_value(keychain_pgn, KEYCHAIN_REQUIRE_PASSWORD_TAG)),
        "requires_keyphrase": _decode_route_bool(_extract_tag_value(keychain_pgn, KEYCHAIN_REQUIRE_KEYPHRASE_TAG)),
        "requires_pqc": requires_pqc,
        "pqc_storage_mode": pqc_storage_mode,
        "unlock_timestamp": int(unlock_timestamp_raw) if unlock_timestamp_raw else None,
        "drand_round": int(drand_round_raw) if drand_round_raw else None,
        "keyphrase_wordlist_id": _extract_tag_value(keychain_pgn, KEYCHAIN_KEYPHRASE_WORDLIST_TAG),
        "aavrit_route": aavrit_route,
        "time_key_gated": time_key_gated,
    }


def attach_header_to_keychain_pgn(keychain_pgn: str, header_bytes: bytes) -> str:
    """Store the public routing header inside keychain.pgn as a PGN tag."""
    header_value = encode_header_tag_value(header_bytes)
    return _replace_or_insert_tag(keychain_pgn, KEYCHAIN_HEADER_TAG, header_value)


def extract_header_from_keychain_pgn(keychain_pgn: str) -> bytes:
    """Read the public routing header from keychain.pgn."""
    header_value = _extract_tag_value(keychain_pgn, KEYCHAIN_HEADER_TAG)
    if header_value is not None:
        return decode_header_tag_value(header_value)
    raise ValueError("Invalid .avk container: keychain.pgn is missing Avikal header")


def validate_metadata_against_header(header_info: dict, metadata: dict) -> None:
    archive_mode = header_info.get("archive_mode")
    provider = header_info.get("provider")

    archive_type = metadata.get("archive_type")
    metadata_provider = metadata.get("timecapsule_provider")

    if archive_mode == ARCHIVE_MODE_MULTI:
        if archive_type != "multi_file":
            raise ValueError("Header and metadata disagree about archive mode")
    elif archive_type not in {None, "single_file"}:
        raise ValueError("Header and metadata disagree about archive mode")

    if provider is None:
        if metadata_provider is not None:
            raise ValueError("Header and metadata disagree about provider")
        return

    if provider != metadata_provider:
        raise ValueError("Header and metadata disagree about provider")
