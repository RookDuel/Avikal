"""Shared keychain unlock flow for legacy and PQC-gated archives.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..chess_metadata import (
    CHESS_ENVELOPE_PQC_PROTECTED,
    decode_chess_to_metadata_enhanced,
    inspect_chess_keychain_envelope,
)
from ..format.header import extract_public_route_tags_from_keychain_pgn
from ..format.container import open_avk_payload_stream
from ..format.header import parse_header_bytes, validate_metadata_against_header
from ..format.metadata_pack import (
    FEATURE_ASSURED_REPORTS,
    FEATURE_INDEXED_PAYLOAD,
    FEATURE_MANDATORY_SIGNATURE,
    METADATA_FORMAT_VERSION_ASSURED,
)
from ..security.archive_signature import (
    build_archive_signature_evidence,
    extract_archive_signature,
    verify_archive_signature,
)
from ..security.pqc_keyfile import (
    PQC_STORAGE_MODE_EMBEDDED,
    read_embedded_pqc_blob,
    read_pqc_keyfile,
)
from ..security.pqc_provider import decapsulate_pqc_archive_material
from ..security.crypto import secure_zero
from avikal_backend.version import __version__


SUPPORTED_REQUIRED_FEATURES = FEATURE_ASSURED_REPORTS | FEATURE_INDEXED_PAYLOAD | FEATURE_MANDATORY_SIGNATURE


@dataclass
class KeychainUnlockResult:
    metadata: dict[str, Any]
    pqc_resolved: bool = False
    pqc_shared_secret: bytes | None = None
    pqc_private_bundle: dict[str, Any] | None = None
    expected_payload_sha256: bytes | None = None
    signed_payload_size: int | None = None
    archive_signature_verified: bool = False


def read_archive_keychain_metadata(
    avk_filepath: str,
    *,
    password: str | None,
    keyphrase: list | None,
    pqc_keyfile_path: str | None = None,
    pqc_keyfile_password: str | None = None,
    skip_timelock: bool = True,
    progress_tracker=None,
    time_key: bytes | None = None,
) -> KeychainUnlockResult:
    """Read and fully verify archive metadata without materializing the payload."""
    with open_avk_payload_stream(avk_filepath) as (header_bytes, keychain_pgn, _payload_stream, embedded_pqc_blob):
        result = unlock_archive_keychain(
            keychain_pgn=keychain_pgn,
            header_bytes=header_bytes,
            password=password,
            keyphrase=keyphrase,
            embedded_pqc_blob=embedded_pqc_blob,
            pqc_keyfile_path=pqc_keyfile_path,
            pqc_keyfile_password=pqc_keyfile_password,
            skip_timelock=skip_timelock,
            progress_tracker=progress_tracker,
            time_key=time_key,
        )
        validate_metadata_against_header(parse_header_bytes(header_bytes), result.metadata)
        if result.signed_payload_size is not None:
            actual_payload_size = getattr(_payload_stream, "avikal_file_size", None)
            if actual_payload_size != result.signed_payload_size:
                raise ValueError("Archive signature payload size binding failed")
        if result.pqc_shared_secret:
            secure_zero(result.pqc_shared_secret)
            result.pqc_shared_secret = None
        result.pqc_private_bundle = None
        return result


def unlock_archive_keychain(
    *,
    keychain_pgn: str,
    header_bytes: bytes,
    password: str | None,
    keyphrase: list | None,
    embedded_pqc_blob: bytes | None,
    pqc_keyfile_path: str | None,
    pqc_keyfile_password: str | None,
    skip_timelock: bool,
    progress_tracker=None,
    time_key: bytes | None = None,
) -> KeychainUnlockResult:
    """Unlock a keychain once, resolving PQC before metadata for the new envelope."""

    def progress(description: str, fraction: float) -> None:
        if progress_tracker is not None:
            progress_tracker.update("metadata", description, fraction)

    progress("Converting PGN moves to metadata bytes", 0.10)

    def decoder_progress(description: str, fraction: float) -> None:
        progress(description, 0.10 + (max(0.0, min(1.0, fraction)) * 0.18))

    decoded = inspect_chess_keychain_envelope(keychain_pgn, progress_callback=decoder_progress)
    route = extract_public_route_tags_from_keychain_pgn(keychain_pgn)
    time_key_gated = bool(route.get("time_key_gated"))
    if decoded["version"] != CHESS_ENVELOPE_PQC_PROTECTED:
        metadata = decode_chess_to_metadata_enhanced(
            keychain_pgn,
            password,
            keyphrase,
            skip_timelock=skip_timelock,
            aad=header_bytes,
            progress_tracker=progress_tracker,
            decoded_envelope=decoded,
            time_key=time_key,
            time_key_gated=time_key_gated,
        )
        if metadata.get("version") == METADATA_FORMAT_VERSION_ASSURED:
            _validate_reader_compatibility(metadata)
            _validate_aavrit_route_binding(metadata, route)
            progress("Verifying mandatory archive signatures", 0.86)
            signature = extract_archive_signature(keychain_pgn, required=True)
            signed = verify_archive_signature(
                signature,
                public_bundle=None,
                header_bytes=header_bytes,
                embedded_pqc_blob=embedded_pqc_blob,
                pqc_algorithm=None,
                pqc_key_id=None,
                pqc_storage_mode=None,
            )
            _validate_signed_metadata_binding(metadata, signed)
            metadata["archive_integrity"] = _integrity_report(signature, signed)
            progress("Archive signatures verified", 1.0)
            return KeychainUnlockResult(
                metadata=metadata,
                expected_payload_sha256=bytes.fromhex(signed["payload_sha256"]),
                signed_payload_size=signed["payload_size"],
                archive_signature_verified=True,
            )
        metadata["archive_integrity"] = {"status": "legacy_unsigned", "verified": False}
        return KeychainUnlockResult(metadata=metadata)

    bootstrap = decoded.get("pqc_bootstrap")
    if not isinstance(bootstrap, dict) or not bootstrap.get("signature_required"):
        raise ValueError("PQC keychain signature requirement is missing")

    if not route.get("available") or route.get("requires_pqc") is not True:
        raise ValueError("PQC keychain route declaration is missing")
    if route.get("pqc_storage_mode") != bootstrap["storage_mode"]:
        raise ValueError("PQC keychain route and bootstrap disagree")

    progress("Unlocking PQC keychain material", 0.32)
    if bootstrap["storage_mode"] == PQC_STORAGE_MODE_EMBEDDED:
        if embedded_pqc_blob is None:
            raise ValueError("PQC keychain requires the embedded pqc.enc member")
        pqc_bundle = read_embedded_pqc_blob(
            embedded_pqc_blob,
            password=password,
            keyphrase=keyphrase,
            header_aad=header_bytes,
            expected_key_id=bootstrap["key_id"],
            expected_algorithm=bootstrap["algorithm"],
        )
    else:
        if embedded_pqc_blob is not None:
            raise ValueError("External PQC keychain contains an unexpected pqc.enc member")
        pqc_bundle = read_pqc_keyfile(
            pqc_keyfile_path,
            password=password,
            keyphrase=keyphrase,
            expected_key_id=bootstrap["key_id"],
            expected_algorithm=bootstrap["algorithm"],
            pqc_keyfile_password=pqc_keyfile_password,
        )

    progress("Verifying and decapsulating PQC keychain", 0.48)
    shared_secret = decapsulate_pqc_archive_material(
        private_bundle=pqc_bundle["private_bundle"],
        public_bundle=pqc_bundle["public_bundle"],
        pqc_ciphertext=bootstrap["pqc_ciphertext"],
        expected_key_id=bootstrap["key_id"],
    )

    progress("Decrypting PQC-gated chess metadata", 0.64)
    metadata = decode_chess_to_metadata_enhanced(
        keychain_pgn,
        password,
        keyphrase,
        skip_timelock=skip_timelock,
        aad=header_bytes,
        progress_tracker=progress_tracker,
        pqc_shared_secret=shared_secret,
        decoded_envelope=decoded,
        time_key=time_key,
        time_key_gated=time_key_gated,
    )
    _validate_metadata_bootstrap_binding(metadata, bootstrap)
    _validate_reader_compatibility(metadata)
    _validate_aavrit_route_binding(metadata, route)

    progress("Verifying archive-level PQC signatures", 0.86)
    signature = extract_archive_signature(keychain_pgn, required=True)
    signed = verify_archive_signature(
        signature,
        public_bundle=pqc_bundle["public_bundle"],
        header_bytes=header_bytes,
        embedded_pqc_blob=embedded_pqc_blob,
        pqc_algorithm=bootstrap["algorithm"],
        pqc_key_id=bootstrap["key_id"],
        pqc_storage_mode=bootstrap["storage_mode"],
    )
    if signed["archive_id"] != bootstrap["archive_id"]:
        raise ValueError("Archive signature and PQC keychain identifier disagree")
    if signed["created_at_utc"] != bootstrap["created_at"]:
        raise ValueError("Archive signature and PQC keychain creation time disagree")

    _validate_signed_metadata_binding(metadata, signed)
    metadata["archive_integrity"] = _integrity_report(signature, signed)

    progress("PQC keychain and archive signatures verified", 1.0)
    return KeychainUnlockResult(
        metadata=metadata,
        pqc_resolved=True,
        pqc_shared_secret=shared_secret,
        pqc_private_bundle=pqc_bundle["private_bundle"],
        expected_payload_sha256=bytes.fromhex(signed["payload_sha256"]),
        signed_payload_size=signed["payload_size"],
        archive_signature_verified=True,
    )


def _validate_aavrit_route_binding(metadata: dict[str, Any], route: dict[str, Any]) -> None:
    if metadata.get("timecapsule_provider") != "aavrit":
        if route.get("aavrit_route") is not None or route.get("time_key_gated"):
            raise ValueError("Non-Aavrit metadata contains an Aavrit public route")
        return
    public = route.get("aavrit_route")
    if not route.get("time_key_gated") or not isinstance(public, dict):
        raise ValueError("Aavrit metadata is missing its authenticated release route")
    authority = public.get("authority")
    if not isinstance(authority, dict):
        raise ValueError("Aavrit authority bundle is missing")
    expected = {
        "file_id": public.get("escrow_id"),
        "server_url": public.get("server_url"),
        "aavrit_server_key_id": authority.get("authority_id"),
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise ValueError(f"Aavrit public route and protected {field} disagree")


def _validate_metadata_bootstrap_binding(metadata: dict[str, Any], bootstrap: dict[str, Any]) -> None:
    if not bool(metadata.get("pqc_required")):
        raise ValueError("PQC-gated keychain metadata disabled required protection")
    expected = {
        "pqc_algorithm": bootstrap["algorithm"],
        "pqc_key_id": bootstrap["key_id"],
        "pqc_storage_mode": bootstrap["storage_mode"],
        "pqc_ciphertext": bootstrap["pqc_ciphertext"],
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise ValueError(f"PQC keychain metadata binding failed for {field}")


def _version_tuple(value: str) -> tuple[int, int, int]:
    try:
        parts = value.split("-", 1)[0].split("+", 1)[0].split(".")
        if len(parts) != 3:
            raise ValueError
        return tuple(int(part) for part in parts)  # type: ignore[return-value]
    except Exception as exc:
        raise ValueError("Archive compatibility version is malformed") from exc


def _validate_reader_compatibility(metadata: dict[str, Any]) -> None:
    if metadata.get("version") != METADATA_FORMAT_VERSION_ASSURED:
        return
    required = int(metadata.get("required_features") or 0)
    unknown = required & ~SUPPORTED_REQUIRED_FEATURES
    if unknown:
        raise ValueError(f"Archive requires unsupported feature flags: 0x{unknown:x}. Update Avikal.")
    minimum = metadata.get("minimum_reader_version")
    if _version_tuple(minimum) > _version_tuple(__version__):
        raise ValueError(f"Archive requires Avikal {minimum} or newer. Update Avikal before opening it.")
    metadata["update_recommended"] = _version_tuple(metadata["created_with_version"]) > _version_tuple(__version__)


def _validate_signed_metadata_binding(metadata: dict[str, Any], signed: dict[str, Any]) -> None:
    if signed.get("version") < 2:
        return
    expected = {
        "created_with_version": metadata.get("created_with_version"),
        "minimum_reader_version": metadata.get("minimum_reader_version"),
        "required_features": metadata.get("required_features"),
        "content_index_sha256": bytes(metadata.get("content_index_hash") or b"").hex(),
        "canonical_manifest_sha256": bytes(metadata.get("manifest_hash") or b"").hex(),
        "payload_merkle_root": bytes(metadata.get("payload_merkle_root") or b"").hex(),
    }
    for field, value in expected.items():
        if signed.get(field) != value:
            raise ValueError(f"Archive signature metadata binding failed for {field}")


def _integrity_report(signature: dict[str, Any], signed: dict[str, Any]) -> dict[str, Any]:
    public_bundle = signature.get("public_bundle") or {}
    identity_kind = signature.get("identity_kind") or "archive"
    algorithms = public_bundle.get("algorithms") if isinstance(public_bundle.get("algorithms"), dict) else {}
    timestamp_evidence = signed.get("timestamp_evidence") if isinstance(signed.get("timestamp_evidence"), dict) else {}
    return {
        "status": "verified",
        "verified": True,
        "scheme": "ML-DSA+SLH-DSA",
        "ml_dsa_verified": True,
        "slh_dsa_verified": True,
        "keychain_binding_verified": True,
        "manifest_signature_verified": True,
        "embedded_pqc_binding_verified": True,
        "archive_id": signed["archive_id"],
        "created_at_utc": signed["created_at_utc"],
        "payload_sha256": signed["payload_sha256"],
        "content_index_sha256": signed.get("content_index_sha256"),
        "canonical_manifest_sha256": signed.get("canonical_manifest_sha256"),
        "payload_merkle_root": signed.get("payload_merkle_root"),
        "identity_id": public_bundle.get("identity_id") or signed.get("signing_identity_id"),
        "identity_fingerprint": public_bundle.get("identity_id") or signed.get("signing_identity_id"),
        "identity_kind": identity_kind,
        "identity_trust": "archive_scoped" if identity_kind == "archive" else "valid_untrusted",
        "algorithms": {
            "ml_dsa": algorithms.get("ml_dsa"),
            "slh_dsa": algorithms.get("slh_dsa"),
        },
        "timestamp_status": signed.get("timestamp_status", "signed_local_time"),
        "timestamp_authority": timestamp_evidence.get("tsa_url"),
        "timestamp_imprint_sha256": timestamp_evidence.get("imprint_sha256"),
        "verification_evidence": build_archive_signature_evidence(signature),
    }
