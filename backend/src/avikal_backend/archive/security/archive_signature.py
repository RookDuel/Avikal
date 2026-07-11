"""Canonical archive-level PQC signatures stored in keychain.pgn.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, BinaryIO

from ..format.header import _replace_or_insert_tag
from .pqc_provider import sign_pqc_archive_manifest, verify_pqc_archive_manifest


ARCHIVE_SIGNATURE_FORMAT = "avikal-archive-signature"
ARCHIVE_SIGNATURE_VERSION = 2
SUPPORTED_ARCHIVE_SIGNATURE_VERSIONS = {1, 2}
ARCHIVE_SIGNATURE_DOMAIN = "AvikalArchiveSignatureV1"

TAG_SIGNATURE_FORMAT = "AvikalArchiveSignatureFormat"
TAG_SIGNATURE_MANIFEST = "AvikalArchiveSignatureManifest"
TAG_SIGNATURE_ML_DSA = "AvikalArchiveMLDSA"
TAG_SIGNATURE_SLH_DSA = "AvikalArchiveSLHDSA"
TAG_SIGNING_PUBLIC_BUNDLE = "AvikalArchiveSigningPublic"
TAG_SIGNING_IDENTITY_KIND = "AvikalArchiveSigningIdentityKind"
_SIGNATURE_TAGS = {
    TAG_SIGNATURE_FORMAT,
    TAG_SIGNATURE_MANIFEST,
    TAG_SIGNATURE_ML_DSA,
    TAG_SIGNATURE_SLH_DSA,
    TAG_SIGNING_PUBLIC_BUNDLE,
    TAG_SIGNING_IDENTITY_KIND,
}
_BASE_SIGNATURE_TAGS = {
    TAG_SIGNATURE_FORMAT,
    TAG_SIGNATURE_MANIFEST,
    TAG_SIGNATURE_ML_DSA,
    TAG_SIGNATURE_SLH_DSA,
}

MAX_MANIFEST_BYTES = 64 * 1024
MAX_ML_DSA_SIGNATURE_BYTES = 16 * 1024
MAX_SLH_DSA_SIGNATURE_BYTES = 128 * 1024
HASH_BYTES = 32


class HashingWriter:
    """Forward writes while hashing the exact member bytes."""

    def __init__(self, target: BinaryIO):
        self._target = target
        self._digest = hashlib.sha256()
        self.bytes_written = 0

    def write(self, data: bytes) -> int:
        value = bytes(data)
        written = self._target.write(value)
        if written is None:
            written = len(value)
        if written != len(value):
            raise OSError("Short write while creating signed payload")
        self._digest.update(value)
        self.bytes_written += written
        return written

    def flush(self) -> None:
        if hasattr(self._target, "flush"):
            self._target.flush()

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _canonical_json(document: dict[str, Any]) -> bytes:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if not encoded or len(encoded) > MAX_MANIFEST_BYTES:
        raise ValueError("Archive signature manifest size is out of bounds")
    return encoded


def build_timestamp_statement(
    *, archive_id: str, created_at: int, payload_sha256: str, keychain_core_pgn: str,
    content_index_sha256: str, canonical_manifest_sha256: str, payload_merkle_root: str,
) -> bytes:
    """Build the immutable statement submitted to an optional RFC 3161 TSA."""
    return _canonical_json({
        "archive_id": archive_id,
        "canonical_manifest_sha256": canonical_manifest_sha256,
        "content_index_sha256": content_index_sha256,
        "created_at_utc": created_at,
        "domain": "AvikalTimestampStatementV1",
        "keychain_core_sha256": sha256_hex(keychain_core_pgn.encode("utf-8")),
        "payload_merkle_root": payload_merkle_root,
        "payload_sha256": payload_sha256,
        "version": 1,
    })


def build_archive_signature_manifest(
    *,
    header_bytes: bytes,
    keychain_core_pgn: str,
    payload_sha256: str,
    payload_size: int,
    embedded_pqc_blob: bytes | None,
    pqc_algorithm: str,
    pqc_key_id: str,
    pqc_storage_mode: str,
    archive_id: str,
    created_at: int,
    created_with_version: str | None = None,
    minimum_reader_version: str | None = None,
    required_features: int = 0,
    content_index_sha256: str | None = None,
    canonical_manifest_sha256: str | None = None,
    payload_merkle_root: str | None = None,
    signing_identity_id: str | None = None,
    timestamp_statement: bytes | None = None,
    timestamp_evidence: dict[str, Any] | None = None,
) -> bytes:
    """Build the deterministic manifest signed by both PQC signature schemes."""
    _require_hex(payload_sha256, "payload SHA-256", HASH_BYTES * 2)
    if pqc_key_id:
        _require_hex(pqc_key_id, "PQC key identifier", HASH_BYTES * 2)
    _require_hex(archive_id, "archive identifier", 32)
    if not isinstance(payload_size, int) or payload_size <= 0:
        raise ValueError("Signed payload size must be positive")
    if not isinstance(created_at, int) or created_at <= 0:
        raise ValueError("Signed creation time is invalid")
    if not isinstance(keychain_core_pgn, str) or not keychain_core_pgn:
        raise ValueError("Signed keychain core is missing")

    embedded_digest = sha256_hex(embedded_pqc_blob) if embedded_pqc_blob is not None else None
    document = {
        "archive_id": archive_id,
        "created_at_utc": created_at,
        "domain": ARCHIVE_SIGNATURE_DOMAIN,
        "embedded_pqc_sha256": embedded_digest,
        "embedded_pqc_size": len(embedded_pqc_blob) if embedded_pqc_blob is not None else 0,
        "format": ARCHIVE_SIGNATURE_FORMAT,
        "header": base64.b64encode(bytes(header_bytes)).decode("ascii"),
        "keychain_core_sha256": sha256_hex(keychain_core_pgn.encode("utf-8")),
        "payload_sha256": payload_sha256,
        "payload_size": payload_size,
        "pqc_algorithm": pqc_algorithm,
        "pqc_key_id": pqc_key_id,
        "pqc_storage_mode": pqc_storage_mode,
        "version": ARCHIVE_SIGNATURE_VERSION,
    }
    if created_with_version is not None:
        document.update(
            {
                "content_index_sha256": content_index_sha256,
                "canonical_manifest_sha256": canonical_manifest_sha256,
                "created_with_version": created_with_version,
                "minimum_reader_version": minimum_reader_version,
                "payload_merkle_root": payload_merkle_root,
                "required_features": int(required_features),
                "signing_identity_id": signing_identity_id,
                "timestamp_evidence": timestamp_evidence or {"status": "unavailable"},
                "timestamp_statement": base64.b64encode(bytes(timestamp_statement or b"")).decode("ascii"),
            }
        )
        _require_hex(content_index_sha256, "content index SHA-256", 64)
        _require_hex(canonical_manifest_sha256, "canonical manifest SHA-256", 64)
        _require_hex(payload_merkle_root, "payload Merkle root", 64)
        _require_hex(signing_identity_id, "signing identity identifier", 64)
        if not timestamp_statement:
            raise ValueError("Archive timestamp statement is missing")
    return _canonical_json(document)


def sign_and_attach_archive_manifest(
    keychain_core_pgn: str,
    *,
    manifest: bytes,
    private_bundle: dict[str, Any],
    public_bundle: dict[str, Any] | None = None,
    identity_kind: str = "archive",
) -> str:
    """Sign the canonical manifest and attach bounded PGN signature tags."""
    signatures = sign_pqc_archive_manifest(private_bundle=private_bundle, manifest=manifest)
    output = keychain_core_pgn
    output = _replace_or_insert_tag(output, TAG_SIGNATURE_FORMAT, f"{ARCHIVE_SIGNATURE_FORMAT}:{ARCHIVE_SIGNATURE_VERSION}")
    output = _replace_or_insert_tag(output, TAG_SIGNATURE_MANIFEST, base64.b64encode(manifest).decode("ascii"))
    output = _replace_or_insert_tag(output, TAG_SIGNATURE_ML_DSA, signatures["ml_dsa"])
    output = _replace_or_insert_tag(output, TAG_SIGNATURE_SLH_DSA, signatures["slh_dsa"])
    if public_bundle is not None:
        public_bytes = _canonical_json(public_bundle)
        output = _replace_or_insert_tag(output, TAG_SIGNING_PUBLIC_BUNDLE, base64.b64encode(public_bytes).decode("ascii"))
        if identity_kind not in {"archive", "creator"}:
            raise ValueError("Unsupported archive signing identity kind")
        output = _replace_or_insert_tag(output, TAG_SIGNING_IDENTITY_KIND, identity_kind)
    return output


def strip_archive_signature_tags(keychain_pgn: str) -> str:
    """Return the exact unsigned PGN core used by the canonical manifest."""
    lines = keychain_pgn.splitlines()
    retained = []
    pattern = re.compile(r"^\[([A-Za-z0-9_]+)\s+\"")
    for line in lines:
        match = pattern.match(line.strip())
        if match and match.group(1) in _SIGNATURE_TAGS:
            continue
        retained.append(line)
    result = "\n".join(retained)
    if keychain_pgn.endswith("\n"):
        result += "\n"
    return result


def extract_archive_signature(keychain_pgn: str, *, required: bool) -> dict[str, Any] | None:
    """Parse bounded signature tags without trusting their content."""
    values = {name: _extract_tag(keychain_pgn, name) for name in _SIGNATURE_TAGS}
    present = [values[name] is not None for name in _BASE_SIGNATURE_TAGS]
    if not any(present):
        if required:
            raise ValueError("Archive signature is required but missing")
        return None
    if not all(present):
        raise ValueError("Archive signature envelope is incomplete")
    format_value = values[TAG_SIGNATURE_FORMAT]
    try:
        signature_version = int(str(format_value).rsplit(":", 1)[1])
    except Exception as exc:
        raise ValueError("Unsupported archive signature format") from exc
    if not str(format_value).startswith(f"{ARCHIVE_SIGNATURE_FORMAT}:") or signature_version not in SUPPORTED_ARCHIVE_SIGNATURE_VERSIONS:
        raise ValueError("Unsupported archive signature format")

    manifest = _decode_b64(values[TAG_SIGNATURE_MANIFEST], "archive signature manifest", MAX_MANIFEST_BYTES)
    ml_dsa = _decode_b64(values[TAG_SIGNATURE_ML_DSA], "ML-DSA archive signature", MAX_ML_DSA_SIGNATURE_BYTES)
    slh_dsa = _decode_b64(values[TAG_SIGNATURE_SLH_DSA], "SLH-DSA archive signature", MAX_SLH_DSA_SIGNATURE_BYTES)
    document = _validate_manifest(manifest)
    signing_public_bundle = None
    identity_kind = None
    public_value = values.get(TAG_SIGNING_PUBLIC_BUNDLE)
    kind_value = values.get(TAG_SIGNING_IDENTITY_KIND)
    if signature_version >= 2:
        if public_value is None or kind_value not in {"archive", "creator"}:
            raise ValueError("Archive signing identity envelope is incomplete")
        public_bytes = _decode_b64(public_value, "archive signing public bundle", 64 * 1024)
        try:
            signing_public_bundle = json.loads(public_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Archive signing public bundle is malformed") from exc
        if _canonical_json(signing_public_bundle) != public_bytes:
            raise ValueError("Archive signing public bundle is not canonical")
        identity_kind = kind_value
    return {
        "manifest": manifest,
        "document": document,
        "signatures": {
            "ml_dsa": base64.b64encode(ml_dsa).decode("ascii"),
            "slh_dsa": base64.b64encode(slh_dsa).decode("ascii"),
        },
        "keychain_core_pgn": strip_archive_signature_tags(keychain_pgn),
        "public_bundle": signing_public_bundle,
        "identity_kind": identity_kind,
        "signature_version": signature_version,
    }


def build_archive_signature_evidence(signature: dict[str, Any]) -> dict[str, Any]:
    """Return bounded public evidence suitable for an exported assurance report."""
    manifest = signature.get("manifest")
    signatures = signature.get("signatures")
    public_bundle = signature.get("public_bundle")
    if not isinstance(manifest, (bytes, bytearray)) or not isinstance(signatures, dict) or not isinstance(public_bundle, dict):
        raise ValueError("Archive signature evidence is incomplete")
    _validate_manifest(bytes(manifest))
    return {
        "format": ARCHIVE_SIGNATURE_FORMAT,
        "signature_version": int(signature.get("signature_version") or 0),
        "identity_kind": signature.get("identity_kind"),
        "manifest": base64.b64encode(bytes(manifest)).decode("ascii"),
        "public_bundle": public_bundle,
        "signatures": {
            "ml_dsa": str(signatures.get("ml_dsa") or ""),
            "slh_dsa": str(signatures.get("slh_dsa") or ""),
        },
    }


def verify_archive_signature_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Verify exported dual-signature evidence without accessing private material."""
    if not isinstance(evidence, dict) or evidence.get("format") != ARCHIVE_SIGNATURE_FORMAT:
        raise ValueError("Unsupported archive report signature evidence")
    version = evidence.get("signature_version")
    if not isinstance(version, int) or version not in SUPPORTED_ARCHIVE_SIGNATURE_VERSIONS:
        raise ValueError("Unsupported archive report signature version")
    try:
        manifest = base64.b64decode(str(evidence.get("manifest") or ""), validate=True)
    except Exception as exc:
        raise ValueError("Archive report signature manifest is malformed") from exc
    if len(manifest) == 0 or len(manifest) > MAX_MANIFEST_BYTES:
        raise ValueError("Archive report signature manifest size is invalid")
    document = _validate_manifest(manifest)
    public_bundle = evidence.get("public_bundle")
    signatures = evidence.get("signatures")
    if not isinstance(public_bundle, dict) or not isinstance(signatures, dict):
        raise ValueError("Archive report signature evidence is incomplete")
    verify_pqc_archive_manifest(
        public_bundle=public_bundle,
        manifest=manifest,
        signatures=signatures,
    )
    identity_id = public_bundle.get("identity_id")
    if document.get("version") >= 2 and document.get("signing_identity_id") != identity_id:
        raise ValueError("Archive report signing identity does not match its public evidence")
    return document


def verify_archive_signature(
    signature: dict[str, Any],
    *,
    public_bundle: dict[str, Any] | None,
    header_bytes: bytes,
    embedded_pqc_blob: bytes | None,
    pqc_algorithm: str,
    pqc_key_id: str,
    pqc_storage_mode: str,
) -> dict[str, Any]:
    """Verify dual signatures and all non-payload archive bindings."""
    manifest = signature["manifest"]
    document = signature["document"]
    verification_bundle = signature.get("public_bundle") or public_bundle
    if not isinstance(verification_bundle, dict):
        raise ValueError("Archive signing public identity is missing")
    verify_pqc_archive_manifest(
        public_bundle=verification_bundle,
        manifest=manifest,
        signatures=signature["signatures"],
    )

    expected_header = base64.b64encode(bytes(header_bytes)).decode("ascii")
    _require_equal(document["header"], expected_header, "archive header")
    _require_equal(
        document["keychain_core_sha256"],
        sha256_hex(signature["keychain_core_pgn"].encode("utf-8")),
        "keychain core",
    )
    _require_equal(document.get("pqc_algorithm"), pqc_algorithm, "PQC algorithm")
    _require_equal(document.get("pqc_key_id"), pqc_key_id, "PQC key identifier")
    _require_equal(document.get("pqc_storage_mode"), pqc_storage_mode, "PQC storage mode")

    actual_embedded_digest = sha256_hex(embedded_pqc_blob) if embedded_pqc_blob is not None else None
    actual_embedded_size = len(embedded_pqc_blob) if embedded_pqc_blob is not None else 0
    _require_equal(document["embedded_pqc_sha256"], actual_embedded_digest, "embedded PQC member")
    _require_equal(document["embedded_pqc_size"], actual_embedded_size, "embedded PQC member size")
    if document.get("version") >= 2:
        from .trusted_timestamp import verify_rfc3161_timestamp

        try:
            statement = base64.b64decode(document["timestamp_statement"], validate=True)
        except Exception as exc:
            raise ValueError("Archive timestamp statement is malformed") from exc
        expected_statement = build_timestamp_statement(
            archive_id=document["archive_id"],
            created_at=document["created_at_utc"],
            payload_sha256=document["payload_sha256"],
            keychain_core_pgn=signature["keychain_core_pgn"],
            content_index_sha256=document["content_index_sha256"],
            canonical_manifest_sha256=document["canonical_manifest_sha256"],
            payload_merkle_root=document["payload_merkle_root"],
        )
        if not hmac.compare_digest(statement, expected_statement):
            raise ValueError("Archive timestamp statement does not match the signed archive commitments")
        public_identity_id = verification_bundle.get("identity_id")
        _require_equal(document.get("signing_identity_id"), public_identity_id, "signing identity")
        document = dict(document)
        document["timestamp_status"] = verify_rfc3161_timestamp(statement, document.get("timestamp_evidence"))
    return document


def _extract_tag(keychain_pgn: str, tag_name: str) -> str | None:
    pattern = re.compile(rf'^\[{re.escape(tag_name)}\s+"([^"]+)"\]$')
    matches = []
    for line in keychain_pgn.splitlines():
        match = pattern.match(line.strip())
        if match:
            matches.append(match.group(1))
    if len(matches) > 1:
        raise ValueError(f"Duplicate {tag_name} tag")
    return matches[0] if matches else None


def _decode_b64(value: str, label: str, maximum: int) -> bytes:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"Malformed {label}") from exc
    if not decoded or len(decoded) > maximum:
        raise ValueError(f"{label.capitalize()} size is out of bounds")
    return decoded


def _validate_manifest(manifest: bytes) -> dict[str, Any]:
    try:
        document = json.loads(manifest.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Archive signature manifest is malformed") from exc
    if not isinstance(document, dict) or _canonical_json(document) != manifest:
        raise ValueError("Archive signature manifest is not canonical")
    if document.get("format") != ARCHIVE_SIGNATURE_FORMAT or document.get("version") not in SUPPORTED_ARCHIVE_SIGNATURE_VERSIONS:
        raise ValueError("Unsupported archive signature manifest")
    if document.get("domain") != ARCHIVE_SIGNATURE_DOMAIN:
        raise ValueError("Archive signature domain is invalid")
    for field in ("payload_sha256", "keychain_core_sha256"):
        _require_hex(document.get(field), field, HASH_BYTES * 2)
    if document.get("pqc_key_id") is not None:
        _require_hex(document.get("pqc_key_id"), "pqc_key_id", HASH_BYTES * 2)
    _require_hex(document.get("archive_id"), "archive identifier", 32)
    if not isinstance(document.get("payload_size"), int) or document["payload_size"] <= 0:
        raise ValueError("Archive signature payload size is invalid")
    if not isinstance(document.get("created_at_utc"), int) or document["created_at_utc"] <= 0:
        raise ValueError("Archive signature creation time is invalid")
    if not isinstance(document.get("embedded_pqc_size"), int) or document["embedded_pqc_size"] < 0:
        raise ValueError("Archive signature PQC size is invalid")
    embedded_digest = document.get("embedded_pqc_sha256")
    if embedded_digest is not None:
        _require_hex(embedded_digest, "embedded PQC digest", HASH_BYTES * 2)
    for field in ("header",):
        if not isinstance(document.get(field), str) or not document[field]:
            raise ValueError(f"Archive signature {field} is invalid")
    if document.get("version") >= 2:
        for field in ("content_index_sha256", "canonical_manifest_sha256", "payload_merkle_root", "signing_identity_id"):
            _require_hex(document.get(field), field, 64)
        for field in ("created_with_version", "minimum_reader_version"):
            if not isinstance(document.get(field), str) or not document[field]:
                raise ValueError(f"Archive signature {field} is invalid")
        if not isinstance(document.get("required_features"), int) or document["required_features"] < 0:
            raise ValueError("Archive signature required feature flags are invalid")
        if not isinstance(document.get("timestamp_statement"), str) or not document["timestamp_statement"]:
            raise ValueError("Archive signature timestamp statement is invalid")
        if not isinstance(document.get("timestamp_evidence"), dict):
            raise ValueError("Archive signature timestamp evidence is invalid")
    return document


def _require_hex(value: Any, label: str, length: int) -> None:
    if not isinstance(value, str) or len(value) != length or re.fullmatch(r"[0-9a-f]+", value) is None:
        raise ValueError(f"Invalid {label}")


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if isinstance(actual, str) and isinstance(expected, str):
        equal = hmac.compare_digest(actual, expected)
    else:
        equal = actual == expected
    if not equal:
        raise ValueError(f"Archive signature binding failed for {label}")
