"""Canonical, redacted assurance reports and offline verification helpers."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import platform
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from avikal_backend.version import __version__

from .security import native_bridge
from .security.archive_signature import verify_archive_signature_evidence
from .security.pqc_provider import provider_status


REPORT_FORMAT = "avikal-assurance-report"
REPORT_SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 2 * 1024 * 1024
_FORBIDDEN_REPORT_KEYS = {
    "password",
    "keyphrase",
    "private_bundle",
    "private_key",
    "master_key",
    "payload_key",
    "derived_key",
    "pqc_shared_secret",
    "absolute_path",
}


def _canonical_json(document: dict[str, Any]) -> bytes:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) == 0 or len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("Assurance report size is out of bounds")
    return encoded


@lru_cache(maxsize=16)
def _hash_file(path_text: str, size: int, mtime_ns: int) -> str:
    del size, mtime_ns
    digest = hashlib.sha256()
    with open(path_text, "rb") as handle:
        while True:
            chunk = handle.read(4 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _file_hash(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        resolved = path.resolve()
        stat = resolved.stat()
        if not resolved.is_file():
            return None
        return _hash_file(str(resolved), stat.st_size, stat.st_mtime_ns)
    except OSError:
        return None


def _runtime_manifest_hash() -> str | None:
    executable_dir = Path(sys.executable).resolve().parent
    candidates = (
        executable_dir.parent / "backend-runtime" / "runtime-manifest.json",
        executable_dir / "backend-runtime" / "runtime-manifest.json",
        Path(__file__).resolve().parents[3] / ".app-build" / "backend-runtime" / "runtime-manifest.json",
    )
    for candidate in candidates:
        digest = _file_hash(candidate)
        if digest:
            return digest
    return None


def _native_memory_lock_available() -> bool:
    if not native_bridge.native_available():
        return False
    try:
        return native_bridge.native_memory_lock_self_test()
    except Exception:
        return False


def build_runtime_attestation() -> dict[str, Any]:
    native_path = None
    if native_bridge.native_module is not None:
        module_path = getattr(native_bridge.native_module, "__file__", None)
        native_path = Path(module_path) if module_path else None
    pqc = provider_status()
    openssl_path = Path(pqc["executable"]) if isinstance(pqc.get("executable"), str) else None
    libcrypto_path = Path(pqc["libcrypto"]) if isinstance(pqc.get("libcrypto"), str) else None
    return {
        "scope": "local_runtime_observation",
        "avikal_version": __version__,
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "packaged": bool(getattr(sys, "frozen", False)),
        "native_crypto_available": native_bridge.native_available(),
        "native_secret_memory_lock_available": _native_memory_lock_available(),
        "native_module_sha256": _file_hash(native_path),
        "pqc_runtime_available": bool(pqc.get("available")),
        "pqc_runtime_sha256": _file_hash(openssl_path),
        "pqc_library_sha256": _file_hash(libcrypto_path),
        "openssl_version": pqc.get("openssl_version"),
        "runtime_manifest_sha256": _runtime_manifest_hash(),
    }

def _assert_redacted(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in _FORBIDDEN_REPORT_KEYS:
                raise ValueError(f"Assurance report contains forbidden field: {'.'.join(path + (normalized,))}")
            _assert_redacted(nested, path + (normalized,))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_redacted(nested, path + (str(index),))

def _timestamp_iso(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        return None
    if timestamp <= 0:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None

def _check(check_id: str, title: str, status: str, reason_code: str, detail: str) -> dict[str, str]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "reason_code": reason_code,
        "detail": detail,
    }

def _build_verification_ledger(document: dict[str, Any], *, report_type: str, has_evidence: bool) -> list[dict[str, str]]:
    assurance = document.get("assurance") if isinstance(document.get("assurance"), dict) else {}
    payload = document.get("payload") if isinstance(document.get("payload"), dict) else {}
    protection = document.get("protection") if isinstance(document.get("protection"), dict) else {}
    creation = report_type == "archive_creation"
    has_index = payload.get("format") == "AVI1" or assurance.get("index_verified") is True
    whole_verified = assurance.get("whole_payload_verified") is True
    selected_verified = assurance.get("selected_content_verified") is True
    timestamp_status = str(assurance.get("timestamp_status") or protection.get("timestamp_status") or "unavailable")
    identity_kind = str(assurance.get("identity_kind") or protection.get("signing_identity_kind") or "archive")
    pqc_enabled = bool(protection.get("pqc")) or assurance.get("pqc_mode") not in {None, "not_enabled"}
    timecapsule = protection.get("timecapsule_provider") or assurance.get("timecapsule_result")

    ledger = [
        _check(
            "archive_signatures", "Dual archive signatures", "passed" if has_evidence else "failed",
            "DUAL_PQC_EVIDENCE_PRESENT" if has_evidence else "SIGNATURE_EVIDENCE_MISSING",
            "ML-DSA and SLH-DSA public verification evidence is attached to this report." if has_evidence else "Archive signature evidence is unavailable.",
        ),
        _check(
            "keychain_binding", "Chess-PGN keychain binding",
            "passed" if creation or assurance.get("keychain_binding_verified") is True else "not_checked",
            "KEYCHAIN_COMMITTED" if creation else "KEYCHAIN_BINDING_VERIFIED" if assurance.get("keychain_binding_verified") is True else "KEYCHAIN_NOT_CHECKED",
            "The signed manifest commits to the exact keychain core." if creation else "The Chess-PGN keychain matched its signed commitment." if assurance.get("keychain_binding_verified") is True else "Keychain binding was not evaluated in this operation.",
        ),
        _check(
            "content_index", "Authenticated content index",
            "passed" if has_index else "not_applicable",
            "INDEX_COMMITTED" if creation and has_index else "INDEX_AUTHENTICATED" if assurance.get("index_verified") is True else "INDEX_NOT_AVAILABLE",
            "The content-index digest is included in the signed archive manifest." if creation and has_index else "The encrypted content index was authenticated before names were displayed." if assurance.get("index_verified") is True else "This archive format does not expose a random-access content index.",
        ),
        _check(
            "manifest", "Canonical manifest commitment",
            "passed" if payload.get("manifest_sha256") or assurance.get("canonical_manifest_sha256") else "not_applicable",
            "MANIFEST_COMMITTED" if payload.get("manifest_sha256") or assurance.get("canonical_manifest_sha256") else "MANIFEST_NOT_AVAILABLE",
            "The canonical manifest digest is bound by both archive signatures." if payload.get("manifest_sha256") or assurance.get("canonical_manifest_sha256") else "No canonical manifest commitment is available for this legacy format.",
        ),
    ]

    if creation:
        ledger.append(_check("payload", "Payload commitment", "passed", "PAYLOAD_COMMITTED_AT_CREATION", "The completed payload digest and Merkle commitment were signed during archive creation."))
    elif whole_verified:
        ledger.append(_check("payload", "Entire payload", "passed", "WHOLE_PAYLOAD_VERIFIED", "Every authenticated payload chunk and the complete payload commitment were verified."))
    elif selected_verified:
        ledger.append(_check("payload", "Selected content", "passed", "SELECTED_CONTENT_VERIFIED", "Only the selected authenticated files were verified. Unselected payload chunks were not read."))
    else:
        ledger.append(_check("payload", "Payload contents", "not_checked", "PAYLOAD_NOT_OPENED", "Archive metadata is authenticated, but payload chunks have not yet been verified."))

    ledger.extend([
        _check(
            "creator_identity", "Signing identity", "passed",
            "PERSISTENT_CREATOR_IDENTITY" if identity_kind == "creator" else "ARCHIVE_SCOPED_SIGNING_IDENTITY",
            "The signature uses a persistent creator identity; recipient trust still depends on fingerprint pinning." if identity_kind == "creator" else "The archive uses a valid, archive-scoped signing identity.",
        ),
        _check(
            "trusted_timestamp", "Trusted creation time",
            "passed" if timestamp_status in {"verified", "trusted_timestamp_verified"} else "not_checked",
            "RFC3161_TIMESTAMP_VERIFIED" if timestamp_status in {"verified", "trusted_timestamp_verified"} else "SIGNED_LOCAL_TIME_ONLY",
            "The RFC 3161 timestamp token was verified against its configured trust anchor." if timestamp_status in {"verified", "trusted_timestamp_verified"} else "Creation time is signed by the archive identity but is not independently vouched for by a trusted timestamp authority.",
        ),
        _check(
            "pqc_confidentiality", "PQC confidentiality", "passed" if pqc_enabled else "not_applicable",
            "HYBRID_PQC_ENABLED" if pqc_enabled else "PQC_CONFIDENTIALITY_NOT_SELECTED",
            "Payload-key access uses the selected ML-KEM and X25519 hybrid profile." if pqc_enabled else "The archive has mandatory PQC signatures, but optional PQC confidentiality was not selected.",
        ),
        _check(
            "timecapsule", "Time-Capsule release", "passed" if timecapsule and timecapsule != "not_applicable" else "not_applicable",
            "TIME_RELEASE_CONFIGURED" if creation and timecapsule else "TIME_RELEASE_VERIFIED" if timecapsule and timecapsule != "not_applicable" else "TIME_RELEASE_NOT_USED",
            "A time-release provider is bound into this archive." if creation and timecapsule else "The configured release condition was verified before metadata access." if timecapsule and timecapsule != "not_applicable" else "This archive does not use Time-Capsule protection.",
        ),
    ])
    return ledger


def finalize_assurance_report(
    report: dict[str, Any],
    *,
    report_type: str,
    signature_evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    document = copy.deepcopy(report)
    archive = document.get("archive") if isinstance(document.get("archive"), dict) else {}
    created_at_iso = _timestamp_iso(archive.get("created_at_utc"))
    if created_at_iso:
        archive["created_at_iso_utc"] = created_at_iso
    has_evidence = isinstance(signature_evidence, dict)
    document["verification_ledger"] = _build_verification_ledger(
        document,
        report_type=report_type,
        has_evidence=has_evidence,
    )
    document["verification_policy"] = {
        "mandatory_archive_signatures": ["ML-DSA", "SLH-DSA"],
        "invalid_signature_behavior": "fail_closed",
        "whole_payload_claim_requires_all_chunks": True,
        "selected_content_claim_is_scope_limited": True,
    }
    document["redaction_declaration"] = {
        "excluded_categories": [
            "passwords_and_keyphrases",
            "private_keys_and_private_pqc_material",
            "derived_keys_and_shared_secrets",
            "absolute_source_paths",
        ],
        "sender_message_included": bool(archive.get("sender_message")),
    }
    document["limitations"] = [
        "Runtime hashes are local observations and are not signed archive commitments.",
        "A valid ephemeral identity proves archive consistency, not a real-world creator identity.",
        "Selected-content verification does not imply that unselected payload chunks were verified.",
    ]
    document.update(
        {
            "format": REPORT_FORMAT,
            "schema_version": REPORT_SCHEMA_VERSION,
            "report_type": report_type,
            "ephemeral": True,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "runtime_attestation": build_runtime_attestation(),
            "verification_evidence": signature_evidence,
            "verification_scope": {
                "archive_commitments": "dual_pqc_signed",
                "runtime_attestation": "local_observation_not_archive_signed",
            },
        }
    )
    document.pop("report_digest_sha256", None)
    _assert_redacted(document)
    document["report_digest_sha256"] = hashlib.sha256(_canonical_json(document)).hexdigest()
    return document


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if isinstance(actual, str) and isinstance(expected, str):
        if not hmac.compare_digest(actual, expected):
            raise ValueError(f"Assurance report {label} does not match its signed evidence")
        return
    if actual != expected:
        raise ValueError(f"Assurance report {label} does not match its signed evidence")


def verify_assurance_report(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict) or report.get("format") != REPORT_FORMAT:
        raise ValueError("Unsupported Avikal assurance report")
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ValueError("Unsupported Avikal assurance report schema")
    _assert_redacted(report)
    expected_digest = report.get("report_digest_sha256")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise ValueError("Assurance report digest is missing")
    unsigned = copy.deepcopy(report)
    unsigned.pop("report_digest_sha256", None)
    actual_digest = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    if not hmac.compare_digest(expected_digest, actual_digest):
        raise ValueError("Assurance report digest verification failed")

    evidence = report.get("verification_evidence")
    if not isinstance(evidence, dict):
        raise ValueError("Assurance report does not contain archive signature evidence")
    signed = verify_archive_signature_evidence(evidence)
    archive = report.get("archive") if isinstance(report.get("archive"), dict) else {}
    compatibility = report.get("compatibility") if isinstance(report.get("compatibility"), dict) else {}
    payload = report.get("payload") if isinstance(report.get("payload"), dict) else {}
    protection = report.get("protection") if isinstance(report.get("protection"), dict) else {}
    assurance = report.get("assurance") if isinstance(report.get("assurance"), dict) else {}

    _require_equal(archive.get("archive_id") or assurance.get("archive_id"), signed.get("archive_id"), "archive identifier")
    _require_equal(archive.get("created_with_version") or compatibility.get("created_with_version"), signed.get("created_with_version"), "producer version")
    _require_equal(payload.get("payload_sha256") or assurance.get("payload_sha256"), signed.get("payload_sha256"), "payload commitment")
    _require_equal(payload.get("index_sha256") or assurance.get("content_index_sha256"), signed.get("content_index_sha256"), "content-index commitment")
    _require_equal(payload.get("manifest_sha256") or assurance.get("canonical_manifest_sha256"), signed.get("canonical_manifest_sha256"), "manifest commitment")
    _require_equal(payload.get("merkle_root_sha256") or assurance.get("payload_merkle_root"), signed.get("payload_merkle_root"), "Merkle commitment")
    identity_id = protection.get("signing_identity_id") or assurance.get("identity_id")
    _require_equal(identity_id, signed.get("signing_identity_id"), "creator identity")
    return {
        "valid": True,
        "format": REPORT_FORMAT,
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_digest_sha256": actual_digest,
        "archive_id": signed.get("archive_id"),
        "created_at_utc": signed.get("created_at_utc"),
        "created_with_version": signed.get("created_with_version"),
        "identity_id": signed.get("signing_identity_id"),
        "signature_scheme": "ML-DSA+SLH-DSA",
    }


def load_and_verify_assurance_report(path: str | os.PathLike[str]) -> dict[str, Any]:
    report_path = Path(path).expanduser().resolve()
    if not report_path.is_file() or report_path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Assurance report file is missing or too large")
    try:
        document = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("Assurance report is not valid UTF-8 JSON") from exc
    return verify_assurance_report(document)
