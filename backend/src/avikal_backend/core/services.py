"""Transport-neutral Avikal core services for CLI and desktop JSON-RPC.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import requests
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from avikal_backend.audit.activity_audit import activity_audit
from avikal_backend.archive.format.container import open_avk_payload_stream
from avikal_backend.archive.security.crypto import secure_zero
from avikal_backend.archive.security.pqc_keyfile import (
    PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET,
    PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
    PQC_STORAGE_MODE_EMBEDDED,
    PQC_STORAGE_MODE_EXTERNAL,
    inspect_pqc_keyfile,
)
from avikal_backend.archive.security.password_validator import validate_password_strength
from avikal_backend.archive.security.pqc_provider import provider_status
from avikal_backend.core.private_workspace import ensure_private_dir
from avikal_backend.core.preview_sessions import PreviewSessionStore
from avikal_backend.core.redaction import redact_text
from avikal_backend.core.temp_janitor import cleanup_startup_temp_artifacts
from avikal_backend.core.schemas import (
    AavritLoginRequest,
    AavritServerCheckRequest,
    ArchiveInspectRequest,
    CancelDecryptRequest,
    DecryptRequest,
    EncryptRequest,
    GenerateKeyphraseRequest,
    PqcKeyfileInspectRequest,
    PreviewCleanupRequest,
    RekeyRequest,
    VerifySessionRequest,
)
from avikal_backend.runtime_paths import drand_helper_path
from avikal_backend.runtime_requirements import ensure_native_crypto_runtime, get_native_runtime_status
from avikal_backend.core.user_preferences import load_user_preferences, save_user_preferences
from avikal_backend.services.ntp_service import (
    get_clock_skew_warning,
    get_ntp_datetime_utc,
    get_ntp_timestamp,
    invalidate_cache as invalidate_ntp_cache,
)
from avikal_backend.version import __version__


log = logging.getLogger("avikal.core")
_crypto_lock = threading.Lock()
_decrypt_cancel_lock = threading.Lock()
_active_decrypt_tokens: set[Any] = set()
_aavrit_lock = threading.RLock()
_aavrit_server_url: str | None = None
_aavrit_mode: str | None = None
DEFAULT_DRAND_HELPER_TIMEOUT_SECONDS = 30


def _set_active_decrypt_token(token: Any) -> None:
    with _decrypt_cancel_lock:
        _active_decrypt_tokens.add(token)


def _clear_active_decrypt_token(token: Any) -> None:
    with _decrypt_cancel_lock:
        _active_decrypt_tokens.discard(token)


def _cancel_active_decrypt_operation() -> bool:
    with _decrypt_cancel_lock:
        tokens = tuple(_active_decrypt_tokens)
    if not tokens:
        return False
    for token in tokens:
        token.cancel()
    return True


class ServiceError(Exception):
    """Normalized service error for non-HTTP transports."""

    def __init__(self, message: str, *, code: int = 500, data: Any | None = None):
        super().__init__(message)
        self.code = int(code)
        self.data = data


_ERROR_PATTERNS = [
    (re.compile(r"authentication failed|auth.*fail|invalid.*token|not authenticated|login.*required", re.I), "Authentication failed. Please try again."),
    (re.compile(r"time.?capsule.*locked|locked.*unlock|unlocks in|time.?lock|still locked", re.I), "This capsule is still locked."),
    (re.compile(r"password validation failed|password must be at least|password must contain|\.avkkey password validation failed", re.I), "Use a strong password with 12+ characters, uppercase, lowercase, number, and symbol."),
    (re.compile(r"password or keyphrase is required|required for protected archive mode", re.I), "This protected archive requires a password or keyphrase."),
    (re.compile(r"old password or keyphrase is required", re.I), "Enter the current archive password or keyphrase to continue."),
    (re.compile(r"new password or keyphrase is required", re.I), "Choose a new password or keyphrase for the rekeyed archive."),
    (re.compile(r"checksum mismatch|invalid word:|invalid length: keyphrase must contain", re.I), "Invalid keyphrase. Please check the phrase and try again."),
    (re.compile(r"incorrect password|wrong password|invalid password|incorrect keyphrase|wrong keyphrase|wrong key|metadata decoding failed|chess metadata decryption failed", re.I), "Incorrect password or keyphrase. Please check and try again."),
    (re.compile(r"wrapped payload key could not be unlocked|payload authentication failed|decryption failed - data corrupted or wrong key", re.I), "The archive could not be unlocked with the provided protections. Check the password, keyphrase, and PQC keyfile, then try again."),
    (re.compile(r"plaintext archives do not need rekey", re.I), "This archive is not protected, so it does not need rekey."),
    (re.compile(r"time-capsule rekey is not supported", re.I), "Time-capsule rekey is not available yet. Decrypt and create a new archive instead."),
    (re.compile(r"pqc rekey is not supported|pqc keyfile rekey is not supported", re.I), "PQC rekey is not available yet. Decrypt and create a new archive instead."),
    (re.compile(r"pqc keyfile not found|requires an external pqc keyfile|provide the \.avkkey|keyfile does not match this archive", re.I), "This archive requires the correct .avkkey file. Please provide the matching PQC keyfile."),
    (re.compile(r"\.avkkey requires its keyfile password|requires.*keyfile password", re.I), "This .avkkey requires its keyfile password."),
    (re.compile(r"incorrect \.avkkey password|corrupted keyfile", re.I), "Incorrect .avkkey password or corrupted keyfile."),
    (re.compile(r"failed to decrypt the pqc keyfile|pqc decapsulation failed", re.I), "The PQC keyfile could not be unlocked. Check the password, keyphrase, and keyfile, then try again."),
    (re.compile(r"missing encrypted member|embedded pqc bundle does not match|failed to decrypt the embedded pqc bundle|invalid embedded pqc bundle|unexpected embedded pqc bundle", re.I), "The embedded PQC protection could not be unlocked. Check the password or keyphrase, or verify that the archive is not corrupted."),
    (re.compile(r"unsupported pqc storage mode|invalid pqc storage mode", re.I), "This archive uses an unsupported PQC storage mode."),
    (re.compile(r"openssl pqc provider is unavailable|avikal_pqc_provider_exec", re.I), "PQC requires the bundled OpenSSL 3.5+ provider runtime. Please use an Avikal build that includes the PQC provider."),
    (re.compile(r"integrity check|file.*corrupt|corrupt.*file|checksum.*fail|hash.*mismatch", re.I), "File integrity check failed. The file may be corrupted."),
    (re.compile(r"system clock differs|system clock appears out of sync|clock skew", re.I), "Your system clock appears out of sync with trusted network time. Correct your Windows date and time settings, then try again."),
    (re.compile(r"ntp|time verification|time sync|time\.google\.com", re.I), "Time verification failed. Check your internet connection."),
    (re.compile(r"network error|connection.*refused|econnrefused|no internet|offline", re.I), "Network error. Check your internet connection and try again."),
    (re.compile(r"file not found|no such file|enoent|path.*not.*exist", re.I), "File not found. Please check the file path."),
    (re.compile(r"permission denied|eacces|access denied", re.I), "Permission denied. Check file permissions."),
]


def friendly_error(raw: str) -> str:
    log.debug("Raw core error: %s", redact_text(raw))
    for pattern, message in _ERROR_PATTERNS:
        if pattern.search(raw):
            return message
    return "An unexpected error occurred. Please try again."


def preserve_time_lock_detail(raw: str) -> str | None:
    text = (raw or "").strip()
    lowered = text.lower()
    if not text:
        return None
    if "locked until" in lowered or "current time:" in lowered:
        return text
    if "still locked" in lowered and ("unlock" in lowered or "available at" in lowered):
        return text
    return None


def _raise(code: int, detail: str) -> None:
    raise ServiceError(detail, code=code, data=detail)


def _validate_pqc_keyfile_password_policy(request: EncryptRequest) -> None:
    mode = request.pqc_keyfile_protection_mode or PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET
    if not request.pqc_enabled or request.pqc_storage_mode != PQC_STORAGE_MODE_EXTERNAL:
        return
    if mode == PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET:
        return
    if mode != PQC_KEYFILE_PROTECTION_DUAL_PASSWORD:
        _raise(400, "Unsupported PQC keyfile protection mode.")
    password = (request.pqc_keyfile_password or "").strip()
    if not password:
        _raise(400, "Enter a .avkkey password to protect the external keyfile.")
    if request.password and password == request.password:
        _raise(400, "The .avkkey password must be different from the archive password.")
    try:
        validate_password_strength(password, min_length=12)
    except ValueError as exc:
        _raise(400, f".avkkey password validation failed: {exc}")


def _validate_archive_password_policy(request: EncryptRequest) -> None:
    password = request.password
    if not password:
        return
    try:
        validate_password_strength(password, min_length=12)
    except ValueError as exc:
        _raise(400, f"Password validation failed: {exc}")


def _validate_rekey_password_policy(request: RekeyRequest) -> None:
    password = request.new_password
    if not password:
        return
    try:
        validate_password_strength(password, min_length=12)
    except ValueError as exc:
        _raise(400, f"Password validation failed: {exc}")


def _request_error(exc: Exception, context: str = "external server") -> ServiceError:
    if isinstance(exc, requests.exceptions.Timeout):
        log.warning("%s request timed out: %s", context, exc)
        return ServiceError("Network error. Check your internet connection and try again.", code=504)
    if isinstance(exc, requests.exceptions.ConnectionError):
        log.warning("%s connection error: %s", context, exc)
        return ServiceError("Network error. Check your internet connection and try again.", code=503)
    return ServiceError(str(exc), code=502)


def _runtime_base_dir() -> Path:
    return Path(os.getenv("AVIKAL_USER_DATA_DIR") or (Path.home() / ".avikal"))


def _ensure_runtime_dirs() -> tuple[Path, Path]:
    base_dir = _runtime_base_dir()
    try:
        log_dir = base_dir / "logs"
        preview_root = base_dir / "preview_sessions"
        ensure_private_dir(base_dir)
        ensure_private_dir(log_dir)
        ensure_private_dir(preview_root)
        return log_dir, preview_root
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "avikal-runtime"
        log_dir = fallback / "logs"
        preview_root = fallback / "preview_sessions"
        ensure_private_dir(fallback)
        ensure_private_dir(log_dir)
        ensure_private_dir(preview_root)
        return log_dir, preview_root


_log_dir, _preview_root = _ensure_runtime_dirs()
_preview_sessions = PreviewSessionStore(_preview_root, log)


def _best_effort_scrub_model_secrets(model, *field_names: str) -> None:
    for field_name in field_names:
        value = getattr(model, field_name, None)
        if value is None:
            continue
        if isinstance(value, str):
            secure_zero(bytearray(value.encode("utf-8")))
            try:
                setattr(model, field_name, None)
            except Exception:
                pass
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, str):
                    secure_zero(bytearray(item.encode("utf-8")))
                    value[index] = ""
            try:
                setattr(model, field_name, None)
            except Exception:
                pass


def _should_use_multi_file_archive(input_files: list[str]) -> bool:
    return len(input_files) > 1 or any(os.path.isdir(path) for path in input_files)


def _validate_avk_structure(avk_filepath: str) -> None:
    if not os.path.exists(avk_filepath):
        _raise(400, "File not found. Please check the file path.")
    try:
        with open_avk_payload_stream(avk_filepath):
            pass
    except ValueError as exc:
        log.warning("validate_avk_structure: %s: %s", avk_filepath, exc)
        _raise(400, "File integrity check failed. The file may be corrupted.")


def _get_pgn_created_time_ist(avk_filepath: str) -> str | None:
    try:
        from datetime import timedelta

        created_utc = datetime.fromtimestamp(os.path.getmtime(avk_filepath), tz=timezone.utc)
        return created_utc.astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat()
    except Exception as exc:
        log.debug("Failed to derive PGN created time for %s: %s", avk_filepath, exc)
        return None


def _best_effort_log_archive_creation(
    request: EncryptRequest,
    *,
    started_at: float,
    unlock_dt: datetime | None,
    response_payload: dict | None = None,
    error_message: str | None = None,
    provider: str | None = None,
) -> None:
    try:
        archive_mode = "timecapsule" if request.use_timecapsule else "regular"
        provider_name = provider or ((request.timecapsule_provider or "unknown").strip().lower() if archive_mode == "timecapsule" else None)
        activity_audit.record_archive_creation(
            request=request,
            archive_mode=archive_mode,
            provider=provider_name,
            unlock_dt=unlock_dt,
            status="success" if response_payload is not None else "failed",
            duration_ms=(time.perf_counter() - started_at) * 1000,
            response_payload=response_payload,
            error_message=error_message,
        )
    except Exception as audit_exc:
        log.warning("Failed to record archive activity audit entry: %s", audit_exc, exc_info=True)


def _best_effort_log_activity_event(
    *,
    action: str,
    status: str,
    started_at: float | None = None,
    provider: str | None = None,
    archive_kind: str | None = None,
    secret_mode: str | None = None,
    pqc_enabled: bool | None = None,
    error_message: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    try:
        activity_audit.record_event(
            action=action,
            status=status,
            duration_ms=((time.perf_counter() - started_at) * 1000) if started_at is not None else None,
            provider=provider,
            archive_kind=archive_kind,
            secret_mode=secret_mode,
            pqc_enabled=pqc_enabled,
            error_message=error_message,
            details=details,
        )
    except Exception as audit_exc:
        log.warning("Failed to record activity audit event: %s", audit_exc, exc_info=True)


def _set_current_aavrit_server_url(raw_url: str) -> str:
    normalized = _normalize_aavrit_server_url(raw_url)
    with _aavrit_lock:
        global _aavrit_server_url
        _aavrit_server_url = normalized
    return normalized


def _get_aavrit_server_url(explicit_url: str | None = None, *, required: bool = True) -> str | None:
    with _aavrit_lock:
        candidate = explicit_url or _aavrit_server_url
    if not candidate:
        if required:
            _raise(400, "Aavrit server URL is not configured.")
        return None
    return _normalize_aavrit_server_url(candidate)


def _set_current_aavrit_mode(mode: str | None) -> str | None:
    with _aavrit_lock:
        global _aavrit_mode
        _aavrit_mode = mode
        return _aavrit_mode


def _get_current_aavrit_mode() -> str | None:
    with _aavrit_lock:
        return _aavrit_mode


def _clear_aavrit_auth_state() -> None:
    with _aavrit_lock:
        global _aavrit_server_url, _aavrit_mode
        _aavrit_server_url = None
        _aavrit_mode = None


def _normalize_aavrit_server_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    if not url:
        _raise(400, "Aavrit server URL is required.")
    local_http_hosts = ("localhost", "127.0.0.1")
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}" if url.startswith(local_http_hosts) else f"https://{url}"
    if url.startswith("http://"):
        normalized_host = url[len("http://"):].split("/", 1)[0].split(":", 1)[0].lower()
        allow_insecure = (os.getenv("NODE_ENV") or "").lower() == "development" and os.getenv("AVIKAL_ALLOW_INSECURE_AAVRIT") == "1"
        if normalized_host not in local_http_hosts and not allow_insecure:
            _raise(400, "Aavrit server URL must use HTTPS.")
    return url.rstrip("/")


def _fetch_aavrit_capabilities(aavrit_url: str) -> dict:
    normalized_url = _normalize_aavrit_server_url(aavrit_url)
    response = requests.get(f"{normalized_url}/config", timeout=20)
    if response.status_code != 200:
        _raise(502, "Aavrit server validation failed.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ServiceError("Aavrit server returned an invalid config response.", code=502) from exc
    mode = payload.get("mode") if isinstance(payload, dict) else None
    if mode not in {"public", "private"}:
        _raise(502, "Aavrit server returned an invalid mode.")
    return {"mode": mode}


def _fetch_aavrit_public_key(aavrit_url: str, session_token: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {session_token}"} if session_token else {}
    response = requests.get(f"{_normalize_aavrit_server_url(aavrit_url)}/public-key", headers=headers, timeout=30)
    if response.status_code == 401:
        _raise(401, "Invalid or expired session")
    if response.status_code != 200:
        _raise(502, "Aavrit server public key fetch failed.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ServiceError("Aavrit server returned an invalid public key response.", code=502) from exc
    if not isinstance(payload, dict) or not payload.get("success"):
        _raise(502, "Aavrit server returned an invalid public key response.")
    key_id = payload.get("key_id")
    sig_alg = payload.get("sig_alg")
    public_key_pem = payload.get("public_key_pem")
    if not isinstance(key_id, str) or sig_alg != "Ed25519" or not isinstance(public_key_pem, str) or not public_key_pem.strip():
        _raise(502, "Aavrit server public key response is invalid.")
    return {"key_id": key_id, "sig_alg": sig_alg, "public_key_pem": public_key_pem}


def _request_aavrit_commit(aavrit_url: str, *, data_hash: str, unlock_timestamp: int, session_token: str | None) -> dict:
    headers = {"Content-Type": "application/json"}
    if session_token:
        headers["Authorization"] = f"Bearer {session_token}"
    try:
        response = requests.post(
            f"{aavrit_url}/commit",
            json={"data_hash": data_hash, "unlock_timestamp": unlock_timestamp},
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as exc:
        raise _request_error(exc, "Aavrit server") from exc
    if response.status_code == 401:
        _raise(401, "Invalid or expired session")
    if response.status_code == 429:
        _raise(429, "Aavrit rate limit exceeded. Please try again later.")
    if response.status_code != 201:
        _raise(502, response.text.strip() or "Aavrit commit failed.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ServiceError("Aavrit server returned an invalid commit response.", code=502) from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("payload"), dict) or not isinstance(payload.get("signature"), str):
        _raise(502, "Aavrit server returned an invalid commit response.")
    return payload


def _request_aavrit_reveal(aavrit_url: str, *, commit_id: str, session_token: str | None) -> dict:
    headers = {"Content-Type": "application/json"}
    if session_token:
        headers["Authorization"] = f"Bearer {session_token}"
    try:
        response = requests.post(f"{aavrit_url}/reveal", json={"commit_id": commit_id}, headers=headers, timeout=30)
    except requests.RequestException as exc:
        raise _request_error(exc, "Aavrit server") from exc
    if response.status_code == 401:
        _raise(401, "Invalid or expired session")
    if response.status_code == 404:
        _raise(404, "Aavrit commit not found.")
    if response.status_code == 429:
        _raise(429, "Aavrit rate limit exceeded. Please try again later.")
    if response.status_code != 200:
        _raise(502, response.text.strip() or "Aavrit reveal failed.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ServiceError("Aavrit server returned an invalid reveal response.", code=502) from exc
    if not isinstance(payload, dict):
        _raise(502, "Aavrit server returned an invalid reveal response.")
    return payload


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode((data + "=" * (-len(data) % 4)).encode("ascii"))


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _build_aavrit_commit_hash(*, commit_id: str, data_hash: str, unlock_timestamp: int, reveal_value: str) -> str:
    return _b64url_encode(hashlib.sha256(_canonical_json_bytes({
        "version": 1,
        "commit_id": commit_id,
        "data_hash": data_hash,
        "unlock_timestamp": unlock_timestamp,
        "reveal_value": reveal_value,
    })).digest())


def _verify_aavrit_signature(payload: dict, signature: str, public_key_pem: str) -> None:
    from cryptography.hazmat.primitives import serialization

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(_b64url_decode(signature), _canonical_json_bytes(payload))
    except Exception as exc:
        raise ServiceError("Aavrit signature verification failed.", code=400) from exc


def _derive_aavrit_time_key(commit_payload: dict, commit_signature: str) -> bytes:
    return hashlib.sha256(_canonical_json_bytes({"payload": commit_payload, "signature": commit_signature})).digest()


def _create_aavrit_data_hash() -> str:
    import secrets

    return _b64url_encode(secrets.token_bytes(32))


def _extract_aavrit_metadata(metadata: dict) -> dict:
    result = {
        "commit_id": metadata.get("file_id"),
        "server_url": metadata.get("server_url"),
        "data_hash": metadata.get("aavrit_data_hash"),
        "commit_hash": metadata.get("aavrit_commit_hash"),
        "server_key_id": metadata.get("aavrit_server_key_id"),
        "commit_signature": metadata.get("aavrit_commit_signature"),
    }
    for field_name, field_value in result.items():
        if not isinstance(field_value, str) or not field_value:
            _raise(400, f"Invalid Aavrit archive metadata: missing {field_name}")
    return result


def _verify_aavrit_session_token(session_token: str, aavrit_server_url: str | None = None) -> dict:
    if not session_token:
        _raise(401, "Authentication session required")
    base_url = _get_aavrit_server_url(aavrit_server_url)
    config = _fetch_aavrit_capabilities(base_url)
    if config["mode"] != "private":
        return {"sub": "aavrit-public-mode", "mode": config["mode"]}
    try:
        response = requests.post(f"{base_url}/auth/verify", headers={"Authorization": f"Bearer {session_token}"}, timeout=30)
    except requests.RequestException as exc:
        raise _request_error(exc, "Aavrit server") from exc
    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError as exc:
            raise ServiceError("Aavrit authentication check failed.", code=502) from exc
        user = payload.get("user", {}) if isinstance(payload, dict) else {}
        return {"sub": user.get("id", "aavrit-authenticated-user"), "mode": "private", "email": user.get("email", ""), "name": user.get("name", "")}
    if response.status_code == 401:
        _raise(401, "Invalid or expired session")
    if response.status_code == 429:
        _raise(429, "Too many authentication attempts. Please try again later.")
    _raise(502, "Aavrit authentication check failed.")


def _build_aavrit_user_payload(*, user_id: str, name: str, email: str) -> dict:
    return {"id": user_id, "name": name, "email": email, "emailVerification": True}


def _resolve_timecapsule_provider(request: EncryptRequest) -> str:
    provider = (request.timecapsule_provider or "aavrit").strip().lower()
    if provider not in {"aavrit", "drand"}:
        _raise(400, "Unsupported time-capsule provider.")
    return provider


def _detect_timecapsule_provider(metadata: dict) -> str | None:
    provider = metadata.get("timecapsule_provider")
    if provider:
        return provider
    if metadata.get("drand_round") and metadata.get("drand_ciphertext"):
        return "drand"
    return None


def _read_avk_public_route(avk_filepath: str) -> tuple[dict, dict]:
    from avikal_backend.archive.format.container import read_avk_header_and_keychain
    from avikal_backend.archive.format.header import ARCHIVE_MODE_MULTI, extract_public_route_tags_from_keychain_pgn, parse_header_bytes

    header_bytes, keychain_pgn = read_avk_header_and_keychain(avk_filepath)
    header_info = parse_header_bytes(header_bytes)
    route_hints = extract_public_route_tags_from_keychain_pgn(keychain_pgn)
    route_hints.update({
        "provider": header_info.get("provider"),
        "archive_type": "multi_file" if header_info.get("archive_mode") == ARCHIVE_MODE_MULTI else "single_file",
        "aad": header_info.get("aad"),
    })
    return header_info, route_hints


def _validate_public_route_inputs(request: DecryptRequest, route_hints: dict) -> None:
    missing: list[str] = []
    if route_hints.get("requires_password") and not request.password:
        missing.append("password")
    if route_hints.get("requires_keyphrase") and not request.keyphrase:
        missing.append("21-word keyphrase")
    if route_hints.get("requires_pqc") and route_hints.get("pqc_storage_mode") != PQC_STORAGE_MODE_EMBEDDED and not request.pqc_keyfile:
        missing.append(".avkkey")
    if not missing:
        return
    if missing == [".avkkey"]:
        _raise(400, "This archive requires the matching .avkkey file before decryption can continue.")
    if len(missing) == 1:
        _raise(400, f"This archive requires its {missing[0]} before decryption can continue.")
    if missing == ["password", "21-word keyphrase"]:
        _raise(400, "This archive requires both its password and 21-word keyphrase before decryption can continue.")
    _raise(400, f"This archive requires {', '.join(missing)} before decryption can continue.")


def _validate_public_timecapsule_lock(route_hints: dict) -> None:
    provider = route_hints.get("provider")
    unlock_timestamp = route_hints.get("unlock_timestamp")
    if provider not in {"drand", "aavrit"} or unlock_timestamp is None:
        return
    from avikal_backend.archive.security.time_lock import format_unlock_time, get_trusted_now

    current_time = get_trusted_now()
    unlock_time = datetime.fromtimestamp(int(unlock_timestamp), tz=timezone.utc)
    if current_time < unlock_time:
        _raise(
            403,
            f"This capsule is still locked. Unlock becomes available at {format_unlock_time(int(unlock_timestamp))}. "
            f"Current time: {current_time.strftime('%Y-%m-%d %H:%M UTC')}",
        )


def _normalize_unlock_datetime_to_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ServiceError(f"Invalid unlock_datetime format: {str(exc)}", code=400) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo or timezone.utc)
    return dt.astimezone(timezone.utc)


def _validate_unlock_datetime_against_ntp(unlock_dt: datetime) -> None:
    try:
        ntp_now = get_ntp_timestamp()
    except RuntimeError:
        _raise(503, "Time verification failed. Check your internet connection and trusted-time availability.")
    unlock_timestamp_check = int(_normalize_unlock_datetime_to_utc(unlock_dt).timestamp())
    if unlock_timestamp_check <= ntp_now:
        trusted_now = datetime.fromtimestamp(ntp_now, tz=timezone.utc).isoformat()
        _raise(400, f"Unlock time must be in the future according to trusted network time. Current trusted time: {trusted_now}")
    if unlock_timestamp_check - ntp_now > 5 * 365 * 24 * 60 * 60:
        max_unlock = datetime.fromtimestamp(ntp_now + 5 * 365 * 24 * 60 * 60, tz=timezone.utc)
        _raise(400, f"Maximum lock duration is 5 years. Maximum allowed unlock date: {max_unlock.isoformat()}")


def _enforce_system_clock_alignment(operation_label: str) -> None:
    skew_warning = get_clock_skew_warning()
    if skew_warning:
        log.warning("Blocking %s because of local clock skew: %s", operation_label, skew_warning)
        _raise(400, "Your system clock appears out of sync with trusted network time. Correct your Windows date and time settings, then try again.")


def _find_node_binary() -> tuple[str, dict[str, str]]:
    node = shutil.which("node") or shutil.which("node.exe")
    if node:
        return node, {}
    electron_exec = os.environ.get("AVIKAL_ELECTRON_EXEC", "").strip()
    if electron_exec and os.path.isfile(electron_exec):
        return electron_exec, {"ELECTRON_RUN_AS_NODE": "1"}
    if os.name == "nt":
        candidates = [
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Program Files (x86)\nodejs\node.exe",
            str(Path.home() / "AppData" / "Roaming" / "nvm" / "current" / "node.exe"),
            str(Path.home() / ".volta" / "bin" / "node.exe"),
            r"C:\ProgramData\chocolatey\bin\node.exe",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate, {}
    return "", {}


def _drand_helper_timeout_seconds() -> int:
    raw = os.environ.get("AVIKAL_DRAND_HELPER_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return DEFAULT_DRAND_HELPER_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_DRAND_HELPER_TIMEOUT_SECONDS
    return max(5, min(120, value))


def _run_drand_helper(payload: dict, *, timeout_seconds: int | None = None) -> dict:
    from avikal_backend.archive.pipeline.progress import OperationCancelled, check_cancelled

    node_binary, node_extra_env = _find_node_binary()
    if not node_binary:
        _raise(500, "drand requires a Node.js runtime which could not be found.")
    helper_path = str(drand_helper_path())
    if not os.path.exists(helper_path):
        _raise(500, "drand helper script is missing. Please reinstall the application.")
    process: subprocess.Popen[str] | None = None
    try:
        check_cancelled()
        process = subprocess.Popen(
            [node_binary, helper_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(Path(helper_path).parent),
            env={**os.environ, **node_extra_env} if node_extra_env else None,
        )
        if process.stdin is not None:
            process.stdin.write(json.dumps(payload))
            process.stdin.close()
        deadline = time.monotonic() + float(timeout_seconds or _drand_helper_timeout_seconds())
        while process.poll() is None:
            check_cancelled()
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate(timeout=2)
                raise subprocess.TimeoutExpired([node_binary, helper_path], timeout_seconds or _drand_helper_timeout_seconds())
            time.sleep(0.1)
        stdout = process.stdout.read() if process.stdout is not None else ""
        stderr = process.stderr.read() if process.stderr is not None else ""
    except subprocess.TimeoutExpired as exc:
        raise ServiceError("drand network request timed out. Please try again.", code=504) from exc
    except OperationCancelled:
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.communicate(timeout=2)
            except Exception:
                pass
        raise
    except Exception as exc:
        raise ServiceError("drand helper execution failed.", code=500) from exc
    raw_output = (stdout or "").strip() or (stderr or "").strip()
    try:
        helper_result = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise ServiceError("drand helper returned an invalid response. Check that the application is installed correctly.", code=500) from exc
    if process.returncode != 0 or not helper_result.get("success"):
        if helper_result.get("status") == "locked":
            unlock_iso = helper_result.get("unlock_iso")
            _raise(403, f"This capsule is still locked. drand unlock becomes available at {unlock_iso}." if unlock_iso else "This capsule is still locked.")
        _raise(503, friendly_error(str(helper_result.get("error") or helper_result.get("message") or "drand operation failed.")))
    return helper_result


def _read_avk_metadata_only(avk_filepath: str, password: str = None, keyphrase: list = None) -> dict:
    from avikal_backend.archive.chess_metadata import decode_chess_to_metadata_enhanced
    from avikal_backend.archive.format.header import parse_header_bytes, validate_metadata_against_header

    try:
        with open_avk_payload_stream(avk_filepath) as (header_bytes, keychain_pgn, _payload_stream, _embedded_pqc):
            pass
    except Exception as exc:
        raise ValueError(f"Failed to open .avk file: {str(exc)}") from exc
    try:
        metadata = decode_chess_to_metadata_enhanced(keychain_pgn, password, keyphrase, skip_timelock=True, aad=header_bytes)
        validate_metadata_against_header(parse_header_bytes(header_bytes), metadata)
        return metadata
    except ValueError as exc:
        error_msg = str(exc)
        if "password protected" in error_msg.lower():
            raise ValueError("This protected archive requires a password or keyphrase.") from exc
        if any(token in error_msg.lower() for token in ("incorrect password", "incorrect keyphrase", "wrong key", "decryption failed", "chess metadata decryption failed")):
            raise ValueError("Incorrect password or keyphrase.") from exc
        raise ValueError(f"Metadata decoding failed: {error_msg}") from exc


async def startup() -> None:
    ensure_native_crypto_runtime("Avikal core")
    await asyncio.to_thread(cleanup_startup_temp_artifacts)
    await asyncio.to_thread(_preview_sessions.cleanup_stale)
    try:
        from avikal_backend.services.ntp_service import prime_ntp_cache_async

        prime_ntp_cache_async()
    except Exception as exc:
        log.debug("Trusted time warmup skipped: %s", exc)


async def runtime_status(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    native = get_native_runtime_status()
    return {
        "success": True,
        "runtime": {
            "native_crypto": {"available": native.available, "import_error": native.import_error},
            "pqc_provider": provider_status(),
            "version": __version__,
        },
    }


async def verify_runtime(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    ensure_native_crypto_runtime("Avikal core")
    return await runtime_status()


async def ntp_time(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        if (_params or {}).get("force_refresh"):
            invalidate_ntp_cache()
        utc_dt = get_ntp_datetime_utc()
        return {"success": True, "timestamp": get_ntp_timestamp(), "utc": utc_dt.isoformat(), "clock_skew_warning": get_clock_skew_warning()}
    except RuntimeError:
        return {"success": False, "error": "Time verification failed. Check your internet connection.", "timestamp": None, "clock_skew_warning": None}


async def check_aavrit_server(params: dict[str, Any]) -> dict[str, Any]:
    body = AavritServerCheckRequest(**params)
    try:
        aavrit_url = _normalize_aavrit_server_url(body.aavrit_url)
        payload = await asyncio.to_thread(_fetch_aavrit_capabilities, aavrit_url)
        _set_current_aavrit_server_url(aavrit_url)
        _set_current_aavrit_mode(payload["mode"])
        return {"success": True, "aavrit_url": aavrit_url, "mode": payload["mode"]}
    except requests.RequestException as exc:
        raise _request_error(exc, "Aavrit server") from exc


async def auth_login(params: dict[str, Any]) -> dict[str, Any]:
    body = AavritLoginRequest(**params)
    try:
        aavrit_url = _normalize_aavrit_server_url(body.aavrit_url)
        mode = (await asyncio.to_thread(_fetch_aavrit_capabilities, aavrit_url))["mode"]
        if mode != "private":
            _raise(400, "Aavrit login is only available when the server is in private mode.")
        response = await asyncio.to_thread(
            requests.post,
            f"{aavrit_url}/auth/login",
            json={"email": body.email, "password": body.password},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if response.status_code == 401:
            _raise(401, "Invalid email or password")
        if response.status_code == 429:
            _raise(429, "Too many login attempts. Please try again later.")
        if response.status_code != 200:
            _raise(502, response.text.strip() or "Aavrit login failed.")
        payload = response.json()
        session_token = payload.get("session_token") if isinstance(payload, dict) else None
        if not isinstance(session_token, str) or not session_token.strip():
            _raise(502, "Aavrit login returned an invalid session.")
        _set_current_aavrit_server_url(aavrit_url)
        _set_current_aavrit_mode(mode)
        user = payload.get("user", {}) if isinstance(payload, dict) else {}
        return {
            "success": True,
            "message": "Aavrit login successful",
            "aavrit_url": aavrit_url,
            "mode": mode,
            "session_token": session_token,
            "user": _build_aavrit_user_payload(
                user_id=user.get("id", "aavrit-authenticated-user"),
                name=user.get("name") or "Aavrit Private Session",
                email=user.get("email", ""),
            ),
        }
    except requests.RequestException as exc:
        raise _request_error(exc, "Aavrit server") from exc
    finally:
        _best_effort_scrub_model_secrets(body, "password")


async def auth_verify_session(params: dict[str, Any]) -> dict[str, Any]:
    body = VerifySessionRequest(**params)
    try:
        aavrit_url = _set_current_aavrit_server_url(body.aavrit_url) if body.aavrit_url else _get_aavrit_server_url()
        decoded = await asyncio.to_thread(_verify_aavrit_session_token, body.session_token, aavrit_url)
        mode = (await asyncio.to_thread(_fetch_aavrit_capabilities, aavrit_url))["mode"]
        _set_current_aavrit_mode(mode)
        return {
            "success": True,
            "message": "Session verified successfully",
            "aavrit_url": aavrit_url,
            "mode": mode,
            "user": _build_aavrit_user_payload(
                user_id=decoded.get("sub", "") or "aavrit-authenticated-user",
                name=decoded.get("name") or "Aavrit Private Session",
                email=decoded.get("email", ""),
            ),
        }
    finally:
        _best_effort_scrub_model_secrets(body, "session_token")


async def auth_profile(params: dict[str, Any]) -> dict[str, Any]:
    token = str(params.get("session_token") or "").strip()
    aavrit_url = _get_aavrit_server_url(params.get("aavrit_url"))
    decoded = await asyncio.to_thread(_verify_aavrit_session_token, token, aavrit_url)
    return {"success": True, "user": _build_aavrit_user_payload(user_id=decoded.get("sub", "aavrit-authenticated-user"), name=decoded.get("name") or "Aavrit Session", email=decoded.get("email", ""))}


async def auth_aavrit_diagnostics(params: dict[str, Any]) -> dict[str, Any]:
    aavrit_url = _get_aavrit_server_url(params.get("aavrit_url"))
    session_token = str(params.get("session_token") or "").strip() or None
    started_at = time.perf_counter()
    config = await asyncio.to_thread(_fetch_aavrit_capabilities, aavrit_url)
    public_key = await asyncio.to_thread(_fetch_aavrit_public_key, aavrit_url, session_token)
    health_status = "unknown"
    try:
        health_response = await asyncio.to_thread(requests.get, f"{aavrit_url}/health", timeout=10)
        health_status = "ok" if health_response.status_code == 200 else f"http_{health_response.status_code}"
    except requests.RequestException:
        health_status = "unreachable"
    public_key_fingerprint = hashlib.sha256(public_key["public_key_pem"].encode("utf-8")).hexdigest()
    latency_ms = int((time.perf_counter() - started_at) * 1000)
    return {
        "success": True,
        "aavrit": {
            "server_url": aavrit_url,
            "mode": config["mode"],
            "status": "reachable",
            "health": health_status,
            "latency_ms": latency_ms,
            "public_key": {
                "key_id": public_key["key_id"],
                "sig_alg": public_key["sig_alg"],
                "fingerprint_sha256": public_key_fingerprint,
            },
        },
    }


async def auth_logout(params: dict[str, Any]) -> dict[str, Any]:
    token = str(params.get("session_token") or "").strip()
    aavrit_url = _get_aavrit_server_url(params.get("aavrit_url"), required=False)
    if token and aavrit_url and _get_current_aavrit_mode() == "private":
        try:
            await asyncio.to_thread(requests.post, f"{aavrit_url}/auth/logout", headers={"Authorization": f"Bearer {token}"}, timeout=30)
        except requests.RequestException as exc:
            log.warning("Aavrit logout request failed: %s", exc)
    _clear_aavrit_auth_state()
    return {"success": True, "message": "Logged out successfully"}


def _create_regular_encryption(request: EncryptRequest, unlock_dt: datetime | None) -> dict:
    from avikal_backend.archive.pipeline.encoder import create_avk_file
    from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
    from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker

    tracker = ProgressTracker("encrypt", [("prepare", 0.10), ("payload", 0.60), ("metadata", 0.20), ("finalize", 0.10)])
    with bind_progress_tracker(tracker):
        if _should_use_multi_file_archive(request.input_files):
            result = create_multi_file_avk(
                input_filepaths=request.input_files,
                output_filepath=request.output_file,
                password=request.password,
                keyphrase=request.keyphrase,
                unlock_datetime=unlock_dt,
                use_timecapsule=False,
                pqc_enabled=request.pqc_enabled,
                pqc_storage_mode=request.pqc_storage_mode,
                pqc_keyfile_output=request.pqc_keyfile_output,
                pqc_keyfile_protection_mode=request.pqc_keyfile_protection_mode,
                pqc_keyfile_password=request.pqc_keyfile_password,
                excluded_input_paths=request.excluded_input_paths,
            )
        else:
            result = create_avk_file(
                input_filepath=request.input_files[0],
                output_filepath=request.output_file,
                password=request.password,
                keyphrase=request.keyphrase,
                unlock_datetime=unlock_dt,
                use_timecapsule=False,
                pqc_enabled=request.pqc_enabled,
                pqc_storage_mode=request.pqc_storage_mode,
                pqc_keyfile_output=request.pqc_keyfile_output,
                pqc_keyfile_protection_mode=request.pqc_keyfile_protection_mode,
                pqc_keyfile_password=request.pqc_keyfile_password,
            )
    return {"success": True, "message": "Files encrypted successfully", "output_file": request.output_file, "result": result}


def _create_timecapsule_via_drand(request: EncryptRequest, unlock_dt: datetime) -> dict:
    from avikal_backend.archive.pipeline.encoder import create_avk_file, generate_key_b
    from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
    from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker

    unlock_dt = _normalize_unlock_datetime_to_utc(unlock_dt)
    tracker = ProgressTracker("timecapsule-encrypt", [("prepare", 0.15), ("provider", 0.15), ("payload", 0.45), ("metadata", 0.15), ("finalize", 0.10)])
    tracker.update("prepare", "Validating unlock time", 0.2, force=True)
    _validate_unlock_datetime_against_ntp(unlock_dt)
    _enforce_system_clock_alignment("drand time-capsule creation")
    key_b = generate_key_b()
    helper_result = _run_drand_helper({"action": "seal", "unlock_timestamp": int(unlock_dt.timestamp()), "key_b_base64": base64.b64encode(key_b).decode("utf-8")})
    with bind_progress_tracker(tracker):
        kwargs = dict(
            password=request.password,
            keyphrase=request.keyphrase,
            unlock_datetime=unlock_dt,
            use_timecapsule=True,
            time_key=key_b,
            timecapsule_provider="drand",
            drand_round=helper_result.get("round"),
            drand_chain_hash=helper_result.get("chain_hash"),
            drand_chain_url=helper_result.get("chain_url"),
            drand_ciphertext=helper_result.get("ciphertext"),
            drand_beacon_id=helper_result.get("beacon_id"),
            pqc_enabled=request.pqc_enabled,
            pqc_storage_mode=request.pqc_storage_mode,
            pqc_keyfile_output=request.pqc_keyfile_output,
            pqc_keyfile_protection_mode=request.pqc_keyfile_protection_mode,
            pqc_keyfile_password=request.pqc_keyfile_password,
        )
        result = create_multi_file_avk(input_filepaths=request.input_files, output_filepath=request.output_file, excluded_input_paths=request.excluded_input_paths, **kwargs) if _should_use_multi_file_archive(request.input_files) else create_avk_file(input_filepath=request.input_files[0], output_filepath=request.output_file, **kwargs)
    return {"success": True, "message": "Time-capsule created successfully with drand timelock", "output_file": request.output_file, "result": result, "provider": "drand", "drand": {"round": helper_result.get("round"), "unlock_iso": helper_result.get("round_unlock_iso"), "chain_hash": helper_result.get("chain_hash"), "chain_url": helper_result.get("chain_url"), "beacon_id": helper_result.get("beacon_id")}}


def _create_timecapsule_via_aavrit(request: EncryptRequest, session_token: str | None, unlock_dt: datetime) -> dict:
    from avikal_backend.archive.pipeline.encoder import create_avk_file
    from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
    from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker

    unlock_dt = _normalize_unlock_datetime_to_utc(unlock_dt)
    _validate_unlock_datetime_against_ntp(unlock_dt)
    aavrit_url = _get_aavrit_server_url()
    config = _fetch_aavrit_capabilities(aavrit_url)
    _set_current_aavrit_mode(config["mode"])
    if config["mode"] == "private":
        if not session_token:
            _raise(401, "Aavrit private mode requires authentication")
        _verify_aavrit_session_token(session_token, aavrit_url)
    unlock_timestamp = int(unlock_dt.timestamp())
    data_hash = _create_aavrit_data_hash()
    commit_response = _request_aavrit_commit(aavrit_url, data_hash=data_hash, unlock_timestamp=unlock_timestamp, session_token=session_token)
    commit_payload = commit_response["payload"]
    commit_signature = commit_response["signature"]
    public_key_info = _fetch_aavrit_public_key(aavrit_url, session_token)
    _verify_aavrit_signature(commit_payload, commit_signature, public_key_info["public_key_pem"])
    if commit_payload.get("data_hash") != data_hash:
        _raise(502, "Aavrit commit response data hash mismatch.")
    if commit_payload.get("unlock_timestamp") != unlock_timestamp:
        _raise(502, "Aavrit commit response unlock timestamp mismatch.")
    if commit_payload.get("server_key_id") != public_key_info["key_id"]:
        _raise(502, "Aavrit commit response key identifier mismatch.")
    key_b = _derive_aavrit_time_key(commit_payload, commit_signature)
    tracker = ProgressTracker("timecapsule-encrypt", [("prepare", 0.15), ("provider", 0.15), ("payload", 0.45), ("metadata", 0.15), ("finalize", 0.10)])
    with bind_progress_tracker(tracker):
        kwargs = dict(
            password=request.password,
            keyphrase=request.keyphrase,
            unlock_datetime=unlock_dt,
            use_timecapsule=True,
            file_id=commit_payload["commit_id"],
            server_url=aavrit_url,
            time_key=key_b,
            timecapsule_provider="aavrit",
            aavrit_data_hash=data_hash,
            aavrit_commit_hash=commit_payload["commit_hash"],
            aavrit_server_key_id=commit_payload["server_key_id"],
            aavrit_commit_signature=commit_signature,
            pqc_enabled=request.pqc_enabled,
            pqc_storage_mode=request.pqc_storage_mode,
            pqc_keyfile_output=request.pqc_keyfile_output,
            pqc_keyfile_protection_mode=request.pqc_keyfile_protection_mode,
            pqc_keyfile_password=request.pqc_keyfile_password,
        )
        result = create_multi_file_avk(input_filepaths=request.input_files, output_filepath=request.output_file, excluded_input_paths=request.excluded_input_paths, **kwargs) if _should_use_multi_file_archive(request.input_files) else create_avk_file(input_filepath=request.input_files[0], output_filepath=request.output_file, **kwargs)
    return {"success": True, "message": "Time-capsule created successfully with Aavrit verification", "output_file": request.output_file, "result": result, "provider": "aavrit", "aavrit": {"mode": config["mode"], "server_url": aavrit_url, "commit_id": commit_payload["commit_id"], "commit_hash": commit_payload["commit_hash"], "server_key_id": commit_payload["server_key_id"]}}


async def archive_encrypt(params: dict[str, Any]) -> dict[str, Any]:
    request = EncryptRequest(**{k: v for k, v in params.items() if k != "session_token"})
    session_token = str(params.get("session_token") or "").strip() or None
    started_at = time.perf_counter()
    unlock_dt = None
    provider = None
    try:
        _validate_archive_password_policy(request)
        _validate_pqc_keyfile_password_policy(request)
        unlock_dt = _normalize_unlock_datetime_to_utc(request.unlock_datetime) if request.unlock_datetime else None
        if request.use_timecapsule:
            if unlock_dt is None:
                _raise(400, "Time-capsule unlock date is required.")
            provider = _resolve_timecapsule_provider(request)
            with _crypto_lock:
                response_payload = await asyncio.to_thread(_create_timecapsule_via_aavrit if provider == "aavrit" else _create_timecapsule_via_drand, request, session_token, unlock_dt) if provider == "aavrit" else await asyncio.to_thread(_create_timecapsule_via_drand, request, unlock_dt)
        else:
            with _crypto_lock:
                response_payload = await asyncio.to_thread(_create_regular_encryption, request, unlock_dt)
        _best_effort_log_archive_creation(request, started_at=started_at, unlock_dt=unlock_dt, response_payload=response_payload, provider=provider)
        return response_payload
    except ServiceError as exc:
        _best_effort_log_archive_creation(request, started_at=started_at, unlock_dt=unlock_dt, error_message=str(exc), provider=provider)
        raise
    except ValueError as exc:
        user_message = friendly_error(str(exc))
        _best_effort_log_archive_creation(request, started_at=started_at, unlock_dt=unlock_dt, error_message=user_message, provider=provider)
        raise ServiceError(user_message, code=400) from exc
    except Exception as exc:
        user_message = friendly_error(str(exc))
        _best_effort_log_archive_creation(request, started_at=started_at, unlock_dt=unlock_dt, error_message=user_message, provider=provider)
        raise ServiceError(user_message, code=500) from exc
    finally:
        _best_effort_scrub_model_secrets(request, "password", "keyphrase", "pqc_keyfile_password")


def _decrypt_timecapsule_with_key(request: DecryptRequest, metadata: dict, key_b: bytes, method_label: str) -> dict:
    from avikal_backend.archive.pipeline.decoder import extract_avk_file
    from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk
    from avikal_backend.archive.security.crypto import verify_time_key_hash
    from avikal_backend.archive.format.header import ARCHIVE_MODE_MULTI

    expected_time_key_hash = metadata.get("time_key_hash")
    if expected_time_key_hash is not None and not verify_time_key_hash(key_b, expected_time_key_hash):
        _raise(400, "Provider unlock key verification failed. The archive or unlock response is invalid.")
    preview_session_id, preview_dir = _preview_sessions.create()
    try:
        header_info, _route_hints = _read_avk_public_route(request.input_file)
        if header_info.get("archive_mode") == ARCHIVE_MODE_MULTI:
            result = extract_multi_file_avk(
                request.input_file,
                preview_dir,
                password=request.password,
                keyphrase=request.keyphrase,
                time_key=key_b,
                pqc_keyfile_path=request.pqc_keyfile,
                pqc_keyfile_password=request.pqc_keyfile_password,
                metadata_override=metadata,
            )
        else:
            output_path = extract_avk_file(
                request.input_file,
                preview_dir,
                password=request.password,
                keyphrase=request.keyphrase,
                time_key=key_b,
                pqc_keyfile_path=request.pqc_keyfile,
                pqc_keyfile_password=request.pqc_keyfile_password,
                metadata_override=metadata,
            )
            result = {"file_count": 1, "filename": os.path.basename(output_path), "output_file": output_path, "path": output_path, "size": os.path.getsize(output_path), "files": [{"filename": os.path.basename(output_path), "path": output_path, "output_file": output_path, "size": os.path.getsize(output_path)}]}
        return {"success": True, "message": f"Time-capsule preview ready via {method_label}", "output_dir": preview_dir, "preview_session_id": preview_session_id, "result": result, "pgn_created_at_ist": _get_pgn_created_time_ist(request.input_file), "pgn_source": "filesystem_mtime_ist"}
    except Exception:
        _preview_sessions.cleanup(preview_session_id)
        raise


def _decrypt_timecapsule_via_aavrit(request: DecryptRequest, session_token: str | None, metadata: dict | None = None) -> dict:
    metadata = metadata or _read_avk_metadata_only(request.input_file, request.password, request.keyphrase)
    aavrit_meta = _extract_aavrit_metadata(metadata)
    aavrit_url = _normalize_aavrit_server_url(aavrit_meta["server_url"])
    config = _fetch_aavrit_capabilities(aavrit_url)
    _set_current_aavrit_mode(config["mode"])
    if config["mode"] == "private":
        if not session_token:
            _raise(401, "Aavrit private mode requires authentication")
        _verify_aavrit_session_token(session_token, aavrit_url)
    public_key_info = _fetch_aavrit_public_key(aavrit_url, session_token)
    commit_payload = {"version": 1, "commit_id": aavrit_meta["commit_id"], "data_hash": aavrit_meta["data_hash"], "unlock_timestamp": metadata.get("unlock_timestamp"), "commit_hash": aavrit_meta["commit_hash"], "hash_alg": "SHA-256", "sig_alg": "Ed25519", "server_key_id": aavrit_meta["server_key_id"]}
    _verify_aavrit_signature(commit_payload, aavrit_meta["commit_signature"], public_key_info["public_key_pem"])
    if public_key_info["key_id"] != aavrit_meta["server_key_id"]:
        _raise(400, "Aavrit server key mismatch.")
    response_data = _request_aavrit_reveal(aavrit_url, commit_id=aavrit_meta["commit_id"], session_token=session_token)
    if response_data.get("success") is False and response_data.get("status") == "locked":
        _raise(403, "Time-capsule locked. Unlock time not reached yet.")
    if response_data.get("success") is not True:
        _raise(502, "Aavrit reveal failed.")
    reveal_payload = response_data.get("payload")
    reveal_signature = response_data.get("signature")
    if not isinstance(reveal_payload, dict) or not isinstance(reveal_signature, str):
        _raise(502, "Aavrit server returned an invalid reveal response.")
    _verify_aavrit_signature(reveal_payload, reveal_signature, public_key_info["public_key_pem"])
    if reveal_payload.get("commit_id") != aavrit_meta["commit_id"]:
        _raise(400, "Aavrit reveal commit mismatch.")
    if reveal_payload.get("data_hash") != aavrit_meta["data_hash"]:
        _raise(400, "Aavrit reveal data hash mismatch.")
    if reveal_payload.get("commit_hash") != aavrit_meta["commit_hash"]:
        _raise(400, "Aavrit reveal commit hash mismatch.")
    if reveal_payload.get("unlock_timestamp") != metadata.get("unlock_timestamp"):
        _raise(400, "Aavrit reveal unlock timestamp mismatch.")
    if reveal_payload.get("server_key_id") != aavrit_meta["server_key_id"]:
        _raise(400, "Aavrit reveal key identifier mismatch.")
    recomputed_commit_hash = _build_aavrit_commit_hash(commit_id=reveal_payload["commit_id"], data_hash=reveal_payload["data_hash"], unlock_timestamp=reveal_payload["unlock_timestamp"], reveal_value=reveal_payload["reveal_value"])
    if recomputed_commit_hash != aavrit_meta["commit_hash"]:
        _raise(400, "Aavrit reveal integrity verification failed.")
    key_b = _derive_aavrit_time_key(commit_payload, aavrit_meta["commit_signature"])
    return _decrypt_timecapsule_with_key(request, metadata, key_b, "aavrit")


def _decrypt_timecapsule_via_drand(request: DecryptRequest, metadata: dict | None = None) -> dict:
    from avikal_backend.archive.pipeline.progress import get_progress_tracker

    tracker = get_progress_tracker()
    metadata = metadata or _read_avk_metadata_only(request.input_file, request.password, request.keyphrase)
    if _detect_timecapsule_provider(metadata) != "drand":
        _raise(400, "This file is not a drand-backed time-capsule.")
    drand_ciphertext = metadata.get("drand_ciphertext")
    drand_round = metadata.get("drand_round")
    if not drand_ciphertext or not drand_round:
        _raise(400, "Invalid drand time-capsule metadata.")
    if tracker:
        tracker.update("provider", "Verifying trusted release time", 0.10, force=True)
    _enforce_system_clock_alignment("drand time-capsule decryption")
    if tracker:
        tracker.update("provider", "Contacting drand threshold network", 0.25, force=True)
    helper_result = _run_drand_helper({
        "action": "open",
        "ciphertext": drand_ciphertext,
        "round": drand_round,
        "expected_chain_hash": metadata.get("drand_chain_hash"),
        "expected_chain_url": metadata.get("drand_chain_url"),
        "expected_beacon_id": metadata.get("drand_beacon_id"),
    })
    if tracker:
        tracker.update("provider", "drand unlock shard received", 0.90, force=True)
    key_b_base64 = helper_result.get("key_b_base64")
    if not key_b_base64:
        _raise(500, "drand helper did not return the unlock shard.")
    if tracker:
        tracker.update("provider", "Opening time-capsule payload", 1.0, force=True)
    return _decrypt_timecapsule_with_key(request, metadata, base64.b64decode(key_b_base64), "drand")


async def archive_decrypt(params: dict[str, Any]) -> dict[str, Any]:
    from avikal_backend.archive.pipeline.progress import (
        CancellationToken,
        OperationCancelled,
        bind_cancellation_token,
        check_cancelled,
    )

    request = DecryptRequest(**{k: v for k, v in params.items() if k != "session_token"})
    session_token = str(params.get("session_token") or "").strip() or None
    cancel_token = CancellationToken()
    _set_active_decrypt_token(cancel_token)
    started_at = time.perf_counter()
    route_hints: dict[str, Any] = {}
    timecapsule_provider: str | None = None

    def log_decrypt_event(status: str, response_payload: dict[str, Any] | None = None, error_message: str | None = None) -> None:
        result = response_payload.get("result") if isinstance(response_payload, dict) else {}
        result = result if isinstance(result, dict) else {}
        action = "timecapsule_unlock_attempt" if timecapsule_provider else "archive_decode"
        _best_effort_log_activity_event(
            action=action,
            status=status,
            started_at=started_at,
            provider=timecapsule_provider,
            archive_kind="multi_file" if (result.get("file_count") or 1) > 1 else "single_file",
            secret_mode=activity_audit._derive_secret_mode(request.password, request.keyphrase),
            pqc_enabled=bool(route_hints.get("requires_pqc")),
            error_message=error_message,
            details={
                "archive_mode": "timecapsule" if timecapsule_provider else "regular",
                "file_count": result.get("file_count"),
                "pqc_keyfile_present": bool(request.pqc_keyfile),
                "unlock_datetime": route_hints.get("unlock_timestamp"),
            },
        )

    try:
        check_cancelled()
        if not os.path.exists(request.input_file):
            _raise(400, f"Input file not found: {request.input_file}")
        from avikal_backend.archive.format.header import ARCHIVE_MODE_MULTI

        header_info, route_hints = await asyncio.to_thread(_read_avk_public_route, request.input_file)
        check_cancelled()
        timecapsule_provider = route_hints.get("provider")
        if route_hints.get("available"):
            _validate_public_route_inputs(request, route_hints)
            _validate_public_timecapsule_lock(route_hints)
        metadata = None
        if timecapsule_provider:
            from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker

            tracker = ProgressTracker("decrypt", [("metadata", 0.22), ("provider", 0.18), ("payload", 0.45), ("finalize", 0.15)])

            def read_timecapsule_metadata() -> dict:
                with bind_cancellation_token(cancel_token), bind_progress_tracker(tracker):
                    tracker.update("metadata", "Reading time-capsule metadata", 0.05, force=True)
                    loaded = _read_avk_metadata_only(request.input_file, request.password, request.keyphrase)
                    tracker.update("metadata", "Time-capsule metadata verified", 1.0, force=True)
                    return loaded

            try:
                metadata = await asyncio.to_thread(read_timecapsule_metadata)
            except OperationCancelled:
                raise
            except Exception as meta_err:
                raise ServiceError(friendly_error(str(meta_err)), code=400) from meta_err
            def decrypt_timecapsule_with_progress() -> dict:
                with bind_cancellation_token(cancel_token), bind_progress_tracker(tracker):
                    if timecapsule_provider == "aavrit":
                        return _decrypt_timecapsule_via_aavrit(request, session_token, metadata)
                    if timecapsule_provider == "drand":
                        return _decrypt_timecapsule_via_drand(request, metadata)
                    _raise(400, "Unsupported time-capsule provider.")
            with _crypto_lock:
                response_payload = await asyncio.to_thread(decrypt_timecapsule_with_progress)
                log_decrypt_event("success", response_payload=response_payload)
                return response_payload

        def decrypt_regular_with_cancel() -> dict:
            with bind_cancellation_token(cancel_token):
                if timecapsule_provider == "aavrit":
                    return _decrypt_timecapsule_via_aavrit(request, session_token, metadata)
                if timecapsule_provider == "drand":
                    return _decrypt_timecapsule_via_drand(request, metadata)
                return _decrypt_regular_preview(request, header_info.get("archive_mode") == ARCHIVE_MODE_MULTI)

        with _crypto_lock:
            response_payload = await asyncio.to_thread(decrypt_regular_with_cancel)
            log_decrypt_event("success", response_payload=response_payload)
            return response_payload
    except OperationCancelled as exc:
        log_decrypt_event("cancelled", error_message="Decryption cancelled by user.")
        raise ServiceError("Decryption cancelled by user.", code=499) from exc
    except ValueError as exc:
        preserved = preserve_time_lock_detail(str(exc))
        message = preserved if preserved is not None else friendly_error(str(exc))
        log_decrypt_event("failed", error_message=message)
        raise ServiceError(message, code=400) from exc
    except ServiceError as exc:
        log_decrypt_event("failed", error_message=str(exc))
        raise
    finally:
        _clear_active_decrypt_token(cancel_token)
        _best_effort_scrub_model_secrets(request, "password", "keyphrase", "pqc_keyfile_password")


def _decrypt_regular_preview(request: DecryptRequest, is_multi_file_archive: bool) -> dict:
    from avikal_backend.archive.pipeline.decoder import extract_avk_file
    from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk
    from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker

    tracker = ProgressTracker("decrypt", [("metadata", 0.20), ("payload", 0.55), ("finalize", 0.25)])
    tracker.update("metadata", "Opening archive", 0.02, force=True)
    preview_session_id, preview_dir = _preview_sessions.create()
    try:
        with bind_progress_tracker(tracker):
            if is_multi_file_archive:
                result = extract_multi_file_avk(request.input_file, preview_dir, password=request.password, keyphrase=request.keyphrase, pqc_keyfile_path=request.pqc_keyfile, pqc_keyfile_password=request.pqc_keyfile_password)
            else:
                output_path = extract_avk_file(request.input_file, preview_dir, password=request.password, keyphrase=request.keyphrase, pqc_keyfile_path=request.pqc_keyfile, pqc_keyfile_password=request.pqc_keyfile_password)
                output_name = os.path.basename(output_path)
                output_size = os.path.getsize(output_path)
                result = {"file_count": 1, "filename": output_name, "output_file": output_path, "path": output_path, "size": output_size, "files": [{"filename": output_name, "path": output_path, "output_file": output_path, "size": output_size}]}
        return {"success": True, "message": f"Multi-file preview ready - {result['file_count']} files decrypted" if is_multi_file_archive else "Single-file preview ready", "output_dir": preview_dir, "preview_session_id": preview_session_id, "result": result, "pgn_created_at_ist": _get_pgn_created_time_ist(request.input_file), "pgn_source": "filesystem_mtime_ist"}
    except Exception:
        _preview_sessions.cleanup(preview_session_id)
        raise


async def archive_inspect(params: dict[str, Any]) -> dict[str, Any]:
    request = ArchiveInspectRequest(**params)
    _validate_avk_structure(request.input_file)
    _header_info, route_hints = await asyncio.to_thread(_read_avk_public_route, request.input_file)
    return {"success": True, "archive": {"provider": route_hints.get("provider"), "archive_type": route_hints.get("archive_type"), "metadata_accessible": bool(route_hints.get("available")), "metadata_requires_secret": False, "password_hint": route_hints.get("requires_password"), "keyphrase_hint": route_hints.get("requires_keyphrase"), "pqc_required": route_hints.get("requires_pqc"), "pqc_storage_mode": route_hints.get("pqc_storage_mode"), "unlock_timestamp": route_hints.get("unlock_timestamp"), "drand_round": route_hints.get("drand_round"), "keyphrase_wordlist_id": route_hints.get("keyphrase_wordlist_id")}}


async def pqc_keyfile_inspect(params: dict[str, Any]) -> dict[str, Any]:
    request = PqcKeyfileInspectRequest(**params)
    started_at = time.perf_counter()
    try:
        result = await asyncio.to_thread(inspect_pqc_keyfile, request.keyfile_path)
        _best_effort_log_activity_event(
            action="pqc_keyfile_inspect",
            status="success",
            started_at=started_at,
            pqc_enabled=True,
            details={
                "pqc_keyfile_present": True,
                "pqc_keyfile_protected": bool(result.get("requires_keyfile_password")),
            },
        )
        return result
    except Exception as exc:
        _best_effort_log_activity_event(
            action="pqc_keyfile_inspect",
            status="failed",
            started_at=started_at,
            pqc_enabled=True,
            error_message=str(exc),
            details={"pqc_keyfile_present": True},
        )
        raise


async def archive_rekey(params: dict[str, Any]) -> dict[str, Any]:
    request = RekeyRequest(**params)
    started_at = time.perf_counter()
    try:
        _validate_rekey_password_policy(request)
        _validate_avk_structure(request.input_file)
        _header_info, route_hints = await asyncio.to_thread(_read_avk_public_route, request.input_file)
        if route_hints.get("provider"):
            _raise(400, "Time-capsule rekey is not supported in this phase.")
        if route_hints.get("requires_pqc"):
            _raise(400, "PQC rekey is not supported in this phase.")
        if not route_hints.get("requires_password") and not route_hints.get("requires_keyphrase"):
            _raise(400, "Plaintext archives do not need rekey.")
        from avikal_backend.archive.pipeline.rekey import rekey_avk_archive

        with _crypto_lock:
            response_payload = await asyncio.to_thread(
                rekey_avk_archive,
                request.input_file,
                old_password=request.old_password,
                old_keyphrase=list(request.old_keyphrase) if request.old_keyphrase else None,
                new_password=request.new_password,
                new_keyphrase=list(request.new_keyphrase) if request.new_keyphrase else None,
                output_filepath=request.output_file,
                force=request.force,
            )
            _best_effort_log_activity_event(
                action="archive_rekey",
                status="success",
                started_at=started_at,
                secret_mode=activity_audit._derive_secret_mode(request.new_password, request.new_keyphrase),
                pqc_enabled=False,
                details={"archive_mode": "regular"},
            )
            return response_payload
    except ServiceError as exc:
        _best_effort_log_activity_event(
            action="archive_rekey",
            status="failed",
            started_at=started_at,
            error_message=str(exc),
            details={"archive_mode": "regular"},
        )
        raise
    except ValueError as exc:
        message = friendly_error(str(exc))
        _best_effort_log_activity_event(
            action="archive_rekey",
            status="failed",
            started_at=started_at,
            error_message=message,
            details={"archive_mode": "regular"},
        )
        raise ServiceError(message, code=400) from exc
    finally:
        _best_effort_scrub_model_secrets(request, "old_password", "old_keyphrase", "new_password", "new_keyphrase")


async def preview_cleanup_session(params: dict[str, Any]) -> dict[str, Any]:
    request = PreviewCleanupRequest(**params)
    removed = await asyncio.to_thread(_preview_sessions.cleanup, request.session_id)
    _best_effort_log_activity_event(
        action="preview_cleanup",
        status="success",
        details={"removed_count": 1 if removed else 0},
    )
    return {"success": True, "removed": removed}


async def preview_cleanup_all(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    removed = await asyncio.to_thread(_preview_sessions.cleanup_all)
    _best_effort_log_activity_event(
        action="preview_cleanup",
        status="success",
        details={"removed_count": removed},
    )
    return {"success": True, "removed": removed}


async def preview_cancel(params: dict[str, Any]) -> dict[str, Any]:
    request = CancelDecryptRequest(**params)
    operation_cancelled = _cancel_active_decrypt_operation()
    removed = await asyncio.to_thread(_preview_sessions.cleanup, request.session_id) if request.session_id else False
    _best_effort_log_activity_event(
        action="decrypt_cancel",
        status="cancelled" if operation_cancelled else "noop",
        details={"removed_count": 1 if removed else 0},
    )
    return {"success": True, "cancelled": operation_cancelled, "removed": removed}


async def keyphrase_generate(params: dict[str, Any]) -> dict[str, Any]:
    request = GenerateKeyphraseRequest(**params)
    from avikal_backend.mnemonic.generator import generate_mnemonic

    return {"success": True, "keyphrase": generate_mnemonic(word_count=request.word_count, language=request.language), "word_count": request.word_count}


async def keyphrase_roman_map(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    from avikal_backend.mnemonic.generator import get_romanized_word_pairs

    return {"success": True, "wordlist_id": "avikal-hi-2048-v1", "roman_wordlist_id": "avikal-hi-roman-2048-v1", "words": get_romanized_word_pairs()}


async def security_settings(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    native = get_native_runtime_status()
    return {
        "success": True,
        "settings": {
            "activity_log": activity_audit.get_summary(),
            "preferences": load_user_preferences(),
            "runtime": {
                "native_crypto": {"available": native.available, "import_error": native.import_error},
                "pqc_provider": provider_status(),
                "version": __version__,
                "preview_root": str(_preview_root),
                "log_dir": str(_log_dir),
            },
        },
    }


async def security_preferences_update(params: dict[str, Any]) -> dict[str, Any]:
    preferences = params.get("preferences", params)
    return {"success": True, "preferences": save_user_preferences(preferences)}


async def security_activity_log_export(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    started_at = time.perf_counter()
    payload = activity_audit.build_markdown_export()
    _best_effort_log_activity_event(
        action="activity_export",
        status="success",
        started_at=started_at,
        details={"expanded_entry_count": payload.get("entry_count")},
    )
    return {"success": True, **payload}


async def security_activity_log_clear(_params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"success": True, "removed": activity_audit.clear()}


METHODS = {
    "runtime.status": runtime_status,
    "runtime.verify": verify_runtime,
    "time.ntp": ntp_time,
    "auth.checkAavritServer": check_aavrit_server,
    "auth.login": auth_login,
    "auth.verifySession": auth_verify_session,
    "auth.profile": auth_profile,
    "auth.aavritDiagnostics": auth_aavrit_diagnostics,
    "auth.logout": auth_logout,
    "archive.encrypt": archive_encrypt,
    "archive.decrypt": archive_decrypt,
    "archive.inspect": archive_inspect,
    "archive.rekey": archive_rekey,
    "pqc.keyfileInspect": pqc_keyfile_inspect,
    "preview.cleanupSession": preview_cleanup_session,
    "preview.cleanupAll": preview_cleanup_all,
    "preview.cancel": preview_cancel,
    "keyphrase.generate": keyphrase_generate,
    "keyphrase.romanMap": keyphrase_roman_map,
    "security.settings": security_settings,
    "security.preferencesUpdate": security_preferences_update,
    "security.activityLogExport": security_activity_log_export,
    "security.activityLogClear": security_activity_log_clear,
}


async def dispatch(method: str, params: dict[str, Any] | None = None) -> Any:
    handler = METHODS.get(method)
    if handler is None:
        raise ServiceError(f"Unknown core method: {method}", code=404)
    payload = params if isinstance(params, dict) else {}
    try:
        return await handler(payload)
    except ServiceError:
        raise
    except ValidationError as exc:
        raise ServiceError(str(exc), code=422, data=exc.errors()) from exc
    except Exception as exc:
        raise ServiceError(friendly_error(str(exc)), code=500) from exc
