#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RookDuel Avikal Backend API Server
FastAPI server for Electron frontend communication

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import os
import sys
from pathlib import Path

import threading
import requests
import base64
from datetime import datetime, timezone, timedelta

# NTP time service (Requirements 9.1, 9.2, 9.3, 9.6, 9.7, 9.8)
from avikal_backend.services.ntp_service import (
    get_ntp_timestamp,
    get_clock_skew_warning,
)
from fastapi import FastAPI, HTTPException, Header, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from avikal_backend.audit.activity_audit import activity_audit
from fastapi.responses import JSONResponse

import uvicorn

from .archive_helpers import (
    best_effort_log_archive_creation as _best_effort_log_archive_creation,
    get_pgn_created_time_ist as _get_pgn_created_time_ist,
    should_use_multi_file_archive as _should_use_multi_file_archive,
    validate_avk_structure,
)
from .runtime import configure_logging, configure_windows_stdio, initialise_runtime_paths


configure_windows_stdio()
_RUNTIME_PATHS, _log_fallback_message = initialise_runtime_paths()
_LOG_DIR = _RUNTIME_PATHS.log_dir
_PREVIEW_SESSION_ROOT = _RUNTIME_PATHS.preview_session_root
log, _file_logging_message = configure_logging(_LOG_DIR)
if _log_fallback_message:
    log.warning(_log_fallback_message)
if _file_logging_message:
    log.warning(_file_logging_message)

# Allow direct script execution from the src layout.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

def create_avk_file(*args, **kwargs):
    try:
        from avikal_backend.archive.pipeline.encoder import create_avk_file as implementation
    except ImportError as exc:
        log.warning("Core encryption module not available: %s", exc)
        raise HTTPException(status_code=500, detail="Core encryption module not available") from exc
    return implementation(*args, **kwargs)


def extract_avk_file(*args, **kwargs):
    try:
        from avikal_backend.archive.pipeline.decoder import extract_avk_file as implementation
    except ImportError as exc:
        log.warning("Core decryption module not available: %s", exc)
        raise HTTPException(status_code=500, detail="Core decryption module not available") from exc
    return implementation(*args, **kwargs)


def generate_key_b(*args, **kwargs):
    try:
        from avikal_backend.archive.pipeline.encoder import generate_key_b as implementation
    except ImportError as exc:
        log.warning("Core key generation module not available: %s", exc)
        raise HTTPException(status_code=500, detail="Core key generation module not available") from exc
    return implementation(*args, **kwargs)


def generate_mnemonic(*args, **kwargs):
    try:
        from avikal_backend.mnemonic.generator import generate_mnemonic as implementation
    except ImportError as exc:
        log.warning("Mnemonic generator not available: %s", exc)
        raise HTTPException(status_code=500, detail="Mnemonic generator not available") from exc
    return implementation(*args, **kwargs)


def get_romanized_word_pairs(*args, **kwargs):
    try:
        from avikal_backend.mnemonic.generator import get_romanized_word_pairs as implementation
    except ImportError as exc:
        log.warning("Mnemonic wordlist helper not available: %s", exc)
        raise HTTPException(status_code=500, detail="Mnemonic wordlist helper not available") from exc
    return implementation(*args, **kwargs)

app = FastAPI(title="RookDuel Avikal API", version="1.0.0")
BACKEND_AUTH_HEADER = "X-Avikal-Backend-Token"
_BACKEND_AUTH_TOKEN = os.getenv("AVIKAL_BACKEND_TOKEN", "").strip() or None

# ---------------------------------------------------------------------------
# Concurrency lock for encryption/decryption operations (Requirement 7.12)
# Prevents race conditions when multiple requests hit the same file.
# ---------------------------------------------------------------------------
_crypto_lock = threading.Lock()

from .errors import (
    friendly_error,
    handle_requests_error,
    preserve_time_lock_detail,
)
from .drand import run_drand_helper
from .preview_sessions import PreviewSessionStore
from .aavrit_crypto import (
    build_aavrit_commit_hash,
    create_aavrit_data_hash,
    derive_aavrit_time_key,
    extract_aavrit_metadata,
    verify_aavrit_signature,
)
from .aavrit_client import (
    fetch_aavrit_capabilities,
    fetch_aavrit_public_key,
    normalize_aavrit_server_url,
    request_aavrit_commit,
    request_aavrit_reveal,
)

_preview_sessions = PreviewSessionStore(_PREVIEW_SESSION_ROOT, log)
_create_preview_session_dir = _preview_sessions.create
_cleanup_preview_session = _preview_sessions.cleanup
_cleanup_all_preview_sessions = _preview_sessions.cleanup_all


def _flatten_validation_detail(detail) -> str:
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict):
        message = detail.get("msg") or detail.get("message") or detail.get("detail")
        location = detail.get("loc")
        if isinstance(location, (list, tuple)):
            location_parts = [str(part) for part in location if str(part) not in {"body", "query", "path"}]
            location_text = ".".join(location_parts)
            if message and location_text:
                return f"{location_text}: {message}"
        if isinstance(message, str) and message.strip():
            return message
        return str(detail)
    if isinstance(detail, list):
        parts = [_flatten_validation_detail(item) for item in detail]
        parts = [part for part in parts if part]
        return "; ".join(parts)
    return str(detail)


def _cleanup_stale_preview_sessions_in_background() -> None:
    def worker() -> None:
        _preview_sessions.cleanup_stale()

    threading.Thread(
        target=worker,
        name="avikal-preview-session-cleanup",
        daemon=True,
    ).start()


@app.on_event("startup")
async def schedule_preview_session_cleanup() -> None:
    _cleanup_stale_preview_sessions_in_background()
    try:
        from avikal_backend.services.ntp_service import prime_ntp_cache_async

        prime_ntp_cache_async()
    except Exception as exc:
        log.debug("Trusted time warmup skipped: %s", exc)
    try:
        from .drand import prime_drand_helper_async

        prime_drand_helper_async()
    except Exception as exc:
        log.debug("drand helper warmup skipped: %s", exc)


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(_request: Request, exc: RequestValidationError):
    detail = _flatten_validation_detail(exc.errors()) or "Invalid request."
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": detail})

# ---------------------------------------------------------------------------

from .config import (
    ALLOWED_CORS_ORIGINS,
    DEFAULT_ALLOWED_CORS_ORIGINS,
)

log.info("Configured backend CORS origins: %s", ", ".join(ALLOWED_CORS_ORIGINS))

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def require_backend_token(request: Request, call_next):
    if _BACKEND_AUTH_TOKEN is None:
        return await call_next(request)

    if request.method.upper() == "OPTIONS" or request.url.path == "/health":
        return await call_next(request)

    provided_token = request.headers.get(BACKEND_AUTH_HEADER)
    if provided_token != _BACKEND_AUTH_TOKEN:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Backend request token is missing or invalid."},
        )

    return await call_next(request)

# Global Aavrit session storage (in production, use secure storage)
current_aavrit_session_token = None
current_aavrit_server_url = None
current_aavrit_mode = None

from .schemas import (
    ArchiveInspectRequest,
    DecryptRequest,
    EncryptRequest,
    GenerateKeyphraseRequest,
    PreviewCleanupRequest,
    VerifySessionRequest,
    AavritLoginRequest,
    AavritServerCheckRequest,
)


def set_current_aavrit_server_url(raw_url: str) -> str:
    global current_aavrit_server_url

    normalized = normalize_aavrit_server_url(raw_url)
    current_aavrit_server_url = normalized
    return normalized

def get_aavrit_server_url(explicit_url: str | None = None, *, required: bool = True) -> str | None:
    candidate = explicit_url or current_aavrit_server_url
    if not candidate:
        if required:
            raise HTTPException(status_code=400, detail="Aavrit server URL is not configured.")
        return None
    return normalize_aavrit_server_url(candidate)

def clear_aavrit_auth_state() -> None:
    global current_aavrit_session_token, current_aavrit_server_url, current_aavrit_mode

    current_aavrit_session_token = None
    current_aavrit_server_url = None
    current_aavrit_mode = None

# Dependency function
def get_aavrit_session_token(
    x_aavrit_session: str | None = Header(default=None, alias="X-Aavrit-Session"),
    x_aavrit_server_url: str | None = Header(default=None, alias="X-Aavrit-Server-URL"),
):
    """Get the current Aavrit session token and optionally restore the active Aavrit server."""
    global current_aavrit_session_token

    session_token = current_aavrit_session_token or x_aavrit_session
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated. Please login first.")
    if not current_aavrit_session_token and x_aavrit_session:
        current_aavrit_session_token = x_aavrit_session
        log.info("Adopted Aavrit session from X-Aavrit-Session header (backend was restarted)")
    if x_aavrit_server_url:
        set_current_aavrit_server_url(x_aavrit_server_url)
    return session_token

# Helper functions
def verify_aavrit_session_token(session_token: str, aavrit_server_url: str | None = None) -> dict:
    """Verify that a provided Aavrit session is accepted by the selected Aavrit server."""
    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication session required")

    base_url = get_aavrit_server_url(aavrit_server_url)
    config = fetch_aavrit_capabilities(base_url)
    if config["mode"] != "private":
        return {"sub": "aavrit-public-mode", "mode": config["mode"]}

    try:
        response = requests.post(
            f"{base_url}/auth/verify",
            headers={"Authorization": f"Bearer {session_token}"},
            timeout=30,
        )
    except requests.RequestException as exc:
        raise handle_requests_error(exc, "Aavrit server")

    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError as exc:
            raise HTTPException(status_code=502, detail="Aavrit authentication check failed.") from exc
        user = payload.get("user", {}) if isinstance(payload, dict) else {}
        return {
            "sub": user.get("id", "aavrit-authenticated-user"),
            "mode": "private",
            "email": user.get("email", ""),
            "name": user.get("name", ""),
        }
    if response.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail="Too many authentication attempts. Please try again later.")
    raise HTTPException(status_code=502, detail="Aavrit authentication check failed.")


def resolve_timecapsule_provider(request: EncryptRequest) -> str:
    provider = (request.timecapsule_provider or "aavrit").strip().lower()
    if provider not in {"aavrit", "drand"}:
        raise HTTPException(status_code=400, detail="Unsupported time-capsule provider.")
    return provider


def detect_timecapsule_provider(metadata: dict) -> str | None:
    provider = metadata.get("timecapsule_provider")
    if provider:
        return provider
    if metadata.get("drand_round") and metadata.get("drand_ciphertext"):
        return "drand"
    return None


def read_avk_public_route(avk_filepath: str) -> tuple[dict, dict]:
    """Read only the public archive routing hints from keychain.pgn."""
    from avikal_backend.archive.format.container import read_avk_header_and_keychain
    from avikal_backend.archive.format.header import (
        ARCHIVE_MODE_MULTI,
        extract_public_route_tags_from_keychain_pgn,
        parse_header_bytes,
    )

    header_bytes, keychain_pgn = read_avk_header_and_keychain(avk_filepath)
    header_info = parse_header_bytes(header_bytes)
    route_hints = extract_public_route_tags_from_keychain_pgn(keychain_pgn)
    route_hints.update(
        {
            "provider": header_info.get("provider"),
            "archive_type": "multi_file" if header_info.get("archive_mode") == ARCHIVE_MODE_MULTI else "single_file",
            "aad": header_info.get("aad"),
        }
    )
    return header_info, route_hints


def validate_public_route_inputs(request: DecryptRequest, route_hints: dict) -> None:
    """Fail fast on missing user inputs using only public non-secret route hints."""
    missing: list[str] = []
    if route_hints.get("requires_password") and not request.password:
        missing.append("password")
    if route_hints.get("requires_keyphrase") and not request.keyphrase:
        missing.append("21-word keyphrase")
    if route_hints.get("requires_pqc") and not request.pqc_keyfile:
        missing.append(".avkkey")

    if missing:
        if missing == [".avkkey"]:
            raise HTTPException(
                status_code=400,
                detail="This archive requires the matching .avkkey file before decryption can continue.",
            )
        if len(missing) == 1:
            raise HTTPException(
                status_code=400,
                detail=f"This archive requires its {missing[0]} before decryption can continue.",
            )
        if missing == ["password", "21-word keyphrase"]:
            raise HTTPException(
                status_code=400,
                detail="This archive requires both its password and 21-word keyphrase before decryption can continue.",
            )
        raise HTTPException(
            status_code=400,
            detail=f"This archive requires {', '.join(missing)} before decryption can continue.",
        )


def validate_public_timecapsule_lock(route_hints: dict) -> None:
    """Fail fast when trusted time proves the capsule is still locked."""
    provider = route_hints.get("provider")
    unlock_timestamp = route_hints.get("unlock_timestamp")
    if provider not in {"drand", "aavrit"} or unlock_timestamp is None:
        return

    from avikal_backend.archive.security.time_lock import format_unlock_time, get_trusted_now

    current_time = get_trusted_now()
    unlock_time = datetime.fromtimestamp(int(unlock_timestamp), tz=timezone.utc)
    if current_time < unlock_time:
        raise HTTPException(
            status_code=403,
            detail=(
                f"This capsule is still locked. Unlock becomes available at "
                f"{format_unlock_time(int(unlock_timestamp))}. Current time: "
                f"{current_time.strftime('%Y-%m-%d %H:%M UTC')}"
            ),
        )


def require_aavrit_auth_if_needed(aavrit_url: str, session_token: str | None) -> dict:
    global current_aavrit_mode

    config = fetch_aavrit_capabilities(aavrit_url)
    current_aavrit_mode = config["mode"]
    if config["mode"] == "private":
        if not session_token:
            raise HTTPException(status_code=401, detail="Aavrit private mode requires authentication")
        verify_aavrit_session_token(session_token, aavrit_url)
    return config


def normalize_unlock_datetime_to_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid unlock_datetime format: {str(exc)}") from exc

    if dt.tzinfo is None:
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        dt = dt.replace(tzinfo=local_tz)

    return dt.astimezone(timezone.utc)


def validate_unlock_datetime_against_ntp(unlock_dt: datetime) -> None:
    try:
        ntp_now = get_ntp_timestamp()
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Time verification failed. Check your internet connection and trusted-time availability."
        )

    unlock_dt = normalize_unlock_datetime_to_utc(unlock_dt)
    unlock_timestamp_check = int(unlock_dt.timestamp())
    if unlock_timestamp_check <= ntp_now:
        trusted_now = datetime.fromtimestamp(ntp_now, tz=timezone.utc).isoformat()
        raise HTTPException(
            status_code=400,
            detail=(
                "Unlock time must be in the future according to trusted network time. "
                f"Current trusted time: {trusted_now}"
            )
        )

    five_years_seconds = 5 * 365 * 24 * 60 * 60
    if unlock_timestamp_check - ntp_now > five_years_seconds:
        max_unlock = datetime.fromtimestamp(ntp_now + five_years_seconds, tz=timezone.utc)
        raise HTTPException(
            status_code=400,
            detail=f"Maximum lock duration is 5 years. Maximum allowed unlock date: {max_unlock.isoformat()}"
        )

    skew_warning = get_clock_skew_warning()
    if skew_warning:
        log.warning("Clock skew detected during timecapsule operation: %s", skew_warning)


def enforce_system_clock_alignment(operation_label: str = "Time-capsule operations") -> None:
    """Reject drand-sensitive flows when the local system clock is clearly out of sync."""
    skew_warning = get_clock_skew_warning()
    if not skew_warning:
        return

    log.warning("Blocking %s because of local clock skew: %s", operation_label, skew_warning)
    raise HTTPException(
        status_code=400,
        detail=(
            "Your system clock appears out of sync with trusted network time. "
            "Correct your Windows date and time settings, then try the drand time-capsule again."
        ),
    )


def decrypt_timecapsule_with_key(request: DecryptRequest, metadata: dict, key_b: bytes, method_label: str):
    log.info("Decrypting with %s split-key architecture...", method_label)
    preview_session_id = None
    try:
        from avikal_backend.archive.security.crypto import verify_time_key_hash

        expected_time_key_hash = metadata.get("time_key_hash")
        if expected_time_key_hash is not None and not verify_time_key_hash(key_b, expected_time_key_hash):
            raise HTTPException(status_code=400, detail="Provider unlock key verification failed. The archive or unlock response is invalid.")

        preview_session_id, preview_dir = _create_preview_session_dir()
        filename = metadata.get('filename', '')
        if filename == "multi_file_container.zip" or filename == "__multi__":
            log.info("Detected multi-file timecapsule container. Extracting all files...")
            from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk

            keyphrase_list = request.keyphrase if request.keyphrase else None
            result = extract_multi_file_avk(
                avk_filepath=request.input_file,
                output_directory=preview_dir,
                password=request.password,
                keyphrase=keyphrase_list,
                time_key=key_b,
                pqc_keyfile_path=request.pqc_keyfile,
                metadata_override=metadata,
            )

            output_filepath = result['output_directory']
            original_data_size = result['total_size']
            log.info("Successfully extracted %d files to %s", result['file_count'], output_filepath)
        else:
            from avikal_backend.archive.pipeline.decoder import extract_avk_file

            output_filepath = extract_avk_file(
                avk_filepath=request.input_file,
                output_directory=preview_dir,
                password=request.password,
                keyphrase=request.keyphrase,
                pqc_keyfile_path=request.pqc_keyfile,
                time_key=key_b,
                metadata_override=metadata,
            )
            original_data_size = os.path.getsize(output_filepath)
            log.info("Successfully decrypted to %s", output_filepath)

        try:
            ist_tz = timezone(timedelta(hours=5, minutes=30))
            created_utc = datetime.fromtimestamp(os.path.getmtime(request.input_file), tz=timezone.utc)
            pgn_created_at_ist = created_utc.astimezone(ist_tz).isoformat()
        except Exception:
            pgn_created_at_ist = None

        if filename == "multi_file_container.zip" or filename == "__multi__":
            return {
                "success": True,
                "message": f"Time-capsule preview ready using {method_label} split-key architecture",
                "output_dir": preview_dir,
                "preview_session_id": preview_session_id,
                "method": method_label,
                "result": result,
                "pgn_created_at_ist": pgn_created_at_ist,
                "pgn_source": "filesystem_mtime_ist"
            }

        return {
            "success": True,
            "message": f"Time-capsule preview ready using {method_label} split-key architecture",
            "output_file": output_filepath,
            "output_dir": preview_dir,
            "preview_session_id": preview_session_id,
            "method": method_label,
            "result": {
                "file_count": 1,
                "filename": metadata.get('filename', os.path.basename(output_filepath)),
                "output_file": output_filepath,
                "path": output_filepath,
                "size": original_data_size,
                "files": [
                    {
                        "filename": metadata.get('filename', os.path.basename(output_filepath)),
                        "output_file": output_filepath,
                        "path": output_filepath,
                        "size": original_data_size,
                    }
                ],
            },
            "pgn_created_at_ist": pgn_created_at_ist,
            "pgn_source": "filesystem_mtime_ist"
        }
    except HTTPException:
        raise
    except ValueError as exc:
        if preview_session_id:
            _cleanup_preview_session(preview_session_id)
        raise HTTPException(status_code=400, detail=friendly_error(str(exc))) from exc
    except Exception:
        if preview_session_id:
            _cleanup_preview_session(preview_session_id)
        raise
    except HTTPException:
        if preview_session_id:
            _cleanup_preview_session(preview_session_id)
        raise
    except Exception as e:
        if preview_session_id:
            _cleanup_preview_session(preview_session_id)
        log.error("%s split-key decryption failed: %s", method_label, e, exc_info=True)
        raise HTTPException(status_code=500, detail=friendly_error(str(e)))

def create_timecapsule_via_aavrit(request: EncryptRequest, session_token: str | None, unlock_dt: datetime):
    """Create an Aavrit-backed time-capsule using commit/reveal verification."""
    try:
        unlock_dt = normalize_unlock_datetime_to_utc(unlock_dt)
        from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker
        tracker = ProgressTracker(
            "timecapsule-encrypt",
            [("prepare", 0.15), ("provider", 0.15), ("payload", 0.45), ("metadata", 0.15), ("finalize", 0.10)],
        )
        tracker.update("prepare", "Validating Aavrit session", 0.2, force=True)
        aavrit_url = get_aavrit_server_url()
        require_aavrit_auth_if_needed(aavrit_url, session_token)
        validate_unlock_datetime_against_ntp(unlock_dt)
        tracker.update("prepare", "Trusted time verified", 1.0)

        unlock_timestamp = int(unlock_dt.timestamp())
        data_hash = create_aavrit_data_hash()

        tracker.update("provider", "Creating Aavrit commit", 0.5)
        commit_response = request_aavrit_commit(
            aavrit_url,
            data_hash=data_hash,
            unlock_timestamp=unlock_timestamp,
            session_token=session_token,
        )
        tracker.update("provider", "Aavrit commit created", 1.0)

        public_key_info = fetch_aavrit_public_key(aavrit_url, session_token)
        commit_payload = commit_response["payload"]
        commit_signature = commit_response["signature"]
        verify_aavrit_signature(commit_payload, commit_signature, public_key_info["public_key_pem"])

        if commit_payload.get("data_hash") != data_hash:
            raise HTTPException(status_code=502, detail="Aavrit commit response data hash mismatch.")
        if commit_payload.get("unlock_timestamp") != unlock_timestamp:
            raise HTTPException(status_code=502, detail="Aavrit commit response unlock timestamp mismatch.")
        if commit_payload.get("server_key_id") != public_key_info["key_id"]:
            raise HTTPException(status_code=502, detail="Aavrit commit response key identifier mismatch.")

        key_b = derive_aavrit_time_key(commit_payload, commit_signature)

        from avikal_backend.archive.pipeline.encoder import create_avk_file

        with bind_progress_tracker(tracker):
            if _should_use_multi_file_archive(request.input_files):
                from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
                result = create_multi_file_avk(
                    input_filepaths=request.input_files,
                    output_filepath=request.output_file,
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
                    pqc_keyfile_output=request.pqc_keyfile_output,
                )
            else:
                result = create_avk_file(
                    input_filepath=request.input_files[0],
                    output_filepath=request.output_file,
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
                    pqc_keyfile_output=request.pqc_keyfile_output,
                )

        return {
            "success": True,
            "message": "Time-capsule created successfully with Aavrit verification",
            "output_file": request.output_file,
            "result": result,
            "provider": "aavrit",
            "aavrit": {
                "mode": current_aavrit_mode,
                "server_url": aavrit_url,
                "commit_id": commit_payload["commit_id"],
                "commit_hash": commit_payload["commit_hash"],
                "server_key_id": commit_payload["server_key_id"],
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error("Aavrit time-capsule creation failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=friendly_error(str(e)))


def create_timecapsule_via_drand(request: EncryptRequest, unlock_dt: datetime):
    """Create a drand-backed public time-capsule with no org-Aavrit dependency."""
    try:
        unlock_dt = normalize_unlock_datetime_to_utc(unlock_dt)
        from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker
        tracker = ProgressTracker(
            "timecapsule-encrypt",
            [("prepare", 0.15), ("provider", 0.15), ("payload", 0.45), ("metadata", 0.15), ("finalize", 0.10)],
        )
        tracker.update("prepare", "Validating unlock time", 0.2, force=True)
        validate_unlock_datetime_against_ntp(unlock_dt)
        enforce_system_clock_alignment("drand time-capsule creation")
        tracker.update("prepare", "Trusted time verified", 1.0)

        key_b = generate_key_b()
        unlock_timestamp = int(unlock_dt.timestamp())
        tracker.update("provider", "Preparing drand timelock", 0.4)
        helper_result = run_drand_helper({
            "action": "seal",
            "unlock_timestamp": unlock_timestamp,
            "key_b_base64": base64.b64encode(key_b).decode("utf-8"),
        })
        tracker.update("provider", "drand timelock prepared", 1.0)

        with bind_progress_tracker(tracker):
            if _should_use_multi_file_archive(request.input_files):
                from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
                result = create_multi_file_avk(
                    input_filepaths=request.input_files,
                    output_filepath=request.output_file,
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
                    pqc_keyfile_output=request.pqc_keyfile_output,
                )
            else:
                from avikal_backend.archive.pipeline.encoder import create_avk_file
                result = create_avk_file(
                    input_filepath=request.input_files[0],
                    output_filepath=request.output_file,
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
                    pqc_keyfile_output=request.pqc_keyfile_output,
                )

        return {
            "success": True,
            "message": "Time-capsule created successfully with drand timelock",
            "output_file": request.output_file,
            "result": result,
            "provider": "drand",
            "drand": {
                "round": helper_result.get("round"),
                "unlock_iso": helper_result.get("round_unlock_iso"),
                "chain_hash": helper_result.get("chain_hash"),
                "chain_url": helper_result.get("chain_url"),
                "beacon_id": helper_result.get("beacon_id"),
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        log.error("drand time-capsule creation failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=friendly_error(str(e)))

def create_regular_encryption(request: EncryptRequest, unlock_dt: datetime):
    """Create regular encryption (no time-capsule)"""
    try:
        from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker
        # Import multi-file encoder for proper multi-file support
        from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
        from avikal_backend.archive.pipeline.encoder import create_avk_file
        tracker = ProgressTracker(
            "encrypt",
            [("prepare", 0.10), ("payload", 0.60), ("metadata", 0.20), ("finalize", 0.10)],
        )
        
        # Use multi-file encoder for multiple inputs and for folder inputs.
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
                    pqc_keyfile_output=request.pqc_keyfile_output,
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
                    pqc_keyfile_output=request.pqc_keyfile_output,
                )
        
        return {
            "success": True,
            "message": "Files encrypted successfully",
            "output_file": request.output_file,
            "result": result
        }
        
    except Exception as e:
        log.error("Regular encryption failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=friendly_error(str(e)))

def read_avk_metadata_only(
    avk_filepath: str,
    password: str = None,
    keyphrase: list = None,
    *,
    header_bytes: bytes | None = None,
    keychain_pgn: str | None = None,
) -> dict:
    """
    Read only metadata from .avk file without decrypting the full payload.
    Used for provider-backed time-capsule flows without decrypting the full payload.
    
    Args:
        avk_filepath: Path to .avk file
        password: Password for metadata decryption (optional)
        keyphrase: Keyphrase list for metadata decryption (optional)
    
    Returns:
        dict: Parsed archive metadata
    """
    from avikal_backend.archive.format.container import open_avk_payload_stream
    from avikal_backend.archive.format.header import parse_header_bytes, validate_metadata_against_header
    from avikal_backend.archive.chess_metadata import decode_chess_to_metadata_enhanced
    
    if header_bytes is None or keychain_pgn is None:
        try:
            with open_avk_payload_stream(avk_filepath) as (header_bytes, keychain_pgn, _payload_stream):
                pass
        except Exception as e:
            raise ValueError(f"Failed to open .avk file: {str(e)}")
    
    try:
        # Decode chess PGN to get metadata (skip timelock for metadata reading)
        metadata = decode_chess_to_metadata_enhanced(
            keychain_pgn,
            password,
            keyphrase,
            skip_timelock=True,
            aad=header_bytes,
        )
        validate_metadata_against_header(parse_header_bytes(header_bytes), metadata)
        return metadata
    except ValueError as e:
        error_msg = str(e)
        if "password protected" in error_msg.lower():
            raise ValueError("This protected archive requires a password or keyphrase.")
        elif (
            "incorrect password" in error_msg.lower()
            or "incorrect keyphrase" in error_msg.lower()
            or "wrong key" in error_msg.lower()
            or "decryption failed" in error_msg.lower()
            or "chess metadata decryption failed" in error_msg.lower()
        ):
            raise ValueError("Incorrect password or keyphrase.")
        else:
            raise ValueError(f"Metadata decoding failed: {error_msg}")


def decrypt_timecapsule_via_aavrit(request: DecryptRequest, session_token: str | None, metadata: dict | None = None):
    """Decrypt an Aavrit-backed time-capsule after reveal verification succeeds."""
    try:
        from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker
        tracker = ProgressTracker(
            "decrypt",
            [("prepare", 0.15), ("provider", 0.15), ("metadata", 0.20), ("payload", 0.35), ("finalize", 0.15)],
        )
        tracker.update("prepare", "Reading archive metadata", 0.25, force=True)
        log.info("Reading metadata from %s", request.input_file)
        if metadata is None:
            try:
                metadata = read_avk_metadata_only(request.input_file, request.password, request.keyphrase)
            except Exception as e:
                raise HTTPException(status_code=400, detail=friendly_error(str(e)))

        aavrit_meta = extract_aavrit_metadata(metadata)
        aavrit_url = normalize_aavrit_server_url(aavrit_meta["server_url"])
        require_aavrit_auth_if_needed(aavrit_url, session_token)

        tracker.update("provider", "Verifying Aavrit commit", 0.45)
        public_key_info = fetch_aavrit_public_key(aavrit_url, session_token)
        commit_payload = {
            "version": 1,
            "commit_id": aavrit_meta["commit_id"],
            "data_hash": aavrit_meta["data_hash"],
            "unlock_timestamp": metadata.get("unlock_timestamp"),
            "commit_hash": aavrit_meta["commit_hash"],
            "hash_alg": "SHA-256",
            "sig_alg": "Ed25519",
            "server_key_id": aavrit_meta["server_key_id"],
        }
        verify_aavrit_signature(commit_payload, aavrit_meta["commit_signature"], public_key_info["public_key_pem"])
        if public_key_info["key_id"] != aavrit_meta["server_key_id"]:
            raise HTTPException(status_code=400, detail="Aavrit server key mismatch.")

        tracker.update("provider", "Requesting Aavrit reveal", 0.7)
        response_data = request_aavrit_reveal(aavrit_url, commit_id=aavrit_meta["commit_id"], session_token=session_token)
        if response_data.get("success") is False and response_data.get("status") == "locked":
            raise HTTPException(status_code=403, detail="Time-capsule locked. Unlock time not reached yet.")
        if response_data.get("success") is not True:
            raise HTTPException(status_code=502, detail="Aavrit reveal failed.")

        reveal_payload = response_data.get("payload")
        reveal_signature = response_data.get("signature")
        if not isinstance(reveal_payload, dict) or not isinstance(reveal_signature, str):
            raise HTTPException(status_code=502, detail="Aavrit server returned an invalid reveal response.")

        verify_aavrit_signature(reveal_payload, reveal_signature, public_key_info["public_key_pem"])
        if reveal_payload.get("commit_id") != aavrit_meta["commit_id"]:
            raise HTTPException(status_code=400, detail="Aavrit reveal commit mismatch.")
        if reveal_payload.get("data_hash") != aavrit_meta["data_hash"]:
            raise HTTPException(status_code=400, detail="Aavrit reveal data hash mismatch.")
        if reveal_payload.get("commit_hash") != aavrit_meta["commit_hash"]:
            raise HTTPException(status_code=400, detail="Aavrit reveal commit hash mismatch.")
        if reveal_payload.get("unlock_timestamp") != metadata.get("unlock_timestamp"):
            raise HTTPException(status_code=400, detail="Aavrit reveal unlock timestamp mismatch.")
        if reveal_payload.get("server_key_id") != aavrit_meta["server_key_id"]:
            raise HTTPException(status_code=400, detail="Aavrit reveal key identifier mismatch.")

        recomputed_commit_hash = build_aavrit_commit_hash(
            commit_id=reveal_payload["commit_id"],
            data_hash=reveal_payload["data_hash"],
            unlock_timestamp=reveal_payload["unlock_timestamp"],
            reveal_value=reveal_payload["reveal_value"],
        )
        if recomputed_commit_hash != aavrit_meta["commit_hash"]:
            raise HTTPException(status_code=400, detail="Aavrit reveal integrity verification failed.")

        key_b = derive_aavrit_time_key(commit_payload, aavrit_meta["commit_signature"])
        tracker.update("provider", "Aavrit reveal verified", 1.0)

        with bind_progress_tracker(tracker):
            return decrypt_timecapsule_with_key(request, metadata, key_b, "aavrit")
        
    except HTTPException:
        raise
    except Exception as e:
        log.error("Aavrit time-capsule decryption failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=friendly_error(str(e)))


def decrypt_timecapsule_via_drand(request: DecryptRequest, metadata: dict | None = None):
    """Decrypt time-capsule using drand timelock release."""
    try:
        from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker
        tracker = ProgressTracker(
            "decrypt",
            [("prepare", 0.15), ("provider", 0.15), ("metadata", 0.20), ("payload", 0.35), ("finalize", 0.15)],
        )
        tracker.update("prepare", "Reading archive metadata", 0.25, force=True)
        log.info("Reading metadata from %s", request.input_file)
        if metadata is None:
            try:
                metadata = read_avk_metadata_only(request.input_file, request.password, request.keyphrase)
            except Exception as e:
                raise HTTPException(status_code=400, detail=friendly_error(str(e)))

        provider = detect_timecapsule_provider(metadata)
        if provider != "drand":
            raise HTTPException(status_code=400, detail="This file is not a drand-backed time-capsule.")

        drand_ciphertext = metadata.get("drand_ciphertext")
        drand_round = metadata.get("drand_round")
        if not drand_ciphertext or not drand_round:
            raise HTTPException(status_code=400, detail="Invalid drand time-capsule metadata.")

        enforce_system_clock_alignment("drand time-capsule decryption")
        tracker.update("provider", "Waiting for drand unlock shard", 0.4)
        helper_result = run_drand_helper({
            "action": "open",
            "ciphertext": drand_ciphertext,
            "round": drand_round,
        })
        tracker.update("provider", "drand unlock shard received", 1.0)

        key_b_base64 = helper_result.get("key_b_base64")
        if not key_b_base64:
            raise HTTPException(status_code=500, detail="drand helper did not return the unlock shard.")

        try:
            key_b = base64.b64decode(key_b_base64)
        except Exception as exc:
            log.error("Failed to decode drand Key B: %s", exc)
            raise HTTPException(status_code=500, detail="Invalid drand unlock payload.")

        with bind_progress_tracker(tracker):
            return decrypt_timecapsule_with_key(request, metadata, key_b, "drand")
    except HTTPException:
        raise
    except Exception as e:
        log.error("drand time-capsule decryption failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=friendly_error(str(e)))

from .routes import router as api_router

app.include_router(api_router)

def start_server(host: str | None = None, port: int | None = None):
    """Start the API server"""
    resolved_host = host or os.getenv("AVIKAL_BACKEND_HOST", "127.0.0.1")
    resolved_port = port if port is not None else int(os.getenv("AVIKAL_BACKEND_PORT", "5000"))
    uvicorn.run(app, host=resolved_host, port=resolved_port, log_level="info")

if __name__ == "__main__":
    start_server()

