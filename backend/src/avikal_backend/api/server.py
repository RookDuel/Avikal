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
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from avikal_backend.audit.activity_audit import activity_audit

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

# Import core modules with error handling
try:
    from avikal_backend.archive.pipeline.decoder import extract_avk_file
    from avikal_backend.archive.pipeline.encoder import create_avk_file, generate_key_b
    from avikal_backend.mnemonic.generator import generate_mnemonic
    log.info("Core modules imported successfully")
except ImportError as e:
    log.warning("Core modules not found: %s", e)
    log.warning("Some encryption features may not work without core modules")
    
    # Create dummy functions for missing modules
    def create_avk_file(*args, **kwargs):
        raise HTTPException(status_code=500, detail="Core encryption module not available")
    
    def extract_avk_file(*args, **kwargs):
        raise HTTPException(status_code=500, detail="Core decryption module not available")
    
    def generate_mnemonic(*args, **kwargs):
        raise HTTPException(status_code=500, detail="Mnemonic generator not available")

app = FastAPI(title="RookDuel Avikal API", version="1.0.0")

# ---------------------------------------------------------------------------
# Concurrency lock for encryption/decryption operations (Requirement 7.12)
# Prevents race conditions when multiple requests hit the same file.
# ---------------------------------------------------------------------------
_crypto_lock = threading.Lock()

from .errors import (
    friendly_error,
    handle_requests_error,
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
_cleanup_stale_preview_sessions = _preview_sessions.cleanup_stale
_create_preview_session_dir = _preview_sessions.create
_cleanup_preview_session = _preview_sessions.cleanup
_cleanup_all_preview_sessions = _preview_sessions.cleanup_all


_cleanup_stale_preview_sessions()

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


def decrypt_timecapsule_with_key(request: DecryptRequest, metadata: dict, key_b: bytes, method_label: str):
    log.info("Decrypting with %s split-key architecture...", method_label)
    preview_session_id = None
    try:
        from avikal_backend.archive.path_safety import resolve_safe_output_path
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
            )

            output_filepath = result['output_directory']
            original_data_size = result['total_size']
            log.info("Successfully extracted %d files to %s", result['file_count'], output_filepath)
        else:
            from avikal_backend.archive.format.container import open_avk_payload_stream
            from avikal_backend.archive.pipeline.payload_streaming import stream_payload_to_file

            keyphrase_list = request.keyphrase if request.keyphrase else None
            master_key = None
            payload_key = None
            final_payload_key = None
            pqc_private_key = metadata.get('pqc_private_key')
            pqc_ciphertext = metadata.get('pqc_ciphertext')
            pqc_shared_secret = None
            try:
                from avikal_backend.archive.security.crypto import derive_hierarchical_keys
                from avikal_backend.archive.security.crypto import (
                    combine_split_keys,
                    derive_pqc_hybrid_payload_key,
                    derive_time_only_payload_key,
                    pqc_decapsulate,
                    secure_zero,
                )
                salt = metadata.get('salt')
                if metadata.get('encryption_method') == 'aes256gcm_stream_timekey':
                    master_key = None
                    payload_key = None
                    final_payload_key = derive_time_only_payload_key(key_b, salt)
                else:
                    master_key, payload_key, _chess_key, salt = derive_hierarchical_keys(request.password, keyphrase_list, salt)
                    key_a = payload_key
                    log.info("Combining Key A (from password) and provider-held Key B...")
                    combined_key = combine_split_keys(key_a, key_b, salt)
                    final_payload_key = combined_key[:32]

                if metadata.get('pqc_required'):
                    from avikal_backend.archive.security.pqc_keyfile import read_pqc_keyfile

                    pqc_key_bundle = read_pqc_keyfile(
                        request.pqc_keyfile,
                        password=request.password,
                        keyphrase=keyphrase_list,
                        expected_key_id=metadata.get('pqc_key_id'),
                        expected_algorithm=metadata.get('pqc_algorithm'),
                    )
                    pqc_private_key = pqc_key_bundle["private_key"]
                    pqc_shared_secret = pqc_decapsulate(pqc_private_key, pqc_ciphertext)
                    if not pqc_shared_secret:
                        raise HTTPException(
                            status_code=400,
                            detail="PQC decapsulation failed. The keyfile does not match this archive or the archive is corrupted."
                        )
                    final_payload_key = derive_pqc_hybrid_payload_key(final_payload_key, pqc_shared_secret, salt)

                with open_avk_payload_stream(request.input_file) as (header_bytes, _keychain_pgn, payload_stream):
                    output_filepath = resolve_safe_output_path(preview_dir, metadata['filename'])
                    stream_result = stream_payload_to_file(
                        payload_stream=payload_stream,
                        output_path=output_filepath,
                        aad=header_bytes,
                        decrypt_key=final_payload_key if metadata.get('encryption_method') != 'plaintext_archive' else None,
                        expected_checksum=metadata['checksum'],
                    )
                original_data_size = stream_result["size"]
                log.info("Successfully decrypted to %s", output_filepath)
            finally:
                if 'secure_zero' in locals():
                    if master_key:
                        secure_zero(master_key)
                    if payload_key:
                        secure_zero(payload_key)
                    if final_payload_key:
                        secure_zero(final_payload_key)
                    if pqc_shared_secret:
                        secure_zero(pqc_shared_secret)
                    if pqc_private_key:
                        secure_zero(pqc_private_key)

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

def read_avk_metadata_only(avk_filepath: str, password: str = None, keyphrase: list = None) -> dict:
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
        elif "incorrect password" in error_msg.lower() or "incorrect keyphrase" in error_msg.lower():
            raise ValueError("Incorrect password or keyphrase.")
        else:
            raise ValueError(f"Metadata decoding failed: {error_msg}")


def decrypt_timecapsule_via_aavrit(request: DecryptRequest, session_token: str | None):
    """Decrypt an Aavrit-backed time-capsule after reveal verification succeeds."""
    try:
        from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker
        tracker = ProgressTracker(
            "decrypt",
            [("prepare", 0.15), ("provider", 0.15), ("metadata", 0.20), ("payload", 0.35), ("finalize", 0.15)],
        )
        tracker.update("prepare", "Reading archive metadata", 0.25, force=True)
        log.info("Reading metadata from %s", request.input_file)
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


def decrypt_timecapsule_via_drand(request: DecryptRequest):
    """Decrypt time-capsule using drand timelock release."""
    try:
        from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker
        tracker = ProgressTracker(
            "decrypt",
            [("prepare", 0.15), ("provider", 0.15), ("metadata", 0.20), ("payload", 0.35), ("finalize", 0.15)],
        )
        tracker.update("prepare", "Reading archive metadata", 0.25, force=True)
        log.info("Reading metadata from %s", request.input_file)
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

def start_server(host="127.0.0.1", port=5000):
    """Start the API server"""
    uvicorn.run(app, host=host, port=port, log_level="info")

if __name__ == "__main__":
    start_server()

