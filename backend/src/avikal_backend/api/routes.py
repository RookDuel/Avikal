"""FastAPI route declarations for the Avikal backend API."""



from __future__ import annotations



import os

import requests

import time

from datetime import datetime



from fastapi import APIRouter, Depends, Header, HTTPException

from pydantic import BaseModel, Field


from avikal_backend.services.ntp_service import get_clock_skew_warning, get_ntp_datetime_utc, get_ntp_timestamp

from starlette.concurrency import run_in_threadpool



from . import server as api



router = APIRouter()



EncryptRequest = api.EncryptRequest

DecryptRequest = api.DecryptRequest

ArchiveInspectRequest = api.ArchiveInspectRequest

RekeyRequest = api.RekeyRequest

PreviewCleanupRequest = api.PreviewCleanupRequest

GenerateKeyphraseRequest = api.GenerateKeyphraseRequest

AavritServerCheckRequest = api.AavritServerCheckRequest

AavritLoginRequest = api.AavritLoginRequest

VerifySessionRequest = api.VerifySessionRequest





def _build_aavrit_user_payload(*, user_id: str, name: str, email: str) -> dict:
    return {
        "id": user_id,
        "name": name,
        "email": email,
        "emailVerification": True,
    }


def _run_with_crypto_lock(func, *args, **kwargs):
    """Run a blocking crypto operation while holding the process crypto lock."""
    with api._crypto_lock:
        return func(*args, **kwargs)

@router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}





@router.get("/api/ntp-time")

async def get_ntp_time_endpoint():

    """

    Get current NTP time from time.google.com.

    Returns trusted UTC time and clock skew diagnostics.

    Requirements: 9.1, 9.2, 9.10, 37.3

    """

    try:

        ntp_ts = get_ntp_timestamp()

        utc_dt = get_ntp_datetime_utc()

        skew_warning = get_clock_skew_warning()



        return {

            "success": True,

            "timestamp": ntp_ts,

            "utc": utc_dt.isoformat(),

            "clock_skew_warning": skew_warning,

        }

    except RuntimeError as e:

        api.log.warning("NTP time endpoint failed: %s", e)

        return {

            "success": False,

            "error": "Time verification failed. Check your internet connection.",

            "timestamp": None,

            "clock_skew_warning": None,

        }





@router.post("/api/auth/check-aavrit-server")

async def check_aavrit_server(body: AavritServerCheckRequest):

    """Validate and describe an Aavrit server before prompting for Aavrit login."""

    try:

        aavrit_url = api.normalize_aavrit_server_url(body.aavrit_url)

        payload = api.fetch_aavrit_capabilities(aavrit_url)

        api.set_current_aavrit_server_url(aavrit_url)

        api.current_aavrit_mode = payload["mode"]

        return {

            "success": True,

            "aavrit_url": aavrit_url,

            "mode": payload["mode"],

        }

    except HTTPException:

        raise

    except requests.RequestException as exc:

        raise api.handle_requests_error(exc, "Aavrit server")

    except Exception as exc:

        api.log.error("Aavrit server validation failed: %s", exc, exc_info=True)

        raise HTTPException(status_code=500, detail="Aavrit server validation failed.")





@router.post("/api/auth/login")

async def authenticate_user(body: AavritLoginRequest):

    """Login to a private Aavrit server and store the returned Aavrit session locally."""

    try:

        aavrit_url = api.normalize_aavrit_server_url(body.aavrit_url)

        mode = api.fetch_aavrit_capabilities(aavrit_url)["mode"]

        if mode != "private":

            raise HTTPException(status_code=400, detail="Aavrit login is only available when the server is in private mode.")



        response = requests.post(

            f"{aavrit_url}/auth/login",

            json={

                "email": body.email,

                "password": body.password,

            },

            headers={"Content-Type": "application/json"},

            timeout=30,

        )



        if response.status_code == 401:

            raise HTTPException(status_code=401, detail="Invalid email or password")

        if response.status_code == 429:

            raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

        if response.status_code != 200:

            detail = response.text.strip() or "Aavrit login failed."

            raise HTTPException(status_code=502, detail=detail)



        try:

            payload = response.json()

        except ValueError as exc:

            raise HTTPException(status_code=502, detail="Aavrit login returned an invalid response.") from exc



        session_token = payload.get("session_token") if isinstance(payload, dict) else None

        if not isinstance(session_token, str) or not session_token.strip():

            raise HTTPException(status_code=502, detail="Aavrit login returned an invalid session.")



        api.current_aavrit_session_token = session_token

        api.set_current_aavrit_server_url(aavrit_url)

        api.current_aavrit_mode = mode



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

    except HTTPException:

        raise

    except requests.RequestException as exc:

        raise api.handle_requests_error(exc, "Aavrit server")

    except Exception as exc:

        api.log.error("Aavrit login failed: %s", exc, exc_info=True)

        raise HTTPException(status_code=500, detail="Aavrit login failed.")





@router.post("/api/auth/verify-session")

async def verify_session(body: VerifySessionRequest):

    """Verify an Aavrit session and restore the current Aavrit session."""

    api.log.debug("verify_session called")



    try:

        aavrit_url = api.set_current_aavrit_server_url(body.aavrit_url) if body.aavrit_url else api.get_aavrit_server_url()

        decoded = api.verify_aavrit_session_token(body.session_token, aavrit_url)

        api.log.debug("Aavrit session verified successfully. Subject: %s", decoded.get("sub"))



        api.current_aavrit_session_token = body.session_token

        api.current_aavrit_mode = api.fetch_aavrit_capabilities(aavrit_url)["mode"]



        user_id = decoded.get("sub", "")



        return {

            "success": True,

            "message": "Session verified successfully",

            "aavrit_url": aavrit_url,

            "mode": api.current_aavrit_mode,

            "user": _build_aavrit_user_payload(

                user_id=user_id or "aavrit-authenticated-user",

                name=decoded.get("name") or "Aavrit Private Session",

                email=decoded.get("email", ""),

            ),

        }



    except HTTPException:

        raise

    except Exception as e:

        api.log.error("Unexpected exception in verify_session: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail=f"Session verification failed: {str(e)}")





@router.get("/api/auth/profile")

async def get_user_profile(session_token: str = Depends(api.get_aavrit_session_token)):

    """Get user profile from the connected Aavrit server."""

    try:

        aavrit_url = api.get_aavrit_server_url()

        decoded = api.verify_aavrit_session_token(session_token, aavrit_url)

        user_id = decoded.get("sub", "aavrit-authenticated-user")

        user_data = _build_aavrit_user_payload(

            user_id=user_id,

            name=decoded.get("name") or "Aavrit Session",

            email=decoded.get("email", ""),

        )

        return {"success": True, "user": user_data}

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(status_code=500, detail=f"Failed to fetch user profile: {str(e)}")



@router.post("/api/auth/logout")

async def logout():

    """Logout user and clear the current Aavrit session."""

    session_token = api.current_aavrit_session_token

    aavrit_url = api.get_aavrit_server_url(required=False)



    if session_token and aavrit_url and api.current_aavrit_mode == "private":

        try:

            requests.post(

                f"{aavrit_url}/auth/logout",

                headers={"Authorization": f"Bearer {session_token}"},

                timeout=30,

            )

        except requests.RequestException as exc:

            api.log.warning("Aavrit logout request failed: %s", exc)



    api.clear_aavrit_auth_state()

    return {"success": True, "message": "Logged out successfully"}



@router.post("/api/encrypt")

async def encrypt_files(request: EncryptRequest, authorization: str = Header(None)):

    """Encrypt files with optional Aavrit or drand time-capsule providers."""

    started_at = time.perf_counter()

    unlock_dt = None

    provider = None

    try:

        # Parse unlock datetime if provided

        if request.unlock_datetime:

            try:

                unlock_dt = api.normalize_unlock_datetime_to_utc(request.unlock_datetime)

            except ValueError as e:

                api.log.error("Invalid unlock_datetime format: %s", e)

                raise HTTPException(status_code=400, detail=f"Invalid unlock_datetime format: {str(e)}")

        

        # If time-capsule is requested, validate authentication

        if request.use_timecapsule:

            if unlock_dt is None:

                raise HTTPException(status_code=400, detail="Time-capsule unlock date is required.")

            provider = api.resolve_timecapsule_provider(request)

            # Extract Aavrit session token from Authorization header for time-capsule

            session_token = None

            if authorization and authorization.startswith("Bearer "):
                session_token = authorization.split(" ")[1]

            api.log.info("Starting %s time-capsule encryption for %d file(s)", provider, len(request.input_files))
            if provider == "aavrit":
                response_payload = await run_in_threadpool(
                    _run_with_crypto_lock,
                    api.create_timecapsule_via_aavrit,
                    request,
                    session_token,
                    unlock_dt,
                )
            else:
                response_payload = await run_in_threadpool(
                    _run_with_crypto_lock,
                    api.create_timecapsule_via_drand,
                    request,
                    unlock_dt,
                )
        else:
            api.log.info("Starting regular encryption for %d file(s)", len(request.input_files))
            # Regular encryption (no time-capsule) - no authentication required
            response_payload = await run_in_threadpool(
                _run_with_crypto_lock,
                api.create_regular_encryption,
                request,
                unlock_dt,
            )


        api._best_effort_log_archive_creation(

            request,

            started_at=started_at,

            unlock_dt=unlock_dt,

            response_payload=response_payload,

            provider=provider,

        )

        return response_payload



    except HTTPException as exc:

        api._best_effort_log_archive_creation(

            request,

            started_at=started_at,

            unlock_dt=unlock_dt,

            error_message=str(exc.detail),

            provider=provider,

        )

        raise

    except Exception as e:

        user_message = api.friendly_error(str(e))

        api._best_effort_log_archive_creation(

            request,

            started_at=started_at,

            unlock_dt=unlock_dt,

            error_message=user_message,

            provider=provider,

        )

        api.log.error("Encrypt endpoint error: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail=user_message)



@router.post("/api/decrypt")

async def decrypt_file(request: DecryptRequest, authorization: str = Header(None)):

    """Decrypt file with regular, Aavrit time-capsule, or drand time-capsule flow."""

    try:

        # Validate input file exists

        if not os.path.exists(request.input_file):

            api.log.error("Decrypt requested for non-existent file: %s", request.input_file)

            raise HTTPException(status_code=400, detail=f"Input file not found: {request.input_file}")



        # Validate .avk file structure before attempting decryption (Requirement 7.9)
        api.log.info("Received decrypt request for %s", request.input_file)

        from avikal_backend.archive.format.header import ARCHIVE_MODE_MULTI

        header_info, route_hints = await run_in_threadpool(api.read_avk_public_route, request.input_file)
        timecapsule_provider = route_hints.get("provider")

        if route_hints.get("available"):
            api.validate_public_route_inputs(request, route_hints)
            api.validate_public_timecapsule_lock(route_hints)

        metadata = None
        if timecapsule_provider:
            try:
                metadata = await run_in_threadpool(
                    api.read_avk_metadata_only,
                    request.input_file,
                    request.password,
                    request.keyphrase,
                )
            except Exception as meta_err:
                api.log.warning("Could not read metadata from %s: %s", request.input_file, meta_err)
                raise HTTPException(status_code=400, detail=api.friendly_error(str(meta_err))) from meta_err

        

        if timecapsule_provider == "aavrit":

            session_token = None

            if authorization and authorization.startswith("Bearer "):

                session_token = authorization.split(" ")[1]

            api.log.info("Starting Aavrit time-capsule decryption for %s", request.input_file)
            return await run_in_threadpool(
                _run_with_crypto_lock,
                api.decrypt_timecapsule_via_aavrit,
                request,
                session_token,
                metadata,
            )
        elif timecapsule_provider == "drand":
            api.log.info("Starting drand time-capsule decryption for %s", request.input_file)
            return await run_in_threadpool(_run_with_crypto_lock, api.decrypt_timecapsule_via_drand, request, metadata)
        else:
            # Regular file decryption - check if it's multi-file or single-file
            from avikal_backend.archive.pipeline.decoder import extract_avk_file
            from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk
            from avikal_backend.archive.pipeline.progress import ProgressTracker, bind_progress_tracker

            def _decrypt_regular_preview():
                with api._crypto_lock:
                    tracker = ProgressTracker(
                        "decrypt",
                        [("metadata", 0.20), ("payload", 0.55), ("finalize", 0.25)],
                    )
                    tracker.update("metadata", "Opening archive", 0.02, force=True)
                    preview_session_id, preview_dir = api._create_preview_session_dir()
                    is_multi_file_archive = header_info.get("archive_mode") == ARCHIVE_MODE_MULTI

                    if is_multi_file_archive:
                        try:
                            with bind_progress_tracker(tracker):
                                result = extract_multi_file_avk(
                                    avk_filepath=request.input_file,
                                    output_directory=preview_dir,
                                    password=request.password,
                                    keyphrase=request.keyphrase,
                                    pqc_keyfile_path=request.pqc_keyfile,
                                )
                        except Exception:
                            api._cleanup_preview_session(preview_session_id)
                            raise

                        return {
                            "success": True,
                            "message": f"Multi-file preview ready - {result['file_count']} files decrypted",
                            "output_dir": preview_dir,
                            "preview_session_id": preview_session_id,
                            "result": result,
                            "pgn_created_at_ist": api._get_pgn_created_time_ist(request.input_file),
                            "pgn_source": "filesystem_mtime_ist"
                        }

                    try:
                        with bind_progress_tracker(tracker):
                            output_path = extract_avk_file(
                                avk_filepath=request.input_file,
                                output_directory=preview_dir,
                                password=request.password,
                                keyphrase=request.keyphrase,
                                pqc_keyfile_path=request.pqc_keyfile,
                            )
                    except Exception:
                        api._cleanup_preview_session(preview_session_id)
                        raise

                    output_name = os.path.basename(output_path)
                    output_size = os.path.getsize(output_path)
                    return {
                        "success": True,
                        "message": "Single-file preview ready",
                        "output_dir": preview_dir,
                        "preview_session_id": preview_session_id,
                        "result": {
                            "file_count": 1,
                            "filename": output_name,
                            "output_file": output_path,
                            "path": output_path,
                            "size": output_size,
                            "files": [
                                {
                                    "filename": output_name,
                                    "path": output_path,
                                    "output_file": output_path,
                                    "size": output_size,
                                }
                            ],
                        },
                        "pgn_created_at_ist": api._get_pgn_created_time_ist(request.input_file),
                        "pgn_source": "filesystem_mtime_ist"
                    }

            return await run_in_threadpool(_decrypt_regular_preview)

    

    except HTTPException:

        raise

    except ValueError as e:

        api.log.warning("Decrypt validation error: %s", e)

        preserved_detail = api.preserve_time_lock_detail(str(e))

        raise HTTPException(

            status_code=400,

            detail=preserved_detail if preserved_detail is not None else api.friendly_error(str(e)),

        )

    except Exception as e:

        api.log.error("Decrypt endpoint error: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail=api.friendly_error(str(e)))





@router.post("/api/archive/inspect")

async def inspect_archive(request: ArchiveInspectRequest):

    try:

        if not os.path.exists(request.input_file):

            raise HTTPException(status_code=400, detail=f"Input file not found: {request.input_file}")



        api.validate_avk_structure(request.input_file)

        _header_info, route_hints = api.read_avk_public_route(request.input_file)



        archive_hints = {

            "provider": route_hints.get("provider"),

            "archive_type": route_hints.get("archive_type"),

            "metadata_accessible": bool(route_hints.get("available")),

            "metadata_requires_secret": False,

            "password_hint": route_hints.get("requires_password"),

            "keyphrase_hint": route_hints.get("requires_keyphrase"),

            "pqc_required": route_hints.get("requires_pqc"),

            "unlock_timestamp": route_hints.get("unlock_timestamp"),

            "drand_round": route_hints.get("drand_round"),

            "keyphrase_wordlist_id": route_hints.get("keyphrase_wordlist_id"),

        }



        return {"success": True, "archive": archive_hints}

    except HTTPException:

        raise

    except Exception as e:

        api.log.error("Archive inspect failed: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail=api.friendly_error(str(e)))


@router.post("/api/archive/rekey")

async def rekey_archive(request: RekeyRequest):

    try:

        if not os.path.exists(request.input_file):

            raise HTTPException(status_code=400, detail=f"Input file not found: {request.input_file}")



        api.validate_avk_structure(request.input_file)

        _header_info, route_hints = await run_in_threadpool(api.read_avk_public_route, request.input_file)



        if route_hints.get("provider"):

            raise HTTPException(status_code=400, detail="Time-capsule rekey is not supported in this phase.")

        if route_hints.get("requires_pqc"):

            raise HTTPException(status_code=400, detail="PQC keyfile rekey is not supported in this phase.")

        if not route_hints.get("requires_password") and not route_hints.get("requires_keyphrase"):

            raise HTTPException(status_code=400, detail="Plaintext archives do not need rekey.")



        from avikal_backend.archive.pipeline.rekey import rekey_avk_archive



        result = await run_in_threadpool(

            _run_with_crypto_lock,

            rekey_avk_archive,

            request.input_file,

            old_password=request.old_password,

            old_keyphrase=request.old_keyphrase,

            new_password=request.new_password,

            new_keyphrase=request.new_keyphrase,

            output_filepath=request.output_file,

            force=request.force,

        )

        return result

    except HTTPException:

        raise

    except ValueError as e:

        raise HTTPException(status_code=400, detail=api.friendly_error(str(e)))

    except Exception as e:

        api.log.error("Archive rekey failed: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail=api.friendly_error(str(e)))





@router.post("/api/decrypt/cleanup-session")

async def cleanup_decrypt_session(request: PreviewCleanupRequest):

    try:

        removed = api._cleanup_preview_session(request.session_id)

        return {"success": True, "removed": removed}

    except Exception as e:

        api.log.error("Preview session cleanup failed: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail="Failed to cleanup preview session")





@router.post("/api/decrypt/cleanup-all")

async def cleanup_all_decrypt_sessions():

    try:

        removed = api._cleanup_all_preview_sessions()

        return {"success": True, "removed": removed}

    except Exception as e:

        api.log.error("Preview session cleanup-all failed: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail="Failed to cleanup preview sessions")





class CancelDecryptRequest(BaseModel):
    session_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")




@router.post("/api/decrypt/cancel")

async def cancel_decrypt(request: CancelDecryptRequest):

    """

    Cancel an in-progress decryption and clean up any partial preview session.

    Called by the frontend immediately after aborting the decrypt fetch so no

    decrypted fragments are left on disk.

    """

    try:

        removed = False

        if request.session_id:

            removed = api._cleanup_preview_session(request.session_id)

        api.log.info(

            "Decrypt cancelled by user. session_id=%s removed=%s",

            request.session_id, removed

        )

        return {"success": True, "cancelled": True, "removed": removed}

    except Exception as e:

        api.log.error("Cancel decrypt cleanup failed: %s", e, exc_info=True)

        return {"success": True, "cancelled": True, "removed": False}

@router.post("/api/generate-keyphrase")

async def generate_keyphrase_endpoint(request: GenerateKeyphraseRequest):

    """Generate Hindi keyphrase"""

    try:

        mnemonic = api.generate_mnemonic(

            word_count=request.word_count,

            language=request.language

        )

        

        return {

            "success": True,

            "keyphrase": mnemonic,

            "word_count": request.word_count

        }

    

    except Exception as e:

        raise HTTPException(status_code=500, detail=str(e))



@router.get("/api/keyphrase/roman-map")

async def get_keyphrase_roman_map():

    """Return romanized typing helpers for the canonical Hindi keyphrase list."""

    try:

        return {

            "success": True,

            "wordlist_id": "avikal-hi-2048-v1",

            "roman_wordlist_id": "avikal-hi-roman-2048-v1",

            "words": api.get_romanized_word_pairs(),

        }

    except Exception as e:

        api.log.error("Keyphrase roman map loading failed: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/security/settings")
async def get_security_settings():

    """Get non-destructive security-related UI data."""

    try:

        return {

            "success": True,

            "settings": {

                "activity_log": api.activity_audit.get_summary(),

            },

        }

    except Exception as e:

        raise HTTPException(status_code=500, detail=f"Failed to get security settings: {str(e)}")





@router.get("/api/security/activity-log/export")

async def export_activity_log():

    """Export archive activity audit data as a Markdown table."""

    try:

        export_payload = api.activity_audit.build_markdown_export()

        return {

            "success": True,

            **export_payload,

        }

    except Exception as e:

        api.log.error("Failed to export activity audit log: %s", e, exc_info=True)

        raise HTTPException(status_code=500, detail="Failed to export activity audit log")







