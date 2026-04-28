"""Archive-related helpers used by API routes and workflows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import os
import time
from typing import Any, List

from fastapi import HTTPException

from avikal_backend.audit.activity_audit import activity_audit
from avikal_backend.archive.format.container import read_avk_container


log = logging.getLogger("avikal.api")


def validate_avk_structure(avk_filepath: str) -> None:
    if not os.path.exists(avk_filepath):
        raise HTTPException(status_code=400, detail="File not found. Please check the file path.")

    try:
        read_avk_container(avk_filepath)
    except ValueError as exc:
        log.warning("validate_avk_structure: %s: %s", avk_filepath, exc)
        raise HTTPException(status_code=400, detail="File integrity check failed. The file may be corrupted.")


def get_pgn_created_time_ist(avk_filepath: str) -> str | None:
    try:
        mtime = os.path.getmtime(avk_filepath)
        created_utc = datetime.fromtimestamp(mtime, tz=timezone.utc)
        ist_tz = timezone(timedelta(hours=5, minutes=30))
        return created_utc.astimezone(ist_tz).isoformat()
    except Exception as exc:
        log.debug("Failed to derive PGN created time for %s: %s", avk_filepath, exc)
        return None


def should_use_multi_file_archive(input_files: List[str]) -> bool:
    return len(input_files) > 1 or any(os.path.isdir(path) for path in input_files)


def best_effort_log_archive_creation(
    request: Any,
    *,
    started_at: float,
    unlock_dt: datetime | None,
    response_payload: dict | None = None,
    error_message: str | None = None,
    provider: str | None = None,
) -> None:
    try:
        archive_mode = "timecapsule" if request.use_timecapsule else "regular"
        provider_name = provider
        if archive_mode == "timecapsule" and not provider_name:
            raw_provider = request.timecapsule_provider or "unknown"
            provider_name = str(raw_provider).strip().lower() or "unknown"

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
