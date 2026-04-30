"""
Trusted UTC time helpers for time-capsule validation and timestamp conversion.

Primary source:
- strict UDP-based Google NTP path

Fallback source:
- cached HTTPS Date-header path from the backend NTP service

System time is never used as a trusted fallback for unlock validation.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


UTC = timezone.utc
IST_OFFSET = timedelta(0)


def _ensure_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _get_trusted_utc_now() -> datetime:
    """
    Return trusted UTC time from the backend NTP service (time.google.com HTTPS).

    Raises:
        ConnectionError: if the NTP service is unreachable
    """
    try:
        from avikal_backend.services.ntp_service import get_ntp_datetime_utc

        return get_ntp_datetime_utc().astimezone(UTC)
    except Exception as exc:
        raise ConnectionError(
            f"Failed to get trusted time from time.google.com. "
            f"Internet connection is required for Avikal time-capsule security. "
            f"Error: {exc}"
        ) from exc



def get_trusted_now_ntp() -> datetime:
    """
    Get current trusted time in UTC.
    Uses strict Google NTP first, then the backend trusted HTTP time fallback.
    """
    try:
        return _get_trusted_utc_now()
    except Exception as exc:
        raise ConnectionError(
            f"Failed to get trusted network time: {str(exc)}. "
            "Internet connection is required for Avikal time-capsule security."
        ) from exc


def get_trusted_now() -> datetime:
    """Public wrapper used by archive workflows."""
    return get_trusted_now_ntp()


def datetime_to_timestamp_ntp(unlock_dt: datetime) -> int:
    """
    Convert a datetime to a Unix timestamp after validating it against trusted UTC time.
    """
    normalized = _ensure_utc_datetime(unlock_dt)

    try:
        current_ntp_time = get_trusted_now_ntp()
        time_diff = abs((normalized - current_ntp_time).total_seconds())
        if time_diff > 5 * 365 * 24 * 3600:
            raise ValueError(
                "Provided datetime is too far from current trusted time. "
                f"Provided: {normalized.strftime('%Y-%m-%d %H:%M UTC')}, "
                f"Current: {current_ntp_time.strftime('%Y-%m-%d %H:%M UTC')}"
            )
    except ConnectionError:
        raise
    except Exception as exc:
        raise ValueError(f"Time validation failed: {str(exc)}") from exc

    return int(normalized.timestamp())


def datetime_to_timestamp(unlock_dt: datetime, use_ntp: bool = False) -> int:
    """
    Convert a datetime to a Unix timestamp in UTC.

    Naive datetimes are treated as UTC to avoid locale-dependent behavior.
    """
    normalized = _ensure_utc_datetime(unlock_dt)
    if use_ntp:
        return datetime_to_timestamp_ntp(normalized)
    return int(normalized.timestamp())


def timestamp_to_datetime(ts: int) -> datetime:
    """Convert a Unix timestamp to an aware UTC datetime."""
    return datetime.fromtimestamp(ts, tz=UTC)


def validate_unlock_time_ntp(unlock_timestamp: int) -> bool:
    """Check if current trusted UTC time is at or past the unlock timestamp."""
    try:
        current_time = get_trusted_now_ntp()
        unlock_time = timestamp_to_datetime(unlock_timestamp)
        return current_time >= unlock_time
    except ConnectionError:
        raise
    except Exception as exc:
        raise ValueError(f"Time validation failed: {str(exc)}") from exc


def validate_unlock_time(unlock_timestamp: int) -> bool:
    """Check if current trusted time is at or past the unlock timestamp."""
    return validate_unlock_time_ntp(unlock_timestamp)


def format_unlock_time(unlock_timestamp: int) -> str:
    """Format timestamp as a human-readable UTC string."""
    return timestamp_to_datetime(unlock_timestamp).strftime("%Y-%m-%d %H:%M UTC")


# Compatibility exports for older imports. They now expose trusted UTC time.
get_ist_now_ntp = get_trusted_now_ntp
get_ist_now = get_trusted_now
