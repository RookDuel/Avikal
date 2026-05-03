#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NTP Time Service for Avikal Desktop Backend
Fetches trusted time from time.google.com exclusively.
Implements 60-second caching and raises errors if NTP sync fails.
Requirements: 9.1, 9.2, 9.3, 9.6, 9.7, 9.8

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import time
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

log = logging.getLogger("avikal.ntp")

# Configuration
NTP_SERVER = "time.google.com"
NTP_URL = f"https://{NTP_SERVER}"
CACHE_DURATION_SECONDS = 60  # 60-second cache (Requirement 9.7)
CLOCK_SKEW_WARNING_SECONDS = 5 * 60  # 5 minutes (Requirement 9.8)
REQUEST_TIMEOUT_SECONDS = 15

# Cache state
_cached_time_ms: Optional[float] = None
_cache_timestamp_ms: Optional[float] = None
_cache_lock = threading.Lock()
_warmup_lock = threading.Lock()
_warmup_thread: Optional[threading.Thread] = None


def _now_ms() -> float:
    """Return current monotonic time in milliseconds."""
    return time.monotonic() * 1000


def _fetch_ntp_time() -> float:
    """
    Fetch current time from time.google.com via HTTP HEAD request.
    Returns time as Unix timestamp in milliseconds.
    Raises RuntimeError if NTP synchronization fails (Requirement 9.6).
    """
    try:
        req = urllib.request.Request(NTP_URL, method="HEAD")
        req.add_header("User-Agent", "Avikal-Desktop/1.0")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            date_header = response.headers.get("Date")
            if not date_header:
                raise RuntimeError("No Date header in NTP response")
            server_dt = parsedate_to_datetime(date_header)
            return server_dt.timestamp() * 1000  # milliseconds
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"NTP synchronization failed: Unable to reach {NTP_SERVER}. "
            f"Check your internet connection. Error: {e}"
        ) from e
    except Exception as e:
        raise RuntimeError(
            f"NTP synchronization failed: {e}"
        ) from e


def get_ntp_time_ms() -> float:
    """
    Get trusted NTP time in milliseconds.
    Uses 60-second cache to avoid excessive requests (Requirement 9.7).
    Raises RuntimeError if NTP synchronization fails (Requirement 9.6).
    """
    global _cached_time_ms, _cache_timestamp_ms

    with _cache_lock:
        now = _now_ms()

        # Check cache
        if _cached_time_ms is not None and _cache_timestamp_ms is not None:
            age_ms = now - _cache_timestamp_ms
            if age_ms < CACHE_DURATION_SECONDS * 1000:
                # Interpolate elapsed time since last NTP sync
                return _cached_time_ms + age_ms

        # Fetch fresh NTP time
        ntp_time_ms = _fetch_ntp_time()

        # Check system clock skew (Requirement 9.8)
        system_time_ms = time.time() * 1000
        skew_ms = abs(system_time_ms - ntp_time_ms)
        if skew_ms > CLOCK_SKEW_WARNING_SECONDS * 1000:
            skew_minutes = round(skew_ms / 60000)
            log.warning(
                "System clock differs from NTP time by %d minutes. "
                "System: %s, NTP: %s",
                skew_minutes,
                datetime.fromtimestamp(system_time_ms / 1000, tz=timezone.utc).isoformat(),
                datetime.fromtimestamp(ntp_time_ms / 1000, tz=timezone.utc).isoformat(),
            )

        # Update cache
        _cached_time_ms = ntp_time_ms
        _cache_timestamp_ms = now

        return ntp_time_ms


def prime_ntp_cache_async() -> bool:
    """Warm the trusted-time cache in the background without blocking app startup."""
    global _warmup_thread

    now = _now_ms()
    if _cached_time_ms is not None and _cache_timestamp_ms is not None:
        if now - _cache_timestamp_ms < CACHE_DURATION_SECONDS * 1000:
            return False

    with _warmup_lock:
        if _warmup_thread is not None and _warmup_thread.is_alive():
            return False

        def worker() -> None:
            try:
                get_ntp_time_ms()
            except RuntimeError as exc:
                log.debug("NTP warmup skipped: %s", exc)

        _warmup_thread = threading.Thread(
            target=worker,
            name="avikal-ntp-warmup",
            daemon=True,
        )
        _warmup_thread.start()
        return True


def get_ntp_timestamp() -> int:
    """
    Get trusted NTP time as Unix timestamp in seconds.
    Raises RuntimeError if NTP synchronization fails.
    """
    return int(get_ntp_time_ms() / 1000)


def get_ntp_datetime_utc() -> datetime:
    """
    Get trusted NTP time as a UTC datetime object.
    Raises RuntimeError if NTP synchronization fails.
    """
    ts = get_ntp_time_ms() / 1000
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def get_clock_skew_warning() -> Optional[str]:
    """
    Check if system clock differs from NTP time by more than 5 minutes.
    Returns a warning string if skew is detected, None otherwise.
    Does NOT raise on NTP failure - returns None instead.
    """
    try:
        ntp_time_ms = get_ntp_time_ms()
        system_time_ms = time.time() * 1000
        skew_ms = abs(system_time_ms - ntp_time_ms)
        if skew_ms > CLOCK_SKEW_WARNING_SECONDS * 1000:
            skew_minutes = round(skew_ms / 60000)
            return (
                f"System clock differs from NTP time by {skew_minutes} minutes. "
                "Please synchronize your system clock."
            )
        return None
    except RuntimeError:
        return None


def invalidate_cache() -> None:
    """Invalidate the NTP time cache (useful for testing)."""
    global _cached_time_ms, _cache_timestamp_ms
    _cached_time_ms = None
    _cache_timestamp_ms = None
