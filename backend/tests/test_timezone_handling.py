"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from datetime import datetime, timezone

from avikal_backend.archive.security.time_lock import datetime_to_timestamp, timestamp_to_datetime
from avikal_backend.cli.inputs import parse_unlock_datetime


def test_time_lock_roundtrip_uses_utc_instants():
    unlock_dt = datetime(2032, 5, 1, 12, 30, tzinfo=timezone.utc)
    unlock_timestamp = datetime_to_timestamp(unlock_dt)
    assert unlock_timestamp == int(unlock_dt.timestamp())
    assert timestamp_to_datetime(unlock_timestamp) == unlock_dt


def test_cli_unlock_parser_emits_utc_datetime():
    unlock_dt = parse_unlock_datetime("2032-05-01 12:30")
    assert unlock_dt is not None
    assert unlock_dt.tzinfo == timezone.utc
