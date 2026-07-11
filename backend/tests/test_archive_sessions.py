"""Lifecycle and capacity tests for process-local archive sessions."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from avikal_backend.core.archive_sessions import ArchiveSessionStore, MAX_SESSIONS, SESSION_IDLE_SECONDS


def _state() -> dict:
    return {
        "header_bytes": b"AVK2\x01\x01\x00\x00",
        "payload_key": b"k" * 32,
        "index": {"files": [], "directories": []},
        "metadata": {"archive_integrity": {"payload_sha256": "00" * 32}},
        "index_meta": {"payload_size": 1},
    }


def test_session_capacity_expiry_change_detection_and_zeroization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("avikal_backend.core.archive_sessions.open_indexed_archive_metadata", lambda *_args, **_kwargs: _state())
    store = ArchiveSessionStore()
    opened = []
    for index in range(MAX_SESSIONS + 1):
        archive = tmp_path / f"archive-{index}.avk"
        archive.write_bytes(b"x")
        opened.append(store.open(
            str(archive), password=None, keyphrase=None, time_key=None,
            pqc_keyfile_path=None, pqc_keyfile_password=None,
        ))
    with pytest.raises(ValueError, match="missing or expired"):
        store.get(opened[0].session_id)

    expiring = opened[-1]
    expiring.last_access = time.monotonic() - SESSION_IDLE_SECONDS - 1
    with pytest.raises(ValueError, match="missing or expired"):
        store.get(expiring.session_id)

    current = opened[-2]
    key_reference = current.payload_key
    assert key_reference is not None and any(key_reference)
    assert store.close(current.session_id) is True
    assert all(value == 0 for value in key_reference)

    remaining = next(session for session in opened[1:-2] if session.session_id in store._sessions)
    Path(remaining.archive_path).write_bytes(b"changed")
    os.utime(remaining.archive_path, None)
    with pytest.raises(ValueError, match="changed after it was authenticated"):
        store.get(remaining.session_id)
    store.close_all()
