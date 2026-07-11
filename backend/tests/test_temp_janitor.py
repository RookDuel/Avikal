"""Crash-recovery cleanup tests for Avikal temp artifacts.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from pathlib import Path

from avikal_backend.core import temp_janitor


def test_registered_output_adjacent_temp_file_is_removed(tmp_path: Path, monkeypatch) -> None:
    runtime_dir = tmp_path / "runtime"
    output_dir = tmp_path / "selected-output"
    output_dir.mkdir()
    stale_payload = output_dir / ".avikal-payload-leftover.payload"
    stale_payload.write_bytes(b"partial payload")

    monkeypatch.setenv("AVIKAL_USER_DATA_DIR", str(runtime_dir))
    monkeypatch.setattr(temp_janitor.tempfile, "gettempdir", lambda: str(tmp_path / "system-temp"))
    monkeypatch.setattr(temp_janitor, "_process_is_alive", lambda _pid: False)

    temp_janitor.register_temp_artifact(stale_payload)
    assert stale_payload.exists()

    removed = temp_janitor.cleanup_startup_temp_artifacts()

    assert removed == 1
    assert not stale_payload.exists()


def test_unregistered_user_file_with_unsafe_name_is_not_removed(tmp_path: Path, monkeypatch) -> None:
    runtime_dir = tmp_path / "runtime"
    user_file = tmp_path / "selected-output" / "normal-user-file.txt"
    user_file.parent.mkdir()
    user_file.write_text("keep", encoding="utf-8")

    monkeypatch.setenv("AVIKAL_USER_DATA_DIR", str(runtime_dir))
    monkeypatch.setattr(temp_janitor.tempfile, "gettempdir", lambda: str(tmp_path / "system-temp"))

    temp_janitor.register_temp_artifact(user_file)
    removed = temp_janitor.cleanup_startup_temp_artifacts()

    assert removed == 0
    assert user_file.exists()


def test_known_temp_root_extract_directory_is_removed(tmp_path: Path, monkeypatch) -> None:
    runtime_dir = tmp_path / "runtime"
    system_temp = tmp_path / "system-temp"
    stale_extract = system_temp / "avikal_extract_deadbeef"
    stale_extract.mkdir(parents=True)
    (stale_extract / "decoded.txt").write_text("temporary preview", encoding="utf-8")

    monkeypatch.setenv("AVIKAL_USER_DATA_DIR", str(runtime_dir))
    monkeypatch.setattr(temp_janitor.tempfile, "gettempdir", lambda: str(system_temp))
    monkeypatch.setattr(temp_janitor, "_UNREGISTERED_CLEANUP_MIN_AGE_SECONDS", 0)

    removed = temp_janitor.cleanup_startup_temp_artifacts()

    assert removed == 1
    assert not stale_extract.exists()


def test_active_process_artifact_is_preserved(tmp_path: Path, monkeypatch) -> None:
    runtime_dir = tmp_path / "runtime"
    active_archive = tmp_path / ".avikal-archive-active.avk"
    active_archive.write_bytes(b"in progress")

    monkeypatch.setenv("AVIKAL_USER_DATA_DIR", str(runtime_dir))
    monkeypatch.setattr(temp_janitor.tempfile, "gettempdir", lambda: str(tmp_path / "system-temp"))

    temp_janitor.register_temp_artifact(active_archive)
    removed = temp_janitor.cleanup_startup_temp_artifacts()

    assert removed == 0
    assert active_archive.exists()
    temp_janitor.unregister_temp_artifact(active_archive)
