"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import shutil
import uuid

from avikal_backend.audit.activity_audit import ActivityAuditLog


@contextmanager
def _workspace_tempdir():
    base = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    base.mkdir(exist_ok=True)
    temp_path = base / f"audit_{uuid.uuid4().hex}"
    temp_path.mkdir()
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


def _build_request(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        input_files=[
            str(tmp_path / "alpha.txt"),
            str(tmp_path / "nested" / "beta.bin"),
        ],
        output_file=str(tmp_path / "secret-output.avk"),
        password="AvikalStrongPass!9Zeta",
        keyphrase=None,
        unlock_datetime=None,
        use_timecapsule=False,
        timecapsule_provider=None,
        pqc_enabled=False,
    )


def test_activity_audit_export_omits_source_file_details():
    with _workspace_tempdir() as tmp_path:
        audit = ActivityAuditLog(base_dir=tmp_path)
        request = _build_request(tmp_path)

        response_payload = {
            "success": True,
            "result": {
                "files": [
                    {"filename": "alpha.txt", "path": "should-not-appear"},
                    {"filename": "nested/beta.bin", "path": "should-not-appear"},
                ],
                "telemetry": {
                    "archive_kind": "multi_file",
                    "expanded_entry_count": 4,
                    "compression_ms": 120.25,
                    "encryption_ms": 220.5,
                    "chess_encoding_ms": 98.75,
                    "total_processing_ms": 439.5,
                    "output_archive_size_bytes": 8192,
                },
            },
        }

        audit.record_archive_creation(
            request=request,
            archive_mode="regular",
            provider=None,
            unlock_dt=None,
            status="success",
            duration_ms=512.9,
            response_payload=response_payload,
        )

        raw_contents = audit.log_file.read_text(encoding="utf-8")
        assert "alpha.txt" not in raw_contents
        assert "beta.bin" not in raw_contents
        assert "secret-output.avk" not in raw_contents

        export_payload = audit.build_markdown_export()
        markdown = export_payload["markdown"]

        assert export_payload["entry_count"] == 1
        assert "alpha.txt" not in markdown
        assert "beta.bin" not in markdown
        assert "secret-output.avk" not in markdown
        assert "multi_file" in markdown
        assert "439.5" in markdown

        summary = audit.get_summary()
        assert summary["entry_count"] == 1
        assert summary["last_event_at"] is not None


def test_activity_audit_export_handles_empty_history():
    with _workspace_tempdir() as tmp_path:
        audit = ActivityAuditLog(base_dir=tmp_path)

        export_payload = audit.build_markdown_export()

        assert export_payload["entry_count"] == 0
        assert "No archive creation events have been recorded yet." in export_payload["markdown"]
        assert export_payload["filename"].startswith("avikal-activity-log-")


def test_activity_audit_hash_chain_and_generic_events():
    with _workspace_tempdir() as tmp_path:
        audit = ActivityAuditLog(base_dir=tmp_path)

        first = audit.record_event(action="archive_decode", status="success", details={"file_count": 2})
        second = audit.record_event(action="preview_cleanup", status="success", details={"removed_count": 1})

        assert first["entry_hash"]
        assert second["prev_hash"] == first["entry_hash"]
        assert audit.get_summary()["chain_status"] == "verified"

        export_payload = audit.build_markdown_export()
        markdown = export_payload["markdown"]
        assert "archive_decode" in markdown
        assert "preview_cleanup" in markdown
        assert "Hash chain: verified" in markdown
