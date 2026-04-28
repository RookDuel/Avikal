"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import json
import os
import platform
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil


def _get_default_data_dir() -> Path:
    override = os.getenv("AVIKAL_USER_DATA_DIR")
    if override:
        return Path(override)
    return Path.home() / ".avikal"


class ActivityAuditLog:
    def __init__(self, base_dir: str | Path | None = None):
        self.base_dir = Path(base_dir) if base_dir else _get_default_data_dir()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.base_dir / "archive_activity_log.jsonl"
        self._lock = threading.Lock()

    def _now_local(self) -> datetime:
        return datetime.now().astimezone()

    def _derive_secret_mode(self, password: str | None, keyphrase: list[str] | None) -> str:
        has_password = bool(password)
        has_keyphrase = bool(keyphrase)
        if has_password and has_keyphrase:
            return "password+keyphrase"
        if has_password:
            return "password"
        if has_keyphrase:
            return "keyphrase"
        return "none"

    def _system_snapshot(self) -> dict[str, Any]:
        try:
            virtual_memory = psutil.virtual_memory()
            process = psutil.Process(os.getpid())
            return {
                "platform": platform.platform(),
                "cpu_cores": psutil.cpu_count() or 0,
                "cpu_percent": round(psutil.cpu_percent(interval=None), 1),
                "ram_gb": round(virtual_memory.total / (1024 ** 3), 2),
                "available_ram_gb": round(virtual_memory.available / (1024 ** 3), 2),
                "memory_percent": round(virtual_memory.percent, 1),
                "process_rss_mb": round(process.memory_info().rss / (1024 ** 2), 2),
                "process_cpu_percent": round(process.cpu_percent(interval=None), 1),
            }
        except Exception:
            return {
                "platform": platform.platform(),
                "cpu_cores": 0,
                "cpu_percent": 0.0,
                "ram_gb": 0.0,
                "available_ram_gb": 0.0,
                "memory_percent": 0.0,
                "process_rss_mb": 0.0,
                "process_cpu_percent": 0.0,
            }

    def _coerce_float(self, value: Any) -> float | None:
        if value is None:
            return None
        try:
            return round(float(value), 2)
        except (TypeError, ValueError):
            return None

    def _coerce_int(self, value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _serialize_unlock_datetime(self, unlock_dt: datetime | None, request_value: str | None) -> str | None:
        if unlock_dt is not None:
            if unlock_dt.tzinfo is None:
                return unlock_dt.isoformat()
            return unlock_dt.astimezone().isoformat()
        return request_value or None

    def record_archive_creation(
        self,
        *,
        request: Any,
        archive_mode: str,
        provider: str | None,
        unlock_dt: datetime | None,
        status: str,
        duration_ms: float | None,
        response_payload: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> dict[str, Any]:
        result = response_payload.get("result") if isinstance(response_payload, dict) else {}
        if not isinstance(result, dict):
            result = {}

        telemetry = result.get("telemetry")
        if not isinstance(telemetry, dict):
            telemetry = {}

        pqc_info = result.get("pqc")
        if not isinstance(pqc_info, dict):
            pqc_info = {}

        input_files = getattr(request, "input_files", None) or []
        selected_input_count = len(input_files)

        now_local = self._now_local()
        entry = {
            "schema_version": 1,
            "event_id": uuid.uuid4().hex[:12],
            "logged_at_local": now_local.isoformat(),
            "timezone": now_local.tzname() or "",
            "action": "archive_create",
            "status": status,
            "archive_mode": archive_mode,
            "timecapsule_provider": provider or "none",
            "archive_kind": telemetry.get("archive_kind") or ("multi_file" if selected_input_count > 1 else "single_file"),
            "selected_input_count": selected_input_count,
            "expanded_entry_count": self._coerce_int(telemetry.get("expanded_entry_count")) or selected_input_count,
            "secret_mode": self._derive_secret_mode(
                getattr(request, "password", None),
                getattr(request, "keyphrase", None),
            ),
            "keyphrase_word_count": len(getattr(request, "keyphrase", None) or []),
            "pqc_enabled": bool(getattr(request, "pqc_enabled", False)),
            "pqc_keyfile_generated": bool(pqc_info.get("enabled")),
            "unlock_datetime": self._serialize_unlock_datetime(
                unlock_dt,
                getattr(request, "unlock_datetime", None),
            ),
            "duration_ms": self._coerce_float(duration_ms),
            "compression_ms": self._coerce_float(telemetry.get("compression_ms")),
            "encryption_ms": self._coerce_float(telemetry.get("encryption_ms")),
            "chess_encoding_ms": self._coerce_float(telemetry.get("chess_encoding_ms")),
            "core_total_ms": self._coerce_float(telemetry.get("total_processing_ms")),
            "output_archive_size_bytes": self._coerce_int(telemetry.get("output_archive_size_bytes")),
            "system": self._system_snapshot(),
            "error": error_message or None,
        }

        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")

        return entry

    def load_entries(self) -> list[dict[str, Any]]:
        if not self.log_file.exists():
            return []

        entries: list[dict[str, Any]] = []
        with self.log_file.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    entries.append(item)
        return entries

    def get_summary(self) -> dict[str, Any]:
        entries = self.load_entries()
        last_entry = entries[-1] if entries else {}
        return {
            "entry_count": len(entries),
            "storage_path": str(self.log_file),
            "last_event_at": last_entry.get("logged_at_local"),
            "export_format": "markdown",
        }

    def _markdown_cell(self, value: Any) -> str:
        if value is None or value == "":
            return "-"
        if isinstance(value, bool):
            text = "Yes" if value else "No"
        elif isinstance(value, float):
            text = f"{value:.2f}".rstrip("0").rstrip(".")
        else:
            text = str(value)
        return text.replace("|", "\\|").replace("\r\n", "<br>").replace("\n", "<br>")

    def build_markdown_export(self) -> dict[str, Any]:
        entries = self.load_entries()
        generated_at = self._now_local()

        lines = [
            "# RookDuel Avikal Activity Audit",
            "",
            f"- Generated at: {generated_at.isoformat()}",
            f"- Entry count: {len(entries)}",
            f"- Raw log storage: `{self.log_file}`",
            "",
            "Source file names, source paths, and source file contents are intentionally excluded.",
            "",
        ]

        if not entries:
            lines.append("No archive creation events have been recorded yet.")
        else:
            lines.extend(
                [
                    "| Event ID | Logged At | Status | Archive Mode | Provider | Archive Kind | Selected Inputs | Expanded Entries | Secret Mode | PQC | Unlock At | Request ms | Core ms | Compress ms | Encrypt ms | Chess ms | AVK Size (B) | CPU Cores | RAM GB | Available RAM GB | CPU % | Process RSS MB | Error |",
                    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
                ]
            )

            for entry in reversed(entries):
                system = entry.get("system") if isinstance(entry.get("system"), dict) else {}
                row = [
                    entry.get("event_id"),
                    entry.get("logged_at_local"),
                    entry.get("status"),
                    entry.get("archive_mode"),
                    entry.get("timecapsule_provider"),
                    entry.get("archive_kind"),
                    entry.get("selected_input_count"),
                    entry.get("expanded_entry_count"),
                    entry.get("secret_mode"),
                    entry.get("pqc_enabled"),
                    entry.get("unlock_datetime"),
                    entry.get("duration_ms"),
                    entry.get("core_total_ms"),
                    entry.get("compression_ms"),
                    entry.get("encryption_ms"),
                    entry.get("chess_encoding_ms"),
                    entry.get("output_archive_size_bytes"),
                    system.get("cpu_cores"),
                    system.get("ram_gb"),
                    system.get("available_ram_gb"),
                    system.get("cpu_percent"),
                    system.get("process_rss_mb"),
                    entry.get("error"),
                ]
                lines.append("| " + " | ".join(self._markdown_cell(value) for value in row) + " |")

        return {
            "entry_count": len(entries),
            "filename": f"avikal-activity-log-{generated_at.strftime('%Y-%m-%d')}.md",
            "markdown": "\n".join(lines) + "\n",
            "storage_path": str(self.log_file),
            "generated_at": generated_at.isoformat(),
        }


activity_audit = ActivityAuditLog()
