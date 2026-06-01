"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import psutil

from avikal_backend.core.private_workspace import ensure_private_dir
from avikal_backend.core.redaction import redact_text
from avikal_backend.core.user_preferences import load_user_preferences


def _get_default_data_dir() -> Path:
    override = os.getenv("AVIKAL_USER_DATA_DIR")
    if override:
        return Path(override)
    return Path.home() / ".avikal"


class ActivityAuditLog:
    def __init__(self, base_dir: str | Path | None = None):
        self.base_dir = Path(base_dir) if base_dir else _get_default_data_dir()
        ensure_private_dir(self.base_dir)
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

    def _canonical_hash_payload(self, entry: dict[str, Any]) -> bytes:
        payload = {key: value for key, value in entry.items() if key != "entry_hash"}
        return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _entry_hash(self, entry: dict[str, Any]) -> str:
        return hashlib.sha256(self._canonical_hash_payload(entry)).hexdigest()

    def _last_entry_hash_unlocked(self) -> str:
        if not self.log_file.exists():
            return ""
        last_hash = ""
        with self.log_file.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                try:
                    entry = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict) and isinstance(entry.get("entry_hash"), str):
                    last_hash = entry["entry_hash"]
        return last_hash

    def _append_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry["prev_hash"] = self._last_entry_hash_unlocked()
            entry["entry_hash"] = self._entry_hash(entry)
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")
        return entry

    def _activity_mode(self) -> str:
        return load_user_preferences().get("privacy", {}).get("activity_log_mode", "minimal")

    def record_event(
        self,
        *,
        action: str,
        status: str,
        duration_ms: float | None = None,
        provider: str | None = None,
        archive_kind: str | None = None,
        secret_mode: str | None = None,
        pqc_enabled: bool | None = None,
        error_message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        activity_mode = self._activity_mode()
        if activity_mode == "off":
            return {}

        now_local = self._now_local()
        safe_details = details if isinstance(details, dict) else {}
        entry = {
            "schema_version": 2,
            "event_id": uuid.uuid4().hex[:12],
            "logged_at_local": now_local.isoformat(),
            "timezone": now_local.tzname() or "",
            "action": str(action or "event"),
            "status": str(status or "unknown"),
            "archive_mode": safe_details.get("archive_mode") or "none",
            "timecapsule_provider": provider or safe_details.get("timecapsule_provider") or "none",
            "archive_kind": archive_kind or safe_details.get("archive_kind") or "unknown",
            "selected_input_count": self._coerce_int(safe_details.get("selected_input_count")),
            "expanded_entry_count": self._coerce_int(safe_details.get("expanded_entry_count")),
            "file_count": self._coerce_int(safe_details.get("file_count")),
            "secret_mode": secret_mode or safe_details.get("secret_mode") or "unknown",
            "keyphrase_word_count": self._coerce_int(safe_details.get("keyphrase_word_count")),
            "pqc_enabled": bool(pqc_enabled) if pqc_enabled is not None else bool(safe_details.get("pqc_enabled")),
            "pqc_keyfile_present": bool(safe_details.get("pqc_keyfile_present")),
            "pqc_keyfile_generated": bool(safe_details.get("pqc_keyfile_generated")),
            "pqc_keyfile_protected": bool(safe_details.get("pqc_keyfile_protected")),
            "unlock_datetime": safe_details.get("unlock_datetime"),
            "duration_ms": self._coerce_float(duration_ms),
            "compression_ms": self._coerce_float(safe_details.get("compression_ms")),
            "encryption_ms": self._coerce_float(safe_details.get("encryption_ms")),
            "chess_encoding_ms": self._coerce_float(safe_details.get("chess_encoding_ms")),
            "core_total_ms": self._coerce_float(safe_details.get("core_total_ms")),
            "output_archive_size_bytes": self._coerce_int(safe_details.get("output_archive_size_bytes")),
            "removed_count": self._coerce_int(safe_details.get("removed_count")),
            "system": self._system_snapshot() if activity_mode == "detailed" else {},
            "error": redact_text(error_message) if error_message else None,
        }
        return self._append_entry(entry)

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
        activity_mode = self._activity_mode()
        if activity_mode == "off":
            return {}

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
            "system": self._system_snapshot() if activity_mode == "detailed" else {},
            "error": redact_text(error_message) if error_message else None,
        }

        with self._lock:
            entry["prev_hash"] = self._last_entry_hash_unlocked()
            entry["entry_hash"] = self._entry_hash(entry)
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")

        return entry

    def _retention_days(self) -> int:
        preferences = load_user_preferences()
        privacy = preferences.get("privacy", {})
        try:
            return int(privacy.get("activity_retention_days", 30))
        except (TypeError, ValueError):
            return 30

    def _apply_retention(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        retention_days = self._retention_days()
        if retention_days <= 0:
            return entries
        cutoff = self._now_local() - timedelta(days=retention_days)
        retained: list[dict[str, Any]] = []
        for entry in entries:
            raw_timestamp = entry.get("logged_at_local")
            if not isinstance(raw_timestamp, str):
                retained.append(entry)
                continue
            try:
                parsed = datetime.fromisoformat(raw_timestamp)
            except ValueError:
                retained.append(entry)
                continue
            if parsed.tzinfo is None:
                parsed = parsed.astimezone()
            if parsed >= cutoff:
                retained.append(entry)
        return retained

    def _rewrite_entries(self, entries: list[dict[str, Any]]) -> None:
        with self._lock:
            if not entries:
                if self.log_file.exists():
                    self.log_file.unlink()
                return
            previous_hash = ""
            with self.log_file.open("w", encoding="utf-8") as handle:
                for entry in entries:
                    entry = dict(entry)
                    entry["prev_hash"] = previous_hash
                    entry["entry_hash"] = self._entry_hash(entry)
                    previous_hash = entry["entry_hash"]
                    handle.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")

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
        retained = self._apply_retention(entries)
        if len(retained) != len(entries):
            self._rewrite_entries(retained)
        return retained

    def get_summary(self) -> dict[str, Any]:
        entries = self.load_entries()
        last_entry = entries[-1] if entries else {}
        chain_status = self.verify_chain(entries)
        return {
            "entry_count": len(entries),
            "storage_path": str(self.log_file),
            "last_event_at": last_entry.get("logged_at_local"),
            "export_format": "markdown",
            "retention_days": self._retention_days(),
            "mode": load_user_preferences().get("privacy", {}).get("activity_log_mode", "minimal"),
            "chain_status": chain_status,
        }

    def verify_chain(self, entries: list[dict[str, Any]] | None = None) -> str:
        items = entries if entries is not None else self.load_entries()
        expected_prev = ""
        saw_hashed = False
        saw_legacy = False
        for entry in items:
            entry_hash = entry.get("entry_hash")
            if not isinstance(entry_hash, str):
                saw_legacy = True
                continue
            saw_hashed = True
            if entry.get("prev_hash", "") != expected_prev:
                return "broken"
            if self._entry_hash(entry) != entry_hash:
                return "broken"
            expected_prev = entry_hash
        if saw_legacy and saw_hashed:
            return "partial"
        if saw_legacy:
            return "legacy"
        return "verified" if saw_hashed else "empty"

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
        redact_diagnostics = bool(load_user_preferences().get("privacy", {}).get("redact_diagnostics", True))

        lines = [
            "# RookDuel Avikal Activity Audit",
            "",
            f"- Generated at: {generated_at.isoformat()}",
            f"- Entry count: {len(entries)}",
            f"- Hash chain: {self.verify_chain(entries)}",
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
                    "| Event ID | Hash | Previous Hash | Action | Logged At | Status | Archive Mode | Provider | Archive Kind | Files | Selected Inputs | Expanded Entries | Secret Mode | PQC | Unlock At | Request ms | Core ms | Compress ms | Encrypt ms | Chess ms | AVK Size (B) | Removed | CPU Cores | RAM GB | Available RAM GB | CPU % | Process RSS MB | Error |",
                    "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
                ]
            )

            for entry in reversed(entries):
                system = {} if redact_diagnostics else (entry.get("system") if isinstance(entry.get("system"), dict) else {})
                row = [
                    entry.get("event_id"),
                    str(entry.get("entry_hash") or "-")[:16],
                    str(entry.get("prev_hash") or "-")[:16],
                    entry.get("action"),
                    entry.get("logged_at_local"),
                    entry.get("status"),
                    entry.get("archive_mode"),
                    entry.get("timecapsule_provider"),
                    entry.get("archive_kind"),
                    entry.get("file_count"),
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
                    entry.get("removed_count"),
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

    def clear(self) -> int:
        entries = self.load_entries()
        count = len(entries)
        with self._lock:
            if self.log_file.exists():
                self.log_file.unlink()
        return count


activity_audit = ActivityAuditLog()
