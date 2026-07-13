"""Durable production diagnostics for support-safe failure analysis.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from avikal_backend.core.private_workspace import ensure_private_dir
from avikal_backend.core.redaction import is_sensitive_key, redact_sensitive, redact_text
from avikal_backend.version import __version__


MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_EXPORT_EVENTS = 400
PATH_KEYS = {
    "input_file",
    "input_files",
    "output_file",
    "output_folder",
    "keyfile_path",
    "pqc_keyfile",
    "archive_path",
    "file_path",
    "path",
}


def _base_dir() -> Path:
    override = os.getenv("AVIKAL_USER_DATA_DIR")
    return Path(override) if override else Path.home() / ".avikal"


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _summarize_path(value: str) -> dict[str, str]:
    text = str(value)
    return {
        "basename": Path(text).name,
        "path_hash": _hash_text(text),
    }


def _sanitize_for_log(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    if depth > 8:
        return "[DEPTH_LIMIT]"
    if key and is_sensitive_key(key):
        return "[REDACTED]"
    normalized_key = (key or "").strip().lower()
    if normalized_key in PATH_KEYS and isinstance(value, str):
        return _summarize_path(value)
    if normalized_key in PATH_KEYS and isinstance(value, list):
        return [_summarize_path(item) if isinstance(item, str) else "[INVALID_PATH]" for item in value[:100]]
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_for_log(item_value, key=str(item_key), depth=depth + 1)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        if len(value) > 200:
            return [_sanitize_for_log(item, depth=depth + 1) for item in value[:200]] + [f"[TRUNCATED_{len(value) - 200}_ITEMS]"]
        return [_sanitize_for_log(item, depth=depth + 1) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_for_log(item, depth=depth + 1) for item in value]
    if isinstance(value, bytes):
        return {"bytes_len": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, str):
        text = redact_text(value)
        if len(text) > 4096:
            return text[:4096] + f"...[TRUNCATED_{len(text) - 4096}_CHARS]"
        return text
    return redact_sensitive(value)


class DiagnosticLog:
    def __init__(self, base_dir: str | Path | None = None):
        self.base_dir = Path(base_dir) if base_dir else _base_dir()
        ensure_private_dir(self.base_dir)
        self.diagnostic_dir = self.base_dir / "diagnostics"
        ensure_private_dir(self.diagnostic_dir)
        self.log_file = self.diagnostic_dir / "avikal-diagnostics.jsonl"
        self._lock = threading.Lock()

    def _rotate_if_needed_unlocked(self) -> None:
        if not self.log_file.exists() or self.log_file.stat().st_size <= MAX_LOG_BYTES:
            return
        rotated = self.diagnostic_dir / "avikal-diagnostics.1.jsonl"
        if rotated.exists():
            rotated.unlink()
        self.log_file.replace(rotated)

    def record(
        self,
        *,
        source: str,
        event: str,
        status: str,
        correlation_id: str | None = None,
        method: str | None = None,
        level: str = "info",
        duration_ms: float | None = None,
        request: Any | None = None,
        response: Any | None = None,
        error: Any | None = None,
        exception: BaseException | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "schema_version": 1,
            "event_id": uuid.uuid4().hex[:16],
            "correlation_id": correlation_id or uuid.uuid4().hex[:16],
            "logged_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": str(source),
            "event": str(event),
            "status": str(status),
            "level": str(level),
            "method": method,
            "duration_ms": round(float(duration_ms), 2) if duration_ms is not None else None,
            "runtime": {
                "avikal_version": __version__,
                "platform": platform.system().lower(),
                "architecture": platform.machine().lower(),
                "packaged_runtime": os.getenv("AVIKAL_PACKAGED_RUNTIME") == "1",
            },
            "request": _sanitize_for_log(request) if request is not None else None,
            "response": _sanitize_for_log(response) if response is not None else None,
            "error": _sanitize_for_log(error) if error is not None else None,
            "details": _sanitize_for_log(details or {}),
        }
        if exception is not None:
            entry["exception"] = {
                "type": type(exception).__name__,
                "message": redact_text(str(exception)),
                "traceback": redact_text("".join(traceback.format_exception(type(exception), exception, exception.__traceback__))),
            }

        with self._lock:
            self._rotate_if_needed_unlocked()
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")
        return entry

    def load_entries(self, limit: int = MAX_EXPORT_EVENTS) -> list[dict[str, Any]]:
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
        return entries[-limit:]

    def get_summary(self) -> dict[str, Any]:
        entries = self.load_entries(limit=1)
        entry_count = 0
        if self.log_file.exists():
            with self.log_file.open("r", encoding="utf-8") as handle:
                entry_count = sum(1 for _ in handle)
        return {
            "entry_count": entry_count,
            "storage_path": str(self.log_file),
            "last_event_at": entries[-1].get("logged_at_utc") if entries else None,
            "max_file_size_bytes": MAX_LOG_BYTES,
            "export_format": "jsonl+markdown",
        }

    def build_markdown_export(self) -> dict[str, Any]:
        entries = self.load_entries()
        generated_at = datetime.now(timezone.utc).isoformat()
        lines = [
            "# RookDuel Avikal Diagnostic Log",
            "",
            f"- Generated at: {generated_at}",
            f"- Exported events: {len(entries)}",
            f"- Raw log storage: `{self.log_file}`",
            "",
            "This support log is redacted. Passwords, keyphrases, private keys, derived keys, and raw file contents are not stored.",
            "",
        ]
        if not entries:
            lines.append("No diagnostic events have been recorded yet.")
        else:
            for entry in reversed(entries):
                lines.extend(
                    [
                        f"## {entry.get('logged_at_utc')} - {entry.get('event')} - {entry.get('status')}",
                        "",
                        f"- Correlation ID: `{entry.get('correlation_id')}`",
                        f"- Source: `{entry.get('source')}`",
                        f"- Method: `{entry.get('method') or '-'}`",
                        f"- Level: `{entry.get('level')}`",
                        f"- Duration ms: `{entry.get('duration_ms') if entry.get('duration_ms') is not None else '-'}`",
                        "",
                        "```json",
                        json.dumps(entry, ensure_ascii=False, indent=2, sort_keys=True),
                        "```",
                        "",
                    ]
                )
        return {
            "success": True,
            "entry_count": len(entries),
            "filename": f"avikal-diagnostics-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.md",
            "markdown": "\n".join(lines) + "\n",
            "storage_path": str(self.log_file),
            "generated_at": generated_at,
        }


diagnostic_log = DiagnosticLog()


class DiagnosticTimer:
    def __init__(self) -> None:
        self.started_at = time.perf_counter()

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.started_at) * 1000
