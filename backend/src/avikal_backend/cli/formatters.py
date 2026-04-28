"""
Output and summary formatting helpers for the backend CLI.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _supports_color(stream) -> bool:
    if os.getenv("NO_COLOR") or os.getenv("AVIKAL_CLI_NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.getenv("TERM") == "dumb":
        return False
    return True


class CliTheme:
    reset = "\033[0m"
    dim = "\033[2m"
    bold = "\033[1m"
    red = "\033[31m"
    green = "\033[32m"
    yellow = "\033[33m"
    blue = "\033[34m"
    magenta = "\033[35m"
    cyan = "\033[36m"
    white = "\033[37m"

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def style(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + self.reset


THEME = CliTheme(_supports_color(sys.stdout))
ERR_THEME = CliTheme(_supports_color(sys.stderr))


def human_size(num_bytes: int | float | None) -> str:
    if num_bytes is None:
        return "unknown"
    value = float(num_bytes)
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    precision = 0 if unit_index == 0 else 2
    return f"{value:.{precision}f} {units[unit_index]}"


def style_heading(text: str) -> str:
    return THEME.style(text, THEME.bold, THEME.cyan)


def style_label(text: str) -> str:
    return THEME.style(text, THEME.bold, THEME.blue)


def style_success(text: str) -> str:
    return THEME.style(text, THEME.bold, THEME.green)


def style_warning(text: str) -> str:
    return THEME.style(text, THEME.bold, THEME.yellow)


def style_error(text: str) -> str:
    return ERR_THEME.style(text, ERR_THEME.bold, ERR_THEME.red)


def style_muted(text: str) -> str:
    return THEME.style(text, THEME.dim)


def _format_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return style_success("yes") if value else style_muted("no")
    if value is None:
        return style_muted("none")
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def _display_key(key: str) -> str:
    overrides = {
        "archive_kind": "Archive Kind",
        "archive_size_bytes": "Archive Size (Bytes)",
        "archive_size_human": "Archive Size",
        "checksum_sha256": "Checksum (SHA-256)",
        "compressed_size_bytes": "Compressed Size (Bytes)",
        "drand_beacon_id": "Drand Beacon ID",
        "drand_chain_url": "Drand Chain URL",
        "drand_round": "Drand Round",
        "elapsed_ms": "Elapsed (ms)",
        "entry_count": "Entry Count",
        "file_count": "File Count",
        "has_chess_salt": "Has Chess Salt",
        "has_drand_ciphertext": "Has Drand Ciphertext",
        "has_payload_salt": "Has Payload Salt",
        "keyphrase_protected": "Keyphrase Protected",
        "manifest_hash_sha256": "Manifest Hash (SHA-256)",
        "member_count": "Container Member Count",
        "output_dir": "Output Directory",
        "output_directory": "Output Directory",
        "output_file": "Output File",
        "output_size_bytes": "Output Size (Bytes)",
        "output_size_human": "Output Size",
        "probe_path": "Probe Path",
        "pqc_algorithm": "PQC Algorithm",
        "pqc_enabled": "PQC Enabled",
        "pqc_key_id": "PQC Key ID",
        "pqc_required": "PQC Required",
        "selected_input_count": "Selected Input Count",
        "size_bytes": "Size (Bytes)",
        "size_human": "Size",
        "timecapsule": "Time Lock Enabled",
        "timecapsule_provider": "Time Lock Provider",
        "timeout_seconds": "Timeout (Seconds)",
        "total_original_size": "Total Original Size (Bytes)",
        "total_size_bytes": "Total Size (Bytes)",
        "total_size_human": "Total Size",
        "unlock_datetime_utc": "Unlock Time (UTC)",
        "unlock_timestamp": "Unlock Timestamp",
        "aavrit": "Aavrit",
    }
    if key in overrides:
        return overrides[key]
    return key.replace("_", " ").strip().title()


def _ordered_items(payload: dict[str, Any]) -> list[tuple[str, Any]]:
    preferred_order = [
        "ok",
        "mode",
        "archive_kind",
        "message",
        "output_file",
        "output_directory",
        "output_dir",
        "selected_input_count",
        "file_count",
        "total_size_bytes",
        "total_size_human",
        "output_size_bytes",
        "output_size_human",
        "timecapsule",
        "pqc_enabled",
        "container",
        "metadata",
        "checks",
        "pqc",
        "telemetry",
        "files",
        "members",
        "result",
    ]
    seen: set[str] = set()
    ordered: list[tuple[str, Any]] = []
    for key in preferred_order:
        if key in payload:
            ordered.append((key, payload[key]))
            seen.add(key)
    for key, value in payload.items():
        if key not in seen:
            ordered.append((key, value))
    return ordered


def _emit_mapping(mapping: dict[str, Any], indent: int = 0) -> None:
    pad = "  " * indent
    for key, value in _ordered_items(mapping):
        if key == "ok":
            continue
        label = style_label(_display_key(key))
        if isinstance(value, dict):
            print(f"{pad}{label}")
            _emit_mapping(value, indent + 1)
        elif isinstance(value, list):
            print(f"{pad}{label}")
            _emit_sequence(value, indent + 1)
        else:
            print(f"{pad}{label}: {_format_scalar(value)}")


def _emit_sequence(values: list[Any], indent: int = 0) -> None:
    pad = "  " * indent
    for item in values:
        if isinstance(item, dict):
            title = None
            for candidate in ("filename", "name", "path", "probe_path"):
                if candidate in item and item[candidate]:
                    title = str(item[candidate])
                    break
            bullet = "- " + (title if title else "item")
            print(f"{pad}{THEME.style(bullet, THEME.magenta)}")
            remainder = dict(item)
            if title:
                for candidate in ("filename", "name", "path", "probe_path"):
                    if remainder.get(candidate) == title:
                        remainder.pop(candidate, None)
                        break
            if remainder:
                _emit_mapping(remainder, indent + 1)
        else:
            print(f"{pad}- {_format_scalar(item)}")


def _build_result_title(payload: dict[str, Any]) -> str:
    mode = str(payload.get("mode", "command")).replace("_", " ").title()
    if payload.get("ok", True):
        return f"[OK] {mode}"
    return f"[INFO] {mode}"


def emit_result(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    title = _build_result_title(payload)
    title_style = style_success if payload.get("ok", True) else style_warning
    print(title_style(title))
    print(style_muted("-" * len(title)))
    _emit_mapping(payload)


def emit_error(message: str, *, context: str | None = None) -> None:
    lines = [message.strip() or "Unknown error"]
    if context:
        lines.append(context.strip())
    print(style_error("[ERROR] Command failed"), file=sys.stderr)
    for line in lines:
        for wrapped in textwrap.wrap(line, width=96) or [""]:
            print(style_error(f"  {wrapped}"), file=sys.stderr)


def build_container_summary(input_path: str) -> dict[str, Any]:
    archive_path = Path(input_path).resolve()
    with zipfile.ZipFile(archive_path, "r") as container_zip:
        members = [
            {
                "name": info.filename,
                "size_bytes": info.file_size,
                "compressed_size_bytes": info.compress_size,
            }
            for info in sorted(container_zip.infolist(), key=lambda item: item.filename)
        ]

    return {
        "path": str(archive_path),
        "archive_size_bytes": archive_path.stat().st_size,
        "archive_size_human": human_size(archive_path.stat().st_size),
        "member_count": len(members),
        "members": members,
    }


def summarize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "version": metadata.get("version"),
        "filename": metadata.get("filename"),
        "encryption_method": metadata.get("encryption_method"),
        "keyphrase_protected": bool(metadata.get("keyphrase_protected")),
        "timecapsule_provider": metadata.get("timecapsule_provider"),
        "drand_round": metadata.get("drand_round"),
        "drand_beacon_id": metadata.get("drand_beacon_id"),
        "drand_chain_url": metadata.get("drand_chain_url"),
        "pqc_required": bool(metadata.get("pqc_required")),
        "pqc_algorithm": metadata.get("pqc_algorithm"),
        "pqc_key_id": metadata.get("pqc_key_id"),
        "archive_type": metadata.get("archive_type"),
        "entry_count": metadata.get("entry_count"),
        "total_original_size": metadata.get("total_original_size"),
        "has_payload_salt": metadata.get("salt") is not None,
        "has_chess_salt": metadata.get("chess_salt") is not None,
        "has_drand_ciphertext": metadata.get("drand_ciphertext") is not None,
    }

    unlock_timestamp = metadata.get("unlock_timestamp")
    if isinstance(unlock_timestamp, int):
        summary["unlock_timestamp"] = unlock_timestamp
        summary["unlock_datetime_utc"] = datetime.fromtimestamp(
            unlock_timestamp,
            tz=timezone.utc,
        ).isoformat()

    checksum = metadata.get("checksum")
    if isinstance(checksum, (bytes, bytearray)):
        summary["checksum_sha256"] = bytes(checksum).hex()

    manifest_hash = metadata.get("manifest_hash")
    if isinstance(manifest_hash, (bytes, bytearray)):
        summary["manifest_hash_sha256"] = bytes(manifest_hash).hex()

    return summary
