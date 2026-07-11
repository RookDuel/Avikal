"""User preference persistence for Avikal core services.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any


ACTIVITY_LOG_MODES = {"off", "minimal", "detailed"}
ACTIVITY_RETENTION_DAYS = {7, 30, 90, 365, 0}
PQC_STORAGE_MODES = {"embedded", "external"}
TIMECAPSULE_PROVIDERS = {"drand", "aavrit"}
OVERWRITE_POLICIES = {"never", "ask", "allow"}
OUTPUT_FOLDER_MODES = {"ask", "remember"}
LARGE_FILE_MODES = {"auto", "low_resource"}
DECODE_OUTPUT_LIMITS = {"standard", "high"}
PREVIEW_CLEANUP_POLICIES = {"on_close_15m", "manual"}
VISUAL_EFFECTS_MODES = {"auto", "effects", "normal"}

DEFAULT_PREFERENCES: dict[str, Any] = {
    "appearance": {
        "visual_effects_mode": "auto",
    },
    "privacy": {
        "activity_log_mode": "minimal",
        "activity_retention_days": 30,
        "redact_diagnostics": True,
    },
    "archive_defaults": {
        "pqc_storage_mode": "embedded",
        "remember_keyfile_folder": False,
        "default_timecapsule_provider": "drand",
        "overwrite_policy": "never",
        "output_folder_mode": "ask",
    },
    "preview": {
        "cleanup_policy": "on_close_15m",
    },
    "advanced": {
        "large_file_mode": "auto",
        "decode_output_limit": "standard",
    },
}


def _base_dir() -> Path:
    override = os.getenv("AVIKAL_USER_DATA_DIR")
    return Path(override) if override else Path.home() / ".avikal"


def _preferences_path() -> Path:
    return _base_dir() / "preferences.json"


def _coerce_bool(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _coerce_choice(value: Any, allowed: set[str], default: str) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in allowed:
            return normalized
    return default


def _coerce_retention_days(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed in ACTIVITY_RETENTION_DAYS else default


def sanitize_preferences(raw: Any) -> dict[str, Any]:
    prefs = deepcopy(DEFAULT_PREFERENCES)
    if not isinstance(raw, dict):
        return prefs

    appearance = raw.get("appearance") if isinstance(raw.get("appearance"), dict) else {}
    prefs["appearance"]["visual_effects_mode"] = _coerce_choice(
        appearance.get("visual_effects_mode"),
        VISUAL_EFFECTS_MODES,
        prefs["appearance"]["visual_effects_mode"],
    )

    privacy = raw.get("privacy") if isinstance(raw.get("privacy"), dict) else {}
    prefs["privacy"]["activity_log_mode"] = _coerce_choice(
        privacy.get("activity_log_mode"),
        ACTIVITY_LOG_MODES,
        prefs["privacy"]["activity_log_mode"],
    )
    prefs["privacy"]["activity_retention_days"] = _coerce_retention_days(
        privacy.get("activity_retention_days"),
        prefs["privacy"]["activity_retention_days"],
    )
    prefs["privacy"]["redact_diagnostics"] = _coerce_bool(
        privacy.get("redact_diagnostics"),
        prefs["privacy"]["redact_diagnostics"],
    )

    archive = raw.get("archive_defaults") if isinstance(raw.get("archive_defaults"), dict) else {}
    prefs["archive_defaults"]["pqc_storage_mode"] = _coerce_choice(
        archive.get("pqc_storage_mode"),
        PQC_STORAGE_MODES,
        prefs["archive_defaults"]["pqc_storage_mode"],
    )
    prefs["archive_defaults"]["remember_keyfile_folder"] = _coerce_bool(
        archive.get("remember_keyfile_folder"),
        prefs["archive_defaults"]["remember_keyfile_folder"],
    )
    prefs["archive_defaults"]["default_timecapsule_provider"] = _coerce_choice(
        archive.get("default_timecapsule_provider"),
        TIMECAPSULE_PROVIDERS,
        prefs["archive_defaults"]["default_timecapsule_provider"],
    )
    prefs["archive_defaults"]["overwrite_policy"] = _coerce_choice(
        archive.get("overwrite_policy"),
        OVERWRITE_POLICIES,
        prefs["archive_defaults"]["overwrite_policy"],
    )
    prefs["archive_defaults"]["output_folder_mode"] = _coerce_choice(
        archive.get("output_folder_mode"),
        OUTPUT_FOLDER_MODES,
        prefs["archive_defaults"]["output_folder_mode"],
    )

    preview = raw.get("preview") if isinstance(raw.get("preview"), dict) else {}
    prefs["preview"]["cleanup_policy"] = _coerce_choice(
        preview.get("cleanup_policy"),
        PREVIEW_CLEANUP_POLICIES,
        prefs["preview"]["cleanup_policy"],
    )

    advanced = raw.get("advanced") if isinstance(raw.get("advanced"), dict) else {}
    prefs["advanced"]["large_file_mode"] = _coerce_choice(
        advanced.get("large_file_mode"),
        LARGE_FILE_MODES,
        prefs["advanced"]["large_file_mode"],
    )
    prefs["advanced"]["decode_output_limit"] = _coerce_choice(
        advanced.get("decode_output_limit"),
        DECODE_OUTPUT_LIMITS,
        prefs["advanced"]["decode_output_limit"],
    )
    return prefs


def load_user_preferences() -> dict[str, Any]:
    path = _preferences_path()
    if not path.exists():
        return deepcopy(DEFAULT_PREFERENCES)
    try:
        return sanitize_preferences(json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return deepcopy(DEFAULT_PREFERENCES)


def save_user_preferences(raw: Any) -> dict[str, Any]:
    prefs = sanitize_preferences(raw)
    path = _preferences_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(prefs, indent=2, sort_keys=True), encoding="utf-8")
    temp_path.replace(path)
    return prefs
