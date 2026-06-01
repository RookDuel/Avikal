"""Sensitive-value redaction helpers for diagnostics.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import re
from typing import Any


REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {
    "authorization",
    "keyphrase",
    "new_keyphrase",
    "new_password",
    "old_keyphrase",
    "old_password",
    "password",
    "pqc_keyfile_password",
    "secret",
    "session_token",
    "token",
}
_KEY_VALUE_PATTERNS = [
    re.compile(r"(?i)\b(password|keyphrase|old_password|new_password|old_keyphrase|new_keyphrase|session_token|token|secret)\b\s*[:=]\s*('[^']*'|\"[^\"]*\"|[^\s,;]+)"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
]


def is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or normalized.endswith("_secret") or normalized.endswith("_token")


def redact_text(value: object) -> str:
    text = str(value)
    for pattern in _KEY_VALUE_PATTERNS:
        if pattern.pattern.lower().startswith("(?i)(bearer"):
            text = pattern.sub(r"\1" + REDACTED, text)
        else:
            text = pattern.sub(lambda match: f"{match.group(1)}={REDACTED}", text)
    return text


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: REDACTED if is_sensitive_key(key) else redact_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value
