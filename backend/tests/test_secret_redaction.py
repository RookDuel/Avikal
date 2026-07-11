"""Secret redaction regression tests.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from avikal_backend.core.redaction import REDACTED, redact_sensitive, redact_text


def test_redacts_sensitive_mapping_fields() -> None:
    payload = {
        "password": "CorrectHorseBatteryStaple",
        "keyphrase": ["ek", "do"],
        "nested": {"session_token": "abc.def.ghi", "safe": "visible"},
    }

    redacted = redact_sensitive(payload)

    assert redacted["password"] == REDACTED
    assert redacted["keyphrase"] == REDACTED
    assert redacted["nested"]["session_token"] == REDACTED
    assert redacted["nested"]["safe"] == "visible"


def test_redacts_secret_shaped_text() -> None:
    text = "password='CorrectHorseBatteryStaple' token=abc.def.ghi Authorization: Bearer secretBearerToken"

    redacted = redact_text(text)

    assert "CorrectHorseBatteryStaple" not in redacted
    assert "abc.def.ghi" not in redacted
    assert "secretBearerToken" not in redacted
    assert REDACTED in redacted
