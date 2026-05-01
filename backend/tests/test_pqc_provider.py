"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import pytest

from avikal_backend.archive.security.pqc_provider import (
    PQC_SUITE_ID,
    compute_pqc_key_id,
    create_pqc_archive_material,
    decapsulate_pqc_archive_material,
    provider_status,
)


def test_pqc_provider_status_shape():
    status = provider_status()

    assert status["provider"] == "openssl"
    assert status["suite"]["suite_id"] == PQC_SUITE_ID
    assert isinstance(status["available"], bool)


def test_openssl_pqc_provider_roundtrip_when_runtime_is_available():
    status = provider_status()
    if not status["available"]:
        pytest.skip(status["reason"])

    material = create_pqc_archive_material(archive_filename="provider-test.avk")
    recovered = decapsulate_pqc_archive_material(
        private_bundle=material["private_bundle"],
        public_bundle=material["public_bundle"],
        pqc_ciphertext=material["ciphertext"],
        expected_key_id=material["key_id"],
    )

    assert material["algorithm"] == PQC_SUITE_ID
    assert len(material["shared_secret"]) >= 32
    assert recovered == material["shared_secret"]
    assert material["key_id"] == compute_pqc_key_id(material["public_bundle"], material["ciphertext"])
