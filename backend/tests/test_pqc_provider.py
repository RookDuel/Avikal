"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import pytest

from avikal_backend.archive.security.pqc_provider import (
    PQC_SUITE_ID,
    _candidate_openssl_paths,
    _openssl_binary_name,
    compute_pqc_key_id,
    create_pqc_archive_material,
    decapsulate_pqc_archive_material,
    provider_status,
)


def test_openssl_binary_name_is_platform_specific():
    assert _openssl_binary_name("win32") == "openssl.exe"
    assert _openssl_binary_name("linux") == "openssl"
    assert _openssl_binary_name("darwin") == "openssl"


def test_candidate_paths_honor_configured_pqc_runtime_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("AVIKAL_PQC_RUNTIME_DIR", str(tmp_path))
    paths = _candidate_openssl_paths()

    expected_binary = _openssl_binary_name()
    assert tmp_path / "bin" / expected_binary in paths
    assert tmp_path / expected_binary in paths


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
    assert material["suite"]["algorithms"]["kem"] == "ML-KEM-1024+X25519"
    assert material["public_bundle"]["keys"]["x25519_public_pem"]
    assert material["private_bundle"]["keys"]["x25519_private_pem"]
