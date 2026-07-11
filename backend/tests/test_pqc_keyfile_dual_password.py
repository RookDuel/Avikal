"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import pytest

from avikal_backend.archive.security.pqc_provider import PQC_SUITE_ID

from avikal_backend.archive.security.pqc_keyfile import (
    PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET,
    PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
    inspect_pqc_keyfile,
    read_pqc_keyfile,
    write_pqc_keyfile,
)


PRIVATE_BUNDLE = {"suite_id": PQC_SUITE_ID, "keys": {"private": "test-private"}}
PUBLIC_BUNDLE = {"suite_id": PQC_SUITE_ID, "keys": {"public": "test-public"}, "signatures": {"ml_dsa": "sig-a", "slh_dsa": "sig-b"}}
PQC_CIPHERTEXT = b"test-pqc-ciphertext"
ARCHIVE_PASSWORD = "ArchiveStrong1!"
KEYFILE_PASSWORD = "KeyfileStrong1!"


def test_normal_external_keyfile_compatibility(tmp_path):
    keyfile = tmp_path / "normal.avkkey"

    written = write_pqc_keyfile(
        str(keyfile),
        password=ARCHIVE_PASSWORD,
        keyphrase=None,
        private_bundle=PRIVATE_BUNDLE,
        public_bundle=PUBLIC_BUNDLE,
        pqc_ciphertext=PQC_CIPHERTEXT,
        archive_filename="archive.avk",
    )

    inspected = inspect_pqc_keyfile(str(keyfile))
    assert inspected["protection_mode"] == PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET
    assert inspected["requires_keyfile_password"] is False

    read = read_pqc_keyfile(
        str(keyfile),
        password=ARCHIVE_PASSWORD,
        keyphrase=None,
        expected_key_id=written["key_id"],
    )
    assert read["private_bundle"] == PRIVATE_BUNDLE
    assert read["public_bundle"] == PUBLIC_BUNDLE


def test_dual_password_keyfile_requires_outer_password(tmp_path):
    keyfile = tmp_path / "wrapped.avkkey"

    written = write_pqc_keyfile(
        str(keyfile),
        password=ARCHIVE_PASSWORD,
        keyphrase=None,
        private_bundle=PRIVATE_BUNDLE,
        public_bundle=PUBLIC_BUNDLE,
        pqc_ciphertext=PQC_CIPHERTEXT,
        archive_filename="archive.avk",
        protection_mode=PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
        keyfile_password=KEYFILE_PASSWORD,
    )

    inspected = inspect_pqc_keyfile(str(keyfile))
    assert inspected["protection_mode"] == PQC_KEYFILE_PROTECTION_DUAL_PASSWORD
    assert inspected["requires_keyfile_password"] is True

    with pytest.raises(ValueError, match="requires its keyfile password"):
        read_pqc_keyfile(
            str(keyfile),
            password=ARCHIVE_PASSWORD,
            keyphrase=None,
            expected_key_id=written["key_id"],
        )

    with pytest.raises(ValueError, match="Incorrect \\.avkkey password"):
        read_pqc_keyfile(
            str(keyfile),
            password=ARCHIVE_PASSWORD,
            keyphrase=None,
            expected_key_id=written["key_id"],
            pqc_keyfile_password="WrongKeyfile1!",
        )

    read = read_pqc_keyfile(
        str(keyfile),
        password=ARCHIVE_PASSWORD,
        keyphrase=None,
        expected_key_id=written["key_id"],
        pqc_keyfile_password=KEYFILE_PASSWORD,
    )
    assert read["private_bundle"] == PRIVATE_BUNDLE


def test_dual_password_then_wrong_archive_secret_still_fails_inner_unlock(tmp_path):
    keyfile = tmp_path / "wrapped.avkkey"
    written = write_pqc_keyfile(
        str(keyfile),
        password=ARCHIVE_PASSWORD,
        keyphrase=None,
        private_bundle=PRIVATE_BUNDLE,
        public_bundle=PUBLIC_BUNDLE,
        pqc_ciphertext=PQC_CIPHERTEXT,
        archive_filename="archive.avk",
        protection_mode=PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
        keyfile_password=KEYFILE_PASSWORD,
    )

    with pytest.raises(ValueError, match="Failed to decrypt the PQC keyfile"):
        read_pqc_keyfile(
            str(keyfile),
            password="WrongArchive1!",
            keyphrase=None,
            expected_key_id=written["key_id"],
            pqc_keyfile_password=KEYFILE_PASSWORD,
        )


def test_dual_password_preserves_leading_and_trailing_spaces(tmp_path):
    keyfile = tmp_path / "space-sensitive.avkkey"
    space_sensitive_password = "  KeyfileStrong1!  "
    written = write_pqc_keyfile(
        str(keyfile),
        password=ARCHIVE_PASSWORD,
        keyphrase=None,
        private_bundle=PRIVATE_BUNDLE,
        public_bundle=PUBLIC_BUNDLE,
        pqc_ciphertext=PQC_CIPHERTEXT,
        archive_filename="archive.avk",
        protection_mode=PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
        keyfile_password=space_sensitive_password,
    )

    read = read_pqc_keyfile(
        str(keyfile),
        password=ARCHIVE_PASSWORD,
        keyphrase=None,
        expected_key_id=written["key_id"],
        pqc_keyfile_password=space_sensitive_password,
    )
    assert read["private_bundle"] == PRIVATE_BUNDLE

    with pytest.raises(ValueError, match="Incorrect \\.avkkey password"):
        read_pqc_keyfile(
            str(keyfile),
            password=ARCHIVE_PASSWORD,
            keyphrase=None,
            expected_key_id=written["key_id"],
            pqc_keyfile_password=space_sensitive_password.strip(),
        )
