from __future__ import annotations

from types import SimpleNamespace

import pytest

from avikal_backend.core.schemas import DecryptRequest
from avikal_backend.core.services import _enforce_creator_trust_policy


IDENTITY_ID = "a" * 64


def _session(kind: str = "persistent"):
    return SimpleNamespace(
        metadata={
            "archive_integrity": {
                "identity_id": IDENTITY_ID,
                "identity_kind": kind,
                "identity_trust": "valid_untrusted",
            }
        }
    )


def test_trusted_creator_is_applied_by_backend():
    session = _session()
    _enforce_creator_trust_policy(session, {IDENTITY_ID: "trusted"})
    assert session.metadata["archive_integrity"]["identity_trust"] == "trusted"


def test_revoked_creator_is_rejected_by_backend():
    with pytest.raises(ValueError, match="locally revoked"):
        _enforce_creator_trust_policy(_session(), {IDENTITY_ID: "revoked"})


def test_archive_scoped_identity_cannot_be_mislabeled_trusted():
    session = _session("archive")
    _enforce_creator_trust_policy(session, {IDENTITY_ID: "trusted"})
    assert session.metadata["archive_integrity"]["identity_trust"] == "archive_scoped"


def test_renderer_cannot_supply_invalid_creator_trust_policy():
    with pytest.raises(ValueError, match="invalid identity"):
        DecryptRequest(input_file="archive.avk", creator_trust_policy={"not-an-id": "trusted"})
