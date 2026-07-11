"""Core Time-Capsule security regressions."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

import pytest

from avikal_backend.archive.pipeline.progress import CancellationToken
from avikal_backend.core import aavrit_client, services
from avikal_backend.core.aavrit_client import AavritClientError, AavritEscrow
from avikal_backend.core.schemas import DecryptRequest, EncryptRequest


def _escrow_fixture() -> AavritEscrow:
    return AavritEscrow(
        time_key=bytes(range(32)),
        protected_metadata={
            "protocol": "aavrit",
            "escrow_id": "escrow-id",
            "data_commitment": "data-commitment",
            "release_key_commitment": "release-key-commitment",
            "authority_id": "authority-id",
            "receipt_sha256": "receipt-sha256",
        },
        public_route={
            "protocol": "aavrit",
            "server_url": "http://localhost:3000",
            "escrow_id": "escrow-id",
            "capability": "capability",
            "authority": {"authority_id": "authority-id"},
        },
    )


def test_core_aavrit_create_uses_random_escrowed_release_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "payload.txt"
    source.write_text("payload", encoding="utf-8")
    unlock_dt = datetime.now(timezone.utc) + timedelta(days=1)
    escrow = _escrow_fixture()

    monkeypatch.setattr(services, "_validate_unlock_datetime_against_ntp", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(services, "_fetch_aavrit_capabilities", lambda *_args, **_kwargs: {"mode": "public", "protocol": "aavrit"})
    monkeypatch.setattr(aavrit_client, "create_escrow", lambda *_args, **_kwargs: escrow)
    services._set_current_aavrit_server_url("http://localhost:3000")

    def fake_create_archive(*_args, **kwargs):
        assert kwargs["time_key"] == escrow.time_key
        assert kwargs["file_id"] == escrow.protected_metadata["escrow_id"]
        assert kwargs["aavrit_data_hash"] == escrow.protected_metadata["data_commitment"]
        assert kwargs["aavrit_commit_hash"] == escrow.protected_metadata["release_key_commitment"]
        assert kwargs["aavrit_server_key_id"] == escrow.protected_metadata["authority_id"]
        assert kwargs["aavrit_commit_signature"] == escrow.protected_metadata["receipt_sha256"]
        assert kwargs["aavrit_route"] == escrow.public_route
        return {"archive_type": "multi_file", "payload_format": "AVI1"}

    monkeypatch.setattr("avikal_backend.archive.pipeline.multi_file_encoder.create_multi_file_avk", fake_create_archive)
    request = EncryptRequest(
        input_files=[str(source)],
        output_file=str(tmp_path / "payload.avk"),
        password="CorrectHorseBatteryStaple!",
        use_timecapsule=True,
        timecapsule_provider="aavrit",
    )
    result = services._create_timecapsule_via_aavrit(request, None, unlock_dt)
    assert result["success"] is True
    assert result["aavrit"]["protocol"] == "aavrit"


def test_core_aavrit_create_propagates_fail_closed_client_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "payload.txt"
    source.write_text("payload", encoding="utf-8")
    unlock_dt = datetime.now(timezone.utc) + timedelta(days=1)
    monkeypatch.setattr(services, "_validate_unlock_datetime_against_ntp", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(services, "_fetch_aavrit_capabilities", lambda *_args, **_kwargs: {"mode": "public", "protocol": "aavrit"})
    monkeypatch.setattr(aavrit_client, "create_escrow", lambda *_args, **_kwargs: (_ for _ in ()).throw(AavritClientError("signature verification failed", status_code=400)))
    services._set_current_aavrit_server_url("http://localhost:3000")
    request = EncryptRequest(
        input_files=[str(source)], output_file=str(tmp_path / "payload.avk"),
        password="CorrectHorseBatteryStaple!", use_timecapsule=True, timecapsule_provider="aavrit",
    )
    with pytest.raises(services.ServiceError, match="signature verification failed"):
        services._create_timecapsule_via_aavrit(request, None, unlock_dt)


def test_core_aavrit_decrypt_verifies_protected_release_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    escrow = _escrow_fixture()
    metadata = {
        "file_id": "escrow-id",
        "aavrit_data_hash": "data-commitment",
        "aavrit_commit_hash": "release-key-commitment",
        "aavrit_server_key_id": "authority-id",
        "aavrit_commit_signature": "receipt-sha256",
        "unlock_timestamp": 1_900_000_000,
    }
    release = {"payload": {"receipt_sha256": "tampered"}, "signatures": {}}
    monkeypatch.setattr(services, "_read_avk_public_route", lambda *_args: ({}, {"time_key_gated": True, "unlock_timestamp": 1_900_000_000, "aavrit_route": escrow.public_route}))
    monkeypatch.setattr(aavrit_client, "release_escrow", lambda *_args, **_kwargs: (escrow.time_key, release))
    monkeypatch.setattr(services, "_read_avk_metadata_only", lambda *_args, **_kwargs: metadata)
    request = DecryptRequest(input_file="unused.avk", password="CorrectHorseBatteryStaple!")
    with pytest.raises(services.ServiceError, match="signed escrow receipt"):
        services._decrypt_timecapsule_via_aavrit(request, None)


def test_core_drand_decrypt_binds_stored_chain_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = {
        "timecapsule_provider": "drand", "drand_round": 12345, "drand_ciphertext": "ciphertext",
        "drand_chain_hash": "chain-hash", "drand_chain_url": "https://drand.example", "drand_beacon_id": "quicknet",
    }
    captured: dict = {}
    monkeypatch.setattr(services, "_enforce_system_clock_alignment", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(services, "_run_drand_helper", lambda payload: captured.update(payload) or {"success": True, "key_b_base64": "QQ=="})
    monkeypatch.setattr(services, "_decrypt_timecapsule_with_key", lambda *_args, **_kwargs: {"success": True})
    result = services._decrypt_timecapsule_via_drand(DecryptRequest(input_file="unused.avk", password="CorrectHorseBatteryStaple!"), metadata)
    assert result["success"] is True
    assert captured["expected_chain_hash"] == metadata["drand_chain_hash"]
    assert captured["expected_chain_url"] == metadata["drand_chain_url"]
    assert captured["expected_beacon_id"] == metadata["drand_beacon_id"]


def test_core_drand_helper_uses_bounded_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    helper = tmp_path / "drand_timelock_helper.mjs"
    helper.write_text("", encoding="utf-8")
    captured: dict[str, object] = {}

    class FakeStdin(StringIO):
        def close(self) -> None:
            captured["stdin"] = self.getvalue()
            super().close()

    class FakeProcess:
        def __init__(self, *_args, **_kwargs) -> None:
            self.stdin = FakeStdin()
            self.stdout = StringIO(json.dumps({"success": True, "key_b_base64": "QQ=="}))
            self.stderr = StringIO("")
            self.returncode = 0

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(services, "_find_node_binary", lambda: ("node", {}))
    monkeypatch.setattr(services, "drand_helper_path", lambda: helper)
    monkeypatch.setattr(services.subprocess, "Popen", FakeProcess)
    monkeypatch.delenv("AVIKAL_DRAND_HELPER_TIMEOUT_SECONDS", raising=False)
    result = services._run_drand_helper({"action": "open", "ciphertext": "abc", "round": 1})
    assert result["key_b_base64"] == "QQ=="
    assert json.loads(captured["stdin"])["action"] == "open"


def test_core_drand_helper_timeout_env_is_clamped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AVIKAL_DRAND_HELPER_TIMEOUT_SECONDS", "999")
    assert services._drand_helper_timeout_seconds() == 120
    monkeypatch.setenv("AVIKAL_DRAND_HELPER_TIMEOUT_SECONDS", "1")
    assert services._drand_helper_timeout_seconds() == 5


def test_preview_cancel_marks_all_active_decrypt_tokens() -> None:
    token_a = CancellationToken()
    token_b = CancellationToken()
    services._set_active_decrypt_token(token_a)
    services._set_active_decrypt_token(token_b)
    try:
        result = asyncio.run(services.preview_cancel({}))
        assert result["cancelled"] is True
        assert token_a.is_cancelled()
        assert token_b.is_cancelled()
    finally:
        services._clear_active_decrypt_token(token_a)
        services._clear_active_decrypt_token(token_b)
