"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import uuid

from avikal_backend.api import server as api_server
import pytest

from avikal_backend.api.errors import friendly_error
from avikal_backend.mnemonic.generator import generate_mnemonic
from avikal_backend.archive.pipeline import encoder as encoder_enhanced, multi_file_encoder
from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk


PASSWORD = "AvikalStrongPass!9Zeta"


@contextmanager
def _workspace_tempdir():
    base = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    base.mkdir(exist_ok=True)
    temp_path = base / f"run_{uuid.uuid4().hex}"
    temp_path.mkdir()
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


def _single_folder_request(folder_path: Path, output_path: Path) -> api_server.EncryptRequest:
    return api_server.EncryptRequest(
        input_files=[str(folder_path)],
        output_file=str(output_path),
        password=PASSWORD,
        use_timecapsule=False,
    )


def test_single_folder_regular_encryption_roundtrip():
    with _workspace_tempdir() as temp_dir:
        source_folder = temp_dir / "Folder1"
        nested_dir = source_folder / "nested"
        nested_dir.mkdir(parents=True)

        alpha = source_folder / "alpha.txt"
        beta = nested_dir / "beta.bin"
        alpha.write_text("folder routing regression\n", encoding="utf-8")
        beta.write_bytes(b"\x00\x01\x02\x03" * 32)

        archive_path = temp_dir / "folder_only.avk"
        output_dir = temp_dir / "out"
        output_dir.mkdir()

        request = _single_folder_request(source_folder, archive_path)

        result = api_server.create_regular_encryption(request, datetime.now())
        assert result["success"] is True

        extracted = extract_multi_file_avk(
            avk_filepath=str(archive_path),
            output_directory=str(output_dir),
            password=PASSWORD,
        )

        restored = {
            Path(entry["path"]).relative_to(output_dir).as_posix(): Path(entry["path"]).read_bytes()
            for entry in extracted["files"]
        }
        assert restored == {
            "Folder1/alpha.txt": alpha.read_bytes(),
            "Folder1/nested/beta.bin": beta.read_bytes(),
        }


def test_single_file_regular_encryption_stays_on_single_file_path(monkeypatch: pytest.MonkeyPatch):
    called = {"single": False}

    def fake_single_file(*args, **kwargs):
        called["single"] = True
        return {"path": kwargs["output_filepath"]}

    def fail_multi_file(*args, **kwargs):
        raise AssertionError("single-file request should not use multi-file encoder")

    monkeypatch.setattr(encoder_enhanced, "create_avk_file", fake_single_file)
    monkeypatch.setattr(multi_file_encoder, "create_multi_file_avk", fail_multi_file)

    with _workspace_tempdir() as temp_dir:
        payload = temp_dir / "single.txt"
        payload.write_text("single file\n", encoding="utf-8")
        archive_path = temp_dir / "single.avk"
        request = api_server.EncryptRequest(
            input_files=[str(payload)],
            output_file=str(archive_path),
            password=PASSWORD,
            use_timecapsule=False,
        )

        result = api_server.create_regular_encryption(request, datetime.now())
        assert result["success"] is True
        assert called["single"] is True


def test_single_folder_drand_timecapsule_routes_to_multi_file_encoder(monkeypatch: pytest.MonkeyPatch):
    called = {"multi": False}

    def fake_multi_file(*args, **kwargs):
        called["multi"] = True
        assert kwargs["input_filepaths"]
        return {"archive_type": "multi_file"}

    def fail_single_file(*args, **kwargs):
        raise AssertionError("single-folder drand request should not use single-file encoder")

    monkeypatch.setattr(api_server, "validate_unlock_datetime_against_ntp", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api_server, "generate_key_b", lambda: b"\x01" * 32)
    monkeypatch.setattr(
        api_server,
        "run_drand_helper",
        lambda payload: {
            "round": 123,
            "chain_hash": "hash",
            "chain_url": "https://example.invalid",
            "ciphertext": "ciphertext",
            "beacon_id": "default",
            "round_unlock_iso": "2030-01-01T00:00:00Z",
        },
    )
    monkeypatch.setattr(multi_file_encoder, "create_multi_file_avk", fake_multi_file)
    monkeypatch.setattr(encoder_enhanced, "create_avk_file", fail_single_file)

    with _workspace_tempdir() as temp_dir:
        folder = temp_dir / "Folder1"
        folder.mkdir()
        (folder / "inside.txt").write_text("drand folder\n", encoding="utf-8")
        archive_path = temp_dir / "folder_only.avk"
        request = _single_folder_request(folder, archive_path)
        request.use_timecapsule = True
        request.timecapsule_provider = "drand"

        result = api_server.create_timecapsule_via_drand(
            request,
            datetime.now() + timedelta(days=1),
        )

        assert result["success"] is True
        assert result["provider"] == "drand"
        assert called["multi"] is True


def test_single_folder_aavrit_timecapsule_routes_to_multi_file_encoder(monkeypatch: pytest.MonkeyPatch):
    called = {"multi": False}

    def fake_multi_file(*args, **kwargs):
        called["multi"] = True
        assert kwargs["input_filepaths"]
        return {"archive_type": "multi_file"}

    def fail_single_file(*args, **kwargs):
        raise AssertionError("single-folder Aavrit request should not use single-file encoder")

    monkeypatch.setattr(api_server, "validate_unlock_datetime_against_ntp", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api_server, "current_aavrit_server_url", "http://localhost:3000")
    monkeypatch.setattr(api_server, "require_aavrit_auth_if_needed", lambda *_args, **_kwargs: {"mode": "private"})
    monkeypatch.setattr(api_server, "create_aavrit_data_hash", lambda: "aavrit-data-hash")
    def fake_request_aavrit_commit(_aavrit_url, *, data_hash, unlock_timestamp, session_token):
        assert session_token == "test-jwt"
        return {
            "payload": {
                "version": 1,
                "commit_id": "8d3c44be-11cc-4b4a-82bc-cf268f3e4e1a",
                "data_hash": data_hash,
                "unlock_timestamp": unlock_timestamp,
                "commit_hash": "aavrit-commit-hash",
                "hash_alg": "SHA-256",
                "sig_alg": "Ed25519",
                "server_key_id": "test-key",
            },
            "signature": "aavrit-commit-signature",
        }

    monkeypatch.setattr(api_server, "request_aavrit_commit", fake_request_aavrit_commit)
    monkeypatch.setattr(
        api_server,
        "fetch_aavrit_public_key",
        lambda *_args, **_kwargs: {"public_key_pem": "unused", "key_id": "test-key", "sig_alg": "Ed25519"},
    )
    monkeypatch.setattr(api_server, "verify_aavrit_signature", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(api_server, "derive_aavrit_time_key", lambda *_args, **_kwargs: b"\x02" * 32)
    monkeypatch.setattr(multi_file_encoder, "create_multi_file_avk", fake_multi_file)
    monkeypatch.setattr(encoder_enhanced, "create_avk_file", fail_single_file)

    with _workspace_tempdir() as temp_dir:
        folder = temp_dir / "Folder1"
        folder.mkdir()
        (folder / "inside.txt").write_text("aavrit folder\n", encoding="utf-8")
        archive_path = temp_dir / "folder_only.avk"
        request = _single_folder_request(folder, archive_path)
        request.use_timecapsule = True
        request.timecapsule_provider = "aavrit"

        result = api_server.create_timecapsule_via_aavrit(
            request,
            "test-jwt",
            datetime.now() + timedelta(days=1),
        )

        assert result["success"] is True
        assert result["result"]["archive_type"] == "multi_file"
        assert called["multi"] is True


def test_timecapsule_rejects_wrong_provider_unlock_key_before_write():
    metadata = {
        "filename": "payload.txt",
        "time_key_hash": b"\x11" * 32,
    }
    request = api_server.DecryptRequest(
        input_file="unused.avk",
        output_dir="out",
    )

    with pytest.raises(api_server.HTTPException, match="Provider unlock key verification failed"):
        api_server.decrypt_timecapsule_with_key(request, metadata, b"\x22" * 32, "aavrit")


def test_copy_file_endpoint_is_not_exposed():
    registered_paths = {route.path for route in api_server.app.routes}
    assert "/api/copy-file" not in registered_paths


def test_default_cors_origins_do_not_allow_null_origin():
    assert "null" not in api_server.DEFAULT_ALLOWED_CORS_ORIGINS


def test_decrypt_request_allows_blank_preview_output_dir():
    request = api_server.DecryptRequest(
        input_file="example.avk",
        output_dir="",
    )
    assert request.output_dir is None


def test_validation_error_details_are_flattened_to_text():
    detail = api_server._flatten_validation_detail(
        [
            {"type": "string_too_short", "loc": ("body", "input_file"), "msg": "String should have at least 1 character"},
            {"type": "string_too_short", "loc": ("body", "output_dir"), "msg": "String should have at least 1 character"},
        ]
    )

    assert isinstance(detail, str)
    assert "input_file" in detail
    assert "output_dir" in detail


def test_public_route_tags_are_written_for_new_archives():
    with _workspace_tempdir() as temp_dir:
        payload = temp_dir / "payload.txt"
        payload.write_text("route tags\n", encoding="utf-8")
        archive_path = temp_dir / "route_tags.avk"
        request = api_server.EncryptRequest(
            input_files=[str(payload)],
            output_file=str(archive_path),
            password=PASSWORD,
            keyphrase=generate_mnemonic(21).split(),
            use_timecapsule=False,
        )

        result = api_server.create_regular_encryption(request, datetime.now())
        assert result["success"] is True

        header_info, route_hints = api_server.read_avk_public_route(str(archive_path))
        assert header_info["provider"] is None
        assert route_hints["available"] is True
        assert route_hints["archive_type"] == "single_file"
        assert route_hints["requires_password"] is True
        assert route_hints["requires_keyphrase"] is True
        assert route_hints["requires_pqc"] is False
        assert route_hints["keyphrase_wordlist_id"]


def test_inspect_archive_uses_public_route_hints_only(monkeypatch: pytest.MonkeyPatch):
    archive_path = Path(__file__).resolve()

    monkeypatch.setattr(api_server, "validate_avk_structure", lambda _path: None)
    monkeypatch.setattr(
        api_server,
        "read_avk_public_route",
        lambda _path: (
            {"provider": "drand", "archive_mode": 0x02},
            {
                "available": True,
                "provider": "drand",
                "archive_type": "multi_file",
                "requires_password": True,
                "requires_keyphrase": True,
                "requires_pqc": True,
                "unlock_timestamp": 1893456000,
                "drand_round": 424242,
                "keyphrase_wordlist_id": "hi2048-v1",
            },
        ),
    )

    def fail_metadata_read(*_args, **_kwargs):
        raise AssertionError("inspect should not decode protected metadata")

    monkeypatch.setattr(api_server, "read_avk_metadata_only", fail_metadata_read)

    from avikal_backend.api import routes as api_routes

    response = asyncio.run(api_routes.inspect_archive(api_server.ArchiveInspectRequest(input_file=str(archive_path))))
    assert response["success"] is True
    assert response["archive"] == {
        "provider": "drand",
        "archive_type": "multi_file",
        "metadata_accessible": True,
        "metadata_requires_secret": False,
        "password_hint": True,
        "keyphrase_hint": True,
        "pqc_required": True,
        "unlock_timestamp": 1893456000,
        "drand_round": 424242,
        "keyphrase_wordlist_id": "hi2048-v1",
    }


def test_decrypt_fast_fails_for_missing_pqc_keyfile(monkeypatch: pytest.MonkeyPatch):
    archive_path = Path(__file__).resolve()

    monkeypatch.setattr(
        api_server,
        "read_avk_public_route",
        lambda _path: (
            {"provider": None, "archive_mode": 0x01},
            {
                "available": True,
                "provider": None,
                "archive_type": "single_file",
                "requires_password": False,
                "requires_keyphrase": False,
                "requires_pqc": True,
            },
        ),
    )

    def fail_metadata_read(*_args, **_kwargs):
        raise AssertionError("missing .avkkey should fail before protected metadata decode")

    monkeypatch.setattr(api_server, "read_avk_metadata_only", fail_metadata_read)

    from avikal_backend.api import routes as api_routes

    request = api_server.DecryptRequest(input_file=str(archive_path), output_dir="")
    with pytest.raises(api_server.HTTPException, match="matching .avkkey file"):
        asyncio.run(api_routes.decrypt_file(request))


def test_decrypt_fast_fails_for_locked_drand_capsule(monkeypatch: pytest.MonkeyPatch):
    archive_path = Path(__file__).resolve()
    future_unlock = int(datetime.now(timezone.utc).timestamp()) + 3600

    monkeypatch.setattr(
        api_server,
        "read_avk_public_route",
        lambda _path: (
            {"provider": "drand", "archive_mode": 0x01},
            {
                "available": True,
                "provider": "drand",
                "archive_type": "single_file",
                "requires_password": False,
                "requires_keyphrase": False,
                "requires_pqc": False,
                "unlock_timestamp": future_unlock,
            },
        ),
    )
    monkeypatch.setattr("avikal_backend.archive.security.time_lock.get_trusted_now", lambda: datetime.now(timezone.utc))

    def fail_metadata_read(*_args, **_kwargs):
        raise AssertionError("locked capsule should fail before protected metadata decode")

    monkeypatch.setattr(api_server, "read_avk_metadata_only", fail_metadata_read)

    from avikal_backend.api import routes as api_routes

    request = api_server.DecryptRequest(input_file=str(archive_path), output_dir="")
    with pytest.raises(api_server.HTTPException, match="still locked"):
        asyncio.run(api_routes.decrypt_file(request))


def test_drand_decrypt_reuses_preloaded_metadata(monkeypatch: pytest.MonkeyPatch):
    archive_path = Path(__file__).resolve()
    metadata = {
        "filename": "payload.txt",
        "drand_round": 123,
        "drand_ciphertext": "ciphertext",
        "time_key_hash": b"\x11" * 32,
        "archive_type": "single_file",
    }
    state = {"metadata_reads": 0}

    monkeypatch.setattr(
        api_server,
        "read_avk_public_route",
        lambda _path: (
            {"provider": "drand", "archive_mode": 0x01},
            {
                "available": True,
                "provider": "drand",
                "archive_type": "single_file",
                "requires_password": False,
                "requires_keyphrase": False,
                "requires_pqc": False,
            },
        ),
    )

    def fake_read_metadata(*_args, **_kwargs):
        state["metadata_reads"] += 1
        return metadata

    monkeypatch.setattr(api_server, "read_avk_metadata_only", fake_read_metadata)
    monkeypatch.setattr(api_server, "decrypt_timecapsule_via_drand", lambda request, provided_metadata=None: {"success": True, "metadata": provided_metadata})

    from avikal_backend.api import routes as api_routes

    request = api_server.DecryptRequest(input_file=str(archive_path), output_dir="")
    result = asyncio.run(api_routes.decrypt_file(request))

    assert result["success"] is True
    assert result["metadata"] is metadata
    assert state["metadata_reads"] == 1


def test_friendly_error_maps_wrong_key_metadata_failures():
    message = friendly_error("Metadata decoding failed: Chess metadata decryption failed: Decryption failed - data corrupted or wrong key")
    assert message == "Incorrect password or keyphrase. Please check and try again."


def test_friendly_error_maps_preview_workspace_failures():
    message = friendly_error(r"[WinError 5] Access is denied: 'C:\\Users\\obara\\.avikal\\preview_sessions\\abc123'")
    assert "preview workspace" in message.lower()


def test_friendly_error_maps_system_clock_skew():
    message = friendly_error("System clock differs from NTP time by 61 minutes. Please synchronize your system clock.")
    assert "system clock" in message.lower()
    assert "windows date and time" in message.lower()


def test_drand_decrypt_rejects_large_system_clock_skew(monkeypatch: pytest.MonkeyPatch):
    metadata = {
        "filename": "payload.txt",
        "drand_round": 123,
        "drand_ciphertext": "ciphertext",
        "time_key_hash": b"\x11" * 32,
        "archive_type": "single_file",
    }
    request = api_server.DecryptRequest(input_file="locked.avk", output_dir="")

    monkeypatch.setattr(api_server, "get_clock_skew_warning", lambda: "System clock differs from NTP time by 61 minutes.")
    monkeypatch.setattr(
        api_server,
        "run_drand_helper",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("drand helper should not run when local clock is clearly out of sync")),
    )

    with pytest.raises(api_server.HTTPException) as exc_info:
        api_server.decrypt_timecapsule_via_drand(request, metadata)

    assert exc_info.value.status_code == 400
    assert "system clock" in exc_info.value.detail.lower()


def test_timecapsule_single_file_wrong_secret_returns_user_error(monkeypatch: pytest.MonkeyPatch):
    preview_dir = Path.cwd() / "preview-test-output"
    monkeypatch.setattr(api_server, "_create_preview_session_dir", lambda: ("preview-session", str(preview_dir)))
    monkeypatch.setattr(api_server, "_cleanup_preview_session", lambda _session_id: True)
    monkeypatch.setattr("avikal_backend.archive.security.crypto.verify_time_key_hash", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        "avikal_backend.archive.pipeline.decoder.extract_avk_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("Wrapped payload key could not be unlocked")),
    )

    request = api_server.DecryptRequest(input_file="locked.avk", output_dir="")
    metadata = {
        "filename": "payload.txt",
        "salt": b"\x06" * 32,
        "checksum": b"\x07" * 32,
        "wrapped_payload_key": b"\x08" * 64,
        "time_key_hash": b"\x09" * 32,
        "encryption_method": "aes256gcm_stream",
    }

    with pytest.raises(api_server.HTTPException) as exc_info:
        api_server.decrypt_timecapsule_with_key(request, metadata, b"\x0A" * 32, "drand")

    assert exc_info.value.status_code == 400
    assert "provided protections" in exc_info.value.detail.lower()


def test_timecapsule_single_file_delegates_to_shared_decoder(monkeypatch: pytest.MonkeyPatch):
    with _workspace_tempdir() as temp_dir:
        preview_dir = temp_dir / "preview"
        preview_dir.mkdir()
        output_file = preview_dir / "payload.txt"
        output_file.write_text("ready", encoding="utf-8")
        calls: dict[str, object] = {}

        monkeypatch.setattr(api_server, "_create_preview_session_dir", lambda: ("preview-session", str(preview_dir)))
        monkeypatch.setattr(api_server, "_cleanup_preview_session", lambda _session_id: True)
        monkeypatch.setattr("avikal_backend.archive.security.crypto.verify_time_key_hash", lambda *_args, **_kwargs: True)

        def fake_extract(*, avk_filepath, output_directory, password=None, keyphrase=None, pqc_keyfile_path=None, time_key=None, metadata_override=None):
            calls["avk_filepath"] = avk_filepath
            calls["output_directory"] = output_directory
            calls["password"] = password
            calls["keyphrase"] = keyphrase
            calls["pqc_keyfile_path"] = pqc_keyfile_path
            calls["time_key"] = time_key
            calls["metadata_override"] = metadata_override
            return str(output_file)

        monkeypatch.setattr("avikal_backend.archive.pipeline.decoder.extract_avk_file", fake_extract)

        metadata = {
            "filename": "payload.txt",
            "salt": b"\x06" * 32,
            "checksum": b"\x07" * 32,
            "time_key_hash": b"\x09" * 32,
            "encryption_method": "aes256gcm_stream",
        }
        request = api_server.DecryptRequest(
            input_file="locked.avk",
            output_dir="",
            password="correct-password",
            keyphrase=["एक"] * 21,
            pqc_keyfile="capsule.avkkey",
        )

        result = api_server.decrypt_timecapsule_with_key(request, metadata, b"\x0A" * 32, "drand")

        assert result["success"] is True
        assert result["output_file"] == str(output_file)
        assert result["result"]["file_count"] == 1
        assert calls["avk_filepath"] == "locked.avk"
        assert calls["output_directory"] == str(preview_dir)
        assert calls["password"] == "correct-password"
        assert calls["keyphrase"] == ["एक"] * 21
        assert calls["pqc_keyfile_path"] == "capsule.avkkey"
        assert calls["time_key"] == b"\x0A" * 32
        assert calls["metadata_override"] is metadata
