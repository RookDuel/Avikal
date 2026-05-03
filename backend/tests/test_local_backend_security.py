"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import contextmanager
from pathlib import Path
import shutil
import uuid

import pytest
from starlette.requests import Request

from avikal_backend.api import server as api_server
from avikal_backend.api.preview_sessions import PreviewSessionStore
from avikal_backend.api import runtime as api_runtime
from avikal_backend.services import ntp_service
from avikal_backend.api import drand as drand_api


@contextmanager
def _workspace_tempdir():
    base = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    base.mkdir(exist_ok=True)
    temp_path = base / f"security_{uuid.uuid4().hex}"
    temp_path.mkdir()
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


def test_backend_token_is_required_for_non_health_routes(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(api_server, "_BACKEND_AUTH_TOKEN", "test-backend-token")

    async def fake_next(_request: Request):
        return api_server.JSONResponse({"ok": True}, status_code=200)

    denied_request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/security/settings",
            "headers": [],
        }
    )
    denied_response = asyncio.run(api_server.require_backend_token(denied_request, fake_next))
    assert denied_response.status_code == 401

    health_request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/health",
            "headers": [],
        }
    )
    health_response = asyncio.run(api_server.require_backend_token(health_request, fake_next))
    assert health_response.status_code == 200

    allowed_request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/security/settings",
            "headers": [
                (api_server.BACKEND_AUTH_HEADER.lower().encode("ascii"), b"test-backend-token"),
            ],
        }
    )
    allowed_response = asyncio.run(api_server.require_backend_token(allowed_request, fake_next))
    assert allowed_response.status_code == 200


def test_preview_session_cleanup_rejects_path_escape():
    with _workspace_tempdir() as temp_dir:
        store = PreviewSessionStore(temp_dir / "preview", logging.getLogger("preview-test"))
        store.root.mkdir(parents=True, exist_ok=True)

        with pytest.raises(ValueError, match="invalid"):
            store.cleanup("../outside")


def test_preview_session_cleanup_only_removes_active_ids():
    with _workspace_tempdir() as temp_dir:
        store = PreviewSessionStore(temp_dir / "preview", logging.getLogger("preview-test"))
        store.root.mkdir(parents=True, exist_ok=True)

        session_id, _session_dir = store.create()
        assert store.cleanup(session_id) is True
        assert not store.cleanup(session_id)
        assert not store.cleanup("0" * 32)


def test_preview_session_create_falls_back_when_primary_root_is_unwritable(monkeypatch: pytest.MonkeyPatch):
    with _workspace_tempdir() as temp_dir:
        primary_root = temp_dir / "primary-preview"
        fallback_root = temp_dir / "fallback-preview"
        primary_root.mkdir(parents=True, exist_ok=True)
        fallback_root.mkdir(parents=True, exist_ok=True)

        store = PreviewSessionStore(primary_root, logging.getLogger("preview-test"), fallback_root=fallback_root)
        real_mkdir = Path.mkdir

        def fake_mkdir(path_self: Path, *args, **kwargs):
            if path_self == primary_root or primary_root in path_self.parents:
                raise PermissionError("primary preview root is read-only")
            return real_mkdir(path_self, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fake_mkdir)

        session_id, session_dir = store.create()
        session_path = Path(session_dir)

        assert session_path.parent == fallback_root.resolve()
        assert session_path.exists()
        assert store.cleanup(session_id) is True
        assert not session_path.exists()


def test_runtime_paths_fall_back_when_preview_root_probe_fails(monkeypatch: pytest.MonkeyPatch):
    with _workspace_tempdir() as temp_dir:
        primary_dir = temp_dir / "primary-user-data"
        fallback_base = temp_dir / "fallback-temp"
        primary_dir.mkdir(parents=True, exist_ok=True)
        fallback_base.mkdir(parents=True, exist_ok=True)

        monkeypatch.setenv("AVIKAL_USER_DATA_DIR", str(primary_dir))
        monkeypatch.setattr(api_runtime.tempfile, "gettempdir", lambda: str(fallback_base))

        def fake_probe(path: Path) -> None:
            if primary_dir in path.parents:
                raise PermissionError("preview root is not writable")

        monkeypatch.setattr(api_runtime, "_probe_preview_root_writable", fake_probe)

        runtime_paths, warning = api_runtime.initialise_runtime_paths()

        assert runtime_paths.preview_session_root == (fallback_base / "avikal-runtime" / "preview_sessions")
        assert warning is not None
        assert "using" in warning.lower()


def test_startup_warms_runtime_helpers(monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []

    monkeypatch.setattr(api_server, "_cleanup_stale_preview_sessions_in_background", lambda: calls.append("cleanup"))
    monkeypatch.setattr(ntp_service, "prime_ntp_cache_async", lambda: calls.append("ntp"))
    monkeypatch.setattr(drand_api, "prime_drand_helper_async", lambda: calls.append("drand"))

    asyncio.run(api_server.schedule_preview_session_cleanup())
    assert calls == ["cleanup", "ntp", "drand"]
