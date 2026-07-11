"""Security tests for the active stdio core preview-session store."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from avikal_backend.core.preview_sessions import PreviewSessionStore


def test_preview_session_cleanup_rejects_path_escape(tmp_path: Path):
    store = PreviewSessionStore(tmp_path / "preview", logging.getLogger("preview-test"))
    store.root.mkdir(parents=True)

    with pytest.raises(ValueError, match="invalid"):
        store.cleanup("../outside")


def test_preview_session_cleanup_only_removes_active_ids(tmp_path: Path):
    store = PreviewSessionStore(tmp_path / "preview", logging.getLogger("preview-test"))
    store.root.mkdir(parents=True)

    session_id, _session_dir = store.create()
    assert store.cleanup(session_id) is True
    assert store.cleanup(session_id) is False
    assert store.cleanup("0" * 32) is False


def test_preview_session_create_falls_back_when_primary_root_is_unwritable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    primary_root = tmp_path / "primary-preview"
    fallback_root = tmp_path / "fallback-preview"
    primary_root.mkdir()
    fallback_root.mkdir()
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
