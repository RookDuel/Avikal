"""Preview-session directory lifecycle management."""

from __future__ import annotations

import logging
from pathlib import Path
import shutil
import tempfile
import threading
import uuid


class PreviewSessionStore:
    def __init__(self, root: Path, log: logging.Logger, fallback_root: Path | None = None):
        self.root = root.resolve()
        self.fallback_root = (
            fallback_root.resolve()
            if fallback_root is not None
            else (Path(tempfile.gettempdir()) / "avikal-runtime" / "preview_sessions").resolve()
        )
        self.log = log
        self._lock = threading.Lock()
        self._active_sessions: set[str] = set()
        self._session_roots: dict[str, Path] = {}

    def _resolve_session_dir(self, session_id: str, root: Path | None = None) -> Path:
        if not isinstance(session_id, str):
            raise ValueError("Preview session id must be a string")

        candidate = session_id.strip().lower()
        if len(candidate) != 32 or any(ch not in "0123456789abcdef" for ch in candidate):
            raise ValueError("Preview session id is invalid")

        root_path = (root or self.root).resolve()
        session_dir = (root_path / candidate).resolve()
        if session_dir.parent != root_path:
            raise ValueError("Preview session path escapes the preview root")
        return session_dir

    def _candidate_roots(self) -> list[Path]:
        candidates: list[Path] = []
        for root in (self.root, self.fallback_root):
            resolved = root.resolve()
            if resolved not in candidates:
                candidates.append(resolved)
        return candidates

    def cleanup_stale(self) -> None:
        for root in self._candidate_roots():
            try:
                if not root.exists():
                    continue
                for entry in root.iterdir():
                    if entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=True)
                    else:
                        try:
                            entry.unlink()
                        except OSError as exc:
                            self.log.debug("Failed to remove stale preview file %s: %s", entry, exc)
            except OSError as exc:
                self.log.warning("Failed to cleanup stale preview sessions in %s: %s", root, exc)

    def create(self) -> tuple[str, str]:
        session_id = uuid.uuid4().hex
        roots = self._candidate_roots()
        last_error: OSError | None = None

        for root in roots:
            session_dir = self._resolve_session_dir(session_id, root)
            try:
                root.mkdir(parents=True, exist_ok=True)
                session_dir.mkdir(parents=True, exist_ok=False)
            except OSError as exc:
                last_error = exc
                if root != self.fallback_root:
                    self.log.warning(
                        "Primary preview-session root %s is unavailable (%s). Falling back to %s",
                        root,
                        exc,
                        self.fallback_root,
                    )
                    self.root = self.fallback_root
                continue

            with self._lock:
                self._active_sessions.add(session_id)
                self._session_roots[session_id] = root
            self.root = root
            return session_id, str(session_dir)

        if last_error is not None:
            raise last_error
        raise OSError("Preview session storage is unavailable")

    def cleanup(self, session_id: str) -> bool:
        if not session_id:
            return False

        # Validate caller-supplied session IDs before consulting the active set.
        self._resolve_session_dir(session_id, self.root)
        with self._lock:
            if session_id not in self._active_sessions:
                return False
            session_root = self._session_roots.get(session_id, self.root)

        session_dir = self._resolve_session_dir(session_id, session_root)

        existed = session_dir.exists()
        shutil.rmtree(session_dir, ignore_errors=True)
        with self._lock:
            self._active_sessions.discard(session_id)
            self._session_roots.pop(session_id, None)
        return existed

    def cleanup_all(self) -> int:
        cleaned = 0
        roots = self._candidate_roots()
        with self._lock:
            roots.extend(root.resolve() for root in self._session_roots.values())
        seen: list[Path] = []
        for root in roots:
            resolved = root.resolve()
            if resolved in seen or not resolved.exists():
                continue
            seen.append(resolved)
            try:
                for entry in list(resolved.iterdir()):
                    if entry.exists():
                        cleaned += 1
                        if entry.is_dir():
                            shutil.rmtree(entry, ignore_errors=True)
                        else:
                            try:
                                entry.unlink()
                            except OSError as exc:
                                self.log.debug("Failed to remove preview session file %s: %s", entry, exc)
            except OSError as exc:
                self.log.warning("Failed to cleanup preview sessions in %s: %s", resolved, exc)
        with self._lock:
            self._active_sessions.clear()
            self._session_roots.clear()
        return cleaned
