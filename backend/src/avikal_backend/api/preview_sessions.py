"""Preview-session directory lifecycle management."""

from __future__ import annotations

import logging
from pathlib import Path
import shutil
import threading
import uuid


class PreviewSessionStore:
    def __init__(self, root: Path, log: logging.Logger):
        self.root = root
        self.log = log
        self._lock = threading.Lock()
        self._active_sessions: set[str] = set()

    def cleanup_stale(self) -> None:
        try:
            for entry in self.root.iterdir():
                if entry.is_dir():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    try:
                        entry.unlink()
                    except OSError as exc:
                        self.log.debug("Failed to remove stale preview file %s: %s", entry, exc)
        except OSError as exc:
            self.log.warning("Failed to cleanup stale preview sessions: %s", exc)

    def create(self) -> tuple[str, str]:
        session_id = uuid.uuid4().hex
        session_dir = self.root / session_id
        session_dir.mkdir(parents=True, exist_ok=False)
        with self._lock:
            self._active_sessions.add(session_id)
        return session_id, str(session_dir)

    def cleanup(self, session_id: str) -> bool:
        if not session_id:
            return False

        session_dir = self.root / session_id
        existed = session_dir.exists()
        shutil.rmtree(session_dir, ignore_errors=True)
        with self._lock:
            self._active_sessions.discard(session_id)
        return existed

    def cleanup_all(self) -> int:
        cleaned = 0
        try:
            for entry in list(self.root.iterdir()):
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
            self.log.warning("Failed to cleanup preview sessions: %s", exc)
        with self._lock:
            self._active_sessions.clear()
        return cleaned
