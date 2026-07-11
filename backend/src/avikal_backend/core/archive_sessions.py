"""Process-local authenticated archive browsing sessions."""

from __future__ import annotations

import os
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from avikal_backend.archive.format.container import open_avk_payload_stream
from avikal_backend.archive.format.indexed_payload import extract_indexed_selection
from avikal_backend.archive.pipeline.multi_file_decoder import open_indexed_archive_metadata
from avikal_backend.archive.security.crypto import secure_zero


SESSION_IDLE_SECONDS = 15 * 60
MAX_SESSIONS = 8


@dataclass
class ArchiveSession:
    session_id: str
    archive_path: str
    archive_size: int
    archive_mtime_ns: int
    header_bytes: bytes
    payload_key: bytearray | None
    index: dict[str, Any]
    metadata: dict[str, Any]
    index_meta: dict[str, Any]
    telemetry: dict[str, Any]
    last_access: float
    operation_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def close(self) -> None:
        with self.operation_lock:
            if self.payload_key is not None:
                secure_zero(self.payload_key)
                self.payload_key = None
            self.index.clear()
            self.metadata.clear()
            self.index_meta.clear()
            self.telemetry.clear()


class ArchiveSessionStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, ArchiveSession] = {}

    def open(
        self,
        archive_path: str,
        *,
        password: str | None,
        keyphrase: list | None,
        time_key: bytes | None,
        pqc_keyfile_path: str | None,
        pqc_keyfile_password: str | None,
    ) -> ArchiveSession:
        resolved = os.path.abspath(archive_path)
        state = open_indexed_archive_metadata(
            resolved,
            password=password,
            keyphrase=keyphrase,
            time_key=time_key,
            pqc_keyfile_path=pqc_keyfile_path,
            pqc_keyfile_password=pqc_keyfile_password,
        )
        stat = os.stat(resolved)
        session = ArchiveSession(
            session_id=secrets.token_hex(32),
            archive_path=resolved,
            archive_size=stat.st_size,
            archive_mtime_ns=stat.st_mtime_ns,
            header_bytes=state["header_bytes"],
            payload_key=bytearray(state["payload_key"]) if state["payload_key"] else None,
            index=state["index"],
            metadata=state["metadata"],
            index_meta=state["index_meta"],
            telemetry=dict(state.get("telemetry") or {}),
            last_access=time.monotonic(),
        )
        with self._lock:
            self._expire_locked()
            while len(self._sessions) >= MAX_SESSIONS:
                oldest_id = min(self._sessions, key=lambda key: self._sessions[key].last_access)
                self._close_locked(oldest_id)
            self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> ArchiveSession:
        with self._lock:
            self._expire_locked()
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError("Archive session is missing or expired")
            try:
                stat = os.stat(session.archive_path)
            except OSError:
                self._close_locked(session_id)
                raise ValueError("Archive is no longer available. Reopen it before continuing.")
            if stat.st_size != session.archive_size or stat.st_mtime_ns != session.archive_mtime_ns:
                self._close_locked(session_id)
                raise ValueError("Archive changed after it was authenticated. Reopen it before continuing.")
            session.last_access = time.monotonic()
            return session

    def extract(self, session_id: str, entry_ids: list[str], output_root: str, *, verify_only: bool = False) -> list[dict]:
        session = self.get(session_id)
        with session.operation_lock:
            with open_avk_payload_stream(session.archive_path) as (_header, _keychain, payload_stream, _pqc):
                return extract_indexed_selection(
                    payload_stream,
                    index=session.index,
                    selected_entry_ids=entry_ids,
                    output_root=output_root,
                    payload_key=bytes(session.payload_key) if session.payload_key is not None else None,
                    header_aad=session.header_bytes,
                    verify_only=verify_only,
                )

    def verify_payload_commitment(self, session_id: str) -> dict[str, Any]:
        from avikal_backend.archive.pipeline.progress import check_cancelled

        session = self.get(session_id)
        integrity = session.metadata.get("archive_integrity") or {}
        expected_hex = integrity.get("payload_sha256")
        if not isinstance(expected_hex, str) or len(expected_hex) != 64:
            raise ValueError("Signed payload commitment is missing")
        with session.operation_lock:
            digest = hashlib.sha256()
            size = 0
            with open_avk_payload_stream(session.archive_path) as (_header, _keychain, payload_stream, _pqc):
                while True:
                    check_cancelled()
                    chunk = payload_stream.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
        if size != session.index_meta.get("payload_size") or not hmac.compare_digest(digest.hexdigest(), expected_hex):
            raise ValueError("Whole-payload signature verification failed")
        return {"payload_sha256": digest.hexdigest(), "payload_size": size}

    def close(self, session_id: str) -> bool:
        with self._lock:
            return self._close_locked(session_id)

    def close_all(self) -> None:
        with self._lock:
            for session_id in list(self._sessions):
                self._close_locked(session_id)

    def _expire_locked(self) -> None:
        now = time.monotonic()
        for session_id, session in list(self._sessions.items()):
            if now - session.last_access > SESSION_IDLE_SECONDS:
                self._close_locked(session_id)

    def _close_locked(self, session_id: str) -> bool:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.close()
        return True
