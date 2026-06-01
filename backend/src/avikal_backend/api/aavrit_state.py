"""Thread-safe local connection context for Aavrit integration."""

from __future__ import annotations

import threading


class AavritConnectionState:
    """Store non-secret Aavrit connection context for the local desktop backend."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._server_url: str | None = None
        self._mode: str | None = None

    def set_server_url(self, server_url: str | None) -> str | None:
        with self._lock:
            self._server_url = server_url
            return self._server_url

    def get_server_url(self) -> str | None:
        with self._lock:
            return self._server_url

    def set_mode(self, mode: str | None) -> str | None:
        with self._lock:
            self._mode = mode
            return self._mode

    def get_mode(self) -> str | None:
        with self._lock:
            return self._mode

    def update(self, *, server_url: str | None = None, mode: str | None = None) -> None:
        with self._lock:
            if server_url is not None:
                self._server_url = server_url
            if mode is not None:
                self._mode = mode

    def clear(self) -> None:
        with self._lock:
            self._server_url = None
            self._mode = None
