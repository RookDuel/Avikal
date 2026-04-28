"""
Structured progress reporting for long-running archive operations.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import builtins
import json
import threading
import time
from contextlib import contextmanager


PROGRESS_PREFIX = "__AVIKAL_PROGRESS__"
_thread_state = threading.local()


class ProgressTracker:
    def __init__(self, operation: str, stages: list[tuple[str, float]], *, file_size: int | None = None):
        self.operation = operation
        self.stages = stages
        self.file_size = file_size
        self.start_time = time.perf_counter()
        self.last_emit_percent = -1.0
        self.last_emit_time = 0.0
        self.stage_offsets: dict[str, float] = {}
        offset = 0.0
        for name, weight in stages:
            self.stage_offsets[name] = offset
            offset += weight

    def set_file_size(self, file_size: int | None) -> None:
        self.file_size = file_size

    def _emit(self, payload: dict, *, force: bool = False) -> None:
        percent = float(payload.get("percentage") or 0.0)
        now = time.perf_counter()
        if not force:
            if abs(percent - self.last_emit_percent) < 1.0 and (now - self.last_emit_time) < 0.4:
                return
        self.last_emit_percent = percent
        self.last_emit_time = now
        builtins.print(f"{PROGRESS_PREFIX}{json.dumps(payload, separators=(',', ':'))}", flush=True)

    def update(
        self,
        stage: str,
        description: str,
        stage_progress: float,
        *,
        file_size: int | None = None,
        compression_ratio: float | None = None,
        force: bool = False,
    ) -> None:
        stage_progress = max(0.0, min(1.0, float(stage_progress)))
        offset = self.stage_offsets.get(stage, 0.0)
        weight = dict(self.stages).get(stage, 0.0)
        fraction = max(0.0, min(1.0, offset + (weight * stage_progress)))
        elapsed = time.perf_counter() - self.start_time
        eta_seconds = None
        if fraction > 0.01:
            eta_seconds = max(0, round((elapsed / fraction) - elapsed))
        payload = {
            "type": "progress",
            "operation": self.operation,
            "status": "running",
            "stage": stage,
            "percentage": round(fraction * 100, 2),
            "currentOperation": description,
            "etaSeconds": eta_seconds,
            "fileSize": file_size if file_size is not None else self.file_size,
            "compressionRatio": compression_ratio,
        }
        self._emit(payload, force=force)

    def complete(self, description: str = "Complete") -> None:
        payload = {
            "type": "progress",
            "operation": self.operation,
            "status": "completed",
            "stage": "complete",
            "percentage": 100.0,
            "currentOperation": description,
            "etaSeconds": 0,
            "fileSize": self.file_size,
            "compressionRatio": None,
        }
        self._emit(payload, force=True)

    def fail(self, description: str = "Failed") -> None:
        payload = {
            "type": "progress",
            "operation": self.operation,
            "status": "error",
            "stage": "error",
            "percentage": max(0.0, self.last_emit_percent),
            "currentOperation": description,
            "etaSeconds": None,
            "fileSize": self.file_size,
            "compressionRatio": None,
        }
        self._emit(payload, force=True)


def get_progress_tracker() -> ProgressTracker | None:
    return getattr(_thread_state, "progress_tracker", None)


@contextmanager
def bind_progress_tracker(tracker: ProgressTracker):
    previous = get_progress_tracker()
    _thread_state.progress_tracker = tracker
    try:
        yield tracker
    finally:
        _thread_state.progress_tracker = previous
