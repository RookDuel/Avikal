"""Progress reporting regressions."""

from __future__ import annotations

import json

from avikal_backend.archive.pipeline.progress import PROGRESS_PREFIX, ProgressTracker


def test_progress_tracker_never_emits_lower_percentage(monkeypatch):
    emitted: list[dict] = []

    def capture_print(message, *args, **kwargs):
        if isinstance(message, str) and message.startswith(PROGRESS_PREFIX):
            emitted.append(json.loads(message[len(PROGRESS_PREFIX):]))

    monkeypatch.setattr("builtins.print", capture_print)

    tracker = ProgressTracker("decrypt", [("payload", 0.75), ("finalize", 0.25)])
    tracker.update("finalize", "Preparing preview files", 0.8, force=True)
    tracker.update("payload", "Decrypting multi-file payload", 0.5, force=True)

    assert [event["percentage"] for event in emitted] == [95.0]
    assert emitted[-1]["currentOperation"] == "Preparing preview files"
