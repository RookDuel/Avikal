"""Runtime tests for the active stdio core drand helper."""

from __future__ import annotations

import io
import json
from pathlib import Path

from avikal_backend.core import services


class _FakeProcess:
    def __init__(self, response: dict) -> None:
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(json.dumps(response))
        self.stderr = io.StringIO()
        self.returncode = 0

    def poll(self) -> int:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def communicate(self, timeout: int | None = None) -> tuple[str, str]:
        return self.stdout.getvalue(), self.stderr.getvalue()


def test_run_drand_helper_uses_bounded_one_shot_process(monkeypatch):
    popen_calls = {"count": 0}

    def fake_popen(*_args, **_kwargs):
        popen_calls["count"] += 1
        return _FakeProcess({"success": True, "provider": "drand", "round": 123, "ciphertext": "abc"})

    monkeypatch.setattr(services.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(services, "_find_node_binary", lambda: ("node", {}))
    monkeypatch.setattr(services, "drand_helper_path", lambda: Path(__file__).resolve())

    result = services._run_drand_helper(
        {"action": "seal", "unlock_timestamp": 1, "key_b_base64": "QQ=="},
        timeout_seconds=5,
    )

    assert popen_calls["count"] == 1
    assert result["round"] == 123
