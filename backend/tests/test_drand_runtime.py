"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import json
from pathlib import Path

from avikal_backend.api import drand as drand_api


class _FakeStdout:
    def __init__(self) -> None:
        self._lines: list[str] = []

    def readline(self) -> str:
        if self._lines:
            return self._lines.pop(0)
        return ""


class _FakeStderr:
    def read(self) -> str:
        return ""


class _FakeStdin:
    def __init__(self, process: "_FakeProcess") -> None:
        self._process = process
        self._buffer = ""

    def write(self, data: str) -> None:
        self._buffer += data

    def flush(self) -> None:
        payload = json.loads(self._buffer.strip() or "{}")
        self._buffer = ""
        action = payload.get("action")
        if action == "seal":
            response = {"success": True, "provider": "drand", "round": 123, "ciphertext": "abc"}
        else:
            response = {"success": True, "provider": "drand", "key_b_base64": "QQ=="}
        self._process.stdout._lines.append(json.dumps(response) + "\n")

    def close(self) -> None:
        return None


class _FakeProcess:
    def __init__(self) -> None:
        self.stdout = _FakeStdout()
        self.stderr = _FakeStderr()
        self.stdin = _FakeStdin(self)
        self._terminated = False

    def poll(self) -> int | None:
        return 0 if self._terminated else None

    def terminate(self) -> None:
        self._terminated = True

    def wait(self, timeout: int | None = None) -> int:
        self._terminated = True
        return 0

    def kill(self) -> None:
        self._terminated = True


def test_run_drand_helper_reuses_persistent_process(monkeypatch):
    popen_calls = {"count": 0}

    def fake_popen(*_args, **_kwargs):
        popen_calls["count"] += 1
        return _FakeProcess()

    monkeypatch.setattr(drand_api.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(drand_api, "_find_node_binary", lambda: ("node", {}))
    monkeypatch.setattr(drand_api, "drand_helper_path", lambda: str(Path(__file__).resolve()))

    drand_api._PERSISTENT_DRAND_HELPER.close()
    try:
        seal_result = drand_api.run_drand_helper({"action": "seal", "unlock_timestamp": 1, "key_b_base64": "QQ=="})
        open_result = drand_api.run_drand_helper({"action": "open", "ciphertext": "abc", "round": 123})
    finally:
        drand_api._PERSISTENT_DRAND_HELPER.close()

    assert popen_calls["count"] == 1
    assert seal_result["round"] == 123
    assert open_result["key_b_base64"] == "QQ=="


def test_run_drand_helper_uses_one_shot_mode_for_electron_runtime(monkeypatch):
    run_calls = {"count": 0}

    class _Completed:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout
            self.stderr = ""
            self.returncode = 0

    def fake_run(*_args, **_kwargs):
        run_calls["count"] += 1
        return _Completed(json.dumps({"success": True, "provider": "drand", "key_b_base64": "QQ=="}))

    monkeypatch.setattr(drand_api.subprocess, "run", fake_run)
    monkeypatch.setattr(drand_api.subprocess, "Popen", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("persistent helper should not be used for Electron runtime")))
    monkeypatch.setattr(drand_api, "_find_node_binary", lambda: ("electron.exe", {"ELECTRON_RUN_AS_NODE": "1"}))
    monkeypatch.setattr(drand_api, "drand_helper_path", lambda: str(Path(__file__).resolve()))

    result = drand_api.run_drand_helper({"action": "open", "ciphertext": "abc", "round": 123})
    assert run_calls["count"] == 1
    assert result["key_b_base64"] == "QQ=="
