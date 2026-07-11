from __future__ import annotations

import io
import json
import asyncio
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from avikal_backend.core import services
from avikal_backend.core.rpc_stdio import RpcProtocolError, _encode_frame, _read_frame


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    elif proc.poll() is None:
        proc.kill()


def test_lsp_frame_roundtrip():
    payload = {"jsonrpc": "2.0", "id": 1, "method": "runtime.status", "params": {}}
    stream = io.BytesIO(_encode_frame(payload))

    assert _read_frame(stream) == payload


def test_lsp_frame_rejects_missing_content_length():
    stream = io.BytesIO(b"Content-Type: application/json\r\n\r\n{}")

    with pytest.raises(RpcProtocolError, match="Content-Length"):
        _read_frame(stream)


def test_lsp_frame_rejects_oversized_content_length():
    stream = io.BytesIO(b"Content-Length: 20971521\r\n\r\n{}")

    with pytest.raises(RpcProtocolError, match="frame length"):
        _read_frame(stream)


def test_core_service_reports_native_runtime():
    result = asyncio.run(services.dispatch("runtime.status", {}))

    assert result["success"] is True
    assert result["runtime"]["native_crypto"]["available"] is True


def test_core_service_rejects_unknown_method():
    with pytest.raises(services.ServiceError, match="Unknown core method"):
        asyncio.run(services.dispatch("missing.method", {}))


def test_crypto_worker_cancellation_finishes_before_next_worker_starts():
    from avikal_backend.archive.pipeline.progress import check_cancelled

    first_started = threading.Event()
    first_stopped = threading.Event()
    second_started = threading.Event()

    def first_worker():
        first_started.set()
        try:
            while True:
                check_cancelled()
                time.sleep(0.01)
        finally:
            first_stopped.set()

    def second_worker():
        second_started.set()
        assert first_stopped.is_set()
        return "completed"

    async def exercise():
        first_task = asyncio.create_task(services._run_crypto_worker(first_worker))
        assert await asyncio.to_thread(first_started.wait, 1.0)
        second_task = asyncio.create_task(services._run_crypto_worker(second_worker))
        await asyncio.sleep(0.05)
        assert not second_started.is_set()

        first_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_task

        assert first_stopped.is_set()
        assert await asyncio.wait_for(second_task, timeout=1.0) == "completed"

    asyncio.run(exercise())


def test_core_stdio_runtime_status_smoke():
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.Popen(
        [sys.executable, str(root / "core_server.py"), "--gui-mode"],
        cwd=str(root.parent),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    try:
        request = {"jsonrpc": "2.0", "id": 7, "method": "runtime.status", "params": {}}
        proc.stdin.write(_encode_frame(request))
        proc.stdin.flush()

        messages = [_read_frame(proc.stdout), _read_frame(proc.stdout)]
        response = next(message for message in messages if message.get("id") == 7)
        assert response["result"]["success"] is True
    finally:
        _terminate_process_tree(proc)


def test_core_stdio_rejects_invalid_request():
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.Popen(
        [sys.executable, str(root / "core_server.py"), "--gui-mode"],
        cwd=str(root.parent),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    try:
        request = {"jsonrpc": "2.0", "id": 9, "method": "", "params": {}}
        proc.stdin.write(_encode_frame(request))
        proc.stdin.flush()

        messages = [_read_frame(proc.stdout), _read_frame(proc.stdout)]
        response = next(message for message in messages if message.get("id") == 9)
        assert response["error"]["code"] == -32600
    finally:
        _terminate_process_tree(proc)


def test_core_stdio_cancel_unknown_request_reports_not_cancelled():
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.Popen(
        [sys.executable, str(root / "core_server.py"), "--gui-mode"],
        cwd=str(root.parent),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    try:
        request = {"jsonrpc": "2.0", "id": 10, "method": "request.cancel", "params": {"id": "missing"}}
        proc.stdin.write(_encode_frame(request))
        proc.stdin.flush()

        messages = [_read_frame(proc.stdout), _read_frame(proc.stdout)]
        response = next(message for message in messages if message.get("id") == 10)
        assert response["result"] == {"success": True, "cancelled": False}
    finally:
        _terminate_process_tree(proc)
