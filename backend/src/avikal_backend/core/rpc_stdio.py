"""
JSON-RPC 2.0 server over LSP-style stdio framing.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import asyncio
import builtins
import json
import sys
import threading
from collections.abc import Callable
from typing import Any, BinaryIO

from avikal_backend.archive.pipeline.progress import PROGRESS_PREFIX
from avikal_backend.core import services
from avikal_backend.core.redaction import redact_sensitive, redact_text


JSONRPC_VERSION = "2.0"


class RpcProtocolError(Exception):
    pass


def _encode_frame(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


def _read_frame(stream: BinaryIO) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if line == b"":
            return None
        if line in {b"\r\n", b"\n"}:
            break
        try:
            key, value = line.decode("ascii").split(":", 1)
        except ValueError as exc:
            raise RpcProtocolError("Malformed JSON-RPC header") from exc
        headers[key.strip().lower()] = value.strip()

    try:
        length = int(headers["content-length"])
    except (KeyError, ValueError) as exc:
        raise RpcProtocolError("Missing or invalid Content-Length header") from exc
    if length <= 0 or length > 20 * 1024 * 1024:
        raise RpcProtocolError("Invalid JSON-RPC frame length")

    body = stream.read(length)
    if len(body) != length:
        raise RpcProtocolError("Unexpected end of JSON-RPC frame")
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RpcProtocolError("Invalid JSON-RPC JSON body") from exc
    if not isinstance(message, dict):
        raise RpcProtocolError("JSON-RPC message must be an object")
    return message


class StdioRpcServer:
    def __init__(self, stdin: BinaryIO, stdout: BinaryIO, stderr):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.loop: asyncio.AbstractEventLoop | None = None
        self.outgoing: asyncio.Queue[dict[str, Any]] | None = None
        self.shutdown_event: asyncio.Event | None = None
        self.tasks: dict[Any, asyncio.Task] = {}
        self._write_lock = threading.Lock()
        self._original_print: Callable[..., Any] = builtins.print

    def _safe_log(self, *args, **kwargs) -> None:
        kwargs.setdefault("file", self.stderr)
        kwargs.setdefault("flush", True)
        self._original_print(*(redact_sensitive(arg) for arg in args), **kwargs)

    def _patched_print(self, *args, **kwargs) -> None:
        text = " ".join(str(arg) for arg in args)
        if text.startswith(PROGRESS_PREFIX):
            try:
                payload = json.loads(text[len(PROGRESS_PREFIX):])
            except json.JSONDecodeError:
                self._safe_log(text)
                return
            self.emit_notification("progress.update", payload)
            return
        self._safe_log(*args, **kwargs)

    def emit_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self.loop is None or self.outgoing is None:
            return
        message = {"jsonrpc": JSONRPC_VERSION, "method": method}
        if params is not None:
            message["params"] = params
        self.loop.call_soon_threadsafe(self.outgoing.put_nowait, message)

    async def _writer(self) -> None:
        assert self.outgoing is not None
        while True:
            message = await self.outgoing.get()
            frame = _encode_frame(message)
            with self._write_lock:
                self.stdout.write(frame)
                self.stdout.flush()

    async def _handle_request(self, message: dict[str, Any]) -> None:
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params")
        if not isinstance(method, str) or not method:
            await self._send_error(request_id, -32600, "Invalid JSON-RPC request")
            return

        if method == "request.cancel":
            original_id = params.get("id") if isinstance(params, dict) else None
            task = self.tasks.get(original_id)
            if task is not None:
                task.cancel()
            if request_id is not None:
                await self._send_result(request_id, {"success": True, "cancelled": task is not None})
            return

        async def run() -> None:
            try:
                result = await services.dispatch(method, params if isinstance(params, dict) else {})
                if request_id is not None:
                    await self._send_result(request_id, result)
            except asyncio.CancelledError:
                if request_id is not None:
                    await self._send_error(request_id, -32800, "Request cancelled")
            except services.ServiceError as exc:
                if request_id is not None:
                    await self._send_error(request_id, exc.code, redact_text(str(exc)), redact_sensitive(exc.data))
            except Exception as exc:
                self._safe_log(f"Unhandled RPC error in {method}: {redact_text(exc)}")
                if request_id is not None:
                    await self._send_error(request_id, -32603, "Internal core error")
            finally:
                if request_id in self.tasks:
                    self.tasks.pop(request_id, None)

        task = asyncio.create_task(run())
        if request_id is not None:
            self.tasks[request_id] = task

    async def _send_result(self, request_id: Any, result: Any) -> None:
        assert self.outgoing is not None
        await self.outgoing.put({"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result})

    async def _send_error(self, request_id: Any, code: int, message: str, data: Any | None = None) -> None:
        assert self.outgoing is not None
        error: dict[str, Any] = {"code": int(code), "message": redact_text(message)}
        if data is not None:
            error["data"] = redact_sensitive(data)
        await self.outgoing.put({"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error})

    def _request_shutdown(self) -> None:
        if self.shutdown_event is not None:
            self.shutdown_event.set()

    def _reader_thread(self) -> None:
        assert self.loop is not None
        while True:
            try:
                message = _read_frame(self.stdin)
            except RpcProtocolError as exc:
                self.loop.call_soon_threadsafe(
                    asyncio.create_task,
                    self._send_error(None, -32700, str(exc)),
                )
                continue
            except Exception as exc:
                self._safe_log(f"JSON-RPC reader stopped: {exc}")
                self.loop.call_soon_threadsafe(self._request_shutdown)
                return
            if message is None:
                self.loop.call_soon_threadsafe(self._request_shutdown)
                return
            self.loop.call_soon_threadsafe(asyncio.create_task, self._handle_request(message))

    async def run(self) -> int:
        self.loop = asyncio.get_running_loop()
        self.outgoing = asyncio.Queue()
        self.shutdown_event = asyncio.Event()
        builtins.print = self._patched_print
        writer_task = asyncio.create_task(self._writer())
        reader = threading.Thread(target=self._reader_thread, name="avikal-rpc-reader", daemon=True)
        reader.start()
        try:
            await services.startup()
            self.emit_notification("runtime.statusChanged", {"state": "ready"})
            await self.shutdown_event.wait()
            return 0
        except asyncio.CancelledError:
            return 0
        finally:
            builtins.print = self._original_print
            writer_task.cancel()


def run_stdio_rpc() -> int:
    server = StdioRpcServer(sys.stdin.buffer, sys.stdout.buffer, sys.stderr)
    try:
        return asyncio.run(server.run())
    except KeyboardInterrupt:
        return 0
