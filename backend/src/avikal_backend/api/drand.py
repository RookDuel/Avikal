"""drand timelock helper integration.

Node.js runtime discovery (3-tier):

  Tier 1 — System PATH  : ``shutil.which("node")``
            Works in development mode and on CI runners (Node.js installed).

  Tier 2 — Electron exec: ``AVIKAL_ELECTRON_EXEC`` env var + ``ELECTRON_RUN_AS_NODE=1``
            Electron ships a full Node.js runtime inside its own binary.
            When the env var is set (by electron/main.js on every launch) we use the
            Electron binary itself as a drop-in node interpreter.  This is the
            official Electron-documented pattern used by VS Code, Cursor, 1Password,
            etc. — zero external installation required, zero added bundle size.

  Tier 3 — Windows fallback paths
            Probes well-known Windows installation directories (Program Files, nvm,
            Volta, Scoop, Chocolatey) for a ``node.exe``.  Edge-case last resort.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import threading

from fastapi import HTTPException

from .errors import friendly_error


log = logging.getLogger("avikal.api")
_DRAND_PROCESS_LOCK = threading.Lock()
_DRAND_WARMUP_LOCK = threading.Lock()
_DRAND_WARMUP_THREAD: threading.Thread | None = None


# ---------------------------------------------------------------------------
# Common Windows Node.js installation paths — Tier 3 fallback
# ---------------------------------------------------------------------------
_WINDOWS_NODE_CANDIDATES: list[str] = [
    r"C:\Program Files\nodejs\node.exe",
    r"C:\Program Files (x86)\nodejs\node.exe",
    # nvm-windows per-user
    str(Path.home() / "AppData" / "Roaming" / "nvm" / "current" / "node.exe"),
    # Volta
    str(Path.home() / ".volta" / "bin" / "node.exe"),
    # Scoop
    str(Path.home() / "scoop" / "apps" / "nodejs" / "current" / "node.exe"),
    # Chocolatey
    r"C:\ProgramData\chocolatey\bin\node.exe",
    r"C:\tools\nodejs\node.exe",
]


def _find_node_binary() -> tuple[str, dict[str, str]]:
    """
    Locate a Node.js-compatible binary and return ``(path, extra_env)``.

    ``extra_env`` is a dict of environment variables that MUST be set when
    spawning the returned binary.  For Tier-1/3 (real node) it is empty.
    For Tier-2 (Electron exec) it contains ``{"ELECTRON_RUN_AS_NODE": "1"}``.

    Returns ``("", {})`` when no Node.js runtime can be found.
    """
    # ------------------------------------------------------------------
    # Tier 1: system node on PATH  (dev mode + CI)
    # ------------------------------------------------------------------
    node = shutil.which("node") or shutil.which("node.exe")
    if node:
        log.debug("drand: using system node at %s", node)
        return node, {}

    # ------------------------------------------------------------------
    # Tier 2: Electron's own bundled Node.js  (production .exe)
    # ------------------------------------------------------------------
    # electron/main.js sets AVIKAL_ELECTRON_EXEC = process.execPath before
    # spawning the Python backend, so this env var is always available when
    # running inside the desktop app.
    electron_exec = os.environ.get("AVIKAL_ELECTRON_EXEC", "").strip()
    if electron_exec and os.path.isfile(electron_exec):
        log.debug("drand: using Electron binary as Node.js runtime (%s)", electron_exec)
        return electron_exec, {"ELECTRON_RUN_AS_NODE": "1"}

    # ------------------------------------------------------------------
    # Tier 3: probe well-known Windows installation directories
    # ------------------------------------------------------------------
    if os.name == "nt":
        for candidate in _WINDOWS_NODE_CANDIDATES:
            if os.path.isfile(candidate):
                log.debug("drand: found Node.js via fallback path: %s", candidate)
                return candidate, {}

    return "", {}


def drand_helper_path() -> str:
    """Absolute path to the drand_timelock_helper.mjs script."""
    # Walk up: drand.py → api/ → avikal_backend/ → src/ → backend/
    project_root = Path(__file__).resolve().parents[3]
    return str(project_root / "scripts" / "drand_timelock_helper.mjs")


def _resolve_drand_runtime() -> tuple[str, dict[str, str], str]:
    node_binary, node_extra_env = _find_node_binary()
    if not node_binary:
        raise HTTPException(
            status_code=500,
            detail=(
                "drand requires a Node.js runtime which could not be found. "
                "If you are using the Avikal desktop app, please reinstall it. "
                "If you are using the CLI, install Node.js from https://nodejs.org/ "
                "and restart."
            ),
        )

    helper_path = drand_helper_path()
    if not os.path.exists(helper_path):
        raise HTTPException(
            status_code=500,
            detail="drand helper script is missing. Please reinstall the application.",
        )
    return node_binary, node_extra_env, helper_path


def _run_drand_helper_once(
    payload: dict,
    *,
    node_binary: str,
    node_extra_env: dict[str, str],
    helper_path: str,
) -> dict:
    run_env = {**os.environ, **node_extra_env} if node_extra_env else None
    tier = "Electron/ELECTRON_RUN_AS_NODE" if node_extra_env else "node"
    log.debug(
        "drand: spawning helper via %s | action=%s | helper=%s",
        tier,
        payload.get("action"),
        helper_path,
    )

    try:
        completed = subprocess.run(
            [node_binary, helper_path],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
            cwd=str(Path(helper_path).parent),
            env=run_env,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("drand helper timed out: %s", exc)
        raise HTTPException(
            status_code=504,
            detail="drand network request timed out. Please try again.",
        )
    except Exception as exc:
        log.error("drand helper execution failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="drand helper execution failed.")

    raw_output = (completed.stdout or "").strip()
    stderr_output = (completed.stderr or "").strip()
    if not raw_output:
        if stderr_output:
            log.error(
                "drand helper produced no stdout. stderr=%r exit=%s",
                stderr_output[:2000],
                completed.returncode,
            )
        raw_output = stderr_output

    helper_result = _parse_drand_helper_result(raw_output, stderr_output)
    if completed.returncode != 0:
        error_message = helper_result.get("error") or helper_result.get("message") or "drand operation failed."
        raise HTTPException(status_code=503, detail=friendly_error(str(error_message)))
    return helper_result


class _PersistentDrandHelper:
    """Small JSON-lines worker around the Node.js drand helper."""

    def __init__(self) -> None:
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._node_binary: str | None = None
        self._node_extra_env: dict[str, str] = {}
        self._helper_path: str | None = None

    def close(self) -> None:
        with self._lock:
            self._terminate_locked()

    def warmup(self) -> None:
        with self._lock:
            self._ensure_started_locked()

    def call(self, payload: dict) -> dict:
        with self._lock:
            return self._call_locked(payload, allow_retry=True)

    def _call_locked(self, payload: dict, *, allow_retry: bool) -> dict:
        process = self._ensure_started_locked()
        request_line = json.dumps(payload, separators=(",", ":")) + "\n"

        try:
            assert process.stdin is not None
            assert process.stdout is not None
            process.stdin.write(request_line)
            process.stdin.flush()
        except Exception as exc:
            self._terminate_locked()
            if allow_retry:
                log.warning("drand helper pipe failed, retrying with fresh process: %s", exc)
                return self._call_locked(payload, allow_retry=False)
            raise HTTPException(status_code=500, detail="drand helper execution failed.") from exc

        read_state: dict[str, object] = {}

        def _read_response() -> None:
            try:
                read_state["line"] = process.stdout.readline()
            except Exception as exc:
                read_state["error"] = exc

        reader = threading.Thread(target=_read_response, name="avikal-drand-readline", daemon=True)
        reader.start()
        reader.join(timeout=60)
        if reader.is_alive():
            self._terminate_locked()
            raise HTTPException(
                status_code=504,
                detail="drand network request timed out. Please try again.",
            )
        if "error" in read_state:
            exc = read_state["error"]
            self._terminate_locked()
            if allow_retry:
                log.warning("drand helper read failed, retrying with fresh process: %s", exc)
                return self._call_locked(payload, allow_retry=False)
            raise HTTPException(status_code=500, detail="drand helper execution failed.") from exc

        response_line = str(read_state.get("line") or "")

        if not response_line:
            stderr_output = ""
            if process.stderr is not None:
                try:
                    stderr_output = process.stderr.read() or ""
                except Exception:
                    stderr_output = ""
            return_code = process.poll()
            self._terminate_locked()
            if allow_retry:
                log.warning(
                    "drand helper returned no response, retrying with fresh process. stderr=%r exit=%s",
                    stderr_output[:2000],
                    return_code,
                )
                return self._call_locked(payload, allow_retry=False)
            log.error(
                "drand helper produced no response. stderr=%r exit=%s",
                stderr_output[:2000],
                return_code,
            )
            raise HTTPException(
                status_code=500,
                detail="drand helper returned an invalid response. Check that the application is installed correctly.",
            )

        return _parse_drand_helper_result(response_line, "")

    def _ensure_started_locked(self) -> subprocess.Popen[str]:
        if self._process is not None and self._process.poll() is None:
            return self._process

        node_binary, node_extra_env = _find_node_binary()
        if not node_binary:
            raise HTTPException(
                status_code=500,
                detail=(
                    "drand requires a Node.js runtime which could not be found. "
                    "If you are using the Avikal desktop app, please reinstall it. "
                    "If you are using the CLI, install Node.js from https://nodejs.org/ "
                    "and restart."
                ),
            )

        helper_path = drand_helper_path()
        if not os.path.exists(helper_path):
            raise HTTPException(
                status_code=500,
                detail="drand helper script is missing. Please reinstall the application.",
            )

        run_env = {**os.environ, **node_extra_env} if node_extra_env else None
        tier = "Electron/ELECTRON_RUN_AS_NODE" if node_extra_env else "node"
        log.debug("drand: starting persistent helper via %s | helper=%s", tier, helper_path)

        try:
            self._process = subprocess.Popen(
                [node_binary, helper_path, "--server"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=str(Path(helper_path).parent),
                env=run_env,
            )
        except OSError as exc:
            raise HTTPException(status_code=500, detail="drand helper execution failed.") from exc

        self._node_binary = node_binary
        self._node_extra_env = dict(node_extra_env)
        self._helper_path = helper_path
        return self._process

    def _terminate_locked(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
        except Exception:
            pass
        try:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass


_PERSISTENT_DRAND_HELPER = _PersistentDrandHelper()
atexit.register(_PERSISTENT_DRAND_HELPER.close)


def prime_drand_helper_async() -> bool:
    """Warm the persistent drand helper in the background without blocking startup."""
    global _DRAND_WARMUP_THREAD
    try:
        _node_binary, node_extra_env, _helper_path = _resolve_drand_runtime()
    except HTTPException:
        return False

    # Electron-as-Node is the production runtime and is more stable in one-shot mode.
    if node_extra_env:
        return False

    with _DRAND_WARMUP_LOCK:
        if _DRAND_WARMUP_THREAD is not None and _DRAND_WARMUP_THREAD.is_alive():
            return False

        def worker() -> None:
            try:
                _PERSISTENT_DRAND_HELPER.warmup()
            except Exception as exc:
                log.debug("drand warmup skipped: %s", exc)

        _DRAND_WARMUP_THREAD = threading.Thread(
            target=worker,
            name="avikal-drand-warmup",
            daemon=True,
        )
        _DRAND_WARMUP_THREAD.start()
        return True


def _parse_drand_helper_result(raw_output: str, stderr_output: str = "") -> dict:
    try:
        helper_result = json.loads((raw_output or "").strip())
    except json.JSONDecodeError:
        log.error(
            "Invalid drand helper response: stdout=%r stderr=%r",
            raw_output,
            stderr_output,
        )
        raise HTTPException(
            status_code=500,
            detail=(
                "drand helper returned an invalid response. "
                "Check that the application is installed correctly."
            ),
        )

    if not isinstance(helper_result, dict):
        raise HTTPException(
            status_code=500,
            detail="drand helper returned an invalid response. Check that the application is installed correctly.",
        )

    if not helper_result.get("success"):
        error_message = (
            helper_result.get("error")
            or helper_result.get("message")
            or "drand operation failed."
        )
        if helper_result.get("status") == "locked":
            available_at = helper_result.get("unlock_iso")
            if available_at:
                raise HTTPException(
                    status_code=403,
                    detail=f"This capsule is still locked. drand unlock becomes available at {available_at}.",
                )
            raise HTTPException(status_code=403, detail="This capsule is still locked.")
        raise HTTPException(status_code=503, detail=friendly_error(str(error_message)))

    return helper_result


def run_drand_helper(payload: dict) -> dict:
    """
    Execute the drand timelock helper and return its parsed JSON result.

    Uses the 3-tier Node.js discovery strategy described in the module
    docstring so that drand works on every user machine regardless of
    whether they have Node.js installed.
    """
    action = payload.get("action")
    node_binary, node_extra_env, helper_path = _resolve_drand_runtime()
    log.debug("drand: dispatching helper request | action=%s", action)
    try:
        if node_extra_env:
            return _run_drand_helper_once(
                payload,
                node_binary=node_binary,
                node_extra_env=node_extra_env,
                helper_path=helper_path,
            )
        return _PERSISTENT_DRAND_HELPER.call(payload)
    except HTTPException:
        raise
    except subprocess.TimeoutExpired as exc:
        log.error("drand helper timed out: %s", exc)
        raise HTTPException(
            status_code=504,
            detail="drand network request timed out. Please try again.",
        )
    except Exception as exc:
        log.error("drand helper execution failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="drand helper execution failed.")
