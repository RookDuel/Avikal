"""Crash-recovery cleanup for Avikal temporary artifacts.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import time

from avikal_backend.core.private_workspace import ensure_private_dir
from avikal_backend.core.secure_delete import secure_remove_file, secure_remove_tree


_REGISTRY_LOCK = threading.Lock()
_UNREGISTERED_CLEANUP_MIN_AGE_SECONDS = 60 * 60
_FILE_PREFIXES = (
    ".avikal-archive-",
    ".avikal-container-",
    ".avikal-container-dec-",
    ".avikal-dec-",
    ".avikal-inspect-",
    ".avikal-payload-",
    ".avikal-rekey-",
    ".avikal-cipher-",
    ".avikal-keyfile-",
)
_DIR_PREFIXES = (
    "avikal_extract_",
    "avikal-pqc-",
    "avikal-volumes-",
)


def _runtime_base_dir() -> Path:
    return Path(os.getenv("AVIKAL_USER_DATA_DIR") or (Path.home() / ".avikal")).resolve()


def _registry_dir() -> Path:
    base = _runtime_base_dir()
    ensure_private_dir(base)
    registry_dir = base / "temp_artifacts"
    ensure_private_dir(registry_dir)
    return registry_dir


def _registry_path() -> Path:
    return _registry_dir() / f"{os.getpid()}.jsonl"


def _registry_paths() -> list[Path]:
    paths = list(_registry_dir().glob("*.jsonl"))
    legacy = _runtime_base_dir() / "temp_artifacts.jsonl"
    if legacy.exists():
        paths.append(legacy)
    return paths


def _is_safe_artifact_path(path: Path) -> bool:
    name = path.name
    if name in {"", ".", ".."}:
        return False
    return name.startswith(_FILE_PREFIXES) or name.startswith(_DIR_PREFIXES)


def register_temp_artifact(path: str | os.PathLike[str], *, kind: str = "file") -> None:
    """Persist a temp artifact path so a later startup can clean it after a crash."""
    try:
        artifact = Path(path).resolve()
        if not _is_safe_artifact_path(artifact):
            return
        record = {
            "path": str(artifact),
            "kind": "dir" if kind == "dir" else "file",
            "created_at": int(time.time()),
            "owner_pid": os.getpid(),
        }
        with _REGISTRY_LOCK:
            registry = _registry_path()
            with registry.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError:
        return


def unregister_temp_artifact(path: str | os.PathLike[str]) -> None:
    try:
        target = str(Path(path).resolve())
        registry = _registry_path()
        if not registry.exists():
            return
        with _REGISTRY_LOCK:
            kept: list[str] = []
            for line in registry.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("path") != target:
                    kept.append(json.dumps(record, separators=(",", ":")))
            registry.write_text(("\n".join(kept) + "\n") if kept else "", encoding="utf-8")
    except OSError:
        return


def _remove_artifact(path: Path, kind: str) -> bool:
    if not _is_safe_artifact_path(path):
        return False
    if not path.exists():
        return False
    if kind == "dir" or path.is_dir():
        return secure_remove_tree(path)
    return secure_remove_file(path)


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            kernel32.GetExitCodeProcess.restype = ctypes.c_int
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return ctypes.get_last_error() == 5
            exit_code = ctypes.c_ulong()
            try:
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return True
                return exit_code.value == 259
            finally:
                kernel32.CloseHandle(handle)
        except (AttributeError, OSError, ValueError):
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _record_owner_is_alive(record: dict) -> bool:
    try:
        return _process_is_alive(int(record.get("owner_pid") or 0))
    except (TypeError, ValueError):
        return False


def _cleanup_registry() -> tuple[int, set[Path]]:
    removed = 0
    protected: set[Path] = set()
    try:
        with _REGISTRY_LOCK:
            for registry in _registry_paths():
                try:
                    raw_lines = registry.read_text(encoding="utf-8").splitlines()
                except OSError:
                    continue
                records: list[dict] = []
                for line in raw_lines:
                    try:
                        record = json.loads(line)
                        if isinstance(record, dict):
                            records.append(record)
                    except json.JSONDecodeError:
                        continue

                active_owner = any(_record_owner_is_alive(record) for record in records)
                if active_owner:
                    for record in records:
                        try:
                            path = Path(str(record.get("path", ""))).resolve()
                        except (OSError, TypeError, ValueError):
                            continue
                        if _is_safe_artifact_path(path):
                            protected.add(path)
                    continue

                kept: list[str] = []
                for record in records:
                    try:
                        path = Path(str(record.get("path", ""))).resolve()
                        kind = "dir" if record.get("kind") == "dir" else "file"
                    except (OSError, TypeError, ValueError):
                        continue
                    if _remove_artifact(path, kind):
                        removed += 1
                    elif path.exists():
                        kept.append(json.dumps(record, separators=(",", ":")))
                if kept:
                    registry.write_text("\n".join(kept) + "\n", encoding="utf-8")
                else:
                    registry.unlink(missing_ok=True)
    except OSError:
        return removed, protected
    return removed, protected


def _cleanup_known_temp_roots(protected: set[Path]) -> int:
    removed = 0
    now = time.time()
    roots = [
        Path(tempfile.gettempdir()).resolve(),
        (Path(tempfile.gettempdir()) / "avikal-pqc-provider").resolve(),
        (_runtime_base_dir() / "preview_sessions").resolve(),
    ]
    seen: set[Path] = set()
    for root in roots:
        if root in seen or not root.exists() or not root.is_dir():
            continue
        seen.add(root)
        try:
            for entry in root.iterdir():
                resolved = entry.resolve()
                if resolved in protected:
                    continue
                try:
                    age = now - entry.stat().st_mtime
                except OSError:
                    continue
                if age < _UNREGISTERED_CLEANUP_MIN_AGE_SECONDS:
                    continue
                if _remove_artifact(resolved, "dir" if entry.is_dir() else "file"):
                    removed += 1
        except OSError:
            continue
    return removed


def cleanup_startup_temp_artifacts() -> int:
    """Best-effort cleanup of interrupted Avikal temp files from earlier runs."""
    removed, protected = _cleanup_registry()
    return removed + _cleanup_known_temp_roots(protected)
