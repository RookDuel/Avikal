"""Crash-recovery cleanup for Avikal temporary artifacts.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time

from avikal_backend.core.private_workspace import ensure_private_dir


_REGISTRY_LOCK = threading.Lock()
_FILE_PREFIXES = (
    ".avikal-archive-",
    ".avikal-container-",
    ".avikal-container-dec-",
    ".avikal-dec-",
    ".avikal-inspect-",
    ".avikal-payload-",
    ".avikal-rekey-",
    ".avikal-cipher-",
)
_DIR_PREFIXES = (
    "avikal_extract_",
    "avikal-pqc-",
)


def _runtime_base_dir() -> Path:
    return Path(os.getenv("AVIKAL_USER_DATA_DIR") or (Path.home() / ".avikal")).resolve()


def _registry_path() -> Path:
    base = _runtime_base_dir()
    ensure_private_dir(base)
    return base / "temp_artifacts.jsonl"


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
        shutil.rmtree(path, ignore_errors=True)
        return True
    try:
        path.unlink()
        return True
    except OSError:
        return False


def _cleanup_registry() -> int:
    removed = 0
    try:
        registry = _registry_path()
        if not registry.exists():
            return 0
        kept: list[str] = []
        with _REGISTRY_LOCK:
            for line in registry.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                    path = Path(str(record.get("path", ""))).resolve()
                    kind = "dir" if record.get("kind") == "dir" else "file"
                except (OSError, TypeError, ValueError, json.JSONDecodeError):
                    continue
                if _remove_artifact(path, kind):
                    removed += 1
                elif path.exists():
                    kept.append(json.dumps(record, separators=(",", ":")))
            registry.write_text(("\n".join(kept) + "\n") if kept else "", encoding="utf-8")
    except OSError:
        return removed
    return removed


def _cleanup_known_temp_roots() -> int:
    removed = 0
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
                if _remove_artifact(entry.resolve(), "dir" if entry.is_dir() else "file"):
                    removed += 1
        except OSError:
            continue
    return removed


def cleanup_startup_temp_artifacts() -> int:
    """Best-effort cleanup of interrupted Avikal temp files from earlier runs."""
    return _cleanup_registry() + _cleanup_known_temp_roots()
