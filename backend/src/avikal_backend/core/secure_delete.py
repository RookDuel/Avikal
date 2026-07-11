"""Best-effort secure removal for Avikal temporary plaintext artifacts.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat


_SCRUB_CHUNK_BYTES = 1024 * 1024


def secure_remove_file(path: str | os.PathLike[str]) -> bool:
    """Overwrite, truncate, and remove a file without following symlink targets.

    This reduces recoverable residue for ordinary files and still falls back to
    unlinking if the filesystem refuses overwrite/truncate. SSD firmware,
    controller caches, filesystem journals, and volume shadow copies can retain
    historical blocks outside application control.
    """

    target = Path(path)
    try:
        if not target.exists() and not target.is_symlink():
            return False
        if target.is_dir() and not target.is_symlink():
            return secure_remove_tree(target)
        _make_writable(target)
        if not target.is_symlink():
            _overwrite_and_truncate(target)
        target.unlink(missing_ok=True)
        return True
    except OSError:
        try:
            target.unlink(missing_ok=True)
            return True
        except OSError:
            return False


def secure_remove_tree(path: str | os.PathLike[str]) -> bool:
    """Remove a directory tree after scrubbing contained regular files."""

    root = Path(path)
    if not root.exists():
        return False
    if not root.is_dir() or root.is_symlink():
        return secure_remove_file(root)

    removed_any = False
    try:
        entries = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    except OSError:
        entries = []
    for entry in entries:
        if entry.is_dir() and not entry.is_symlink():
            try:
                _make_writable(entry)
                entry.rmdir()
                removed_any = True
            except OSError:
                continue
        else:
            removed_any = secure_remove_file(entry) or removed_any
    try:
        _make_writable(root)
        root.rmdir()
        return True
    except OSError:
        return removed_any


def _overwrite_and_truncate(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size <= 0:
        _truncate(path)
        return

    zeros = b"\0" * min(_SCRUB_CHUNK_BYTES, size)
    try:
        with path.open("r+b", buffering=0) as handle:
            remaining = size
            while remaining > 0:
                written = min(len(zeros), remaining)
                handle.write(zeros[:written])
                remaining -= written
            handle.flush()
            os.fsync(handle.fileno())
            handle.truncate(0)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        _truncate(path)


def _truncate(path: Path) -> None:
    try:
        with path.open("wb"):
            pass
    except OSError:
        return


def _make_writable(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IWRITE)
    except OSError:
        return
