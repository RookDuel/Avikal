"""
Path and filename safety helpers for Avikal archive extraction.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os


_WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_WINDOWS_INVALID_FILENAME_CHARS = set('<>:"/\\|?*')


def _validate_windows_path_component(component: str, *, allow_path_separators: bool = False) -> str:
    if not isinstance(component, str):
        raise ValueError("Archive path component must be a string")

    if component != component.strip():
        raise ValueError("Archive path component must not contain leading or trailing whitespace")
    candidate = component
    if not candidate:
        raise ValueError("Archive path component must not be empty")
    if candidate in {".", ".."}:
        raise ValueError("Archive path component is invalid")
    if "\x00" in candidate:
        raise ValueError("Archive path component contains invalid characters")
    if candidate.endswith((" ", ".")):
        raise ValueError("Archive path component must not end with spaces or periods")
    if not allow_path_separators and ("/" in candidate or "\\" in candidate):
        raise ValueError("Archive path component must not contain path separators")
    if any(ord(ch) < 32 for ch in candidate):
        raise ValueError("Archive path component contains control characters")
    if any(ch in _WINDOWS_INVALID_FILENAME_CHARS for ch in candidate):
        raise ValueError("Archive path component contains invalid Windows filename characters")

    stem = candidate.split(".", 1)[0].lower()
    if stem in _WINDOWS_RESERVED_NAMES:
        raise ValueError("Archive path component uses a reserved device name")

    return candidate


def normalize_single_archive_filename(filename: str) -> str:
    """Validate a single-file archive output name and reject unsafe paths."""
    if not isinstance(filename, str):
        raise ValueError("Archive filename must be a string")
    if filename != filename.strip():
        raise ValueError("Archive filename must not contain leading or trailing whitespace")
    candidate = filename
    if candidate != os.path.basename(candidate):
        raise ValueError("Archive filename must not contain path separators")
    return _validate_windows_path_component(candidate)


def normalize_multi_archive_relative_path(path: str) -> str:
    """Validate a relative multi-file archive path for safe Windows extraction."""
    if not isinstance(path, str):
        raise ValueError("Archive entry path must be a string")

    if path != path.strip():
        raise ValueError("Archive entry path must not contain leading or trailing whitespace")
    candidate = path.replace("\\", "/")
    if not candidate:
        raise ValueError("Archive entry path must not be empty")
    if candidate.startswith("/"):
        raise ValueError("Archive entry path must be relative")

    parts = candidate.split("/")
    safe_parts: list[str] = []
    for part in parts:
        if not part:
            raise ValueError("Archive entry path contains empty path components")
        safe_parts.append(_validate_windows_path_component(part))

    return "/".join(safe_parts)


def resolve_safe_output_path(output_directory: str, filename: str) -> str:
    """Return an output path guaranteed to remain inside the extraction root."""
    safe_name = normalize_single_archive_filename(filename)
    root = os.path.abspath(output_directory)
    candidate = os.path.abspath(os.path.join(root, safe_name))
    if os.path.commonpath([root, candidate]) != root:
        raise ValueError("Resolved output path escapes the extraction directory")
    return candidate


def resolve_safe_relative_output_path(output_directory: str, relative_path: str) -> str:
    """Return a multi-file output path guaranteed to remain inside the extraction root."""
    safe_relpath = normalize_multi_archive_relative_path(relative_path)
    root = os.path.abspath(output_directory)
    candidate = os.path.abspath(os.path.join(root, *safe_relpath.split("/")))
    if os.path.commonpath([root, candidate]) != root:
        raise ValueError("Resolved output path escapes the extraction directory")
    return candidate
