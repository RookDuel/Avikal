"""Fail-closed validation for archive source filesystem objects."""

from __future__ import annotations

import os
import stat


def is_link_or_reparse_point(path: str) -> bool:
    """Return true for symbolic links, junctions, and Windows reparse points."""
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if callable(isjunction) and isjunction(path):
        return True
    try:
        attributes = int(getattr(os.lstat(path), "st_file_attributes", 0))
    except OSError:
        return False
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def assert_safe_input_file(path: str) -> os.stat_result:
    if is_link_or_reparse_point(path):
        raise ValueError(f"Archive input links and reparse points are not allowed: {path}")
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"Unable to inspect archive input: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Archive input is not a regular file: {path}")
    return info


def assert_safe_input_directory(path: str) -> os.stat_result:
    if is_link_or_reparse_point(path):
        raise ValueError(f"Archive input links and reparse points are not allowed: {path}")
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"Unable to inspect archive input: {path}") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"Archive input is not a directory: {path}")
    return info
