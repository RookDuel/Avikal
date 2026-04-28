"""
Canonical manifest handling for encrypted multi-file AVK payloads.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import json
import posixpath
import zipfile

from ..path_safety import normalize_multi_archive_relative_path


INTERNAL_MANIFEST_PATH = "__avikal__/manifest.v1.json"
RESERVED_ENTRY_PREFIX = "__avikal__/"
MAX_MANIFEST_BYTES = 32 * 1024 * 1024


def normalize_user_archive_path(path: str) -> str:
    """Normalize a user-facing archive path and reject dangerous or reserved names."""
    if not isinstance(path, str):
        raise ValueError("Archive entry path must be a non-empty string")
    if path != path.strip():
        raise ValueError("Archive entry path must not contain leading or trailing whitespace")
    if not path:
        raise ValueError("Archive entry path must be a non-empty string")

    normalized = posixpath.normpath(path.replace("\\", "/"))
    normalized = normalized.lstrip("/")

    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise ValueError("Archive entry path is invalid")
    if ":" in normalized.split("/")[0]:
        raise ValueError("Archive entry path must be relative")
    if normalized == "__avikal__" or normalized.startswith(RESERVED_ENTRY_PREFIX):
        raise ValueError("Archive entry path conflicts with reserved Avikal metadata")
    return normalize_multi_archive_relative_path(normalized)


def is_internal_manifest_path(path: str) -> bool:
    try:
        normalized = posixpath.normpath(path.replace("\\", "/").strip()).lstrip("/")
    except Exception:
        return False
    return normalized == INTERNAL_MANIFEST_PATH or normalized.startswith(RESERVED_ENTRY_PREFIX)


def build_archive_manifest(files: list[dict], total_original_size: int) -> dict:
    """Build a canonical manifest for the encrypted multi-file payload."""
    if not isinstance(total_original_size, int) or total_original_size < 0:
        raise ValueError("Manifest total_original_size must be a non-negative integer")

    normalized_files = []
    seen_names: set[str] = set()
    aggregate_size = 0

    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("Manifest file entry must be an object")

        filename = normalize_user_archive_path(entry.get("filename", ""))
        size = entry.get("size")
        checksum = entry.get("checksum")

        if not isinstance(size, int) or size < 0:
            raise ValueError("Manifest file size must be a non-negative integer")
        if not isinstance(checksum, str) or len(checksum) != 64:
            raise ValueError("Manifest file checksum must be a 64-character hex digest")
        if any(ch not in "0123456789abcdef" for ch in checksum.lower()):
            raise ValueError("Manifest file checksum must be lowercase hex")
        if filename in seen_names:
            raise ValueError(f"Duplicate archive entry detected: {filename}")

        seen_names.add(filename)
        aggregate_size += size
        normalized_files.append(
            {
                "filename": filename,
                "size": size,
                "checksum": checksum.lower(),
            }
        )

    normalized_files.sort(key=lambda item: item["filename"])

    if aggregate_size != total_original_size:
        raise ValueError("Manifest total_original_size does not match file entries")

    return {
        "version": 1,
        "file_count": len(normalized_files),
        "total_original_size": total_original_size,
        "files": normalized_files,
    }


def serialize_archive_manifest(manifest: dict) -> bytes:
    validated = validate_archive_manifest(manifest)
    return json.dumps(
        validated,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def validate_archive_manifest(manifest: dict) -> dict:
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be an object")
    if manifest.get("version") != 1:
        raise ValueError("Unsupported manifest version")

    file_count = manifest.get("file_count")
    total_original_size = manifest.get("total_original_size")
    files = manifest.get("files")

    if not isinstance(file_count, int) or file_count < 0:
        raise ValueError("Manifest file_count must be a non-negative integer")
    if not isinstance(total_original_size, int) or total_original_size < 0:
        raise ValueError("Manifest total_original_size must be a non-negative integer")
    if not isinstance(files, list):
        raise ValueError("Manifest files must be a list")
    if len(files) != file_count:
        raise ValueError("Manifest file_count does not match files list")

    return build_archive_manifest(files, total_original_size)


def load_archive_manifest(container_zip: zipfile.ZipFile) -> tuple[dict, bytes]:
    """Read and validate the internal payload manifest from a container ZIP."""
    try:
        manifest_info = container_zip.getinfo(INTERNAL_MANIFEST_PATH)
    except KeyError as exc:
        raise ValueError("Encrypted payload manifest is missing") from exc

    if manifest_info.is_dir():
        raise ValueError("Encrypted payload manifest entry is invalid")
    if manifest_info.file_size <= 0 or manifest_info.file_size > MAX_MANIFEST_BYTES:
        raise ValueError("Encrypted payload manifest size is out of bounds")

    try:
        manifest_bytes = container_zip.read(INTERNAL_MANIFEST_PATH)
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Encrypted payload manifest is invalid") from exc

    return validate_archive_manifest(manifest), manifest_bytes
