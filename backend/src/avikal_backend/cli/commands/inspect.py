"""
Inspection-oriented commands for the backend CLI.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ...archive.chess_metadata import decode_chess_to_metadata_enhanced
from ...archive.format.container import read_avk_container
from ...archive.format.header import parse_header_bytes, validate_metadata_against_header
from ...archive.pipeline.multi_file_decoder import inspect_multi_file_avk
from ..formatters import build_container_summary, human_size, summarize_metadata
from ..inputs import load_keyphrase, resolve_single_input


def decode_archive_metadata(
    input_path: str,
    *,
    password: str | None,
    keyphrase: list[str] | None,
    skip_timelock: bool,
) -> dict[str, Any]:
    header_bytes, keychain_pgn, _payload = read_avk_container(input_path)
    header_info = parse_header_bytes(header_bytes)
    metadata = decode_chess_to_metadata_enhanced(
        keychain_pgn,
        password=password,
        keyphrase=keyphrase,
        skip_timelock=skip_timelock,
        aad=header_bytes,
    )
    validate_metadata_against_header(header_info, metadata)
    return metadata


def detect_archive_kind(
    input_path: str,
    *,
    password: str | None,
    keyphrase: list[str] | None,
    skip_timelock: bool = False,
) -> tuple[str, dict[str, Any] | None]:
    metadata = decode_archive_metadata(
        input_path,
        password=password,
        keyphrase=keyphrase,
        skip_timelock=skip_timelock,
    )
    archive_kind = "multi_file" if metadata.get("archive_type") == "multi_file" else "single_file"
    return archive_kind, metadata


def inspect_archive(args: argparse.Namespace) -> dict[str, Any]:
    input_path = resolve_single_input(
        args.input,
        pick=getattr(args, "pick", False),
        title="Select Avikal archive to inspect",
        filetypes=[("Avikal archive", "*.avk"), ("All files", "*.*")],
    )
    header_bytes, keychain_pgn, _payload = read_avk_container(input_path)
    header_info = parse_header_bytes(header_bytes)
    result = {
        "ok": True,
        "mode": "inspect",
        "container": build_container_summary(input_path),
        "metadata": None,
    }

    keyphrase = load_keyphrase(args)
    if args.password or keyphrase:
        metadata = decode_chess_to_metadata_enhanced(
            keychain_pgn,
            password=args.password,
            keyphrase=keyphrase,
            skip_timelock=args.skip_timelock,
            aad=header_bytes,
        )
        validate_metadata_against_header(header_info, metadata)
        result["metadata"] = summarize_metadata(metadata)

    return result


def validate_archive(args: argparse.Namespace) -> dict[str, Any]:
    result = inspect_archive(args)
    result["mode"] = "validate"
    result["checks"] = {
        "container_structure": True,
        "metadata_decrypted": result["metadata"] is not None,
        "timelock_bypassed": bool(args.skip_timelock),
    }
    return result


def contents_archive(args: argparse.Namespace) -> dict[str, Any]:
    keyphrase = load_keyphrase(args)
    input_path = resolve_single_input(
        args.input,
        pick=getattr(args, "pick", False),
        title="Select Avikal archive to list contents",
        filetypes=[("Avikal archive", "*.avk"), ("All files", "*.*")],
    )
    archive_kind, metadata = detect_archive_kind(
        input_path,
        password=args.password,
        keyphrase=keyphrase,
        skip_timelock=args.skip_timelock,
    )

    if archive_kind == "multi_file":
        manifest_result = inspect_multi_file_avk(
            avk_filepath=input_path,
            password=args.password,
            keyphrase=keyphrase,
            pqc_keyfile_path=args.pqc_keyfile,
        )
        files = [
            {
                "filename": entry["filename"],
                "size_bytes": entry["size"],
                "size_human": human_size(entry["size"]),
                "checksum_sha256": entry["checksum"],
            }
            for entry in manifest_result["manifest"]["files"]
        ]
        return {
            "ok": True,
            "mode": "contents",
            "archive_kind": archive_kind,
            "container": build_container_summary(input_path),
            "metadata": summarize_metadata(metadata) if metadata else None,
            "file_count": manifest_result["file_count"],
            "total_size_bytes": manifest_result["total_size"],
            "total_size_human": human_size(manifest_result["total_size"]),
            "files": files,
        }

    metadata_summary = summarize_metadata(metadata) if metadata else None
    single_name = (metadata_summary.get("filename") if metadata_summary else None) or Path(input_path).stem
    return {
        "ok": True,
        "mode": "contents",
        "archive_kind": archive_kind,
        "container": build_container_summary(input_path),
        "metadata": metadata_summary,
        "file_count": 1,
        "files": [
            {
                "filename": single_name,
            }
        ],
    }
