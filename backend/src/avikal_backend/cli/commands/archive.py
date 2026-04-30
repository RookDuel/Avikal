"""
Archive creation and extraction commands for the backend CLI.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ...archive.pipeline.decoder import extract_avk_file
from ...archive.pipeline.encoder import create_avk_file
from ...archive.pipeline.multi_file_decoder import extract_multi_file_avk
from ...archive.pipeline.multi_file_encoder import create_multi_file_avk
from ..formatters import human_size, summarize_metadata
from ..inputs import (
    default_archive_output,
    ensure_input_paths_exist,
    load_keyphrase,
    pick_output_dir_dialog,
    pick_save_file_dialog,
    parse_unlock_datetime,
    prepare_output_file,
    resolve_encode_inputs,
    resolve_single_input,
)
from .inspect import detect_archive_kind


def encode_archive(args: argparse.Namespace) -> dict[str, Any]:
    keyphrase = load_keyphrase(args)
    unlock_dt = parse_unlock_datetime(args.unlock)
    if args.timecapsule and not unlock_dt:
        raise ValueError("Time-capsule mode requires --unlock.")
    if unlock_dt and not args.timecapsule:
        raise ValueError("Use --timecapsule together with --unlock.")

    input_paths = resolve_encode_inputs(args)
    ensure_input_paths_exist(input_paths)

    output_candidate = args.output or default_archive_output(input_paths)
    if getattr(args, "pick_output", False):
        selected_output = pick_save_file_dialog(
            title="Choose archive output location",
            default_path=output_candidate,
            default_extension=".avk",
        )
        if selected_output:
            output_candidate = selected_output

    output_path = prepare_output_file(
        output_candidate,
        force=args.force,
    )

    if len(input_paths) == 1 and Path(input_paths[0]).is_file():
        engine_result = create_avk_file(
            input_filepath=input_paths[0],
            output_filepath=output_path,
            unlock_datetime=unlock_dt,
            password=args.password,
            keyphrase=keyphrase,
            username=args.username,
            variations_per_round=args.variations,
            use_timecapsule=args.timecapsule,
            pqc_enabled=args.pqc,
            pqc_keyfile_output=args.pqc_keyfile_output,
        )
        archive_kind = "single_file"
        selected_input_count = 1
    else:
        engine_result = create_multi_file_avk(
            input_filepaths=input_paths,
            output_filepath=output_path,
            unlock_datetime=unlock_dt,
            password=args.password,
            keyphrase=keyphrase,
            username=args.username,
            variations_per_round=args.variations,
            use_timecapsule=args.timecapsule,
            pqc_enabled=args.pqc,
            pqc_keyfile_output=args.pqc_keyfile_output,
        )
        archive_kind = "multi_file"
        selected_input_count = len(input_paths)

    payload: dict[str, Any] = {
        "ok": True,
        "mode": "encode",
        "archive_kind": archive_kind,
        "selected_input_count": selected_input_count,
        "output_file": output_path,
        "output_size_bytes": Path(output_path).stat().st_size,
        "output_size_human": human_size(Path(output_path).stat().st_size),
        "timecapsule": bool(args.timecapsule),
        "pqc_enabled": bool(args.pqc),
    }

    if engine_result.get("pqc"):
        payload["pqc"] = engine_result["pqc"]
    if engine_result.get("file_count") is not None:
        payload["file_count"] = engine_result["file_count"]
    if engine_result.get("total_size") is not None:
        payload["total_size_bytes"] = engine_result["total_size"]
        payload["total_size_human"] = human_size(engine_result["total_size"])
    if engine_result.get("telemetry"):
        payload["telemetry"] = engine_result["telemetry"]

    return payload


def decode_archive(args: argparse.Namespace) -> dict[str, Any]:
    keyphrase = load_keyphrase(args)
    input_path = resolve_single_input(
        args.input,
        pick=getattr(args, "pick", False),
        title="Select Avikal archive to decode",
        filetypes=[("Avikal archive", "*.avk"), ("All files", "*.*")],
    )
    if not Path(input_path).exists():
        raise ValueError(f"Input file not found: {input_path}")

    output_dir_value = args.output_dir
    if getattr(args, "pick_output_dir", False):
        selected_output_dir = pick_output_dir_dialog(title="Select output folder for extraction")
        if selected_output_dir:
            output_dir_value = selected_output_dir

    output_dir = Path(output_dir_value).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    archive_kind, metadata = detect_archive_kind(
        input_path,
        password=args.password,
        keyphrase=keyphrase,
        # skip_timelock=True here: this call is only for archive-type detection
        # (single vs. multi-file). The time-lock is enforced inside the pipeline
        # decoders that follow. Using False crashes the CLI on any locked archive.
        skip_timelock=True,
    )

    if archive_kind == "multi_file":
        decoded_result = extract_multi_file_avk(
            avk_filepath=input_path,
            output_directory=str(output_dir),
            password=args.password,
            keyphrase=keyphrase,
            pqc_keyfile_path=args.pqc_keyfile,
        )
        return {
            "ok": True,
            "mode": "decode",
            "archive_kind": archive_kind,
            "output_directory": str(output_dir),
            "file_count": decoded_result["file_count"],
            "total_size_bytes": decoded_result["total_size"],
            "total_size_human": human_size(decoded_result["total_size"]),
            "files": decoded_result["files"],
            "metadata": summarize_metadata(metadata) if metadata else None,
        }

    extracted_path = extract_avk_file(
        avk_filepath=input_path,
        output_directory=str(output_dir),
        password=args.password,
        keyphrase=keyphrase,
        pqc_keyfile_path=args.pqc_keyfile,
    )
    extracted_file = Path(extracted_path)
    return {
        "ok": True,
        "mode": "decode",
        "archive_kind": archive_kind,
        "output_file": str(extracted_file),
        "output_size_bytes": extracted_file.stat().st_size,
        "output_size_human": human_size(extracted_file.stat().st_size),
        "metadata": summarize_metadata(metadata) if metadata else None,
    }
