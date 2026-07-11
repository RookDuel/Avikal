"""
Archive creation and extraction commands for the backend CLI.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
from pathlib import Path
import shutil
from typing import Any

from ...core.secure_delete import secure_remove_file, secure_remove_tree
from ...archive.format.container import read_avk_header_and_keychain
from ...archive.format.header import extract_public_route_tags_from_keychain_pgn, parse_header_bytes
from ...archive.path_safety import resolve_safe_relative_output_path
from ...archive.pipeline.decoder import extract_avk_file
from ...archive.pipeline.multi_file_decoder import extract_multi_file_avk
from ...archive.pipeline.multi_file_encoder import create_multi_file_avk
from ..formatters import human_size, summarize_metadata
from ..inputs import (
    default_archive_output,
    ensure_input_paths_exist,
    load_keyphrase,
    load_password,
    pick_output_dir_dialog,
    pick_save_file_dialog,
    parse_unlock_datetime,
    prepare_output_file,
    resolve_encode_inputs,
    resolve_single_input,
)
from .inspect import detect_archive_kind


def _load_pqc_keyfile_password(args: argparse.Namespace, *, confirm: bool = False) -> str | None:
    if not getattr(args, "pqc_keyfile_password_prompt", False):
        return None
    password = getpass.getpass(".avkkey password: ")
    if confirm:
        repeated = getpass.getpass("Confirm .avkkey password: ")
        if password != repeated:
            raise ValueError(".avkkey passwords do not match")
    return password


def _provider_from_public_route(input_path: str) -> str | None:
    header_bytes, keychain_pgn = read_avk_header_and_keychain(input_path)
    header_info = parse_header_bytes(header_bytes)
    route_hints = extract_public_route_tags_from_keychain_pgn(keychain_pgn)
    return header_info.get("provider") or route_hints.get("provider")


def _run_core_service(coro) -> dict[str, Any]:
    try:
        return asyncio.run(coro)
    except Exception as exc:
        if exc.__class__.__name__ != "ServiceError":
            raise
        raise ValueError(str(exc)) from exc


def _commit_core_preview_to_output(core_result: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    preview_dir = Path(core_result.get("output_dir") or "").resolve()
    preview_session_id = str(core_result.get("preview_session_id") or "")
    if not preview_dir.exists() or not preview_session_id:
        raise ValueError("Provider decrypt did not return a valid preview session.")

    result = core_result.get("result") if isinstance(core_result.get("result"), dict) else {}
    files = result.get("files") if isinstance(result.get("files"), list) else []
    if not files:
        raise ValueError("Provider decrypt did not return extracted files.")

    committed_files: list[dict[str, Any]] = []
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        for file_info in files:
            source = Path(str(file_info.get("path") or file_info.get("output_file") or "")).resolve()
            try:
                source.relative_to(preview_dir)
            except ValueError as exc:
                raise ValueError("Provider decrypt returned a file outside its preview directory.") from exc
            if not source.is_file():
                raise ValueError("Provider decrypt returned a missing preview file.")

            relative_name = str(file_info.get("filename") or source.name).replace(os.sep, "/")
            final_path = Path(resolve_safe_relative_output_path(str(output_dir), relative_name))
            if final_path.exists():
                raise ValueError(f"Refusing to overwrite existing extracted file: {relative_name}")
            final_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, final_path)
            size = final_path.stat().st_size
            committed_files.append({"filename": relative_name.replace("/", os.sep), "path": str(final_path), "size": size})
    except Exception:
        for file_info in committed_files:
            secure_remove_file(file_info["path"])
        raise
    finally:
        from ...core import services

        try:
            asyncio.run(services.preview_cleanup_session({"session_id": preview_session_id}))
        except Exception:
            secure_remove_tree(preview_dir)
        else:
            secure_remove_tree(preview_dir)

    total_size = sum(file_info["size"] for file_info in committed_files)
    return {
        "ok": True,
        "mode": "decode",
        "archive_kind": "multi_file" if len(committed_files) > 1 else "single_file",
        "provider": core_result.get("provider") or "drand",
        "output_directory": str(output_dir),
        "file_count": len(committed_files),
        "total_size_bytes": total_size,
        "total_size_human": human_size(total_size),
        "files": committed_files,
    }


def encode_archive(args: argparse.Namespace) -> dict[str, Any]:
    password = load_password(args, confirm=bool(getattr(args, "password_prompt", False)))
    keyphrase = load_keyphrase(args)
    pqc_keyfile_password = _load_pqc_keyfile_password(args, confirm=True)
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
    provider = getattr(args, "timecapsule_provider", "local")
    if provider != "local" and not args.timecapsule:
        raise ValueError("Use --timecapsule together with --timecapsule-provider.")
    if provider == "drand":
        from ...core import services

        core_result = _run_core_service(
            services.archive_encrypt(
                {
                    "input_files": input_paths,
                    "output_file": output_path,
                    "password": password,
                    "keyphrase": keyphrase,
                    "unlock_datetime": unlock_dt.isoformat() if unlock_dt else None,
                    "use_timecapsule": True,
                    "timecapsule_provider": "drand",
                    "pqc_enabled": args.pqc,
                    "pqc_keyfile_output": args.pqc_keyfile_output,
                    "pqc_keyfile_protection_mode": "dual_password" if pqc_keyfile_password else "archive_secret",
                    "pqc_keyfile_password": pqc_keyfile_password,
                }
            )
        )
        return {
            "ok": True,
            "mode": "encode",
            "archive_kind": "multi_file" if len(input_paths) > 1 or any(Path(path).is_dir() for path in input_paths) else "single_file",
            "selected_input_count": len(input_paths),
            "output_file": output_path,
            "output_size_bytes": Path(output_path).stat().st_size,
            "output_size_human": human_size(Path(output_path).stat().st_size),
            "timecapsule": True,
            "timecapsule_provider": "drand",
            "pqc_enabled": bool(args.pqc),
            "drand": core_result.get("drand"),
        }

    engine_result = create_multi_file_avk(
        input_filepaths=input_paths,
        output_filepath=output_path,
        unlock_datetime=unlock_dt,
        password=password,
        keyphrase=keyphrase,
        username=args.username,
        variations_per_round=args.variations,
        use_timecapsule=args.timecapsule,
        pqc_enabled=args.pqc,
        pqc_keyfile_output=args.pqc_keyfile_output,
        pqc_keyfile_protection_mode="dual_password" if pqc_keyfile_password else "archive_secret",
        pqc_keyfile_password=pqc_keyfile_password,
    )
    archive_kind = "single_file_indexed" if len(input_paths) == 1 and Path(input_paths[0]).is_file() else "multi_file"
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
    if engine_result.get("creation_report"):
        payload["report"] = engine_result["creation_report"]
    if args.timecapsule:
        payload["timecapsule_provider"] = provider

    return payload


def decode_archive(args: argparse.Namespace) -> dict[str, Any]:
    password = load_password(args)
    keyphrase = load_keyphrase(args)
    pqc_keyfile_password = _load_pqc_keyfile_password(args)
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

    provider = _provider_from_public_route(input_path)
    if provider == "drand":
        from ...core import services

        core_result = _run_core_service(
            services.archive_decrypt(
                {
                    "input_file": input_path,
                    "output_dir": str(output_dir),
                    "password": password,
                    "keyphrase": keyphrase,
                    "pqc_keyfile": args.pqc_keyfile,
                    "pqc_keyfile_password": pqc_keyfile_password,
                }
            )
        )
        return _commit_core_preview_to_output(core_result, output_dir)
    if provider == "aavrit":
        raise ValueError("Aavrit time-capsule CLI decrypt requires Aavrit authentication and is not enabled in this CLI release.")

    archive_kind, metadata = detect_archive_kind(
        input_path,
        password=password,
        keyphrase=keyphrase,
        # skip_timelock=True here: this call is only for archive-type detection
        # (single vs. multi-file). The time-lock is enforced inside the pipeline
        # decoders that follow. Using False crashes the CLI on any locked archive.
        skip_timelock=True,
        pqc_keyfile_path=args.pqc_keyfile,
        pqc_keyfile_password=pqc_keyfile_password,
    )

    if archive_kind == "multi_file":
        decoded_result = extract_multi_file_avk(
            avk_filepath=input_path,
            output_directory=str(output_dir),
            password=password,
            keyphrase=keyphrase,
            pqc_keyfile_path=args.pqc_keyfile,
            pqc_keyfile_password=pqc_keyfile_password,
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
        password=password,
        keyphrase=keyphrase,
        pqc_keyfile_path=args.pqc_keyfile,
        pqc_keyfile_password=pqc_keyfile_password,
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
