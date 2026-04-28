"""
Input normalization helpers for the backend CLI.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def normalize_input_paths(values: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        resolved = str(Path(raw).expanduser().resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        normalized.append(resolved)
    return normalized


def ensure_input_paths_exist(paths: list[str]) -> None:
    missing = [path for path in paths if not Path(path).exists()]
    if missing:
        raise ValueError(f"Input path not found: {missing[0]}")


def _create_dialog_root():
    try:
        import tkinter as tk
    except Exception as exc:
        raise ValueError("System file picker is unavailable in this Python runtime.") from exc

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    return root


def pick_files_dialog(*, title: str, multiple: bool = True, filetypes: Iterable[tuple[str, str]] | None = None) -> list[str]:
    root = _create_dialog_root()
    try:
        from tkinter import filedialog

        if multiple:
            selected = filedialog.askopenfilenames(title=title, filetypes=list(filetypes or []))
            return [str(Path(path).resolve()) for path in selected if path]

        selected = filedialog.askopenfilename(title=title, filetypes=list(filetypes or []))
        return [str(Path(selected).resolve())] if selected else []
    finally:
        root.destroy()


def pick_folder_dialog(*, title: str) -> str | None:
    root = _create_dialog_root()
    try:
        from tkinter import filedialog

        selected = filedialog.askdirectory(title=title, mustexist=True)
        return str(Path(selected).resolve()) if selected else None
    finally:
        root.destroy()


def pick_save_file_dialog(*, title: str, default_path: str | None = None, default_extension: str = ".avk") -> str | None:
    root = _create_dialog_root()
    try:
        from tkinter import filedialog

        initialdir = None
        initialfile = None
        if default_path:
            candidate = Path(default_path).expanduser()
            initialdir = str(candidate.parent.resolve()) if candidate.parent else None
            initialfile = candidate.name

        selected = filedialog.asksaveasfilename(
            title=title,
            defaultextension=default_extension,
            filetypes=[("Avikal archive", "*.avk"), ("All files", "*.*")],
            initialdir=initialdir,
            initialfile=initialfile,
        )
        return str(Path(selected).resolve()) if selected else None
    finally:
        root.destroy()


def pick_output_dir_dialog(*, title: str) -> str | None:
    root = _create_dialog_root()
    try:
        from tkinter import filedialog

        selected = filedialog.askdirectory(title=title, mustexist=False)
        return str(Path(selected).resolve()) if selected else None
    finally:
        root.destroy()


def default_archive_output(inputs: list[str]) -> str:
    if len(inputs) == 1:
        return inputs[0] + ".avk"
    first = Path(inputs[0])
    stem = first.stem or first.name or "avikal-bundle"
    return str(first.with_name(f"{stem}-bundle.avk"))


def prepare_output_file(path_value: str, *, force: bool) -> str:
    output_path = Path(path_value).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists() and not force:
        raise ValueError(f"Output file already exists: {output_path}. Use --force to overwrite.")
    return str(output_path)


def load_keyphrase(args: argparse.Namespace) -> list[str] | None:
    if args.keyphrase and args.keyphrase_file:
        raise ValueError("Use either --keyphrase or --keyphrase-file, not both.")

    if args.keyphrase_file:
        content = Path(args.keyphrase_file).read_text(encoding="utf-8").strip()
        words = [word for word in content.split() if word]
        return words or None

    if args.keyphrase:
        words = [word for word in args.keyphrase.split() if word]
        return words or None

    return None


def resolve_encode_inputs(args: argparse.Namespace) -> list[str]:
    values = list(args.inputs or [])

    if getattr(args, "pick_files", False):
        values.extend(
            pick_files_dialog(
                title="Select files to archive",
                multiple=True,
                filetypes=[("All files", "*.*")],
            )
        )

    if getattr(args, "pick_folder", False):
        selected_folder = pick_folder_dialog(title="Select folder to archive")
        if selected_folder:
            values.append(selected_folder)

    normalized = normalize_input_paths(values)
    if not normalized:
        raise ValueError("No input files or folders were provided. Use paths or picker options.")
    return normalized


def resolve_single_input(
    path_value: str | None,
    *,
    pick: bool,
    title: str,
    filetypes: Iterable[tuple[str, str]] | None = None,
) -> str:
    if path_value:
        return str(Path(path_value).expanduser().resolve())

    if pick:
        selected = pick_files_dialog(title=title, multiple=False, filetypes=filetypes)
        if selected:
            return selected[0]

    raise ValueError("No input file was provided. Use a path or --pick.")


def parse_unlock_datetime(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        local_dt = datetime.strptime(raw, "%Y-%m-%d %H:%M").replace(tzinfo=local_tz)
        return local_dt.astimezone(timezone.utc)
    except ValueError as exc:
        raise ValueError('Invalid unlock time format. Use "YYYY-MM-DD HH:MM".') from exc
