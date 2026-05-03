"""
Rekey command for rotating Avikal archive credentials.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ...archive.pipeline.rekey import rekey_avk_archive
from ..formatters import human_size
from ..inputs import load_keyphrase_fields, load_password_fields, resolve_single_input


def rekey_archive(args: argparse.Namespace) -> dict[str, Any]:
    input_path = resolve_single_input(
        args.input,
        pick=getattr(args, "pick", False),
        title="Select Avikal archive to rekey",
        filetypes=[("Avikal archive", "*.avk"), ("All files", "*.*")],
    )
    if not Path(input_path).exists():
        raise ValueError(f"Input file not found: {input_path}")

    old_password = load_password_fields(
        args,
        password_attr="old_password",
        prompt_attr="old_password_prompt",
        stdin_attr="old_password_stdin",
        prompt_label="Current password",
    )
    new_password = load_password_fields(
        args,
        password_attr="new_password",
        prompt_attr="new_password_prompt",
        stdin_attr="new_password_stdin",
        prompt_label="New password",
        confirm=bool(getattr(args, "new_password_prompt", False)),
    )
    old_keyphrase = load_keyphrase_fields(
        args,
        keyphrase_attr="old_keyphrase",
        keyphrase_file_attr="old_keyphrase_file",
    )
    new_keyphrase = load_keyphrase_fields(
        args,
        keyphrase_attr="new_keyphrase",
        keyphrase_file_attr="new_keyphrase_file",
    )

    result = rekey_avk_archive(
        input_path,
        old_password=old_password,
        old_keyphrase=old_keyphrase,
        new_password=new_password,
        new_keyphrase=new_keyphrase,
        output_filepath=args.output,
        variations_per_round=args.variations,
        force=bool(args.force),
    )
    output_path = Path(result["output_file"])
    result["output_size_bytes"] = output_path.stat().st_size
    result["output_size_human"] = human_size(output_path.stat().st_size)
    return result
