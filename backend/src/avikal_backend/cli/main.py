"""
Top-level CLI entrypoint for the Avikal backend.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import argparse
import sys

from .formatters import emit_error, emit_result
from .parser import build_parser
from ..runtime_requirements import ensure_native_crypto_runtime


def _run_command(handler, args: argparse.Namespace) -> int:
    try:
        emit_result(handler(args), args.json)
        return 0
    except Exception as exc:
        emit_error(str(exc), context="Use --json for machine-readable output or --help for command usage.")
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 1

    if getattr(handler, "__name__", "") != "doctor_backend":
        try:
            ensure_native_crypto_runtime("Avikal CLI")
        except RuntimeError as exc:
            emit_error(str(exc), context="Install a native-backed Avikal package or rebuild the backend extension.")
            return 1

    return _run_command(handler, args)
