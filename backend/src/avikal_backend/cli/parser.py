"""
Argument parser construction for the backend CLI.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import argparse
import textwrap

from .. import __version__
from .commands import (
    contents_archive,
    decode_archive,
    doctor_backend,
    encode_archive,
    inspect_archive,
    validate_archive,
)
from .formatters import style_heading, style_label, style_muted


class AvikalHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog: str):
        super().__init__(prog, max_help_position=30, width=100)

    def start_section(self, heading: str) -> None:
        super().start_section(style_heading(heading.title()))

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            return super()._format_action_invocation(action)
        return style_label(super()._format_action_invocation(action))


class AvikalArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        help_text = super().format_help()
        banner = textwrap.dedent(
            f"""
            {style_heading('Avikal CLI')}
            {style_muted('Professional archive operations for secure archives, inspection, and runtime checks')}
            """
        ).strip()
        return f"{banner}\n\n{help_text}"


def _add_secret_inputs(parser: argparse.ArgumentParser, *, password_help: str, keyphrase_help: str) -> None:
    access_group = parser.add_argument_group("Access Credentials")
    access_group.add_argument("--password", "-p", help=password_help)
    access_group.add_argument("--keyphrase", help=keyphrase_help)
    access_group.add_argument("--keyphrase-file", "-K", help="Read the 21-word keyphrase from a UTF-8 text file")


def _add_pick_input(parser: argparse.ArgumentParser, *, action_help: str) -> None:
    source_group = parser.add_argument_group("Source Selection")
    source_group.add_argument("input", nargs="?", help="Input .avk file path")
    source_group.add_argument("--pick", "-P", action="store_true", help=action_help)


def build_parser() -> argparse.ArgumentParser:
    parser = AvikalArgumentParser(
        prog="avikal",
        description="Create, extract, inspect, validate, and diagnose Avikal archives from one CLI.",
        formatter_class=AvikalHelpFormatter,
        epilog=textwrap.dedent(
            """
            Command Guide:
              encode / enc      Create a new .avk archive from files or folders
              decode / dec      Extract an .avk archive to a directory
              inspect / info    Read container and metadata details without extraction
              contents / ls     List the logical files stored in an archive
              validate / check  Confirm container structure and optional metadata access
              doctor / diag     Verify Python/runtime readiness and optional Aavrit connectivity

            Quick Start:
              avikal enc document.pdf -p "StrongPass#123"
              avikal enc --pick-files --pick-output -p "StrongPass#123"
              avikal enc --pick-folder --timecapsule -u "2026-05-01 12:00" -p "StrongPass#123"
              avikal dec locked.avk -d output -p "StrongPass#123"
              avikal info locked.avk -p "StrongPass#123"
              avikal ls locked.avk -p "StrongPass#123"
              avikal check locked.avk
              avikal doctor --aavrit-url https://aavrit.example

            Python module entrypoints:
              python -m avikal_backend.cli --help
              python -m avikal_backend enc document.pdf -p "StrongPass#123"

            Help Tips:
              avikal <command> --help
              avikal enc --help
              avikal doctor --help
            """
        ),
    )
    parser.add_argument("--version", action="version", version=f"Avikal backend {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="command", help="Available commands")

    encode_parser = subparsers.add_parser(
        "encode",
        aliases=["enc"],
        help="Create an .avk archive (alias: enc)",
        description="Create a single-file, multi-file, or folder-backed Avikal archive with password, keyphrase, PQC, and optional time-lock protection.",
        formatter_class=AvikalHelpFormatter,
        epilog=textwrap.dedent(
            """
            What this command does:
              - Accepts one file, several files, or a full folder as input
              - Produces one .avk archive
              - Can add password, keyphrase, PQC keyfile, and time-lock protection

            Common examples:
              avikal enc document.pdf -p "StrongPass#123"
              avikal enc photo.jpg notes.txt -o bundle.avk -p "StrongPass#123"
              avikal enc --pick-folder --pick-output -p "StrongPass#123"
              avikal enc reports --timecapsule -u "2026-05-01 12:00" -p "StrongPass#123"
              avikal enc secret.docx -p "StrongPass#123" --pqc

            Notes:
              - Use either --keyphrase or --keyphrase-file, not both.
              - Time-lock mode requires both --timecapsule and --unlock.
              - If the output file already exists, add --force to overwrite it.
            """
        ),
    )
    encode_inputs = encode_parser.add_argument_group("Input Selection")
    encode_inputs.add_argument("inputs", nargs="*", help="One or more input files or folders")
    encode_inputs.add_argument("--pick-files", "-F", action="store_true", help="Open the file picker and add one or more files")
    encode_inputs.add_argument("--pick-folder", "-D", action="store_true", help="Open the folder picker and add one folder")

    encode_protection = encode_parser.add_argument_group("Protection")
    encode_protection.add_argument("--password", "-p", help="Password used to protect the archive")
    encode_protection.add_argument("--keyphrase", help="Space-separated 21-word keyphrase wrapped in quotes")
    encode_protection.add_argument("--keyphrase-file", "-K", help="Read the 21-word keyphrase from a UTF-8 text file")
    encode_protection.add_argument("--pqc", action="store_true", help="Generate and require an external .avkkey file for decryption")
    encode_protection.add_argument("--pqc-keyfile-output", help="Custom output path for the generated .avkkey file")

    encode_timelock = encode_parser.add_argument_group("Time Lock")
    encode_timelock.add_argument("--timecapsule", action="store_true", help="Enable time-lock protection for the archive")
    encode_timelock.add_argument("--unlock", "-u", help='Unlock date and time in your local timezone using "YYYY-MM-DD HH:MM"')

    encode_tuning = encode_parser.add_argument_group("Archive Settings")
    encode_tuning.add_argument("--username", default="", help="Optional archive signature or username label")
    encode_tuning.add_argument("--variations", "-v", type=int, default=5, help="Chess-encoding variations per round")

    encode_output = encode_parser.add_argument_group("Output")
    encode_output.add_argument("--pick-output", "-O", action="store_true", help="Open the save dialog to choose the .avk destination")
    encode_output.add_argument("--output", "-o", help="Output .avk file path")
    encode_output.add_argument("--force", action="store_true", help="Overwrite the output archive if it already exists")

    encode_automation = encode_parser.add_argument_group("Automation")
    encode_automation.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    encode_parser.set_defaults(handler=encode_archive)

    decode_parser = subparsers.add_parser(
        "decode",
        aliases=["dec", "extract"],
        help="Extract an .avk archive (aliases: dec, extract)",
        description="Extract an archive into a target directory using the required password, keyphrase, and optional PQC keyfile.",
        formatter_class=AvikalHelpFormatter,
        epilog=textwrap.dedent(
            """
            What this command does:
              - Opens an existing .avk archive
              - Detects whether it is a single-file or multi-file archive
              - Extracts the payload into the selected output directory

            Common examples:
              avikal dec locked.avk -d output -p "StrongPass#123"
              avikal dec locked.avk -d output --keyphrase-file phrase.txt
              avikal dec locked.avk -d output -p "StrongPass#123" --pqc-keyfile locked.avkkey
              avikal dec --pick --pick-output-dir -p "StrongPass#123"
            """
        ),
    )
    decode_source = decode_parser.add_argument_group("Source Selection")
    decode_source.add_argument("input", nargs="?", help="Input .avk file path")
    decode_source.add_argument("--pick", "-P", action="store_true", help="Open the file picker to choose an input .avk archive")

    _add_secret_inputs(
        decode_parser,
        password_help="Password used to decrypt the archive",
        keyphrase_help="Space-separated 21-word keyphrase wrapped in quotes",
    )

    decode_output = decode_parser.add_argument_group("Output")
    decode_output.add_argument("--pick-output-dir", "-O", action="store_true", help="Open the folder picker to choose the extraction directory")
    decode_output.add_argument("--output-dir", "-d", default=".", help="Extraction directory")

    decode_optional = decode_parser.add_argument_group("Optional Inputs")
    decode_optional.add_argument("--pqc-keyfile", help="Path to the external .avkkey file")

    decode_automation = decode_parser.add_argument_group("Automation")
    decode_automation.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    decode_parser.set_defaults(handler=decode_archive)

    inspect_parser = subparsers.add_parser(
        "inspect",
        aliases=["info"],
        help="Inspect archive metadata (alias: info)",
        description="Read container and metadata details without extracting payload contents.",
        formatter_class=AvikalHelpFormatter,
        epilog=textwrap.dedent(
            """
            What this command does:
              - Reads archive container information immediately
              - Optionally decrypts metadata when you provide access credentials
              - Never writes extracted payload files

            Common examples:
              avikal info locked.avk
              avikal info locked.avk -p "StrongPass#123"
              avikal info locked.avk --keyphrase-file phrase.txt
              avikal info locked.avk -p "StrongPass#123" --skip-timelock
            """
        ),
    )
    _add_pick_input(inspect_parser, action_help="Open the file picker to choose an input .avk archive")
    _add_secret_inputs(
        inspect_parser,
        password_help="Optional password used to decrypt metadata",
        keyphrase_help="Optional 21-word keyphrase wrapped in quotes",
    )
    inspect_options = inspect_parser.add_argument_group("Inspection Controls")
    inspect_options.add_argument("--skip-timelock", action="store_true", help="Attempt metadata inspection even before the unlock time")
    inspect_options.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    inspect_parser.set_defaults(handler=inspect_archive)

    contents_parser = subparsers.add_parser(
        "contents",
        aliases=["ls", "list"],
        help="List logical archive contents (aliases: ls, list)",
        description="List the logical files stored in an archive without fully extracting them.",
        formatter_class=AvikalHelpFormatter,
        epilog=textwrap.dedent(
            """
            What this command does:
              - Lists the logical files represented by the archive
              - Shows filenames, sizes, and checksums for multi-file archives
              - Helps confirm archive contents before extraction

            Common examples:
              avikal ls locked.avk -p "StrongPass#123"
              avikal ls locked.avk --keyphrase-file phrase.txt
              avikal ls locked.avk -p "StrongPass#123" --pqc-keyfile locked.avkkey
            """
        ),
    )
    _add_pick_input(contents_parser, action_help="Open the file picker to choose an input .avk archive")
    _add_secret_inputs(
        contents_parser,
        password_help="Optional password used to inspect contents",
        keyphrase_help="Optional 21-word keyphrase wrapped in quotes",
    )
    contents_options = contents_parser.add_argument_group("Inspection Controls")
    contents_options.add_argument("--pqc-keyfile", help="Path to the external .avkkey file for PQC-protected multi-file archives")
    contents_options.add_argument("--skip-timelock", action="store_true", help="Attempt listing contents even before the unlock time")
    contents_options.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    contents_parser.set_defaults(handler=contents_archive)

    validate_parser = subparsers.add_parser(
        "validate",
        aliases=["check"],
        help="Validate archive integrity (alias: check)",
        description="Validate archive structure and, when credentials are supplied, confirm metadata can be decrypted and verified.",
        formatter_class=AvikalHelpFormatter,
        epilog=textwrap.dedent(
            """
            What this command does:
              - Confirms the archive container is readable
              - Optionally verifies that metadata can be decrypted
              - Helps distinguish a structurally valid archive from one you can actually open

            Common examples:
              avikal check locked.avk
              avikal check locked.avk -p "StrongPass#123"
              avikal check locked.avk --keyphrase-file phrase.txt --skip-timelock
            """
        ),
    )
    _add_pick_input(validate_parser, action_help="Open the file picker to choose an input .avk archive")
    _add_secret_inputs(
        validate_parser,
        password_help="Optional password used to validate metadata access",
        keyphrase_help="Optional 21-word keyphrase wrapped in quotes",
    )
    validate_options = validate_parser.add_argument_group("Validation Controls")
    validate_options.add_argument("--skip-timelock", action="store_true", help="Attempt metadata validation even before the unlock time")
    validate_options.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    validate_parser.set_defaults(handler=validate_archive)

    doctor_parser = subparsers.add_parser(
        "doctor",
        aliases=["diag"],
        help="Check backend runtime readiness (alias: diag)",
        description="Probe Python/runtime dependencies, filesystem access, and optional Aavrit endpoint health in one report.",
        formatter_class=AvikalHelpFormatter,
        epilog=textwrap.dedent(
            """
            What this command does:
              - Verifies required Python packages can be imported
              - Checks that the current working directory is writable
              - Optionally probes Aavrit /health and /config endpoints

            Common examples:
              avikal diag
              avikal diag --aavrit-url https://aavrit.example
              avikal diag --aavrit-url https://aavrit.example --timeout 5

            Notes:
              - --aavrit-url is the primary flag.
              - --aavrit-url is still accepted as a compatibility alias for the CLI flag name only.
            """
        ),
    )
    doctor_checks = doctor_parser.add_argument_group("Connectivity Checks")
    doctor_checks.add_argument("--aavrit-url", "--aavrit-url", dest="aavrit_url", help="Optional Aavrit base URL to probe")
    doctor_checks.add_argument("--timeout", "-t", type=float, default=10.0, help="HTTP timeout in seconds for Aavrit probes")

    doctor_output = doctor_parser.add_argument_group("Automation")
    doctor_output.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    doctor_parser.set_defaults(handler=doctor_backend)

    return parser
