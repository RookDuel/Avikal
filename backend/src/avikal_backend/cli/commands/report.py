"""Offline assurance-report verification."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ...archive.reporting import load_and_verify_assurance_report


def verify_report_file(args: argparse.Namespace) -> dict[str, Any]:
    report_path = Path(args.input).expanduser().resolve()
    result = load_and_verify_assurance_report(report_path)
    return {
        "ok": True,
        "mode": "verify_report",
        "report_file": str(report_path),
        "verification": result,
    }
