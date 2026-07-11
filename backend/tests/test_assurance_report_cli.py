from __future__ import annotations

from avikal_backend.cli.parser import build_parser


def test_verify_report_command_is_registered():
    args = build_parser().parse_args(["verify-report", "report.json", "--json"])
    assert args.command == "verify-report"
    assert args.input == "report.json"
    assert args.json is True
    assert args.handler.__name__ == "verify_report_file"
