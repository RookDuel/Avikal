"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from argparse import Namespace
import importlib
from pathlib import Path
from types import SimpleNamespace
import tomllib

from setuptools import find_packages

from avikal_backend.cli.commands import archive as archive_commands
from avikal_backend.cli.commands.doctor import doctor_backend
from avikal_backend.cli.commands.doctor import EXPECTED_HYBRID_KEM
from avikal_backend.cli.commands.doctor import REQUIRED_RUNTIME_IMPORTS
from avikal_backend.cli.inputs import load_password
from avikal_backend.cli.parser import build_parser


cli_main_module = importlib.import_module("avikal_backend.cli.main")


def test_cli_help_includes_aliases_and_command_guide():
    parser = build_parser()

    help_text = parser.format_help()

    assert "Command Guide:" in help_text
    assert "encode / enc" in help_text
    assert "contents / ls" in help_text
    assert "rekey / rotate" in help_text
    assert "doctor / diag" in help_text
    assert "Help Tips:" in help_text


def test_cli_short_aliases_resolve_to_expected_handlers():
    parser = build_parser()

    assert parser.parse_args(["enc", "alpha.txt"]).handler.__name__ == "encode_archive"
    assert parser.parse_args(["dec", "alpha.avk"]).handler.__name__ == "decode_archive"
    assert parser.parse_args(["info", "alpha.avk"]).handler.__name__ == "inspect_archive"
    assert parser.parse_args(["ls", "alpha.avk"]).handler.__name__ == "contents_archive"
    assert parser.parse_args(["check", "alpha.avk"]).handler.__name__ == "validate_archive"
    assert parser.parse_args(["rotate", "alpha.avk"]).handler.__name__ == "rekey_archive"
    assert parser.parse_args(["diag"]).handler.__name__ == "doctor_backend"


def test_doctor_accepts_aavrit_url_flag():
    parser = build_parser()

    args = parser.parse_args(["diag", "--aavrit-url", "https://example.com", "--timeout", "5"])

    assert args.aavrit_url == "https://example.com"
    assert args.timeout == 5.0


def test_cli_secure_password_input_modes_parse():
    parser = build_parser()

    enc_args = parser.parse_args(["enc", "alpha.txt", "--password-prompt"])
    dec_args = parser.parse_args(["dec", "alpha.avk", "--password-stdin"])

    assert enc_args.password_prompt is True
    assert enc_args.password is None
    assert dec_args.password_stdin is True
    assert dec_args.password is None


def test_cli_drand_timecapsule_provider_parses():
    parser = build_parser()

    args = parser.parse_args([
        "enc",
        "alpha.txt",
        "--timecapsule",
        "--timecapsule-provider",
        "drand",
        "--unlock",
        "2026-05-01 12:00",
    ])

    assert args.timecapsule is True
    assert args.timecapsule_provider == "drand"


def test_cli_rekey_password_roles_parse():
    parser = build_parser()

    args = parser.parse_args(["rekey", "alpha.avk", "--old-password-prompt", "--new-password-prompt"])

    assert args.handler.__name__ == "rekey_archive"
    assert args.old_password_prompt is True
    assert args.new_password_prompt is True


def test_load_password_rejects_multiple_input_modes():
    args = Namespace(password="secret", password_prompt=True, password_stdin=False)

    try:
        load_password(args)
    except ValueError as exc:
        assert "only one password input mode" in str(exc)
    else:
        raise AssertionError("load_password accepted conflicting password modes")


def test_load_password_from_stdin(monkeypatch):
    class FakeStdin:
        def readline(self):
            return "ScriptSecret#123\n"

    monkeypatch.setattr("avikal_backend.cli.inputs.sys.stdin", FakeStdin())

    assert load_password(Namespace(password=None, password_prompt=False, password_stdin=True)) == "ScriptSecret#123"


def test_doctor_reports_aavrit_checks_without_raising_on_probe_failures(monkeypatch):
    responses = {
        "https://aavrit.example/health": SimpleNamespace(ok=True, status_code=200),
        "https://aavrit.example/config": RuntimeError("boom"),
    }

    def fake_get(url, timeout):
        response = responses[url]
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr("avikal_backend.cli.commands.doctor.requests.get", fake_get)

    result = doctor_backend(Namespace(aavrit_url="https://aavrit.example", timeout=2.5))

    assert result["ok"] is False
    assert result["checks"]["aavrit"]["base_url"] == "https://aavrit.example"
    assert result["checks"]["aavrit"]["timeout_seconds"] == 2.5
    assert result["checks"]["aavrit"]["health"]["ok"] is True
    assert result["checks"]["aavrit"]["config"]["ok"] is False
    assert "error" in result["checks"]["aavrit"]["config"]


def test_doctor_reports_hybrid_pqc_suite_readiness(monkeypatch):
    def fake_provider_status():
        return {
            "available": True,
            "provider": "openssl",
            "suite": {
                "suite_id": "avikal-pqc-openssl-hybrid-kem-triple-stack-v1",
                "algorithms": {
                    "kem": EXPECTED_HYBRID_KEM,
                },
            },
        }

    monkeypatch.setattr("avikal_backend.cli.commands.doctor.provider_status", fake_provider_status)

    result = doctor_backend(Namespace(aavrit_url=None, timeout=2.5))

    assert result["checks"]["pqc_hybrid_suite"]["ok"] is True
    assert result["checks"]["pqc_hybrid_suite"]["expected_kem"] == EXPECTED_HYBRID_KEM
    assert result["checks"]["pqc_hybrid_suite"]["reported_kem"] == EXPECTED_HYBRID_KEM


def test_doctor_reports_native_crypto_status(monkeypatch):
    monkeypatch.setattr(
        "avikal_backend.cli.commands.doctor.get_native_runtime_status",
        lambda: SimpleNamespace(available=True, import_error=None),
    )

    result = doctor_backend(Namespace(aavrit_url=None, timeout=2.5))

    assert result["checks"]["native_crypto"]["available"] is True
    assert result["checks"]["native_crypto"]["import_error"] is None


def test_cli_main_fails_closed_when_native_runtime_is_missing(monkeypatch):
    monkeypatch.setattr(
        cli_main_module,
        "ensure_native_crypto_runtime",
        lambda _surface: (_ for _ in ()).throw(RuntimeError("native runtime missing")),
    )

    exit_code = cli_main_module.main(["enc", "alpha.txt", "--password", "secret"])

    assert exit_code == 1


def test_cli_doctor_is_allowed_to_run_without_native_runtime(monkeypatch):
    monkeypatch.setattr(
        cli_main_module,
        "ensure_native_crypto_runtime",
        lambda _surface: (_ for _ in ()).throw(RuntimeError("native runtime missing")),
    )
    monkeypatch.setattr(
        "avikal_backend.cli.commands.doctor.get_native_runtime_status",
        lambda: SimpleNamespace(available=False, import_error="native runtime missing"),
    )

    exit_code = cli_main_module.main(["doctor", "--json"])

    assert exit_code == 0


def test_doctor_runtime_imports_match_cli_scope():
    assert "requests" in REQUIRED_RUNTIME_IMPORTS
    assert "cryptography" in REQUIRED_RUNTIME_IMPORTS
    assert "pqcrypto" not in REQUIRED_RUNTIME_IMPORTS
    assert "fastapi" not in REQUIRED_RUNTIME_IMPORTS
    assert "uvicorn" not in REQUIRED_RUNTIME_IMPORTS
    assert "jwt" not in REQUIRED_RUNTIME_IMPORTS


def test_pyproject_scopes_pypi_package_to_cli_and_shared_core():
    backend_root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((backend_root / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["name"] == "avikal"
    assert pyproject["project"]["description"] == "Avikal CLI and shared archive engine for secure .avk workflows."
    assert "exclude" not in pyproject["tool"]["setuptools"]["packages"]["find"]
    assert pyproject["tool"]["setuptools"]["dynamic"]["dependencies"]["file"] == ["requirements-cli.txt"]


def test_cli_requirements_file_excludes_desktop_api_dependencies():
    backend_root = Path(__file__).resolve().parents[1]
    requirements = (backend_root / "requirements-cli.txt").read_text(encoding="utf-8")

    assert "requests==" in requirements
    assert "cryptography==" in requirements
    assert "pqcrypto==" not in requirements
    assert "liboqs" not in requirements
    assert "fastapi==" not in requirements
    assert "uvicorn==" not in requirements
    assert "python-multipart==" not in requirements
    assert "PyJWT==" not in requirements


def test_setuptools_package_discovery_keeps_cli_support_modules():
    backend_root = Path(__file__).resolve().parents[1]
    packages = find_packages(where=str(backend_root / "src"))

    assert "avikal_backend" in packages
    assert "avikal_backend.cli" in packages
    assert "avikal_backend.archive" in packages
    assert "avikal_backend.services" in packages
    assert "avikal_backend.audit" in packages


def test_cli_commits_provider_preview_to_requested_output_dir(tmp_path):
    preview_dir = tmp_path / "preview"
    preview_dir.mkdir()
    source = preview_dir / "nested" / "report.txt"
    source.parent.mkdir()
    source.write_text("drand output", encoding="utf-8")
    output_dir = tmp_path / "out"

    result = archive_commands._commit_core_preview_to_output(
        {
            "output_dir": str(preview_dir),
            "preview_session_id": "session-1",
            "provider": "drand",
            "result": {
                "files": [
                    {
                        "filename": "nested/report.txt",
                        "path": str(source),
                        "size": source.stat().st_size,
                    }
                ]
            },
        },
        output_dir,
    )

    assert result["ok"] is True
    assert result["provider"] == "drand"
    assert (output_dir / "nested" / "report.txt").read_text(encoding="utf-8") == "drand output"
    assert not preview_dir.exists()
