"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import shutil
import uuid

import pytest

from avikal_backend.archive.pipeline.decoder import extract_avk_file_enhanced
from avikal_backend.archive.pipeline.encoder import create_avk_file_enhanced
from avikal_backend.mnemonic.generator import HindiMnemonic
from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk
from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
from avikal_backend.archive.security.pqc_provider import PQC_SUITE_ID, provider_status


PASSWORD = "AvikalStrongPass!9Zeta"
WRONG_PASSWORD = "WrongPass!9Theta"


VALID_PROTECTION_CASES = [
    ("single", "password", True, False, False),
    ("single", "keyphrase", False, True, False),
    ("single", "password_keyphrase", True, True, False),
    ("multi_file", "password", True, False, False),
    ("multi_file", "keyphrase", False, True, False),
    ("multi_file", "password_keyphrase", True, True, False),
    ("multi_folder", "password", True, False, False),
    ("multi_folder", "keyphrase", False, True, False),
    ("multi_folder", "password_keyphrase", True, True, False),
]


@contextmanager
def _workspace_tempdir():
    base = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    base.mkdir(exist_ok=True)
    temp_path = base / f"run_{uuid.uuid4().hex}"
    temp_path.mkdir()
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture(scope="module")
def keyphrases() -> tuple[list[str], list[str]]:
    mnemonic = HindiMnemonic()
    return mnemonic.generate(21), mnemonic.generate(21)


def _build_fixture_inputs(root: Path, archive_kind: str) -> tuple[list[str], dict[str, bytes]]:
    if archive_kind == "single":
        payload = root / "single_payload.txt"
        payload.write_bytes(b"Avikal protection matrix single-file payload\n" * 8)
        return [str(payload)], {payload.name: payload.read_bytes()}

    if archive_kind == "multi_file":
        expected = {}
        input_paths = []
        for index in range(3):
            file_path = root / f"multi_{index}.txt"
            content = (f"Avikal multi-file #{index}\n".encode("utf-8")) * (index + 2)
            file_path.write_bytes(content)
            expected[file_path.name] = content
            input_paths.append(str(file_path))
        return input_paths, expected

    if archive_kind == "multi_folder":
        expected = {}
        folders = []

        docs = root / "docs"
        docs.mkdir()
        report = docs / "report.txt"
        report.write_bytes(b"docs/report\n" * 5)
        expected["docs/report.txt"] = report.read_bytes()
        folders.append(str(docs))

        notes = root / "notes"
        nested = notes / "nested"
        nested.mkdir(parents=True)
        todo = notes / "todo.txt"
        todo.write_bytes(b"notes/todo\n" * 3)
        deep = nested / "deep.bin"
        deep.write_bytes(b"\x00\x01\x02\x03" * 16)
        expected["notes/todo.txt"] = todo.read_bytes()
        expected["notes/nested/deep.bin"] = deep.read_bytes()
        folders.append(str(notes))

        return folders, expected

    raise ValueError(f"Unsupported archive kind: {archive_kind}")


def _collect_extracted_outputs(output_directory: Path, archive_kind: str, extraction_result) -> dict[str, bytes]:
    if archive_kind == "single":
        extracted_path = Path(extraction_result)
        return {extracted_path.name: extracted_path.read_bytes()}

    extracted = {}
    for entry in extraction_result["files"]:
        path = Path(entry["path"])
        rel_path = path.relative_to(output_directory).as_posix()
        extracted[rel_path] = path.read_bytes()
    return extracted


def _create_archive(
    *,
    archive_kind: str,
    root: Path,
    expected_password: str | None,
    expected_keyphrase: list[str] | None,
    pqc_enabled: bool,
):
    root.mkdir(parents=True, exist_ok=True)
    inputs, expected = _build_fixture_inputs(root, archive_kind)
    archive_path = root / f"{archive_kind}.avk"
    pqc_keyfile_path = root / f"{archive_kind}.avkkey"

    if archive_kind == "single":
        result = create_avk_file_enhanced(
            str(Path(inputs[0])),
            str(archive_path),
            password=expected_password,
            keyphrase=expected_keyphrase,
            use_timecapsule=False,
            pqc_enabled=pqc_enabled,
            pqc_keyfile_output=str(pqc_keyfile_path) if pqc_enabled else None,
        )
    else:
        result = create_multi_file_avk(
            input_filepaths=inputs,
            output_filepath=str(archive_path),
            password=expected_password,
            keyphrase=expected_keyphrase,
            use_timecapsule=False,
            pqc_enabled=pqc_enabled,
            pqc_keyfile_output=str(pqc_keyfile_path) if pqc_enabled else None,
        )

    resolved_keyfile = None
    if pqc_enabled:
        resolved_keyfile = result["pqc"]["keyfile"]

    return archive_path, expected, resolved_keyfile


def _extract_archive(
    *,
    archive_kind: str,
    archive_path: Path,
    output_directory: Path,
    password: str | None,
    keyphrase: list[str] | None,
    pqc_keyfile_path: str | None,
):
    if archive_kind == "single":
        return extract_avk_file_enhanced(
            str(archive_path),
            str(output_directory),
            password=password,
            keyphrase=keyphrase,
            pqc_keyfile_path=pqc_keyfile_path,
        )

    return extract_multi_file_avk(
        avk_filepath=str(archive_path),
        output_directory=str(output_directory),
        password=password,
        keyphrase=keyphrase,
        pqc_keyfile_path=pqc_keyfile_path,
    )


@pytest.mark.parametrize(
    ("archive_kind", "case_name", "use_password", "use_keyphrase", "use_pqc"),
    VALID_PROTECTION_CASES,
    ids=[f"{kind}_{name}" for kind, name, *_ in VALID_PROTECTION_CASES],
)
def test_archive_roundtrip_valid_protection_matrix(
    archive_kind: str,
    case_name: str,
    use_password: bool,
    use_keyphrase: bool,
    use_pqc: bool,
    keyphrases: tuple[list[str], list[str]],
):
    del case_name
    correct_keyphrase, _ = keyphrases

    expected_password = PASSWORD if use_password else None
    expected_keyphrase = correct_keyphrase if use_keyphrase else None

    with _workspace_tempdir() as temp_dir:
        archive_path, expected, pqc_keyfile_path = _create_archive(
            archive_kind=archive_kind,
            root=temp_dir,
            expected_password=expected_password,
            expected_keyphrase=expected_keyphrase,
            pqc_enabled=use_pqc,
        )
        output_dir = temp_dir / "out"
        output_dir.mkdir()

        extraction_result = _extract_archive(
            archive_kind=archive_kind,
            archive_path=archive_path,
            output_directory=output_dir,
            password=expected_password,
            keyphrase=expected_keyphrase,
            pqc_keyfile_path=pqc_keyfile_path,
        )

        extracted = _collect_extracted_outputs(output_dir, archive_kind, extraction_result)
        assert extracted == expected


def test_single_password_wrong_password_is_rejected():
    with _workspace_tempdir() as temp_dir:
        archive_path, _, _ = _create_archive(
            archive_kind="single",
            root=temp_dir,
            expected_password=PASSWORD,
            expected_keyphrase=None,
            pqc_enabled=False,
        )
        output_dir = temp_dir / "out"
        output_dir.mkdir()

        with pytest.raises(ValueError, match="Incorrect password|password incorrect|Wrong password"):
            _extract_archive(
                archive_kind="single",
                archive_path=archive_path,
                output_directory=output_dir,
                password=WRONG_PASSWORD,
                keyphrase=None,
                pqc_keyfile_path=None,
            )


def test_single_keyphrase_missing_keyphrase_is_rejected(keyphrases: tuple[list[str], list[str]]):
    correct_keyphrase, _ = keyphrases
    with _workspace_tempdir() as temp_dir:
        archive_path, _, _ = _create_archive(
            archive_kind="single",
            root=temp_dir,
            expected_password=None,
            expected_keyphrase=correct_keyphrase,
            pqc_enabled=False,
        )
        output_dir = temp_dir / "out"
        output_dir.mkdir()

        with pytest.raises(ValueError, match="Incorrect password|keyphrase"):
            _extract_archive(
                archive_kind="single",
                archive_path=archive_path,
                output_directory=output_dir,
                password=None,
                keyphrase=None,
                pqc_keyfile_path=None,
            )


def test_single_keyphrase_wrong_keyphrase_is_rejected(keyphrases: tuple[list[str], list[str]]):
    correct_keyphrase, wrong_keyphrase = keyphrases
    with _workspace_tempdir() as temp_dir:
        archive_path, _, _ = _create_archive(
            archive_kind="single",
            root=temp_dir,
            expected_password=None,
            expected_keyphrase=correct_keyphrase,
            pqc_enabled=False,
        )
        output_dir = temp_dir / "out"
        output_dir.mkdir()

        with pytest.raises(ValueError, match="Incorrect password|keyphrase|Wrong password"):
            _extract_archive(
                archive_kind="single",
                archive_path=archive_path,
                output_directory=output_dir,
                password=None,
                keyphrase=wrong_keyphrase,
                pqc_keyfile_path=None,
            )


def test_single_pqc_uses_or_requires_openssl_provider():
    with _workspace_tempdir() as temp_dir:
        payload = temp_dir / "payload.txt"
        payload.write_bytes(b"pqc provider must be bundled")
        archive_path = temp_dir / "provider.avk"
        keyfile_path = temp_dir / "provider.avkkey"

        if not provider_status()["available"]:
            with pytest.raises(RuntimeError, match="OpenSSL PQC provider is unavailable"):
                create_avk_file_enhanced(
                    str(payload),
                    str(archive_path),
                    password=PASSWORD,
                    keyphrase=None,
                    use_timecapsule=False,
                    pqc_enabled=True,
                    pqc_keyfile_output=str(keyfile_path),
                )
            assert not archive_path.exists()
            return

        result = create_avk_file_enhanced(
            str(payload),
            str(archive_path),
            password=PASSWORD,
            keyphrase=None,
            use_timecapsule=False,
            pqc_enabled=True,
            pqc_keyfile_output=str(keyfile_path),
        )
        assert archive_path.exists()
        assert keyfile_path.exists()
        assert result["pqc"]["keyfile"] == str(keyfile_path)


def test_multi_pqc_uses_or_requires_openssl_provider():
    with _workspace_tempdir() as temp_dir:
        input_path = temp_dir / "payload.txt"
        input_path.write_bytes(b"multi pqc provider must be bundled")
        archive_path = temp_dir / "provider.avk"
        keyfile_path = temp_dir / "provider.avkkey"

        if not provider_status()["available"]:
            with pytest.raises(RuntimeError, match="OpenSSL PQC provider is unavailable"):
                create_multi_file_avk(
                    input_filepaths=[str(input_path)],
                    output_filepath=str(archive_path),
                    password=PASSWORD,
                    keyphrase=None,
                    use_timecapsule=False,
                    pqc_enabled=True,
                    pqc_keyfile_output=str(keyfile_path),
                )
            assert not archive_path.exists()
            return

        result = create_multi_file_avk(
            input_filepaths=[str(input_path)],
            output_filepath=str(archive_path),
            password=PASSWORD,
            keyphrase=None,
            use_timecapsule=False,
            pqc_enabled=True,
            pqc_keyfile_output=str(keyfile_path),
        )
        assert archive_path.exists()
        assert keyfile_path.exists()
        assert result["pqc"]["keyfile"] == str(keyfile_path)


def test_pqc_without_provider_fails_closed(monkeypatch: pytest.MonkeyPatch):
    def unavailable_material(*_args, **_kwargs):
        raise RuntimeError("OpenSSL PQC provider is unavailable")

    monkeypatch.setattr(
        "avikal_backend.archive.pipeline.encoder.create_pqc_archive_material",
        unavailable_material,
    )
    with _workspace_tempdir() as temp_dir:
        payload = temp_dir / "payload.txt"
        payload.write_bytes(b"pqc provider must be bundled")
        archive_path = temp_dir / "provider.avk"

        with pytest.raises(RuntimeError, match="OpenSSL PQC provider is unavailable"):
            create_avk_file_enhanced(
                str(payload),
                str(archive_path),
                password=PASSWORD,
                keyphrase=None,
                use_timecapsule=False,
                pqc_enabled=True,
                pqc_keyfile_output=str(temp_dir / "provider.avkkey"),
            )
        assert not archive_path.exists()


def test_pqc_provider_status_reports_fixed_suite_when_unavailable():
    status = provider_status()

    assert status["provider"] == "openssl"
    assert status["suite"]["suite_id"] == PQC_SUITE_ID
    if not status["available"]:
        assert "OpenSSL PQC provider is unavailable" in status["reason"]


def test_multi_file_wrong_password_is_rejected():
    with _workspace_tempdir() as temp_dir:
        archive_path, _, _ = _create_archive(
            archive_kind="multi_file",
            root=temp_dir,
            expected_password=PASSWORD,
            expected_keyphrase=None,
            pqc_enabled=False,
        )
        output_dir = temp_dir / "out"
        output_dir.mkdir()

        with pytest.raises(ValueError, match="Incorrect password|password incorrect|Wrong password"):
            _extract_archive(
                archive_kind="multi_file",
                archive_path=archive_path,
                output_directory=output_dir,
                password=WRONG_PASSWORD,
                keyphrase=None,
                pqc_keyfile_path=None,
            )


def test_multi_folder_wrong_keyphrase_is_rejected(keyphrases: tuple[list[str], list[str]]):
    correct_keyphrase, wrong_keyphrase = keyphrases
    with _workspace_tempdir() as temp_dir:
        archive_path, _, _ = _create_archive(
            archive_kind="multi_folder",
            root=temp_dir,
            expected_password=None,
            expected_keyphrase=correct_keyphrase,
            pqc_enabled=False,
        )
        output_dir = temp_dir / "out"
        output_dir.mkdir()

        with pytest.raises(ValueError, match="Incorrect password|keyphrase|Wrong password"):
            _extract_archive(
                archive_kind="multi_folder",
                archive_path=archive_path,
                output_directory=output_dir,
                password=None,
                keyphrase=wrong_keyphrase,
                pqc_keyfile_path=None,
            )


def test_single_pqc_without_secret_is_rejected():
    with _workspace_tempdir() as temp_dir:
        payload = temp_dir / "payload.txt"
        payload.write_bytes(b"pqc requires a human secret")
        archive_path = temp_dir / "invalid.avk"

        with pytest.raises(ValueError, match="PQC keyfile mode requires a password or keyphrase"):
            create_avk_file_enhanced(
                str(payload),
                str(archive_path),
                password=None,
                keyphrase=None,
                use_timecapsule=False,
                pqc_enabled=True,
                pqc_keyfile_output=str(temp_dir / "invalid.avkkey"),
            )
