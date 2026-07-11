#!/usr/bin/env python3
"""
Test multiple files with different protection scenarios.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile

sys.path.insert(0, ".")

from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk
import pytest

from avikal_backend.archive.format.multifile_stream import (
    build_multifile_stream_manifest,
    extract_multifile_stream_from_plaintext_chunks,
    extract_multifile_stream_container,
    iter_multifile_stream_chunks,
    scan_multifile_entries,
)
from avikal_backend.archive.pipeline import multi_file_decoder as multi_file_decoder_module
from avikal_backend.archive.pipeline.multi_file_encoder import _collect_entries, create_multi_file_avk
from avikal_backend.mnemonic.generator import generate_mnemonic


def test_protection_scenarios() -> None:
    print("=== TESTING MULTIPLE FILES WITH DIFFERENT PROTECTION SCENARIOS ===")

    test_files: list[str] = []
    test_contents = [
        b"This is the first test file content for multi-file testing",
        b"Second file with different content here - contains important data",
        b"Third file containing some other data for comprehensive testing",
    ]

    for index, content in enumerate(test_contents):
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_file{index + 1}.txt") as handle:
            handle.write(content)
            test_files.append(handle.name)

    print(f"Created {len(test_files)} test files")

    scenarios = [
        {
            "name": "Password Only Protection",
            "password": "MyS3cur3P@ssw0rd!",
            "keyphrase": None,
        },
        {
            "name": "Keyphrase Only Protection",
            "password": None,
            "keyphrase": generate_mnemonic(21).split(),
        },
        {
            "name": "Both Password and Keyphrase Protection",
            "password": "Str0ngP@ssw0rd!",
            "keyphrase": generate_mnemonic(21).split(),
        },
    ]

    results: list[str] = []

    try:
        for scenario in scenarios:
            print(f"\n--- Testing: {scenario['name']} ---")
            avk_file = tempfile.mktemp(suffix=".avk")

            try:
                create_multi_file_avk(
                    input_filepaths=test_files,
                    output_filepath=avk_file,
                    password=scenario["password"],
                    keyphrase=scenario["keyphrase"],
                    use_timecapsule=False,
                )
                print("  PASS Multi-file encryption successful")

                output_dir = tempfile.mkdtemp()
                extraction_result = extract_multi_file_avk(
                    avk_filepath=avk_file,
                    output_directory=output_dir,
                    password=scenario["password"],
                    keyphrase=scenario["keyphrase"],
                )

                extracted_files = extraction_result["files"]
                if len(extracted_files) != len(test_files):
                    results.append(
                        f"{scenario['name']}: FAIL - File count mismatch (got {len(extracted_files)} expected {len(test_files)})"
                    )
                    continue

                print(f"  PASS All {len(extracted_files)} files extracted successfully")

                content_matches = 0
                for extracted_file in extracted_files:
                    with open(extracted_file["path"], "rb") as handle:
                        decrypted_content = handle.read()
                    if decrypted_content in test_contents:
                        content_matches += 1

                if content_matches != len(test_files):
                    results.append(
                        f"{scenario['name']}: FAIL - Content mismatch ({content_matches}/{len(test_files)})"
                    )
                    continue

                print("  PASS All file contents match original files")
                results.append(f"{scenario['name']}: PASS")

                try:
                    wrong_output_dir = tempfile.mkdtemp()
                    extract_multi_file_avk(
                        avk_filepath=avk_file,
                        output_directory=wrong_output_dir,
                        password="wrongpassword" if scenario["password"] else None,
                        keyphrase=["गलत", "शब्द"] * 10 if scenario["keyphrase"] else None,
                    )
                    results[-1] += " - Security FAIL"
                except ValueError as exc:
                    if any(token in str(exc).lower() for token in ("password", "keyphrase", "incorrect")):
                        print("  PASS Security working - wrong credentials rejected")
                    else:
                        print(f"  WARN Unexpected wrong-credential error: {exc}")
                finally:
                    shutil.rmtree(wrong_output_dir, ignore_errors=True)
                    shutil.rmtree(output_dir, ignore_errors=True)
                    if os.path.exists(avk_file):
                        os.unlink(avk_file)

            except Exception as exc:
                print(f"  FAIL Test failed: {exc}")
                results.append(f"{scenario['name']}: FAIL - {exc}")
                if os.path.exists(avk_file):
                    os.unlink(avk_file)
    finally:
        for test_file in test_files:
            if os.path.exists(test_file):
                os.unlink(test_file)

    print("\n=== TEST RESULTS SUMMARY ===")
    for result in results:
        print(f"  {result}")

    failures = [result for result in results if "FAIL" in result]
    assert not failures, f"Unexpected multi-file protection failures: {failures}"


def test_collect_entries_excludes_nested_file_and_directory(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    keep_file = root / "keep.txt"
    skip_file = root / "skip.txt"
    skip_dir = root / "skip_dir"
    nested_skip = skip_dir / "nested.txt"
    keep_file.write_text("keep", encoding="utf-8")
    skip_file.write_text("skip", encoding="utf-8")
    skip_dir.mkdir()
    nested_skip.write_text("nested", encoding="utf-8")

    entries = _collect_entries([str(root)], [str(skip_file), str(skip_dir)])
    arcnames = [arcname for _path, arcname in entries]

    assert arcnames == ["root/keep.txt"]


def test_collect_entries_rejects_exclusion_outside_selected_roots(tmp_path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside.txt"
    root.mkdir()
    (root / "keep.txt").write_text("keep", encoding="utf-8")
    outside.write_text("outside", encoding="utf-8")

    with pytest.raises(ValueError, match="Excluded input path"):
        _collect_entries([str(root)], [str(outside)])


def test_create_multi_file_fails_when_exclusions_remove_every_file(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    only_file = root / "only.txt"
    only_file.write_text("only", encoding="utf-8")

    with pytest.raises(ValueError, match="No files were found"):
        create_multi_file_avk(
            input_filepaths=[str(root)],
            output_filepath=str(tmp_path / "out.avk"),
            password="Str0ngP@ssw0rd!",
            excluded_input_paths=[str(only_file)],
        )


def test_multifile_stream_roundtrip_without_plaintext_zip(tmp_path) -> None:
    root = tmp_path / "input"
    nested = root / "nested"
    nested.mkdir(parents=True)
    first = root / "first.txt"
    second = nested / "second.txt"
    first.write_bytes(b"alpha")
    second.write_bytes(b"beta" * 1024)

    entries = [(str(first), "input/first.txt"), (str(second), "input/nested/second.txt")]
    file_info, total_size = scan_multifile_entries(entries)
    manifest, manifest_bytes = build_multifile_stream_manifest(file_info, total_size)
    stream_path = tmp_path / "payload.avm3"
    stream_path.write_bytes(b"".join(iter_multifile_stream_chunks(entries, manifest_bytes)))

    output_root = tmp_path / "out"
    extracted = extract_multifile_stream_container(str(stream_path), str(output_root), manifest)

    assert len(extracted) == 2
    assert (output_root / "input" / "first.txt").read_bytes() == b"alpha"
    assert (output_root / "input" / "nested" / "second.txt").read_bytes() == b"beta" * 1024


def test_multifile_stream_extracts_from_plaintext_chunks(tmp_path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"alpha")
    second.write_bytes(b"beta" * 1024)

    entries = [(str(first), "first.txt"), (str(second), "second.txt")]
    file_info, total_size = scan_multifile_entries(entries)
    manifest, manifest_bytes = build_multifile_stream_manifest(file_info, total_size)

    raw_stream = b"".join(iter_multifile_stream_chunks(entries, manifest_bytes))
    chunks = (raw_stream[index:index + 37] for index in range(0, len(raw_stream), 37))
    output_root = tmp_path / "chunked-out"

    extracted = extract_multifile_stream_from_plaintext_chunks(
        chunks,
        str(output_root),
        expected_manifest_hash=hashlib.sha256(manifest_bytes).digest(),
        expected_entry_count=manifest["file_count"],
        expected_total_size=manifest["total_original_size"],
    )

    assert len(extracted) == 2
    assert (output_root / "first.txt").read_bytes() == b"alpha"
    assert (output_root / "second.txt").read_bytes() == b"beta" * 1024


def test_current_multifile_avk_extracts_without_materialized_payload_container(
    tmp_path,
    monkeypatch,
) -> None:
    source_dir = tmp_path / "input"
    source_dir.mkdir()
    (source_dir / "first.txt").write_bytes(b"alpha")
    (source_dir / "second.txt").write_bytes(b"beta" * 1024)
    avk_path = tmp_path / "archive.avk"
    output_dir = tmp_path / "out"

    create_multi_file_avk(
        input_filepaths=[str(source_dir)],
        output_filepath=str(avk_path),
    )

    def fail_materialized_decode(*_args, **_kwargs):
        raise AssertionError("current AVM payload should not materialize a temp container")

    monkeypatch.setattr(multi_file_decoder_module, "stream_payload_to_file", fail_materialized_decode)

    result = extract_multi_file_avk(
        avk_filepath=str(avk_path),
        output_directory=str(output_dir),
    )

    assert len(result["files"]) == 2
    assert (output_dir / "input" / "first.txt").read_bytes() == b"alpha"
    assert (output_dir / "input" / "second.txt").read_bytes() == b"beta" * 1024


def test_multifile_stream_rejects_trailing_data(tmp_path) -> None:
    item = tmp_path / "item.txt"
    item.write_bytes(b"payload")
    entries = [(str(item), "item.txt")]
    file_info, total_size = scan_multifile_entries(entries)
    manifest, manifest_bytes = build_multifile_stream_manifest(file_info, total_size)
    stream_path = tmp_path / "payload.avm3"
    stream_path.write_bytes(b"".join(iter_multifile_stream_chunks(entries, manifest_bytes)) + b"trailing")

    with pytest.raises(ValueError, match="trailing data"):
        extract_multifile_stream_container(str(stream_path), str(tmp_path / "out"), manifest)


if __name__ == "__main__":
    test_protection_scenarios()
