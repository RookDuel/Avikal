"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager
import io
import random
import shutil
from pathlib import Path
import uuid
import zipfile

import pytest

from avikal_backend.archive.format.container import open_avk_payload_stream, read_avk_container
from avikal_backend.archive.format.header import attach_header_to_keychain_pgn
from avikal_backend.archive.format.manifest import INTERNAL_MANIFEST_PATH, load_archive_manifest, serialize_archive_manifest
from avikal_backend.chess import Board, Move, pgn
from avikal_backend.archive.chess_metadata import (
    decode_chess_to_metadata_enhanced,
    encode_metadata_to_chess_enhanced,
)
from avikal_backend.archive.compression import compress_data, decompress_data
from avikal_backend.chess_codec.decoder import PGNDecoder
from avikal_backend.chess_codec.encoder import ChessGenerator
from avikal_backend.archive.security.crypto import (
    add_random_padding,
    compute_checksum,
    derive_hierarchical_keys,
    remove_padding,
)
from avikal_backend.archive.security.key_wrap import unwrap_payload_key
from avikal_backend.archive.format.metadata import pack_cascade_metadata
from avikal_backend.archive.pipeline.decoder import extract_avk_file_enhanced
from avikal_backend.archive.pipeline.encoder import create_avk_file_enhanced
from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk
from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk
from avikal_backend.archive.pipeline.payload_streaming import stream_file_to_payload, stream_payload_to_file


def _max_sideline_depth(node, depth: int = 0) -> int:
    best = depth
    for index, child in enumerate(node.variations):
        child_depth = depth if index == 0 else depth + 1
        best = max(best, _max_sideline_depth(child, child_depth))
    return best


def _iter_nodes(node):
    yield node
    for child in node.variations:
        yield from _iter_nodes(child)


def _forced_variation_codec(variations_per_round: int = 2) -> tuple[ChessGenerator, PGNDecoder]:
    generator = ChessGenerator(variations_per_round=variations_per_round)
    generator.MAX_MAINLINE_PLIES = 2
    generator.MAX_VAR_PLIES = 1

    decoder = PGNDecoder()
    decoder.MAX_VAR_PLIES = 1
    return generator, decoder


@contextmanager
def _workspace_tempdir():
    base = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    base.mkdir(exist_ok=True)
    temp_path = base / f"run_{uuid.uuid4().hex}"
    temp_path.mkdir()
    try:
        yield str(temp_path)
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


def test_kingside_castle_san_ignores_non_king_moves_to_same_target():
    board = Board("1rB1k2r/p1q1pp1p/1p1p1np1/3P4/4n1P1/P1N1b2b/RP2KP1P/2B3QR b k g3 0 18")

    move = board.parse_san("O-O")

    assert move == Move.from_uci("e8g8")


def test_queenside_castle_san_ignores_non_king_moves_to_same_target():
    board = Board("r3k2r/8/1n6/8/8/8/8/4K3 b q - 0 1")

    move = board.parse_san("O-O-O")

    assert move == Move.from_uci("e8c8")


def test_recursive_variation_roundtrip_forced_nesting():
    generator, decoder = _forced_variation_codec()
    value = (10**40) + 123456789

    pgn_text = generator.encode_to_pgn(value)
    game = pgn.read_game(io.StringIO(pgn_text))

    assert game is not None
    assert "(" in pgn_text
    assert _max_sideline_depth(game) >= 2
    assert decoder.decode_from_pgn(pgn_text) == value


def test_recursive_variation_parser_writer_roundtrip():
    generator, decoder = _forced_variation_codec(variations_per_round=3)
    value = (10**50) + 987654321

    original_pgn = generator.encode_to_pgn(value)
    game = pgn.read_game(io.StringIO(original_pgn))

    assert game is not None

    rendered = str(game)
    reparsed = pgn.read_game(io.StringIO(rendered))

    assert reparsed is not None
    assert decoder.decode_from_pgn(original_pgn) == value
    assert decoder.decode_from_pgn(rendered) == value
    assert _max_sideline_depth(reparsed) >= 2


def test_board_curated_legal_moves_and_san():
    cases = [
        {
            "fen": Board().fen(),
            "count": 20,
            "must_include": {
                ("e2e4", "e4"),
                ("g1f3", "Nf3"),
                ("b1c3", "Nc3"),
                ("a2a4", "a4"),
            },
        },
        {
            "fen": "1rB1k2r/p1q1pp1p/1p1p1np1/3P4/4n1P1/P1N1b2b/RP2KP1P/2B3QR b k g3 0 18",
            "count": 46,
            "must_include": {
                ("e8g8", "O-O"),
                ("h3f1", "Bf1+"),
                ("c7c4", "Qc4+"),
                ("e4c3", "Nxc3+"),
            },
        },
        {
            "fen": "r3k2r/8/1n6/8/8/8/8/4K3 b q - 0 1",
            "count": 30,
            "must_include": {
                ("e8c8", "O-O-O"),
                ("a8a1", "Ra1+"),
                ("b6c8", "Nc8"),
                ("h8h7", "Rh7"),
            },
        },
        {
            "fen": "4k3/1P6/8/8/8/8/6p1/4K3 w - - 0 1",
            "count": 8,
            "must_include": {
                ("b7b8q", "b8=Q+"),
                ("b7b8r", "b8=R+"),
                ("b7b8b", "b8=B"),
                ("e1e2", "Ke2"),
            },
        },
        {
            "fen": "rnbqkbnr/pppp1ppp/8/4p3/3Pp3/8/PPP1PPPP/RNBQKBNR w KQkq e6 0 3",
            "count": 28,
            "must_include": {
                ("d4e5", "dxe5"),
                ("c1h6", "Bh6"),
                ("e1d2", "Kd2"),
                ("g1f3", "Nf3"),
            },
        },
    ]

    for case in cases:
        board = Board(case["fen"])
        actual = {(move.uci(), board.san(move)) for move in board.legal_moves}

        assert len(actual) == case["count"], case["fen"]
        assert case["must_include"].issubset(actual), case["fen"]


def test_enhanced_single_file_archive_roundtrip():
    with _workspace_tempdir() as temp_dir:
        temp_path = Path(temp_dir)
        payload = temp_path / "payload.txt"
        archive = temp_path / "single.avk"
        output_dir = temp_path / "single_out"
        output_dir.mkdir()

        expected = b"Avikal single-file archive smoke test\n" * 32
        payload.write_bytes(expected)

        create_avk_file_enhanced(
            str(payload),
            str(archive),
            password="AvikalStrongPass!9Zeta",
            use_timecapsule=False,
        )

        restored_path = extract_avk_file_enhanced(
            str(archive),
            str(output_dir),
            password="AvikalStrongPass!9Zeta",
        )

        assert Path(restored_path).read_bytes() == expected


def test_enhanced_multi_file_archive_roundtrip():
    with _workspace_tempdir() as temp_dir:
        temp_path = Path(temp_dir)
        archive = temp_path / "bundle.avk"
        output_dir = temp_path / "bundle_out"
        output_dir.mkdir()

        inputs = []
        expected_contents = {}
        for index in range(3):
            file_path = temp_path / f"input_{index}.txt"
            content = (f"Avikal multi-file smoke #{index}\n".encode("utf-8")) * (index + 3)
            file_path.write_bytes(content)
            inputs.append(str(file_path))
            expected_contents[file_path.name] = content

        create_multi_file_avk(
            input_filepaths=inputs,
            output_filepath=str(archive),
            password="AvikalStrongPass!9Zeta",
            use_timecapsule=False,
        )

        result = extract_multi_file_avk(
            avk_filepath=str(archive),
            output_directory=str(output_dir),
            password="AvikalStrongPass!9Zeta",
        )

        extracted = {Path(entry["path"]).name: Path(entry["path"]).read_bytes() for entry in result["files"]}
        assert extracted == expected_contents


def test_multi_file_keychain_stays_compact_with_large_file_count():
    with _workspace_tempdir() as temp_dir:
        temp_path = Path(temp_dir)
        archive = temp_path / "large_bundle.avk"

        inputs = []
        for index in range(200):
            file_path = temp_path / f"input_{index:03d}.txt"
            file_path.write_text(f"Avikal manifest pressure test #{index}\n", encoding="utf-8")
            inputs.append(str(file_path))

        create_multi_file_avk(
            input_filepaths=inputs,
            output_filepath=str(archive),
            password="AvikalStrongPass!9Zeta",
            use_timecapsule=False,
        )

        header_bytes, keychain_pgn, _payload_bytes = read_avk_container(str(archive))
        metadata = decode_chess_to_metadata_enhanced(
            keychain_pgn,
            password="AvikalStrongPass!9Zeta",
            aad=header_bytes,
        )

        assert metadata["archive_type"] == "multi_file"
        assert metadata["entry_count"] == 200
        assert metadata["total_original_size"] > 0
        assert isinstance(metadata["manifest_hash"], bytes) and len(metadata["manifest_hash"]) == 32
        assert "multi_file" not in metadata
        assert len(keychain_pgn.encode("utf-8")) < 30000


def test_multi_file_manifest_hash_mismatch_is_rejected():
    with _workspace_tempdir() as temp_dir:
        temp_path = Path(temp_dir)
        archive = temp_path / "bundle.avk"
        tampered_archive = temp_path / "tampered_bundle.avk"
        output_dir = temp_path / "bundle_out"
        output_dir.mkdir()

        inputs = []
        for index in range(2):
            file_path = temp_path / f"input_{index}.txt"
            file_path.write_bytes((f"manifest test #{index}\n".encode("utf-8")) * 4)
            inputs.append(str(file_path))

        create_multi_file_avk(
            input_filepaths=inputs,
            output_filepath=str(archive),
            password="AvikalStrongPass!9Zeta",
            use_timecapsule=False,
        )

        header_bytes, keychain_pgn, _encrypted_payload = read_avk_container(str(archive))
        metadata = decode_chess_to_metadata_enhanced(
            keychain_pgn,
            password="AvikalStrongPass!9Zeta",
            aad=header_bytes,
        )
        _, payload_key, _, _ = derive_hierarchical_keys(
            "AvikalStrongPass!9Zeta",
            None,
            metadata["salt"],
        )
        if metadata.get("wrapped_payload_key"):
            payload_key = unwrap_payload_key(metadata["wrapped_payload_key"], payload_key, header_bytes)

        temp_container = temp_path / "container.zip"
        with open_avk_payload_stream(str(archive)) as (_header_bytes, _keychain_pgn, payload_stream):
            stream_payload_to_file(
                payload_stream=payload_stream,
                output_path=str(temp_container),
                aad=header_bytes,
                decrypt_key=payload_key,
                expected_checksum=metadata["checksum"],
            )
        container_data = temp_container.read_bytes()

        with zipfile.ZipFile(io.BytesIO(container_data), "r") as container_zip:
            manifest, _ = load_archive_manifest(container_zip)
            user_entries = {
                info.filename: container_zip.read(info.filename)
                for info in container_zip.infolist()
                if not info.is_dir() and info.filename != INTERNAL_MANIFEST_PATH
            }

        tampered_manifest = copy.deepcopy(manifest)
        tampered_manifest["files"][0]["checksum"] = "0" * 64
        tampered_manifest_bytes = serialize_archive_manifest(tampered_manifest)

        rebuilt_container = io.BytesIO()
        with zipfile.ZipFile(rebuilt_container, "w", zipfile.ZIP_STORED) as container_zip:
            for filename, file_bytes in user_entries.items():
                container_zip.writestr(filename, file_bytes)
            container_zip.writestr(INTERNAL_MANIFEST_PATH, tampered_manifest_bytes)
        rebuilt_container_data = rebuilt_container.getvalue()

        rebuilt_checksum = compute_checksum(rebuilt_container_data)
        rebuilt_compressed = compress_data(
            rebuilt_container_data,
            source_name="multi_file_container.zip",
            hint="container",
        )
        rebuilt_padded, _ = add_random_padding(rebuilt_compressed)
        rebuilt_input = temp_path / "rebuilt_padded.bin"
        rebuilt_payload_path = temp_path / "rebuilt.payload"
        rebuilt_input.write_bytes(rebuilt_padded)
        stream_file_to_payload(
            input_path=str(rebuilt_input),
            payload_path=str(rebuilt_payload_path),
            aad=header_bytes,
            encrypt_key=payload_key,
        )
        rebuilt_encrypted_payload = rebuilt_payload_path.read_bytes()

        rebuilt_metadata = pack_cascade_metadata(
            metadata["salt"],
            metadata.get("pqc_ciphertext"),
            None,
            metadata["unlock_timestamp"],
            metadata["filename"],
            rebuilt_checksum,
            metadata["encryption_method"],
            metadata.get("keyphrase_protected", False),
            chess_salt=metadata.get("chess_salt"),
            timelock_mode=metadata.get("timelock_mode", "convenience"),
            file_id=metadata.get("file_id"),
            server_url=metadata.get("server_url"),
            time_key_hash=metadata.get("time_key_hash"),
            timecapsule_provider=metadata.get("timecapsule_provider"),
            drand_round=metadata.get("drand_round"),
            drand_chain_hash=metadata.get("drand_chain_hash"),
            drand_chain_url=metadata.get("drand_chain_url"),
            drand_ciphertext=metadata.get("drand_ciphertext"),
            drand_beacon_id=metadata.get("drand_beacon_id"),
            pqc_required=metadata.get("pqc_required", False),
            pqc_algorithm=metadata.get("pqc_algorithm"),
            pqc_key_id=metadata.get("pqc_key_id"),
            archive_type=metadata.get("archive_type"),
            entry_count=metadata.get("entry_count"),
            total_original_size=metadata.get("total_original_size"),
            manifest_hash=metadata.get("manifest_hash"),
            payload_key_wrap_algorithm=metadata.get("payload_key_wrap_algorithm"),
            wrapped_payload_key=metadata.get("wrapped_payload_key"),
        )
        rebuilt_keychain = encode_metadata_to_chess_enhanced(
            rebuilt_metadata,
            password="AvikalStrongPass!9Zeta",
            keyphrase=None,
            variations_per_round=5,
            use_timecapsule=False,
            aad=header_bytes,
        )
        rebuilt_keychain = attach_header_to_keychain_pgn(rebuilt_keychain, header_bytes)

        with zipfile.ZipFile(tampered_archive, "w", zipfile.ZIP_DEFLATED) as archive_zip:
            archive_zip.writestr("keychain.pgn", rebuilt_keychain)
            archive_zip.writestr("payload.enc", rebuilt_encrypted_payload)

        with pytest.raises(ValueError, match="manifest|checksum|corrupted"):
            extract_multi_file_avk(
                avk_filepath=str(tampered_archive),
                output_directory=str(output_dir),
                password="AvikalStrongPass!9Zeta",
            )
