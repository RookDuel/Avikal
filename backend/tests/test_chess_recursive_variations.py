"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from contextlib import contextmanager
import io
import random
import shutil
from pathlib import Path
import uuid
import zipfile

import pytest

from avikal_backend.archive.format.container import read_avk_container
from avikal_backend.chess import Board, Move, pgn
from avikal_backend.archive.chess_metadata import (
    decode_chess_to_metadata_enhanced,
    encode_metadata_to_chess_enhanced,
)
from avikal_backend.archive.compression import decompress_data
from avikal_backend.chess_codec.decoder import PGNDecoder
from avikal_backend.chess_codec.encoder import ChessGenerator
from avikal_backend.chess_codec.native_bridge import (
    native_chess_available,
    native_decode_chess_pgn_integer,
    native_encode_chess_pgn_integer,
)
from avikal_backend.archive.pipeline.decoder import extract_avk_file_enhanced
from avikal_backend.archive.pipeline.encoder import create_avk_file_enhanced
from avikal_backend.archive.pipeline.multi_file_decoder import extract_multi_file_avk
from avikal_backend.archive.pipeline.multi_file_encoder import create_multi_file_avk


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


@pytest.mark.parametrize("variations_per_round", [1, 2, 3, 5])
def test_decoder_roundtrip_across_variation_round_settings(variations_per_round):
    generator = ChessGenerator(variations_per_round=variations_per_round)
    decoder = PGNDecoder()
    value = int.from_bytes((b"Avikal PGN decoder compatibility " * 12) + bytes([variations_per_round]), "big")

    pgn_text = generator.encode_to_pgn(value)
    rendered = str(pgn.read_game(io.StringIO(pgn_text)))

    assert decoder.decode_from_pgn(pgn_text) == value
    assert decoder.decode_from_pgn(rendered) == value


def test_decoder_progress_callback_reports_internal_stages():
    generator, decoder = _forced_variation_codec(variations_per_round=2)
    value = (10**44) + 1122334455
    pgn_text = generator.encode_to_pgn(value)
    events = []

    decoded = decoder.decode_from_pgn(pgn_text, progress_callback=lambda description, fraction: events.append((description, fraction)))

    assert decoded == value
    assert any(description == "Parsing keychain PGN" for description, _ in events)
    assert any(description == "Decoding recursive PGN variations" for description, _ in events)
    assert any(description == "Reconstructing metadata integer" for description, _ in events)
    assert all(0.0 <= fraction <= 1.0 for _, fraction in events)


@pytest.mark.skipif(not native_chess_available(), reason="native Chess-PGN codec extension is not built")
@pytest.mark.parametrize("variations_per_round", [1, 2, 3, 5])
def test_native_chess_codec_parity_with_python(variations_per_round):
    value = int.from_bytes((b"Avikal native chess parity " * 20) + bytes([variations_per_round]), "big")

    python_pgn = ChessGenerator(variations_per_round=variations_per_round).encode_to_pgn(value)
    native_from_python, _ = native_decode_chess_pgn_integer(python_pgn)
    native_pgn, native_stats = native_encode_chess_pgn_integer(value, variations_per_round)
    python_from_native = PGNDecoder().decode_from_pgn(native_pgn)
    native_from_native, _ = native_decode_chess_pgn_integer(native_pgn)

    assert native_from_python == value
    assert python_from_native == value
    assert native_from_native == value
    assert native_stats["mainline_plies"] > 0


@pytest.mark.skipif(not native_chess_available(), reason="native Chess-PGN codec extension is not built")
def test_native_chess_codec_rejects_malformed_pgn():
    with pytest.raises(ValueError, match="PGN|game|san|move|Empty"):
        native_decode_chess_pgn_integer("not a chess pgn")


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
        assert len(keychain_pgn.encode("utf-8")) < 128 * 1024


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

        _header_bytes, keychain_pgn, encrypted_payload = read_avk_container(str(archive))
        tampered_payload = bytearray(encrypted_payload)
        tampered_payload[-100] ^= 0x01
        with zipfile.ZipFile(tampered_archive, "w") as archive_zip:
            archive_zip.writestr("payload.enc", tampered_payload, compress_type=zipfile.ZIP_STORED)
            archive_zip.writestr("keychain.pgn", keychain_pgn, compress_type=zipfile.ZIP_DEFLATED)

        with pytest.raises(ValueError, match="index|integrity|authentication|Failed"):
            extract_multi_file_avk(
                avk_filepath=str(tampered_archive),
                output_directory=str(output_dir),
                password="AvikalStrongPass!9Zeta",
            )
