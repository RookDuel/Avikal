"""Chess PGN encoder for Avikal metadata integers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import os

from .. import chess


def _escape_tag(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _format_ply(board: chess.Board, move: chess.Move, legal_moves: list) -> str:
    prefix = f"{board.fullmove_number}. " if board.turn else f"{board.fullmove_number}... "
    return prefix + board.san(move, legal_moves)


class ChessGenerator:
    """Encode integers into a single chess game with recursive variations."""

    MAX_VAR_PLIES = 40
    MAX_MAINLINE_PLIES = 250
    VARIATIONS_PER_ROUND = 5
    MAX_RECURSION_DEPTH = 10
    USE_DEPTH_LIMIT = False

    def __init__(self, variations_per_round: int = 5, use_depth_limit: bool = False):
        """Initialize encoder variation settings."""
        self.variations_per_round = max(1, variations_per_round)
        self.use_depth_limit = use_depth_limit
        self._move_text = {}
        self.stats = {
            "mainline_plies": 0,
            "variation_plies": 0,
            "total_variations": 0,
            "total_plies": 0,
            "max_variations_at_position": 0,
            "positions_with_variations": 0,
            "max_nesting_depth": 0,
            "total_variation_branches": 0,
        }

    def get_stats(self) -> dict:
        """Return encoding statistics."""
        return self.stats.copy()

    def _reset_stats(self):
        """Reset stats for a new encoding run."""
        self._move_text = {}
        self.stats = {
            "mainline_plies": 0,
            "variation_plies": 0,
            "total_variations": 0,
            "total_plies": 0,
            "max_variations_at_position": 0,
            "positions_with_variations": 0,
            "max_nesting_depth": 0,
            "total_variation_branches": 0,
        }

    def encode_to_pgn(self, num: int) -> str:
        """Encode NUM into a single chess PGN."""
        if num < 1:
            raise ValueError("NUM must be >= 1")

        if self._native_route_allowed():
            from .native_bridge import native_chess_available, native_encode_chess_pgn_integer

            if native_chess_available():
                pgn_text, native_stats = native_encode_chess_pgn_integer(num, self.variations_per_round)
                self._reset_stats()
                self.stats.update({key: int(value) for key, value in native_stats.items() if key in self.stats})
                return pgn_text

        self._reset_stats()
        game = chess.pgn.Game()

        game.headers["Event"] = "Chess PGN Crypto"
        game.headers["Site"] = "Encrypted Data"
        game.headers["Date"] = "????.??.??"
        game.headers["Round"] = "-"
        game.headers["White"] = "RookDuel Encode"
        game.headers["Black"] = "Message"
        game.headers["Result"] = "*"
        game.headers["VariationsPerRound"] = str(self.variations_per_round)

        remaining = self._encode_mainline(game, num)
        if remaining > 0:
            remaining = self._distribute_variations(game, remaining)

        if remaining > 0:
            raise ValueError(f"Could not encode all data (remaining: {remaining})")

        self.stats["total_plies"] = self.stats["mainline_plies"] + self.stats["variation_plies"]
        return self._export_generated_pgn(game)

    def _native_route_allowed(self) -> bool:
        """Use Rust only for the production codec shape it can prove by parity."""
        return (
            os.environ.get("AVIKAL_CHESS_CODEC_FORCE_PYTHON") != "1"
            and self.MAX_MAINLINE_PLIES == 250
            and self.MAX_VAR_PLIES == 40
            and not self.use_depth_limit
        )

    def _add_encoded_move(self, node: chess.pgn.GameNode, board: chess.Board, move: chess.Move, legal_moves: list) -> chess.pgn.GameNode:
        """Add a move and cache its PGN text while the source board is already available."""
        move_text = _format_ply(board, move, legal_moves)
        child = node.add_variation(move)
        self._move_text[id(child)] = move_text
        board.push(move)
        return child

    def _export_generated_pgn(self, game: chess.pgn.Game) -> str:
        """Write the generated PGN using cached SAN text from encode time."""
        ordered = []
        seen = set()
        for tag in chess.pgn.MAIN_TAGS:
            if tag in game.headers:
                ordered.append((tag, game.headers[tag]))
                seen.add(tag)
        for tag, value in game.headers.items():
            if tag not in seen:
                ordered.append((tag, value))

        header_lines = [f'[{name} "{_escape_tag(value)}"]' for name, value in ordered]
        movetext = self._write_cached_line(game)
        movetext.append(game.headers.get("Result", "*"))
        return "\n".join(header_lines) + "\n\n" + " ".join(movetext).strip() + "\n"

    def _write_cached_branch(self, branch: chess.pgn.ChildNode) -> str:
        segments = [self._move_text.get(id(branch))]
        if segments[0] is None:
            raise ValueError("Generated PGN is missing cached move text")
        segments.extend(self._write_cached_line(branch))
        return " ".join(segments)

    def _write_cached_line(self, node: chess.pgn.GameNode) -> list[str]:
        segments = []
        cursor = node
        while cursor.variations:
            mainline = cursor.variations[0]
            move_text = self._move_text.get(id(mainline))
            if move_text is None:
                raise ValueError("Generated PGN is missing cached mainline text")
            segments.append(move_text)
            for sideline in cursor.variations[1:]:
                segments.append(f"({self._write_cached_branch(sideline)})")
            cursor = mainline
        return segments

    def _encode_mainline(self, game: chess.pgn.Game, num: int) -> int:
        """Encode the first segment into the mainline."""
        node = game
        remaining = num
        board = chess.Board()

        while remaining > 0 and self.stats["mainline_plies"] < self.MAX_MAINLINE_PLIES:
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
            if not legal_moves:
                break

            base = len(legal_moves)
            move_index = (remaining - 1) % base
            remaining = (remaining - 1) // base

            node = self._add_encoded_move(node, board, legal_moves[move_index], legal_moves)
            self.stats["mainline_plies"] += 1

        return remaining

    def _distribute_variations(self, game: chess.pgn.Game, num: int) -> int:
        """Distribute remaining data across recursive variations."""
        return self._distribute_variations_recursive(game, num, depth=0)

    def _distribute_variations_recursive(self, parent_node: chess.pgn.Game, num: int, depth: int) -> int:
        """Recursively distribute variations at the current depth."""
        if num == 0:
            return num
        if self.use_depth_limit and depth >= self.MAX_RECURSION_DEPTH:
            return num

        remaining = num
        positions = self._collect_positions_at_level(parent_node, depth)
        if not positions:
            return remaining

        is_mainline_level = depth == 0
        variation_endpoints = []

        while remaining > 0:
            made_progress = False
            for pos_info in positions:
                if remaining == 0:
                    break

                node = pos_info["node"]
                legal_moves = pos_info["legal_moves"]
                board = pos_info["board"]
                available_moves = pos_info["available_moves"]
                if not available_moves:
                    continue

                for _ in range(self.variations_per_round):
                    if remaining == 0 or not available_moves:
                        break

                    remaining, endpoint = self._add_single_variation_with_endpoint(
                        node,
                        board,
                        legal_moves,
                        available_moves,
                        remaining,
                    )
                    if endpoint:
                        variation_endpoints.append(endpoint)

                    self.stats["total_variations"] += 1
                    self.stats["total_variation_branches"] += 1
                    made_progress = True

            if not made_progress:
                break

        if is_mainline_level:
            for pos_info in positions:
                node = pos_info["node"]
                num_vars = len(node.variations) - 1
                if num_vars > 0:
                    self.stats["positions_with_variations"] += 1
                self.stats["max_variations_at_position"] = max(
                    self.stats["max_variations_at_position"],
                    num_vars,
                )

        self.stats["max_nesting_depth"] = max(self.stats["max_nesting_depth"], depth)
        if remaining > 0 and variation_endpoints:
            if not self.use_depth_limit or depth + 1 < self.MAX_RECURSION_DEPTH:
                for endpoint in variation_endpoints:
                    if remaining == 0:
                        break
                    remaining = self._distribute_variations_recursive(endpoint, remaining, depth + 1)

        return remaining

    def _collect_positions_at_level(self, parent_node, depth: int) -> list:
        """Collect positions at the current variation level."""
        if depth == 0:
            return self._collect_mainline_positions(parent_node)

        board = parent_node.board()
        legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
        if legal_moves:
            return [{
                "node": parent_node,
                "legal_moves": legal_moves,
                "available_moves": legal_moves[:],
                "board": board.copy(),
            }]
        return []

    def _collect_mainline_positions(self, game: chess.pgn.Game) -> list:
        """Collect all mainline positions that can hold variations."""
        positions = []
        node = game
        board = chess.Board()

        while node.variations:
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())

            if len(legal_moves) > 1:
                mainline_move = node.variations[0].move
                mainline_index = legal_moves.index(mainline_move)
                positions.append(
                    {
                        "node": node,
                        "mainline_index": mainline_index,
                        "legal_moves": legal_moves,
                        "available_moves": [m for m in legal_moves if m != mainline_move],
                        "board": board.copy(),
                    }
                )

            board.push(node.variations[0].move)
            node = node.variations[0]

        return positions

    def _add_single_variation(self, node: chess.pgn.GameNode, available_moves: list, num: int) -> int:
        """Add a single variation and return remaining data."""
        remaining, _ = self._add_single_variation_with_endpoint(node, node.board(), available_moves, available_moves, num)
        return remaining

    def _add_single_variation_with_endpoint(self, node: chess.pgn.GameNode, board: chess.Board, legal_moves: list, available_moves: list, num: int) -> tuple:
        """Add a single variation and return remaining data plus endpoint."""
        if not available_moves or num == 0:
            return num, None

        remaining = num
        base = len(available_moves)
        move_index = (remaining - 1) % base
        remaining = (remaining - 1) // base
        selected_move = available_moves.pop(move_index)

        branch_board = board.copy()
        var_node = self._add_encoded_move(node, branch_board, selected_move, legal_moves)
        self.stats["variation_plies"] += 1
        return self._encode_variation_branch_with_endpoint(var_node, branch_board, remaining, 1)

    def _encode_variation_branch(self, node: chess.pgn.GameNode, num: int, ply_count: int) -> int:
        """Encode data along a variation branch."""
        remaining, _ = self._encode_variation_branch_with_endpoint(node, node.board(), num, ply_count)
        return remaining

    def _encode_variation_branch_with_endpoint(self, node: chess.pgn.GameNode, board: chess.Board, num: int, ply_count: int) -> tuple:
        """Encode a variation branch and return its endpoint."""
        if num == 0 or ply_count >= self.MAX_VAR_PLIES:
            return num, node

        legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
        if not legal_moves:
            return num, node

        remaining = num
        base = len(legal_moves)
        move_index = (remaining - 1) % base
        remaining = (remaining - 1) // base

        next_node = self._add_encoded_move(node, board, legal_moves[move_index], legal_moves)
        self.stats["variation_plies"] += 1
        return self._encode_variation_branch_with_endpoint(next_node, board, remaining, ply_count + 1)
