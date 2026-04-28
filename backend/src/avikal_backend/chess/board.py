"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from .constants import (
    BISHOP_RAYS,
    BLACK,
    FILES,
    KING_DELTAS,
    KNIGHT_DELTAS,
    PROMOTION_PIECES,
    QUEEN_RAYS,
    ROOK_RAYS,
    RANKS,
    STARTING_FEN,
    WHITE,
)
from .move import Move, Square, file_of, parse_square, rank_of, square_name, to_square


SAN_PATTERN = re.compile(
    r"^(?:(O-O(?:-O)?)|([KQRBN])?([a-h])?([1-8])?(x)?([a-h][1-8])(?:=([QRBN]))?)$"
)


class InvalidMoveError(ValueError):
    pass


class IllegalMoveError(ValueError):
    pass


class AmbiguousMoveError(ValueError):
    pass


@dataclass(slots=True)
class BoardSnapshot:
    cells: list[str | None]
    turn: bool
    castling: str
    ep_square: int | None
    halfmove_clock: int
    fullmove_number: int


def _piece_color(piece: str) -> bool:
    return WHITE if piece.isupper() else BLACK


def _piece_role(piece: str) -> str:
    return piece.upper()


def _same_side(piece: str | None, color: bool) -> bool:
    return piece is not None and _piece_color(piece) == color


def _enemy_side(piece: str | None, color: bool) -> bool:
    return piece is not None and _piece_color(piece) != color


def _inside(file_index: int, rank_index: int) -> bool:
    return 0 <= file_index < 8 and 0 <= rank_index < 8


class Board:
    starting_fen = STARTING_FEN

    def __init__(self, fen: str | None = STARTING_FEN, *, chess960: bool = False) -> None:
        self.chess960 = chess960
        self.cells: list[str | None] = [None] * 64
        self.turn = WHITE
        self.castling = "KQkq"
        self.ep_square: int | None = None
        self.halfmove_clock = 0
        self.fullmove_number = 1
        self.move_stack: list[Move] = []
        self._undos: list[BoardSnapshot] = []
        if fen is not None:
            self.set_fen(fen)

    def copy(self, *, stack: bool | int = True) -> "Board":
        clone = Board(None, chess960=self.chess960)
        clone.cells = self.cells[:]
        clone.turn = self.turn
        clone.castling = self.castling
        clone.ep_square = self.ep_square
        clone.halfmove_clock = self.halfmove_clock
        clone.fullmove_number = self.fullmove_number
        if stack:
            limit = len(self.move_stack) if stack is True else int(stack)
            clone.move_stack = self.move_stack[-limit:].copy()
        return clone

    @property
    def legal_moves(self) -> list[Move]:
        return list(self.generate_legal_moves())

    def piece_at(self, square: Square) -> str | None:
        return self.cells[square]

    def set_fen(self, fen: str) -> None:
        parts = fen.split()
        if len(parts) != 6:
            raise ValueError(f"invalid fen: {fen!r}")

        board_part, turn_part, castling_part, ep_part, halfmove_part, fullmove_part = parts
        rows = board_part.split("/")
        if len(rows) != 8:
            raise ValueError(f"invalid fen board: {fen!r}")

        rebuilt: list[str | None] = []
        for row in reversed(rows):
            expanded: list[str | None] = []
            for char in row:
                if char.isdigit():
                    expanded.extend([None] * int(char))
                elif char in "prnbqkPRNBQK":
                    expanded.append(char)
                else:
                    raise ValueError(f"invalid fen piece: {char!r}")
            if len(expanded) != 8:
                raise ValueError(f"invalid fen rank width: {row!r}")
            rebuilt.extend(expanded)

        self.cells = rebuilt
        self.turn = WHITE if turn_part == "w" else BLACK
        self.castling = "" if castling_part == "-" else "".join(symbol for symbol in "KQkq" if symbol in castling_part)
        self.ep_square = None if ep_part == "-" else parse_square(ep_part)
        self.halfmove_clock = int(halfmove_part)
        self.fullmove_number = int(fullmove_part)
        self.move_stack.clear()
        self._undos.clear()

    def fen(self) -> str:
        rows: list[str] = []
        for rank_index in range(7, -1, -1):
            blank_run = 0
            parts: list[str] = []
            for file_index in range(8):
                piece = self.cells[to_square(file_index, rank_index)]
                if piece is None:
                    blank_run += 1
                    continue
                if blank_run:
                    parts.append(str(blank_run))
                    blank_run = 0
                parts.append(piece)
            if blank_run:
                parts.append(str(blank_run))
            rows.append("".join(parts))
        turn_token = "w" if self.turn == WHITE else "b"
        rights = self.castling or "-"
        ep = "-" if self.ep_square is None else square_name(self.ep_square)
        return f"{'/'.join(rows)} {turn_token} {rights} {ep} {self.halfmove_clock} {self.fullmove_number}"

    def ply(self) -> int:
        return (self.fullmove_number - 1) * 2 + (0 if self.turn == WHITE else 1)

    def is_game_over(self) -> bool:
        return (
            self.is_checkmate()
            or self.is_stalemate()
            or self.is_insufficient_material()
            or self.halfmove_clock >= 150
        )

    def is_check(self) -> bool:
        return self._in_check(self.turn)

    def is_checkmate(self) -> bool:
        return self.is_check() and not self.legal_moves

    def is_stalemate(self) -> bool:
        return not self.is_check() and not self.legal_moves

    def is_insufficient_material(self) -> bool:
        material = [_piece_role(piece) for piece in self.cells if piece and _piece_role(piece) != "K"]
        if not material:
            return True
        if len(material) == 1 and material[0] in {"B", "N"}:
            return True
        if len(material) == 2 and material == ["B", "B"]:
            bishops = [index for index, piece in enumerate(self.cells) if piece and _piece_role(piece) == "B"]
            colors = {(file_of(square) + rank_of(square)) % 2 for square in bishops}
            return len(colors) == 1
        return False

    def generate_legal_moves(self):
        for move in self._generate_pseudo_legal():
            probe = self.copy(stack=False)
            probe._apply_move(move)
            if not probe._in_check(self.turn):
                yield move

    def _generate_pseudo_legal(self):
        for origin, piece in enumerate(self.cells):
            if not _same_side(piece, self.turn):
                continue
            role = _piece_role(piece)
            if role == "P":
                yield from self._pawn_moves(origin, piece)
            elif role == "N":
                yield from self._jump_moves(origin, KNIGHT_DELTAS)
            elif role == "B":
                yield from self._ray_moves(origin, BISHOP_RAYS)
            elif role == "R":
                yield from self._ray_moves(origin, ROOK_RAYS)
            elif role == "Q":
                yield from self._ray_moves(origin, QUEEN_RAYS)
            elif role == "K":
                yield from self._jump_moves(origin, KING_DELTAS)
                yield from self._castle_moves(origin, piece)

    def _pawn_moves(self, origin: Square, piece: str):
        current_file = file_of(origin)
        current_rank = rank_of(origin)
        step = 1 if _piece_color(piece) == WHITE else -1
        home_rank = 1 if _piece_color(piece) == WHITE else 6
        last_rank = 7 if _piece_color(piece) == WHITE else 0

        next_rank = current_rank + step
        if _inside(current_file, next_rank):
            target = to_square(current_file, next_rank)
            if self.cells[target] is None:
                if next_rank == last_rank:
                    for promotion in PROMOTION_PIECES:
                        yield Move(origin, target, promotion)
                else:
                    yield Move(origin, target)

                jump_rank = current_rank + (2 * step)
                jump_square = to_square(current_file, jump_rank) if _inside(current_file, jump_rank) else None
                if current_rank == home_rank and jump_square is not None and self.cells[jump_square] is None:
                    yield Move(origin, jump_square)

        for delta_file in (-1, 1):
            capture_file = current_file + delta_file
            capture_rank = current_rank + step
            if not _inside(capture_file, capture_rank):
                continue
            target = to_square(capture_file, capture_rank)
            if _enemy_side(self.cells[target], self.turn) or target == self.ep_square:
                if capture_rank == last_rank:
                    for promotion in PROMOTION_PIECES:
                        yield Move(origin, target, promotion)
                else:
                    yield Move(origin, target)

    def _jump_moves(self, origin: Square, deltas: tuple[tuple[int, int], ...]):
        start_file = file_of(origin)
        start_rank = rank_of(origin)
        for delta_file, delta_rank in deltas:
            target_file = start_file + delta_file
            target_rank = start_rank + delta_rank
            if not _inside(target_file, target_rank):
                continue
            target = to_square(target_file, target_rank)
            if not _same_side(self.cells[target], self.turn):
                yield Move(origin, target)

    def _ray_moves(self, origin: Square, rays: tuple[tuple[int, int], ...]):
        start_file = file_of(origin)
        start_rank = rank_of(origin)
        for delta_file, delta_rank in rays:
            file_cursor = start_file + delta_file
            rank_cursor = start_rank + delta_rank
            while _inside(file_cursor, rank_cursor):
                target = to_square(file_cursor, rank_cursor)
                occupant = self.cells[target]
                if occupant is None:
                    yield Move(origin, target)
                else:
                    if _piece_color(occupant) != self.turn:
                        yield Move(origin, target)
                    break
                file_cursor += delta_file
                rank_cursor += delta_rank

    def _castle_moves(self, origin: Square, piece: str):
        if self._in_check(self.turn):
            return

        if piece == "K" and origin == parse_square("e1"):
            if (
                "K" in self.castling
                and self.cells[parse_square("h1")] == "R"
                and self._castle_lane(("f1", "g1"), ("f1", "g1"))
            ):
                yield Move(origin, parse_square("g1"))
            if (
                "Q" in self.castling
                and self.cells[parse_square("a1")] == "R"
                and self._castle_lane(("d1", "c1", "b1"), ("d1", "c1"))
            ):
                yield Move(origin, parse_square("c1"))
        elif piece == "k" and origin == parse_square("e8"):
            if (
                "k" in self.castling
                and self.cells[parse_square("h8")] == "r"
                and self._castle_lane(("f8", "g8"), ("f8", "g8"))
            ):
                yield Move(origin, parse_square("g8"))
            if (
                "q" in self.castling
                and self.cells[parse_square("a8")] == "r"
                and self._castle_lane(("d8", "c8", "b8"), ("d8", "c8"))
            ):
                yield Move(origin, parse_square("c8"))

    def _castle_lane(self, empty_squares: tuple[str, ...], safe_squares: tuple[str, ...]) -> bool:
        for name in empty_squares:
            if self.cells[parse_square(name)] is not None:
                return False
        for name in safe_squares:
            if self.is_attacked_by(not self.turn, parse_square(name)):
                return False
        return True

    def is_attacked_by(self, attacker_color: bool, target: Square) -> bool:
        target_file = file_of(target)
        target_rank = rank_of(target)

        pawn_rank = target_rank - 1 if attacker_color == WHITE else target_rank + 1
        for pawn_file in (target_file - 1, target_file + 1):
            if _inside(pawn_file, pawn_rank):
                piece = self.cells[to_square(pawn_file, pawn_rank)]
                if piece == ("P" if attacker_color == WHITE else "p"):
                    return True

        for delta_file, delta_rank in KNIGHT_DELTAS:
            source_file = target_file + delta_file
            source_rank = target_rank + delta_rank
            if _inside(source_file, source_rank):
                piece = self.cells[to_square(source_file, source_rank)]
                if piece == ("N" if attacker_color == WHITE else "n"):
                    return True

        for rays, symbols in ((ROOK_RAYS, {"R", "Q"}), (BISHOP_RAYS, {"B", "Q"})):
            for delta_file, delta_rank in rays:
                file_cursor = target_file + delta_file
                rank_cursor = target_rank + delta_rank
                while _inside(file_cursor, rank_cursor):
                    piece = self.cells[to_square(file_cursor, rank_cursor)]
                    if piece is None:
                        file_cursor += delta_file
                        rank_cursor += delta_rank
                        continue
                    if _piece_color(piece) == attacker_color and _piece_role(piece) in symbols:
                        return True
                    break

        for delta_file, delta_rank in ((-1, -1), (0, -1), (1, -1), (-1, 0), (1, 0), (-1, 1), (0, 1), (1, 1)):
            source_file = target_file + delta_file
            source_rank = target_rank + delta_rank
            if _inside(source_file, source_rank):
                piece = self.cells[to_square(source_file, source_rank)]
                if piece == ("K" if attacker_color == WHITE else "k"):
                    return True

        return False

    def _find_king(self, color: bool) -> Square | None:
        marker = "K" if color == WHITE else "k"
        for index, piece in enumerate(self.cells):
            if piece == marker:
                return index
        return None

    def _in_check(self, color: bool) -> bool:
        king_square = self._find_king(color)
        return king_square is not None and self.is_attacked_by(not color, king_square)

    def push(self, move: Move) -> None:
        self._undos.append(
            BoardSnapshot(
                self.cells[:],
                self.turn,
                self.castling,
                self.ep_square,
                self.halfmove_clock,
                self.fullmove_number,
            )
        )
        self.move_stack.append(move)
        self._apply_move(move)

    def pop(self) -> Move:
        if not self._undos:
            raise IndexError("no moves to pop")
        move = self.move_stack.pop()
        snapshot = self._undos.pop()
        self.cells = snapshot.cells
        self.turn = snapshot.turn
        self.castling = snapshot.castling
        self.ep_square = snapshot.ep_square
        self.halfmove_clock = snapshot.halfmove_clock
        self.fullmove_number = snapshot.fullmove_number
        return move

    def _apply_move(self, move: Move) -> None:
        piece = self.cells[move.from_square]
        if piece is None:
            raise IllegalMoveError(f"no piece on {square_name(move.from_square)}")

        role = _piece_role(piece)
        capture = self._is_capture(move)
        self._update_castling_rights(move, piece)

        if role == "P" and move.to_square == self.ep_square and self.cells[move.to_square] is None:
            captured_rank = rank_of(move.to_square) - 1 if self.turn == WHITE else rank_of(move.to_square) + 1
            self.cells[to_square(file_of(move.to_square), captured_rank)] = None

        self.cells[move.from_square] = None

        if role == "K" and abs(file_of(move.to_square) - file_of(move.from_square)) == 2:
            self._move_rook_for_castle(move)

        piece_to_place = piece
        if move.promotion:
            piece_to_place = move.promotion.upper() if self.turn == WHITE else move.promotion.lower()
        self.cells[move.to_square] = piece_to_place

        if role == "P" and abs(rank_of(move.to_square) - rank_of(move.from_square)) == 2:
            middle_rank = (rank_of(move.to_square) + rank_of(move.from_square)) // 2
            self.ep_square = to_square(file_of(move.from_square), middle_rank)
        else:
            self.ep_square = None

        self.halfmove_clock = 0 if role == "P" or capture else self.halfmove_clock + 1
        if self.turn == BLACK:
            self.fullmove_number += 1
        self.turn = not self.turn

    def _move_rook_for_castle(self, move: Move) -> None:
        if move.to_square == parse_square("g1"):
            rook_from, rook_to = parse_square("h1"), parse_square("f1")
        elif move.to_square == parse_square("c1"):
            rook_from, rook_to = parse_square("a1"), parse_square("d1")
        elif move.to_square == parse_square("g8"):
            rook_from, rook_to = parse_square("h8"), parse_square("f8")
        else:
            rook_from, rook_to = parse_square("a8"), parse_square("d8")
        self.cells[rook_to] = self.cells[rook_from]
        self.cells[rook_from] = None

    def _update_castling_rights(self, move: Move, piece: str) -> None:
        rights = set(self.castling)
        if piece == "K":
            rights.difference_update({"K", "Q"})
        elif piece == "k":
            rights.difference_update({"k", "q"})

        rook_rights = {"a1": "Q", "h1": "K", "a8": "q", "h8": "k"}
        from_name = square_name(move.from_square)
        to_name = square_name(move.to_square)
        if from_name in rook_rights:
            rights.discard(rook_rights[from_name])
        if to_name in rook_rights:
            rights.discard(rook_rights[to_name])
        self.castling = "".join(symbol for symbol in "KQkq" if symbol in rights)

    def _is_capture(self, move: Move) -> bool:
        piece = self.cells[move.from_square]
        target_piece = self.cells[move.to_square]
        if target_piece is not None:
            return True
        return piece is not None and _piece_role(piece) == "P" and move.to_square == self.ep_square and file_of(move.from_square) != file_of(move.to_square)

    def san(self, move: Move) -> str:
        legal = self.legal_moves
        if move not in legal:
            raise IllegalMoveError(f"illegal move for san: {move.uci()} in {self.fen()}")

        piece = self.cells[move.from_square]
        assert piece is not None
        role = _piece_role(piece)

        if role == "K" and abs(file_of(move.to_square) - file_of(move.from_square)) == 2:
            notation = "O-O" if file_of(move.to_square) > file_of(move.from_square) else "O-O-O"
        else:
            capture = self._is_capture(move)
            target_name = square_name(move.to_square)

            if role == "P":
                prefix = FILES[file_of(move.from_square)] if capture else ""
                notation = prefix + ("x" if capture else "") + target_name
                if move.promotion:
                    notation += "=" + move.promotion.upper()
            else:
                notation = role + self._disambiguation(move, legal)
                if capture:
                    notation += "x"
                notation += target_name

        probe = self.copy(stack=False)
        probe.push(move)
        if probe.is_checkmate():
            return notation + "#"
        if probe.is_check():
            return notation + "+"
        return notation

    def _disambiguation(self, move: Move, legal_moves: list[Move]) -> str:
        origin_piece = self.cells[move.from_square]
        assert origin_piece is not None
        role = _piece_role(origin_piece)
        rivals = []
        for candidate in legal_moves:
            if candidate == move or candidate.to_square != move.to_square:
                continue
            piece = self.cells[candidate.from_square]
            if piece and _piece_role(piece) == role:
                rivals.append(candidate)
        if not rivals:
            return ""

        same_file = any(file_of(candidate.from_square) == file_of(move.from_square) for candidate in rivals)
        same_rank = any(rank_of(candidate.from_square) == rank_of(move.from_square) for candidate in rivals)
        if same_file and same_rank:
            return square_name(move.from_square)
        if same_file:
            return RANKS[rank_of(move.from_square)]
        return FILES[file_of(move.from_square)]

    def parse_san(self, token: str) -> Move:
        san_token = token.strip()
        while san_token and san_token[-1] in "+#!?":
            san_token = san_token[:-1]

        if san_token in {"O-O", "0-0"}:
            target = parse_square("g1" if self.turn == WHITE else "g8")
            candidates = [
                move
                for move in self.legal_moves
                if move.to_square == target
                and self.cells[move.from_square] is not None
                and _piece_role(self.cells[move.from_square]) == "K"
                and abs(file_of(move.to_square) - file_of(move.from_square)) == 2
            ]
            if len(candidates) != 1:
                raise IllegalMoveError(f"illegal castle: {token!r} in {self.fen()}")
            return candidates[0]

        if san_token in {"O-O-O", "0-0-0"}:
            target = parse_square("c1" if self.turn == WHITE else "c8")
            candidates = [
                move
                for move in self.legal_moves
                if move.to_square == target
                and self.cells[move.from_square] is not None
                and _piece_role(self.cells[move.from_square]) == "K"
                and abs(file_of(move.to_square) - file_of(move.from_square)) == 2
            ]
            if len(candidates) != 1:
                raise IllegalMoveError(f"illegal castle: {token!r} in {self.fen()}")
            return candidates[0]

        match = SAN_PATTERN.match(san_token)
        if not match:
            raise InvalidMoveError(f"invalid san: {token!r}")

        _, piece_hint, source_file, source_rank, capture_hint, target_name, promotion_hint = match.groups()
        role = piece_hint or "P"
        target = parse_square(target_name)
        promotion = promotion_hint.lower() if promotion_hint else None

        matches = []
        for move in self.legal_moves:
            piece = self.cells[move.from_square]
            if piece is None or _piece_role(piece) != role:
                continue
            if move.to_square != target or move.promotion != promotion:
                continue
            if source_file is not None and FILES[file_of(move.from_square)] != source_file:
                continue
            if source_rank is not None and RANKS[rank_of(move.from_square)] != source_rank:
                continue
            if capture_hint and not self._is_capture(move):
                continue
            if not capture_hint and role != "P" and self._is_capture(move):
                continue
            matches.append(move)

        if not matches:
            raise IllegalMoveError(f"illegal san: {token!r} in {self.fen()}")
        if len(matches) > 1:
            raise AmbiguousMoveError(f"ambiguous san: {token!r} in {self.fen()}")
        return matches[0]
"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""
