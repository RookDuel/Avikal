"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional, TextIO, Union

from .board import Board
from .move import Move


HEADER_PATTERN = re.compile(r'^\[([A-Za-z0-9][A-Za-z0-9_+#=:-]*)\s+"((?:[^"\\]|\\.)*)"\]\s*$')
RESULT_TOKENS = {"1-0", "0-1", "1/2-1/2", "*"}
MAIN_TAGS = ("Event", "Site", "Date", "Round", "White", "Black", "Result")


def _escape_tag(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _unescape_tag(value: str) -> str:
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _is_move_number(token: str) -> bool:
    return (token.endswith(".") and token[:-1].isdigit()) or (token.endswith("...") and token[:-3].isdigit())


def _strip_embedded_move_number(token: str) -> str:
    if "." not in token or not token[0].isdigit():
        return token
    trimmed = token
    while trimmed and (trimmed[0].isdigit() or trimmed[0] == "."):
        trimmed = trimmed[1:]
    return trimmed or token


def _scan_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    cursor = 0
    while cursor < len(text):
        char = text[cursor]
        if char.isspace():
            cursor += 1
            continue
        if char == ";":
            while cursor < len(text) and text[cursor] != "\n":
                cursor += 1
            continue
        if char == "{":
            cursor += 1
            depth = 1
            while cursor < len(text) and depth:
                if text[cursor] == "{":
                    depth += 1
                elif text[cursor] == "}":
                    depth -= 1
                cursor += 1
            continue
        if char in "()":
            tokens.append(char)
            cursor += 1
            continue
        start = cursor
        while cursor < len(text) and not text[cursor].isspace() and text[cursor] not in "{}();()":
            cursor += 1
        tokens.append(text[start:cursor])
    return tokens


class Headers(dict[str, str]):
    def __init__(self, initial: Optional[dict[str, str]] = None) -> None:
        defaults = {
            "Event": "?",
            "Site": "?",
            "Date": "????.??.??",
            "Round": "?",
            "White": "?",
            "Black": "?",
            "Result": "*",
        }
        super().__init__(defaults)
        if initial:
            self.update(initial)

    def board(self) -> Board:
        return Board(self.get("FEN", Board.starting_fen))


class GameNode:
    def __init__(self, *, comment: Union[str, list[str]] = "") -> None:
        if isinstance(comment, list):
            self.comments = comment[:]
        elif comment:
            self.comments = [comment]
        else:
            self.comments = []
        self.starting_comments: list[str] = []
        self.nags: set[int] = set()
        self.variations: list[ChildNode] = []

    @property
    def parent(self) -> Optional["GameNode"]:
        return None

    @property
    def move(self) -> Optional[Move]:
        return None

    @property
    def root(self) -> "GameNode":
        node: GameNode = self
        while node.parent is not None:
            node = node.parent
        return node

    def board(self) -> Board:
        raise NotImplementedError

    def add_variation(
        self,
        move: Move,
        *,
        comment: Union[str, list[str]] = "",
        starting_comment: Union[str, list[str]] = "",
        nags: Iterable[int] = (),
    ) -> "ChildNode":
        branch = ChildNode(self, move, comment=comment, starting_comment=starting_comment, nags=nags)
        self.variations.append(branch)
        return branch

    def add_main_variation(
        self,
        move: Move,
        *,
        comment: Union[str, list[str]] = "",
        starting_comment: Union[str, list[str]] = "",
        nags: Iterable[int] = (),
    ) -> "ChildNode":
        branch = self.add_variation(move, comment=comment, starting_comment=starting_comment, nags=nags)
        self.promote_to_main(branch)
        return branch

    def variation(self, move_or_index: Union[int, Move, "GameNode"]) -> "ChildNode":
        if isinstance(move_or_index, int):
            return self.variations[move_or_index]
        for branch in self.variations:
            if branch is move_or_index or branch.move == move_or_index:
                return branch
        raise KeyError(move_or_index)

    def promote_to_main(self, move_or_index: Union[int, Move, "GameNode"]) -> None:
        branch = self.variation(move_or_index)
        self.variations.remove(branch)
        self.variations.insert(0, branch)

    def end(self) -> "GameNode":
        node: GameNode = self
        while node.variations:
            node = node.variations[0]
        return node


class ChildNode(GameNode):
    def __init__(
        self,
        parent: GameNode,
        move: Move,
        *,
        comment: Union[str, list[str]] = "",
        starting_comment: Union[str, list[str]] = "",
        nags: Iterable[int] = (),
    ) -> None:
        super().__init__(comment=comment)
        self._parent = parent
        self._move = move
        if isinstance(starting_comment, list):
            self.starting_comments = starting_comment[:]
        elif starting_comment:
            self.starting_comments = [starting_comment]
        self.nags = set(nags)

    @property
    def parent(self) -> GameNode:
        return self._parent

    @property
    def move(self) -> Move:
        return self._move

    def board(self) -> Board:
        history: list[Move] = []
        cursor: GameNode = self
        while isinstance(cursor, ChildNode):
            history.append(cursor.move)
            cursor = cursor.parent
        board = cursor.board()
        for move in reversed(history):
            board.push(move)
        return board


class Game(GameNode):
    def __init__(self, headers: Optional[dict[str, str]] = None) -> None:
        super().__init__()
        self.headers = Headers(headers)

    def board(self) -> Board:
        return self.headers.board()

    def setup(self, board_or_fen: Union[Board, str]) -> None:
        fen = board_or_fen.fen() if isinstance(board_or_fen, Board) else board_or_fen
        if fen == Board.starting_fen:
            self.headers.pop("FEN", None)
            self.headers.pop("SetUp", None)
        else:
            self.headers["FEN"] = fen
            self.headers["SetUp"] = "1"

    def __str__(self) -> str:
        return export_pgn(self)


def _ordered_headers(headers: Headers) -> list[tuple[str, str]]:
    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()
    for tag in MAIN_TAGS:
        if tag in headers:
            ordered.append((tag, headers[tag]))
            seen.add(tag)
    for tag, value in headers.items():
        if tag not in seen:
            ordered.append((tag, value))
    return ordered


def _format_ply(board: Board, move: Move) -> str:
    prefix = f"{board.fullmove_number}. " if board.turn else f"{board.fullmove_number}... "
    return prefix + board.san(move)


def _write_branch(branch: ChildNode, base_board: Board) -> str:
    segments = [_format_ply(base_board, branch.move)]
    base_board.push(branch.move)
    segments.extend(_write_line(branch, base_board))
    return " ".join(segments)


def _write_line(node: GameNode, board: Board) -> list[str]:
    segments: list[str] = []
    cursor = node
    while cursor.variations:
        mainline = cursor.variations[0]
        segments.append(_format_ply(board, mainline.move))
        for sideline in cursor.variations[1:]:
            segments.append(f"({_write_branch(sideline, board.copy())})")
        board.push(mainline.move)
        cursor = mainline
    return segments


def export_pgn(game: Game) -> str:
    header_lines = [f'[{name} "{_escape_tag(value)}"]' for name, value in _ordered_headers(game.headers)]
    movetext = _write_line(game, game.board())
    movetext.append(game.headers.get("Result", "*"))
    return "\n".join(header_lines) + "\n\n" + " ".join(movetext).strip() + "\n"


def _split_headers(source: str) -> tuple[Headers, str]:
    headers = Headers()
    lines = source.lstrip("\ufeff").splitlines()
    line_index = 0
    saw_header = False
    while line_index < len(lines):
        stripped = lines[line_index].strip()
        if not stripped:
            line_index += 1
            if saw_header:
                break
            continue
        match = HEADER_PATTERN.match(stripped)
        if not match:
            break
        key, value = match.groups()
        headers[key] = _unescape_tag(value)
        saw_header = True
        line_index += 1
    return headers, "\n".join(lines[line_index:])


def read_game(handle: TextIO) -> Optional[Game]:
    source = handle.read()
    if not source.strip():
        return None

    headers, movetext = _split_headers(source)
    game = Game(headers)
    current: GameNode = game
    board = game.board()
    branch_stack: list[tuple[GameNode, Board]] = []

    for token in _scan_tokens(movetext):
        token = _strip_embedded_move_number(token)
        if token == "(":
            if current.parent is None:
                continue
            branch_stack.append((current, board.copy()))
            current = current.parent
            board = current.board()
            continue
        if token == ")":
            if branch_stack:
                current, board = branch_stack.pop()
            continue
        if token.startswith("$") or token in {"!", "?", "!!", "??", "!?", "?!"} or _is_move_number(token):
            continue
        if token in RESULT_TOKENS:
            if not branch_stack:
                game.headers["Result"] = token
            continue

        move = board.parse_san(token)
        current = current.add_variation(move)
        board.push(move)

    return game
"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""
