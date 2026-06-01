// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Atharva Sen Barai.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::collections::HashMap;

const WHITE: bool = true;
const BLACK: bool = false;
const FILES: &[u8; 8] = b"abcdefgh";
const RANKS: &[u8; 8] = b"12345678";
const PROMOTIONS: [char; 4] = ['q', 'r', 'b', 'n'];
const KNIGHT_DELTAS: [(i8, i8); 8] = [
    (1, 2),
    (2, 1),
    (2, -1),
    (1, -2),
    (-1, -2),
    (-2, -1),
    (-2, 1),
    (-1, 2),
];
const KING_DELTAS: [(i8, i8); 8] = [
    (-1, -1),
    (0, -1),
    (1, -1),
    (-1, 0),
    (1, 0),
    (-1, 1),
    (0, 1),
    (1, 1),
];
const ROOK_RAYS: [(i8, i8); 4] = [(1, 0), (-1, 0), (0, 1), (0, -1)];
const BISHOP_RAYS: [(i8, i8); 4] = [(1, 1), (1, -1), (-1, 1), (-1, -1)];
const WK: u8 = 0b0001;
const WQ: u8 = 0b0010;
const BK: u8 = 0b0100;
const BQ: u8 = 0b1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct ChessMove {
    from: u8,
    to: u8,
    promotion: Option<char>,
}

impl ChessMove {
    fn uci(&self) -> String {
        let mut token = format!("{}{}", square_name(self.from), square_name(self.to));
        if let Some(promotion) = self.promotion {
            token.push(promotion.to_ascii_lowercase());
        }
        token
    }
}

#[derive(Clone)]
struct Board {
    cells: [char; 64],
    turn: bool,
    castling: u8,
    ep_square: Option<u8>,
    halfmove_clock: u32,
    fullmove_number: u32,
}

#[derive(Clone)]
struct Node {
    parent: Option<usize>,
    mv: Option<ChessMove>,
    variations: Vec<usize>,
    move_text: Option<String>,
    board_cache: Option<Board>,
    legal_cache: Option<Vec<ChessMove>>,
    index_cache: Option<HashMap<ChessMove, usize>>,
}

struct Game {
    headers: HashMap<String, String>,
    nodes: Vec<Node>,
}

#[derive(Default, Clone)]
struct CodecStats {
    mainline_plies: u64,
    variation_plies: u64,
    total_variations: u64,
    total_plies: u64,
    max_variations_at_position: u64,
    positions_with_variations: u64,
    max_nesting_depth: u64,
    total_variation_branches: u64,
}

struct PositionState {
    legal_moves: Vec<ChessMove>,
    move_index: HashMap<ChessMove, usize>,
    board: Board,
}

fn value_error(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(message.into())
}

fn inside(file: i8, rank: i8) -> bool {
    (0..8).contains(&file) && (0..8).contains(&rank)
}

fn file_of(square: u8) -> u8 {
    square % 8
}

fn rank_of(square: u8) -> u8 {
    square / 8
}

fn to_square(file: i8, rank: i8) -> u8 {
    (rank as u8) * 8 + file as u8
}

fn square_name(square: u8) -> String {
    format!(
        "{}{}",
        FILES[file_of(square) as usize] as char,
        RANKS[rank_of(square) as usize] as char
    )
}

fn parse_square(name: &str) -> Result<u8, String> {
    let bytes = name.as_bytes();
    if bytes.len() != 2 {
        return Err(format!("invalid square: {name}"));
    }
    let file = FILES
        .iter()
        .position(|value| *value == bytes[0])
        .ok_or_else(|| format!("invalid square: {name}"))?;
    let rank = RANKS
        .iter()
        .position(|value| *value == bytes[1])
        .ok_or_else(|| format!("invalid square: {name}"))?;
    Ok((rank * 8 + file) as u8)
}

fn piece_color(piece: char) -> Option<bool> {
    if piece == '.' {
        None
    } else {
        Some(piece.is_ascii_uppercase())
    }
}

fn piece_role(piece: char) -> char {
    piece.to_ascii_uppercase()
}

fn same_side(piece: char, color: bool) -> bool {
    piece_color(piece).is_some_and(|piece_color| piece_color == color)
}

fn enemy_side(piece: char, color: bool) -> bool {
    piece_color(piece).is_some_and(|piece_color| piece_color != color)
}

impl Board {
    fn starting() -> Self {
        let mut cells = ['.'; 64];
        for (index, piece) in ['R', 'N', 'B', 'Q', 'K', 'B', 'N', 'R'].iter().enumerate() {
            cells[index] = *piece;
            cells[8 + index] = 'P';
            cells[48 + index] = 'p';
            cells[56 + index] = piece.to_ascii_lowercase();
        }
        Self {
            cells,
            turn: WHITE,
            castling: WK | WQ | BK | BQ,
            ep_square: None,
            halfmove_clock: 0,
            fullmove_number: 1,
        }
    }

    fn sorted_legal_moves(&self) -> Vec<ChessMove> {
        let mut moves = self.legal_moves();
        moves.sort_by_key(|mv| mv.uci());
        moves
    }

    fn legal_moves(&self) -> Vec<ChessMove> {
        let color = self.turn;
        let mut legal = Vec::new();
        for mv in self.pseudo_legal_moves() {
            let mut probe = self.clone();
            if probe.apply_move(mv).is_ok() && !probe.in_check(color) {
                legal.push(mv);
            }
        }
        legal
    }

    fn pseudo_legal_moves(&self) -> Vec<ChessMove> {
        let mut moves = Vec::new();
        for origin in 0..64u8 {
            let piece = self.cells[origin as usize];
            if !same_side(piece, self.turn) {
                continue;
            }
            match piece_role(piece) {
                'P' => self.pawn_moves(origin, piece, &mut moves),
                'N' => self.jump_moves(origin, &KNIGHT_DELTAS, &mut moves),
                'B' => self.ray_moves(origin, &BISHOP_RAYS, &mut moves),
                'R' => self.ray_moves(origin, &ROOK_RAYS, &mut moves),
                'Q' => {
                    self.ray_moves(origin, &ROOK_RAYS, &mut moves);
                    self.ray_moves(origin, &BISHOP_RAYS, &mut moves);
                }
                'K' => {
                    self.jump_moves(origin, &KING_DELTAS, &mut moves);
                    self.castle_moves(origin, piece, &mut moves);
                }
                _ => {}
            }
        }
        moves
    }

    fn pawn_moves(&self, origin: u8, piece: char, moves: &mut Vec<ChessMove>) {
        let current_file = file_of(origin) as i8;
        let current_rank = rank_of(origin) as i8;
        let step = if piece_color(piece) == Some(WHITE) {
            1
        } else {
            -1
        };
        let home_rank = if piece_color(piece) == Some(WHITE) {
            1
        } else {
            6
        };
        let last_rank = if piece_color(piece) == Some(WHITE) {
            7
        } else {
            0
        };

        let next_rank = current_rank + step;
        if inside(current_file, next_rank) {
            let target = to_square(current_file, next_rank);
            if self.cells[target as usize] == '.' {
                if next_rank == last_rank {
                    for promotion in PROMOTIONS {
                        moves.push(ChessMove {
                            from: origin,
                            to: target,
                            promotion: Some(promotion),
                        });
                    }
                } else {
                    moves.push(ChessMove {
                        from: origin,
                        to: target,
                        promotion: None,
                    });
                }

                let jump_rank = current_rank + (2 * step);
                if current_rank == home_rank && inside(current_file, jump_rank) {
                    let jump_square = to_square(current_file, jump_rank);
                    if self.cells[jump_square as usize] == '.' {
                        moves.push(ChessMove {
                            from: origin,
                            to: jump_square,
                            promotion: None,
                        });
                    }
                }
            }
        }

        for delta_file in [-1, 1] {
            let capture_file = current_file + delta_file;
            let capture_rank = current_rank + step;
            if !inside(capture_file, capture_rank) {
                continue;
            }
            let target = to_square(capture_file, capture_rank);
            if enemy_side(self.cells[target as usize], self.turn) || self.ep_square == Some(target)
            {
                if capture_rank == last_rank {
                    for promotion in PROMOTIONS {
                        moves.push(ChessMove {
                            from: origin,
                            to: target,
                            promotion: Some(promotion),
                        });
                    }
                } else {
                    moves.push(ChessMove {
                        from: origin,
                        to: target,
                        promotion: None,
                    });
                }
            }
        }
    }

    fn jump_moves(&self, origin: u8, deltas: &[(i8, i8)], moves: &mut Vec<ChessMove>) {
        let start_file = file_of(origin) as i8;
        let start_rank = rank_of(origin) as i8;
        for (delta_file, delta_rank) in deltas {
            let target_file = start_file + delta_file;
            let target_rank = start_rank + delta_rank;
            if !inside(target_file, target_rank) {
                continue;
            }
            let target = to_square(target_file, target_rank);
            if !same_side(self.cells[target as usize], self.turn) {
                moves.push(ChessMove {
                    from: origin,
                    to: target,
                    promotion: None,
                });
            }
        }
    }

    fn ray_moves(&self, origin: u8, rays: &[(i8, i8)], moves: &mut Vec<ChessMove>) {
        let start_file = file_of(origin) as i8;
        let start_rank = rank_of(origin) as i8;
        for (delta_file, delta_rank) in rays {
            let mut file_cursor = start_file + delta_file;
            let mut rank_cursor = start_rank + delta_rank;
            while inside(file_cursor, rank_cursor) {
                let target = to_square(file_cursor, rank_cursor);
                let occupant = self.cells[target as usize];
                if occupant == '.' {
                    moves.push(ChessMove {
                        from: origin,
                        to: target,
                        promotion: None,
                    });
                } else {
                    if enemy_side(occupant, self.turn) {
                        moves.push(ChessMove {
                            from: origin,
                            to: target,
                            promotion: None,
                        });
                    }
                    break;
                }
                file_cursor += delta_file;
                rank_cursor += delta_rank;
            }
        }
    }

    fn castle_moves(&self, origin: u8, piece: char, moves: &mut Vec<ChessMove>) {
        if self.in_check(self.turn) {
            return;
        }
        let e1 = parse_square("e1").unwrap();
        let e8 = parse_square("e8").unwrap();
        if piece == 'K' && origin == e1 {
            if self.castling & WK != 0
                && self.cells[parse_square("h1").unwrap() as usize] == 'R'
                && self.castle_lane(&["f1", "g1"], &["f1", "g1"])
            {
                moves.push(ChessMove {
                    from: origin,
                    to: parse_square("g1").unwrap(),
                    promotion: None,
                });
            }
            if self.castling & WQ != 0
                && self.cells[parse_square("a1").unwrap() as usize] == 'R'
                && self.castle_lane(&["d1", "c1", "b1"], &["d1", "c1"])
            {
                moves.push(ChessMove {
                    from: origin,
                    to: parse_square("c1").unwrap(),
                    promotion: None,
                });
            }
        } else if piece == 'k' && origin == e8 {
            if self.castling & BK != 0
                && self.cells[parse_square("h8").unwrap() as usize] == 'r'
                && self.castle_lane(&["f8", "g8"], &["f8", "g8"])
            {
                moves.push(ChessMove {
                    from: origin,
                    to: parse_square("g8").unwrap(),
                    promotion: None,
                });
            }
            if self.castling & BQ != 0
                && self.cells[parse_square("a8").unwrap() as usize] == 'r'
                && self.castle_lane(&["d8", "c8", "b8"], &["d8", "c8"])
            {
                moves.push(ChessMove {
                    from: origin,
                    to: parse_square("c8").unwrap(),
                    promotion: None,
                });
            }
        }
    }

    fn castle_lane(&self, empty_squares: &[&str], safe_squares: &[&str]) -> bool {
        for name in empty_squares {
            if self.cells[parse_square(name).unwrap() as usize] != '.' {
                return false;
            }
        }
        for name in safe_squares {
            if self.is_attacked_by(!self.turn, parse_square(name).unwrap()) {
                return false;
            }
        }
        true
    }

    fn is_attacked_by(&self, attacker_color: bool, target: u8) -> bool {
        let target_file = file_of(target) as i8;
        let target_rank = rank_of(target) as i8;

        let pawn_rank = if attacker_color == WHITE {
            target_rank - 1
        } else {
            target_rank + 1
        };
        for pawn_file in [target_file - 1, target_file + 1] {
            if inside(pawn_file, pawn_rank) {
                let piece = self.cells[to_square(pawn_file, pawn_rank) as usize];
                if piece == if attacker_color == WHITE { 'P' } else { 'p' } {
                    return true;
                }
            }
        }

        for (delta_file, delta_rank) in KNIGHT_DELTAS {
            let source_file = target_file + delta_file;
            let source_rank = target_rank + delta_rank;
            if inside(source_file, source_rank) {
                let piece = self.cells[to_square(source_file, source_rank) as usize];
                if piece == if attacker_color == WHITE { 'N' } else { 'n' } {
                    return true;
                }
            }
        }

        for (rays, symbols) in [(&ROOK_RAYS[..], ['R', 'Q']), (&BISHOP_RAYS[..], ['B', 'Q'])] {
            for (delta_file, delta_rank) in rays {
                let mut file_cursor = target_file + delta_file;
                let mut rank_cursor = target_rank + delta_rank;
                while inside(file_cursor, rank_cursor) {
                    let piece = self.cells[to_square(file_cursor, rank_cursor) as usize];
                    if piece == '.' {
                        file_cursor += delta_file;
                        rank_cursor += delta_rank;
                        continue;
                    }
                    if piece_color(piece) == Some(attacker_color)
                        && symbols.contains(&piece_role(piece))
                    {
                        return true;
                    }
                    break;
                }
            }
        }

        for (delta_file, delta_rank) in KING_DELTAS {
            let source_file = target_file + delta_file;
            let source_rank = target_rank + delta_rank;
            if inside(source_file, source_rank) {
                let piece = self.cells[to_square(source_file, source_rank) as usize];
                if piece == if attacker_color == WHITE { 'K' } else { 'k' } {
                    return true;
                }
            }
        }

        false
    }

    fn find_king(&self, color: bool) -> Option<u8> {
        let marker = if color == WHITE { 'K' } else { 'k' };
        self.cells
            .iter()
            .position(|piece| *piece == marker)
            .map(|idx| idx as u8)
    }

    fn in_check(&self, color: bool) -> bool {
        self.find_king(color)
            .is_some_and(|king_square| self.is_attacked_by(!color, king_square))
    }

    fn is_capture(&self, mv: ChessMove) -> bool {
        let piece = self.cells[mv.from as usize];
        let target = self.cells[mv.to as usize];
        target != '.'
            || (piece != '.'
                && piece_role(piece) == 'P'
                && self.ep_square == Some(mv.to)
                && file_of(mv.from) != file_of(mv.to))
    }

    fn apply_move(&mut self, mv: ChessMove) -> Result<(), String> {
        let piece = self.cells[mv.from as usize];
        if piece == '.' {
            return Err(format!("no piece on {}", square_name(mv.from)));
        }
        let role = piece_role(piece);
        let capture = self.is_capture(mv);
        self.update_castling_rights(mv, piece);

        if role == 'P' && self.ep_square == Some(mv.to) && self.cells[mv.to as usize] == '.' {
            let captured_rank = if self.turn == WHITE {
                rank_of(mv.to) - 1
            } else {
                rank_of(mv.to) + 1
            };
            self.cells[to_square(file_of(mv.to) as i8, captured_rank as i8) as usize] = '.';
        }

        self.cells[mv.from as usize] = '.';
        if role == 'K' && (file_of(mv.to) as i8 - file_of(mv.from) as i8).abs() == 2 {
            self.move_rook_for_castle(mv);
        }

        let mut placed = piece;
        if let Some(promotion) = mv.promotion {
            placed = if self.turn == WHITE {
                promotion.to_ascii_uppercase()
            } else {
                promotion.to_ascii_lowercase()
            };
        }
        self.cells[mv.to as usize] = placed;

        if role == 'P' && (rank_of(mv.to) as i8 - rank_of(mv.from) as i8).abs() == 2 {
            let middle_rank = (rank_of(mv.to) + rank_of(mv.from)) / 2;
            self.ep_square = Some(to_square(file_of(mv.from) as i8, middle_rank as i8));
        } else {
            self.ep_square = None;
        }

        self.halfmove_clock = if role == 'P' || capture {
            0
        } else {
            self.halfmove_clock + 1
        };
        if self.turn == BLACK {
            self.fullmove_number += 1;
        }
        self.turn = !self.turn;
        Ok(())
    }

    fn move_rook_for_castle(&mut self, mv: ChessMove) {
        let (rook_from, rook_to) = match square_name(mv.to).as_str() {
            "g1" => ("h1", "f1"),
            "c1" => ("a1", "d1"),
            "g8" => ("h8", "f8"),
            _ => ("a8", "d8"),
        };
        let from = parse_square(rook_from).unwrap();
        let to = parse_square(rook_to).unwrap();
        self.cells[to as usize] = self.cells[from as usize];
        self.cells[from as usize] = '.';
    }

    fn update_castling_rights(&mut self, mv: ChessMove, piece: char) {
        match piece {
            'K' => self.castling &= !(WK | WQ),
            'k' => self.castling &= !(BK | BQ),
            _ => {}
        }
        for (name, bit) in [("a1", WQ), ("h1", WK), ("a8", BQ), ("h8", BK)] {
            let sq = parse_square(name).unwrap();
            if mv.from == sq || mv.to == sq {
                self.castling &= !bit;
            }
        }
    }

    fn san(&self, mv: ChessMove, legal_moves: &[ChessMove]) -> Result<String, String> {
        if !legal_moves.contains(&mv) {
            return Err(format!("illegal move for san: {}", mv.uci()));
        }
        let piece = self.cells[mv.from as usize];
        let role = piece_role(piece);
        let mut notation =
            if role == 'K' && (file_of(mv.to) as i8 - file_of(mv.from) as i8).abs() == 2 {
                if file_of(mv.to) > file_of(mv.from) {
                    "O-O".to_string()
                } else {
                    "O-O-O".to_string()
                }
            } else {
                let capture = self.is_capture(mv);
                let target_name = square_name(mv.to);
                if role == 'P' {
                    let mut token = String::new();
                    if capture {
                        token.push(FILES[file_of(mv.from) as usize] as char);
                        token.push('x');
                    }
                    token.push_str(&target_name);
                    if let Some(promotion) = mv.promotion {
                        token.push('=');
                        token.push(promotion.to_ascii_uppercase());
                    }
                    token
                } else {
                    let mut token = String::new();
                    token.push(role);
                    token.push_str(&self.disambiguation(mv, legal_moves));
                    if capture {
                        token.push('x');
                    }
                    token.push_str(&target_name);
                    token
                }
            };

        let mut probe = self.clone();
        probe.apply_move(mv)?;
        let gives_check = probe.in_check(probe.turn);
        if gives_check && probe.legal_moves().is_empty() {
            notation.push('#');
        } else if gives_check {
            notation.push('+');
        }
        Ok(notation)
    }

    fn disambiguation(&self, mv: ChessMove, legal_moves: &[ChessMove]) -> String {
        let origin_piece = self.cells[mv.from as usize];
        let role = piece_role(origin_piece);
        let rivals: Vec<ChessMove> = legal_moves
            .iter()
            .copied()
            .filter(|candidate| {
                *candidate != mv
                    && candidate.to == mv.to
                    && piece_role(self.cells[candidate.from as usize]) == role
            })
            .collect();
        if rivals.is_empty() {
            return String::new();
        }
        let same_file = rivals
            .iter()
            .any(|candidate| file_of(candidate.from) == file_of(mv.from));
        let same_rank = rivals
            .iter()
            .any(|candidate| rank_of(candidate.from) == rank_of(mv.from));
        if same_file && same_rank {
            square_name(mv.from)
        } else if same_file {
            (RANKS[rank_of(mv.from) as usize] as char).to_string()
        } else {
            (FILES[file_of(mv.from) as usize] as char).to_string()
        }
    }

    fn parse_san(&self, token: &str, legal_moves: &[ChessMove]) -> Result<ChessMove, String> {
        let mut san = token.trim().to_string();
        while san.ends_with(['+', '#', '!', '?']) {
            san.pop();
        }
        if san == "O-O" || san == "0-0" {
            let target = parse_square(if self.turn == WHITE { "g1" } else { "g8" })?;
            let candidates: Vec<ChessMove> = legal_moves
                .iter()
                .copied()
                .filter(|mv| {
                    mv.to == target
                        && piece_role(self.cells[mv.from as usize]) == 'K'
                        && (file_of(mv.to) as i8 - file_of(mv.from) as i8).abs() == 2
                })
                .collect();
            return single_move(candidates, token, self);
        }
        if san == "O-O-O" || san == "0-0-0" {
            let target = parse_square(if self.turn == WHITE { "c1" } else { "c8" })?;
            let candidates: Vec<ChessMove> = legal_moves
                .iter()
                .copied()
                .filter(|mv| {
                    mv.to == target
                        && piece_role(self.cells[mv.from as usize]) == 'K'
                        && (file_of(mv.to) as i8 - file_of(mv.from) as i8).abs() == 2
                })
                .collect();
            return single_move(candidates, token, self);
        }

        let mut body = san.as_str();
        let mut promotion = None;
        if let Some(eq_index) = body.find('=') {
            let suffix = &body[eq_index + 1..];
            promotion = suffix.chars().next().map(|ch| ch.to_ascii_lowercase());
            body = &body[..eq_index];
        }
        if body.len() < 2 {
            return Err(format!("invalid san: {token}"));
        }
        let target_name = &body[body.len() - 2..];
        let target = parse_square(target_name)?;
        let mut prefix = &body[..body.len() - 2];
        let capture_hint = prefix.contains('x');
        prefix = prefix.trim_end_matches('x');
        let first = prefix.chars().next();
        let role = if matches!(first, Some('K' | 'Q' | 'R' | 'B' | 'N')) {
            prefix = &prefix[1..];
            first.unwrap()
        } else {
            'P'
        };
        let mut source_file = None;
        let mut source_rank = None;
        for ch in prefix.chars() {
            if FILES.contains(&(ch as u8)) {
                source_file = Some(ch);
            } else if RANKS.contains(&(ch as u8)) {
                source_rank = Some(ch);
            } else {
                return Err(format!("invalid san: {token}"));
            }
        }

        let candidates: Vec<ChessMove> = legal_moves
            .iter()
            .copied()
            .filter(|mv| {
                let piece = self.cells[mv.from as usize];
                if piece == '.' || piece_role(piece) != role {
                    return false;
                }
                if mv.to != target || mv.promotion != promotion {
                    return false;
                }
                if source_file.is_some_and(|hint| FILES[file_of(mv.from) as usize] as char != hint)
                {
                    return false;
                }
                if source_rank.is_some_and(|hint| RANKS[rank_of(mv.from) as usize] as char != hint)
                {
                    return false;
                }
                if capture_hint && !self.is_capture(*mv) {
                    return false;
                }
                if !capture_hint && role != 'P' && self.is_capture(*mv) {
                    return false;
                }
                true
            })
            .collect();
        single_move(candidates, token, self)
    }
}

fn single_move(
    candidates: Vec<ChessMove>,
    token: &str,
    board: &Board,
) -> Result<ChessMove, String> {
    match candidates.len() {
        1 => Ok(candidates[0]),
        0 => Err(format!(
            "illegal san: {token} in side {}",
            if board.turn { "white" } else { "black" }
        )),
        _ => Err(format!("ambiguous san: {token}")),
    }
}

impl Game {
    fn new() -> Self {
        let mut headers = HashMap::new();
        headers.insert("Event".to_string(), "?".to_string());
        headers.insert("Site".to_string(), "?".to_string());
        headers.insert("Date".to_string(), "????.??.??".to_string());
        headers.insert("Round".to_string(), "?".to_string());
        headers.insert("White".to_string(), "?".to_string());
        headers.insert("Black".to_string(), "?".to_string());
        headers.insert("Result".to_string(), "*".to_string());
        Self {
            headers,
            nodes: vec![Node {
                parent: None,
                mv: None,
                variations: Vec::new(),
                move_text: None,
                board_cache: None,
                legal_cache: None,
                index_cache: None,
            }],
        }
    }

    fn generated(variations_per_round: usize) -> Self {
        let mut game = Self::new();
        game.headers
            .insert("Event".to_string(), "Chess PGN Crypto".to_string());
        game.headers
            .insert("Site".to_string(), "Encrypted Data".to_string());
        game.headers
            .insert("Date".to_string(), "????.??.??".to_string());
        game.headers.insert("Round".to_string(), "-".to_string());
        game.headers
            .insert("White".to_string(), "RookDuel Encode".to_string());
        game.headers
            .insert("Black".to_string(), "Message".to_string());
        game.headers.insert("Result".to_string(), "*".to_string());
        game.headers.insert(
            "VariationsPerRound".to_string(),
            variations_per_round.to_string(),
        );
        game
    }

    fn add_variation(&mut self, parent: usize, mv: ChessMove, move_text: Option<String>) -> usize {
        let index = self.nodes.len();
        self.nodes.push(Node {
            parent: Some(parent),
            mv: Some(mv),
            variations: Vec::new(),
            move_text,
            board_cache: None,
            legal_cache: None,
            index_cache: None,
        });
        self.nodes[parent].variations.push(index);
        index
    }

    fn cache_position(&mut self, node: usize, board: &Board, legal_moves: Vec<ChessMove>) {
        if self.nodes[node].legal_cache.is_some() {
            return;
        }
        let move_index = legal_moves
            .iter()
            .enumerate()
            .map(|(idx, mv)| (*mv, idx))
            .collect();
        self.nodes[node].board_cache = Some(board.clone());
        self.nodes[node].legal_cache = Some(legal_moves);
        self.nodes[node].index_cache = Some(move_index);
    }

    fn board_for_node(&self, node: usize) -> Board {
        if let Some(board) = &self.nodes[node].board_cache {
            return board.clone();
        }
        let mut history = Vec::new();
        let mut cursor = node;
        while let Some(parent) = self.nodes[cursor].parent {
            history.push(self.nodes[cursor].mv.unwrap());
            cursor = parent;
        }
        let mut board = Board::starting();
        for mv in history.iter().rev() {
            let _ = board.apply_move(*mv);
        }
        board
    }
}

fn stats_dict(py: Python<'_>, stats: &CodecStats) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new_bound(py);
    dict.set_item("mainline_plies", stats.mainline_plies)?;
    dict.set_item("variation_plies", stats.variation_plies)?;
    dict.set_item("total_variations", stats.total_variations)?;
    dict.set_item("total_plies", stats.total_plies)?;
    dict.set_item(
        "max_variations_at_position",
        stats.max_variations_at_position,
    )?;
    dict.set_item("positions_with_variations", stats.positions_with_variations)?;
    dict.set_item("max_nesting_depth", stats.max_nesting_depth)?;
    dict.set_item("total_variation_branches", stats.total_variation_branches)?;
    Ok(dict.into())
}

fn canonical(mut value: Vec<u8>) -> Vec<u8> {
    let first_non_zero = value.iter().position(|byte| *byte != 0);
    match first_non_zero {
        Some(index) => {
            if index > 0 {
                value.drain(0..index);
            }
            value
        }
        None => Vec::new(),
    }
}

fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn sub_one(value: &[u8]) -> Result<Vec<u8>, String> {
    if is_zero(value) {
        return Err("integer underflow".to_string());
    }
    let mut output = value.to_vec();
    for byte in output.iter_mut().rev() {
        if *byte > 0 {
            *byte -= 1;
            break;
        }
        *byte = 0xff;
    }
    Ok(canonical(output))
}

fn div_rem_small(value: &[u8], divisor: u32) -> (Vec<u8>, u32) {
    let mut output = Vec::with_capacity(value.len());
    let mut rem = 0u32;
    for byte in value {
        let acc = (rem << 8) + (*byte as u32);
        output.push((acc / divisor) as u8);
        rem = acc % divisor;
    }
    (canonical(output), rem)
}

fn mul_small(value: &[u8], factor: u32) -> Vec<u8> {
    if is_zero(value) || factor == 0 {
        return Vec::new();
    }
    let mut output = vec![0u8; value.len() + 4];
    let mut carry = 0u32;
    let mut out_index = output.len();
    for byte in value.iter().rev() {
        let acc = (*byte as u32) * factor + carry;
        out_index -= 1;
        output[out_index] = (acc & 0xff) as u8;
        carry = acc >> 8;
    }
    while carry > 0 {
        out_index -= 1;
        output[out_index] = (carry & 0xff) as u8;
        carry >>= 8;
    }
    canonical(output[out_index..].to_vec())
}

fn add_small(value: &[u8], addend: u32) -> Vec<u8> {
    let mut output = value.to_vec();
    let mut carry = addend;
    let mut index = output.len();
    while carry > 0 {
        if index == 0 {
            output.insert(0, 0);
            index = 1;
        }
        index -= 1;
        let acc = output[index] as u32 + (carry & 0xff);
        output[index] = (acc & 0xff) as u8;
        carry = (carry >> 8) + (acc >> 8);
    }
    canonical(output)
}

fn add_big(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u16;
    let mut ia = a.len() as isize - 1;
    let mut ib = b.len() as isize - 1;
    while ia >= 0 || ib >= 0 || carry > 0 {
        let av = if ia >= 0 { a[ia as usize] as u16 } else { 0 };
        let bv = if ib >= 0 { b[ib as usize] as u16 } else { 0 };
        let sum = av + bv + carry;
        output.push((sum & 0xff) as u8);
        carry = sum >> 8;
        ia -= 1;
        ib -= 1;
    }
    output.reverse();
    canonical(output)
}

fn mul_big(a: &[u8], b: &[u8]) -> Vec<u8> {
    if is_zero(a) || is_zero(b) {
        return Vec::new();
    }
    let mut tmp = vec![0u32; a.len() + b.len()];
    for (ia, av) in a.iter().rev().enumerate() {
        for (ib, bv) in b.iter().rev().enumerate() {
            let idx = tmp.len() - 1 - ia - ib;
            tmp[idx] += (*av as u32) * (*bv as u32);
        }
    }
    for idx in (1..tmp.len()).rev() {
        let carry = tmp[idx] >> 8;
        tmp[idx] &= 0xff;
        tmp[idx - 1] += carry;
    }
    let mut output = Vec::with_capacity(tmp.len() + 4);
    let mut first = tmp[0];
    if first > 0xff {
        let mut prefix = Vec::new();
        while first > 0 {
            prefix.push((first & 0xff) as u8);
            first >>= 8;
        }
        prefix.reverse();
        output.extend(prefix);
    } else {
        output.push(first as u8);
    }
    output.extend(tmp.into_iter().skip(1).map(|value| value as u8));
    canonical(output)
}

fn num_from_moves(moves_data: &[(usize, usize)]) -> (Vec<u8>, Vec<u8>) {
    let mut num = Vec::new();
    let mut capacity = vec![1u8];
    for (move_index, base) in moves_data.iter().rev() {
        num = add_small(&mul_small(&num, *base as u32), (*move_index + 1) as u32);
    }
    for (_, base) in moves_data {
        capacity = mul_small(&capacity, *base as u32);
    }
    (num, capacity)
}

struct NativeEncoder {
    game: Game,
    stats: CodecStats,
    variations_per_round: usize,
    use_depth_limit: bool,
    max_recursion_depth: usize,
}

impl NativeEncoder {
    fn new(variations_per_round: usize) -> Self {
        Self {
            game: Game::generated(variations_per_round),
            stats: CodecStats::default(),
            variations_per_round: variations_per_round.max(1),
            use_depth_limit: false,
            max_recursion_depth: 10,
        }
    }

    fn encode(mut self, num_bytes: &[u8]) -> Result<(String, CodecStats), String> {
        let mut remaining = canonical(num_bytes.to_vec());
        if is_zero(&remaining) {
            return Err("NUM must be >= 1".to_string());
        }
        remaining = self.encode_mainline(remaining)?;
        if !is_zero(&remaining) {
            remaining = self.distribute_variations(remaining, 0, 0)?;
        }
        if !is_zero(&remaining) {
            return Err("Could not encode all data".to_string());
        }
        self.stats.total_plies = self.stats.mainline_plies + self.stats.variation_plies;
        let pgn = self.export_pgn();
        Ok((pgn, self.stats))
    }

    fn add_encoded_move(
        &mut self,
        node: usize,
        board: &mut Board,
        mv: ChessMove,
        legal_moves: &[ChessMove],
    ) -> Result<usize, String> {
        let prefix = if board.turn == WHITE {
            format!("{}. ", board.fullmove_number)
        } else {
            format!("{}... ", board.fullmove_number)
        };
        let move_text = prefix + &board.san(mv, legal_moves)?;
        let child = self.game.add_variation(node, mv, Some(move_text));
        board.apply_move(mv)?;
        Ok(child)
    }

    fn encode_mainline(&mut self, mut remaining: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut node = 0usize;
        let mut board = Board::starting();
        while !is_zero(&remaining) && self.stats.mainline_plies < 250 {
            let legal_moves = board.sorted_legal_moves();
            if legal_moves.is_empty() {
                break;
            }
            let base = legal_moves.len() as u32;
            let adjusted = sub_one(&remaining)?;
            let (next_remaining, move_index) = div_rem_small(&adjusted, base);
            node = self.add_encoded_move(
                node,
                &mut board,
                legal_moves[move_index as usize],
                &legal_moves,
            )?;
            remaining = next_remaining;
            self.stats.mainline_plies += 1;
        }
        Ok(remaining)
    }

    fn distribute_variations(
        &mut self,
        num: Vec<u8>,
        parent_node: usize,
        depth: usize,
    ) -> Result<Vec<u8>, String> {
        if is_zero(&num) {
            return Ok(num);
        }
        if self.use_depth_limit && depth >= self.max_recursion_depth {
            return Ok(num);
        }

        let mut remaining = num;
        let mut positions = self.collect_positions_at_level(parent_node, depth);
        if positions.is_empty() {
            return Ok(remaining);
        }

        let is_mainline_level = depth == 0;
        let mut variation_endpoints: Vec<usize> = Vec::new();
        while !is_zero(&remaining) {
            let mut made_progress = false;
            for position in positions.iter_mut() {
                if is_zero(&remaining) || position.available_moves.is_empty() {
                    continue;
                }
                for _ in 0..self.variations_per_round {
                    if is_zero(&remaining) || position.available_moves.is_empty() {
                        break;
                    }
                    let (next_remaining, endpoint) =
                        self.add_single_variation_with_endpoint(position, remaining)?;
                    remaining = next_remaining;
                    variation_endpoints.push(endpoint);
                    self.stats.total_variations += 1;
                    self.stats.total_variation_branches += 1;
                    made_progress = true;
                }
            }
            if !made_progress {
                break;
            }
        }

        if is_mainline_level {
            for position in &positions {
                let num_vars = self.game.nodes[position.node]
                    .variations
                    .len()
                    .saturating_sub(1);
                if num_vars > 0 {
                    self.stats.positions_with_variations += 1;
                }
                self.stats.max_variations_at_position =
                    self.stats.max_variations_at_position.max(num_vars as u64);
            }
        }
        self.stats.max_nesting_depth = self.stats.max_nesting_depth.max(depth as u64);

        if !is_zero(&remaining) {
            for endpoint in variation_endpoints {
                if is_zero(&remaining) {
                    break;
                }
                if !self.use_depth_limit || depth + 1 < self.max_recursion_depth {
                    remaining = self.distribute_variations(remaining, endpoint, depth + 1)?;
                }
            }
        }
        Ok(remaining)
    }

    fn collect_positions_at_level(&self, parent_node: usize, depth: usize) -> Vec<EncodePosition> {
        if depth == 0 {
            return self.collect_mainline_positions(parent_node);
        }
        let board = self.game.board_for_node(parent_node);
        let legal_moves = board.sorted_legal_moves();
        if legal_moves.is_empty() {
            Vec::new()
        } else {
            vec![EncodePosition {
                node: parent_node,
                legal_moves: legal_moves.clone(),
                available_moves: legal_moves,
                board,
            }]
        }
    }

    fn collect_mainline_positions(&self, game_node: usize) -> Vec<EncodePosition> {
        let mut positions = Vec::new();
        let mut node = game_node;
        let mut board = Board::starting();
        while !self.game.nodes[node].variations.is_empty() {
            let legal_moves = board.sorted_legal_moves();
            if legal_moves.len() > 1 {
                let mainline = self.game.nodes[node].variations[0];
                let mainline_move = self.game.nodes[mainline].mv.unwrap();
                let available_moves = legal_moves
                    .iter()
                    .copied()
                    .filter(|mv| *mv != mainline_move)
                    .collect();
                positions.push(EncodePosition {
                    node,
                    legal_moves,
                    available_moves,
                    board: board.clone(),
                });
            }
            let mainline = self.game.nodes[node].variations[0];
            let _ = board.apply_move(self.game.nodes[mainline].mv.unwrap());
            node = mainline;
        }
        positions
    }

    fn add_single_variation_with_endpoint(
        &mut self,
        position: &mut EncodePosition,
        remaining: Vec<u8>,
    ) -> Result<(Vec<u8>, usize), String> {
        let base = position.available_moves.len() as u32;
        let adjusted = sub_one(&remaining)?;
        let (next_remaining, move_index) = div_rem_small(&adjusted, base);
        let selected = position.available_moves.remove(move_index as usize);
        let mut branch_board = position.board.clone();
        let var_node = self.add_encoded_move(
            position.node,
            &mut branch_board,
            selected,
            &position.legal_moves,
        )?;
        self.stats.variation_plies += 1;
        self.encode_variation_branch_with_endpoint(var_node, branch_board, next_remaining, 1)
    }

    fn encode_variation_branch_with_endpoint(
        &mut self,
        node: usize,
        mut board: Board,
        num: Vec<u8>,
        ply_count: usize,
    ) -> Result<(Vec<u8>, usize), String> {
        if is_zero(&num) || ply_count >= 40 {
            return Ok((num, node));
        }
        let legal_moves = board.sorted_legal_moves();
        if legal_moves.is_empty() {
            return Ok((num, node));
        }
        let base = legal_moves.len() as u32;
        let adjusted = sub_one(&num)?;
        let (remaining, move_index) = div_rem_small(&adjusted, base);
        let next_node = self.add_encoded_move(
            node,
            &mut board,
            legal_moves[move_index as usize],
            &legal_moves,
        )?;
        self.stats.variation_plies += 1;
        self.encode_variation_branch_with_endpoint(next_node, board, remaining, ply_count + 1)
    }

    fn export_pgn(&self) -> String {
        let main_tags = ["Event", "Site", "Date", "Round", "White", "Black", "Result"];
        let mut header_lines = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for tag in main_tags {
            if let Some(value) = self.game.headers.get(tag) {
                header_lines.push(format!("[{} \"{}\"]", tag, escape_tag(value)));
                seen.insert(tag.to_string());
            }
        }
        let mut extra: Vec<_> = self
            .game
            .headers
            .iter()
            .filter(|(key, _)| !seen.contains(*key))
            .collect();
        extra.sort_by(|a, b| a.0.cmp(b.0));
        for (key, value) in extra {
            header_lines.push(format!("[{} \"{}\"]", key, escape_tag(value)));
        }
        let mut moves = self.write_cached_line(0);
        moves.push(
            self.game
                .headers
                .get("Result")
                .cloned()
                .unwrap_or_else(|| "*".to_string()),
        );
        format!(
            "{}\n\n{}\n",
            header_lines.join("\n"),
            moves.join(" ").trim()
        )
    }

    fn write_cached_line(&self, node: usize) -> Vec<String> {
        let mut segments = Vec::new();
        let mut cursor = node;
        while !self.game.nodes[cursor].variations.is_empty() {
            let mainline = self.game.nodes[cursor].variations[0];
            segments.push(
                self.game.nodes[mainline]
                    .move_text
                    .clone()
                    .unwrap_or_default(),
            );
            for sideline in self.game.nodes[cursor].variations.iter().skip(1) {
                segments.push(format!("({})", self.write_cached_branch(*sideline)));
            }
            cursor = mainline;
        }
        segments
    }

    fn write_cached_branch(&self, branch: usize) -> String {
        let mut segments = Vec::new();
        segments.push(
            self.game.nodes[branch]
                .move_text
                .clone()
                .unwrap_or_default(),
        );
        segments.extend(self.write_cached_line(branch));
        segments.join(" ")
    }
}

struct EncodePosition {
    node: usize,
    legal_moves: Vec<ChessMove>,
    available_moves: Vec<ChessMove>,
    board: Board,
}

fn escape_tag(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

struct NativeDecoder {
    game: Game,
    variations_per_round: usize,
    state_cache: HashMap<usize, PositionState>,
}

impl NativeDecoder {
    fn parse(pgn_text: &str) -> Result<Self, String> {
        let game = read_game(pgn_text)?;
        if game.nodes[0].variations.is_empty() {
            return Err("Empty game".to_string());
        }
        let variations_per_round = game
            .headers
            .get("VariationsPerRound")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        Ok(Self {
            game,
            variations_per_round,
            state_cache: HashMap::new(),
        })
    }

    fn decode(mut self) -> Result<(Vec<u8>, CodecStats), String> {
        let mainline_positions = self.collect_mainline_positions(0, true);
        let (mainline_num, mainline_capacity) = self.decode_mainline(&mainline_positions)?;
        let variation_num = self.decode_distributed_variations(0)?;
        let value = if is_zero(&variation_num) {
            mainline_num
        } else {
            add_big(&mainline_num, &mul_big(&variation_num, &mainline_capacity))
        };
        Ok((value, CodecStats::default()))
    }

    fn position_state(&mut self, node: usize, board: Option<Board>) -> PositionState {
        if let Some(state) = self.state_cache.get(&node) {
            return PositionState {
                legal_moves: state.legal_moves.clone(),
                move_index: state.move_index.clone(),
                board: state.board.clone(),
            };
        }
        let board_state = self.game.nodes[node]
            .board_cache
            .clone()
            .or(board)
            .unwrap_or_else(|| self.game.board_for_node(node));
        let legal_moves = self.game.nodes[node]
            .legal_cache
            .clone()
            .unwrap_or_else(|| board_state.sorted_legal_moves());
        let move_index = self.game.nodes[node]
            .index_cache
            .clone()
            .unwrap_or_else(|| {
                legal_moves
                    .iter()
                    .enumerate()
                    .map(|(idx, mv)| (*mv, idx))
                    .collect()
            });
        let state = PositionState {
            legal_moves,
            move_index,
            board: board_state,
        };
        self.state_cache.insert(
            node,
            PositionState {
                legal_moves: state.legal_moves.clone(),
                move_index: state.move_index.clone(),
                board: state.board.clone(),
            },
        );
        state
    }

    fn decode_mainline(&self, positions: &[usize]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut moves_data = Vec::new();
        for node in positions {
            if self.game.nodes[*node].variations.is_empty() {
                break;
            }
            let main_node = self.game.nodes[*node].variations[0];
            let state = self.state_for_cached_node(*node)?;
            let mv = self.game.nodes[main_node].mv.unwrap();
            let move_index = *state
                .move_index
                .get(&mv)
                .ok_or_else(|| format!("Illegal move: {}", mv.uci()))?;
            moves_data.push((move_index, state.legal_moves.len()));
        }
        if moves_data.is_empty() {
            return Err("No valid moves".to_string());
        }
        Ok(num_from_moves(&moves_data))
    }

    fn state_for_cached_node(&self, node: usize) -> Result<PositionState, String> {
        let board = self.game.nodes[node]
            .board_cache
            .clone()
            .unwrap_or_else(|| self.game.board_for_node(node));
        let legal_moves = self.game.nodes[node]
            .legal_cache
            .clone()
            .unwrap_or_else(|| board.sorted_legal_moves());
        let move_index = self.game.nodes[node]
            .index_cache
            .clone()
            .unwrap_or_else(|| {
                legal_moves
                    .iter()
                    .enumerate()
                    .map(|(idx, mv)| (*mv, idx))
                    .collect()
            });
        Ok(PositionState {
            legal_moves,
            move_index,
            board,
        })
    }

    fn decode_distributed_variations(&mut self, game_node: usize) -> Result<Vec<u8>, String> {
        let mut all_variations = Vec::new();
        self.collect_variations_recursive(game_node, &mut all_variations, 0, None)?;
        let mut total = Vec::new();
        for (var_num, capacity) in all_variations.into_iter().rev() {
            total = add_big(&mul_big(&total, &capacity), &var_num);
        }
        Ok(total)
    }

    fn collect_variations_recursive(
        &mut self,
        parent_node: usize,
        all_variations: &mut Vec<(Vec<u8>, Vec<u8>)>,
        depth: usize,
        parent_board: Option<Board>,
    ) -> Result<(), String> {
        let positions = if depth == 0 {
            self.collect_mainline_positions(parent_node, false)
        } else {
            let state = self.position_state(parent_node, parent_board);
            if state.legal_moves.is_empty() {
                Vec::new()
            } else {
                self.state_cache.insert(parent_node, state);
                vec![parent_node]
            }
        };
        if positions.is_empty() {
            return Ok(());
        }
        let max_vars = positions
            .iter()
            .map(|node| {
                self.game.nodes[*node]
                    .variations
                    .len()
                    .saturating_sub(if depth == 0 { 1 } else { 0 })
            })
            .max()
            .unwrap_or(0);
        let mut var_index = 0usize;
        let mut endpoints = Vec::new();
        while var_index < max_vars {
            for node in &positions {
                let variations = if depth == 0 {
                    self.game.nodes[*node]
                        .variations
                        .iter()
                        .skip(1)
                        .copied()
                        .collect::<Vec<_>>()
                } else {
                    self.game.nodes[*node].variations.clone()
                };
                let mainline_move = if depth == 0 {
                    let mainline = self.game.nodes[*node].variations[0];
                    self.game.nodes[mainline].mv
                } else {
                    None
                };
                for offset in 0..self.variations_per_round {
                    let current_var_index = var_index + offset;
                    if current_var_index < variations.len() {
                        let var_node = variations[current_var_index];
                        let (var_num, capacity, endpoint, endpoint_board) = self
                            .decode_single_variation_with_endpoint(
                                *node,
                                var_node,
                                mainline_move,
                                current_var_index,
                                depth,
                            )?;
                        all_variations.push((var_num, capacity));
                        endpoints.push((endpoint, endpoint_board));
                    }
                }
            }
            var_index += self.variations_per_round;
        }
        for (endpoint, endpoint_board) in endpoints {
            self.collect_variations_recursive(
                endpoint,
                all_variations,
                depth + 1,
                Some(endpoint_board),
            )?;
        }
        Ok(())
    }

    fn collect_mainline_positions(&mut self, game_node: usize, include_forced: bool) -> Vec<usize> {
        let mut positions = Vec::new();
        let mut node = game_node;
        let mut board = Board::starting();
        while !self.game.nodes[node].variations.is_empty() {
            let state = self.position_state(node, Some(board.clone()));
            if include_forced || state.legal_moves.len() > 1 {
                positions.push(node);
            }
            let mainline = self.game.nodes[node].variations[0];
            let _ = board.apply_move(self.game.nodes[mainline].mv.unwrap());
            node = mainline;
        }
        positions
    }

    fn decode_single_variation_with_endpoint(
        &mut self,
        parent_node: usize,
        var_node: usize,
        mainline_move: Option<ChessMove>,
        var_round: usize,
        depth: usize,
    ) -> Result<(Vec<u8>, Vec<u8>, usize, Board), String> {
        let parent_state = self.position_state(parent_node, None);
        let mut used_moves = Vec::new();
        if depth == 0 {
            if let Some(mv) = mainline_move {
                used_moves.push(mv);
            }
        }
        let variations = if depth == 0 {
            self.game.nodes[parent_node]
                .variations
                .iter()
                .skip(1)
                .copied()
                .collect::<Vec<_>>()
        } else {
            self.game.nodes[parent_node].variations.clone()
        };
        for (idx, variation) in variations.iter().enumerate() {
            if idx < var_round {
                used_moves.push(self.game.nodes[*variation].mv.unwrap());
            }
        }
        let var_move = self.game.nodes[var_node].mv.unwrap();
        let mut move_index = None;
        let mut base = 0usize;
        for mv in &parent_state.legal_moves {
            if used_moves.contains(mv) {
                continue;
            }
            if *mv == var_move {
                move_index = Some(base);
            }
            base += 1;
        }
        let Some(move_index) = move_index else {
            return Ok((Vec::new(), vec![1], var_node, parent_state.board));
        };
        let mut branch_board = parent_state.board.clone();
        branch_board.apply_move(var_move)?;
        let (branch_num, branch_capacity, endpoint, endpoint_board) =
            self.decode_variation_branch_with_endpoint(var_node, branch_board)?;
        let total_num = add_small(
            &mul_small(&branch_num, base as u32),
            (move_index + 1) as u32,
        );
        let total_capacity = mul_small(&branch_capacity, base as u32);
        Ok((total_num, total_capacity, endpoint, endpoint_board))
    }

    fn decode_variation_branch_with_endpoint(
        &mut self,
        node: usize,
        board: Board,
    ) -> Result<(Vec<u8>, Vec<u8>, usize, Board), String> {
        let mut moves_data = Vec::new();
        let mut current = node;
        let mut current_board = board;
        let mut ply_count = 1usize;
        while !self.game.nodes[current].variations.is_empty() && ply_count < 40 {
            let next_node = self.game.nodes[current].variations[0];
            let state = self.position_state(current, Some(current_board.clone()));
            if state.legal_moves.is_empty() {
                break;
            }
            let mv = self.game.nodes[next_node].mv.unwrap();
            let Some(move_index) = state.move_index.get(&mv).copied() else {
                break;
            };
            moves_data.push((move_index, state.legal_moves.len()));
            current_board.apply_move(mv)?;
            current = next_node;
            ply_count += 1;
        }
        let (num, capacity) = num_from_moves(&moves_data);
        Ok((
            num,
            if is_zero(&capacity) {
                vec![1]
            } else {
                capacity
            },
            current,
            current_board,
        ))
    }
}

fn read_game(pgn_text: &str) -> Result<Game, String> {
    let (headers, movetext) = split_headers(pgn_text);
    let mut game = Game::new();
    for (key, value) in headers {
        game.headers.insert(key, value);
    }
    let mut current = 0usize;
    let mut board = Board::starting();
    let mut branch_stack: Vec<(usize, Board)> = Vec::new();
    let mut parent_board_by_child: HashMap<usize, Board> = HashMap::new();

    for raw_token in scan_tokens(&movetext) {
        let token = strip_embedded_move_number(&raw_token);
        if token.is_empty() {
            continue;
        }
        if token == "(" {
            let Some(parent) = game.nodes[current].parent else {
                continue;
            };
            branch_stack.push((current, board.clone()));
            let child = current;
            current = parent;
            board = parent_board_by_child
                .get(&child)
                .cloned()
                .unwrap_or_else(|| game.board_for_node(current));
            continue;
        }
        if token == ")" {
            if let Some((saved_current, saved_board)) = branch_stack.pop() {
                current = saved_current;
                board = saved_board;
            }
            continue;
        }
        if token.starts_with('$')
            || matches!(token.as_str(), "!" | "?" | "!!" | "??" | "!?" | "?!")
            || is_move_number(&token)
        {
            continue;
        }
        if matches!(token.as_str(), "1-0" | "0-1" | "1/2-1/2" | "*") {
            if branch_stack.is_empty() {
                game.headers.insert("Result".to_string(), token);
            }
            continue;
        }
        let legal_moves = board.sorted_legal_moves();
        game.cache_position(current, &board, legal_moves.clone());
        let mv = board.parse_san(&token, &legal_moves)?;
        let parent_board = board.clone();
        current = game.add_variation(current, mv, None);
        parent_board_by_child.insert(current, parent_board);
        board.apply_move(mv)?;
    }
    Ok(game)
}

fn split_headers(source: &str) -> (HashMap<String, String>, String) {
    let mut headers = HashMap::new();
    let mut body_start = 0usize;
    let mut saw_header = false;
    for line in source.trim_start_matches('\u{feff}').lines() {
        let stripped = line.trim();
        body_start += line.len() + 1;
        if stripped.is_empty() {
            if saw_header {
                break;
            }
            continue;
        }
        if !(stripped.starts_with('[') && stripped.ends_with(']')) {
            body_start = body_start.saturating_sub(line.len() + 1);
            break;
        }
        if let Some(space_idx) = stripped.find(' ') {
            let key = stripped[1..space_idx].to_string();
            let value_part = stripped[space_idx + 1..stripped.len() - 1].trim();
            if value_part.starts_with('"') && value_part.ends_with('"') {
                headers.insert(key, unescape_tag(&value_part[1..value_part.len() - 1]));
                saw_header = true;
            }
        }
    }
    let body = if body_start <= source.len() {
        source[body_start..].to_string()
    } else {
        String::new()
    };
    (headers, body)
}

fn unescape_tag(value: &str) -> String {
    value.replace("\\\"", "\"").replace("\\\\", "\\")
}

fn is_move_number(token: &str) -> bool {
    (token.ends_with('.')
        && token[..token.len() - 1]
            .chars()
            .all(|ch| ch.is_ascii_digit()))
        || (token.ends_with("...")
            && token[..token.len() - 3]
                .chars()
                .all(|ch| ch.is_ascii_digit()))
}

fn strip_embedded_move_number(token: &str) -> String {
    if !token.as_bytes().first().is_some_and(u8::is_ascii_digit) || !token.contains('.') {
        return token.to_string();
    }
    let trimmed = token.trim_start_matches(|ch: char| ch.is_ascii_digit() || ch == '.');
    if trimmed.is_empty() {
        token.to_string()
    } else {
        trimmed.to_string()
    }
}

fn scan_tokens(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut cursor = 0usize;
    while cursor < chars.len() {
        let ch = chars[cursor];
        if ch.is_whitespace() {
            cursor += 1;
            continue;
        }
        if ch == ';' {
            while cursor < chars.len() && chars[cursor] != '\n' {
                cursor += 1;
            }
            continue;
        }
        if ch == '{' {
            cursor += 1;
            let mut depth = 1usize;
            while cursor < chars.len() && depth > 0 {
                if chars[cursor] == '{' {
                    depth += 1;
                } else if chars[cursor] == '}' {
                    depth -= 1;
                }
                cursor += 1;
            }
            continue;
        }
        if ch == '(' || ch == ')' {
            tokens.push(ch.to_string());
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < chars.len()
            && !chars[cursor].is_whitespace()
            && !matches!(chars[cursor], '{' | '}' | '(' | ')' | ';')
        {
            cursor += 1;
        }
        tokens.push(chars[start..cursor].iter().collect());
    }
    tokens
}

#[pyfunction]
pub fn encode_chess_pgn_integer(
    py: Python<'_>,
    num_bytes: &[u8],
    variations_per_round: usize,
) -> PyResult<(String, Py<PyDict>)> {
    let encoder = NativeEncoder::new(variations_per_round);
    let (pgn, stats) = encoder.encode(num_bytes).map_err(value_error)?;
    Ok((pgn, stats_dict(py, &stats)?))
}

#[pyfunction]
pub fn decode_chess_pgn_integer(
    py: Python<'_>,
    pgn_text: &str,
) -> PyResult<(Py<PyBytes>, Py<PyDict>)> {
    let decoder = NativeDecoder::parse(pgn_text).map_err(value_error)?;
    let (num_bytes, stats) = decoder.decode().map_err(value_error)?;
    Ok((
        PyBytes::new_bound(py, &num_bytes).into(),
        stats_dict(py, &stats)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bigint_multiply_preserves_high_carry() {
        let left = vec![0xff; 128];
        let right = vec![0xfe; 96];
        let product = mul_big(&left, &right);

        assert!(product.len() >= left.len());
        assert!(!is_zero(&product));
        assert_ne!(product[0], 0);
    }

    #[test]
    fn native_chess_codec_roundtrip_large_integer() {
        let mut value = b"Avikal native chess roundtrip ".repeat(72);
        value.push(1);

        let encoder = NativeEncoder::new(5);
        let (pgn_text, encode_stats) = encoder.encode(&value).unwrap();
        let decoder = NativeDecoder::parse(&pgn_text).unwrap();
        let (decoded, _decode_stats) = decoder.decode().unwrap();

        assert_eq!(decoded, value);
        assert!(encode_stats.mainline_plies > 0);
        assert!(pgn_text.contains("VariationsPerRound"));
    }
}
