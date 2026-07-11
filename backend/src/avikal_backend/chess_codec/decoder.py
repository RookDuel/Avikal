"""Chess PGN decoder for Avikal metadata integers.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import io
import os
from dataclasses import dataclass
from typing import Callable

from .. import chess


@dataclass
class _PositionState:
    node: chess.pgn.GameNode
    legal_moves: list
    move_index: dict
    board: chess.Board


class PGNDecoder:
    """Decode recursive-variation chess PGNs back to integers."""
    
    MAX_VAR_PLIES = 40  # Max plies for each variation branch
    
    def __init__(self):
        """Initialize decoder."""
        self.variations_per_round = 1
        self._state_cache = {}
        self._progress_callback = None
        self._progress_ticks = 0
        self.last_stats: dict[str, int] = {}
    
    def decode_from_pgn(self, pgn_text: str, progress_callback: Callable[[str, float], None] | None = None) -> int:
        """Decode PGN to NUM."""
        if not pgn_text or not isinstance(pgn_text, str):
            raise ValueError("Invalid PGN")

        if self._native_route_allowed():
            from .native_bridge import native_chess_available, native_decode_chess_pgn_integer

            if native_chess_available():
                if progress_callback is not None:
                    progress_callback("Parsing keychain PGN", 0.05)
                    progress_callback("Decoding recursive PGN variations", 0.55)
                    progress_callback("Reconstructing metadata integer", 0.92)
                value, stats = native_decode_chess_pgn_integer(pgn_text)
                self.last_stats = dict(stats or {})
                return value
        
        try:
            self.last_stats = {}
            self._state_cache = {}
            self._progress_callback = progress_callback
            self._progress_ticks = 0
            self._progress("Parsing keychain PGN", 0.05, force=True)
            pgn_io = io.StringIO(pgn_text.strip())
            game = chess.pgn.read_game(pgn_io)
            
            if game is None:
                raise ValueError("Could not parse PGN")
            
            if not game.variations:
                raise ValueError("Empty game")

            self.last_stats = self._observed_stats(game)
            
            # Read variations_per_round from the header, falling back to 1 if absent or invalid.
            self.variations_per_round = 1
            if "VariationsPerRound" in game.headers:
                try:
                    self.variations_per_round = int(game.headers["VariationsPerRound"])
                except (ValueError, TypeError):
                    self.variations_per_round = 1
            
            self._progress("Precomputing chess positions", 0.18, force=True)
            mainline_positions = self._collect_mainline_positions(game, include_forced=True)
            mainline_num, mainline_capacity = self._decode_mainline(game, mainline_positions)
            
            self._progress("Decoding recursive PGN variations", 0.35, force=True)
            variation_num = self._decode_distributed_variations(game)
            
            if variation_num > 0:
                self._progress("Reconstructing metadata integer", 0.92, force=True)
                return mainline_num + variation_num * mainline_capacity
            
            self._progress("Reconstructing metadata integer", 0.92, force=True)
            return mainline_num
            
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"PGN parsing failed: {str(e)}")
        finally:
            self._state_cache = {}
            self._progress_callback = None

    @staticmethod
    def _observed_stats(game: chess.pgn.Game) -> dict[str, int]:
        """Measure the observable PGN tree without replaying board positions."""
        stats = {
            "mainline_plies": 0,
            "variation_plies": 0,
            "total_variations": 0,
            "total_plies": 0,
            "max_variations_at_position": 0,
            "positions_with_variations": 0,
            "max_nesting_depth": 0,
            "total_variation_branches": 0,
        }
        stack = [(game, True, 0)]
        while stack:
            node, on_mainline, depth = stack.pop()
            explicit_branches = max(0, len(node.variations) - 1)
            if explicit_branches:
                stats["positions_with_variations"] += 1
                stats["max_variations_at_position"] = max(
                    stats["max_variations_at_position"], explicit_branches
                )
                stats["total_variations"] += explicit_branches
                stats["total_variation_branches"] += explicit_branches
            for index, child in enumerate(node.variations):
                child_on_mainline = on_mainline and index == 0
                child_depth = depth if index == 0 else depth + 1
                if child_on_mainline:
                    stats["mainline_plies"] += 1
                else:
                    stats["variation_plies"] += 1
                    stats["max_nesting_depth"] = max(stats["max_nesting_depth"], child_depth)
                stack.append((child, child_on_mainline, child_depth))
        stats["total_plies"] = stats["mainline_plies"] + stats["variation_plies"]
        return stats

    def _native_route_allowed(self) -> bool:
        """Use Rust only for default production PGN branch semantics."""
        return os.environ.get("AVIKAL_CHESS_CODEC_FORCE_PYTHON") != "1" and self.MAX_VAR_PLIES == 40

    def _progress(self, description: str, fraction: float, *, force: bool = False) -> None:
        """Emit decoder progress if a metadata progress callback is bound."""
        if self._progress_callback is None:
            return
        self._progress_ticks += 1
        if force or self._progress_ticks % 64 == 0 or fraction >= 0.9:
            self._progress_callback(description, fraction)

    def _position_state(self, node: chess.pgn.GameNode, board: chess.Board | None = None) -> _PositionState:
        """Return cached legal-move state for a node without repeated ancestry replay."""
        cache_key = id(node)
        cached = self._state_cache.get(cache_key)
        if cached is not None:
            return cached

        parsed_board = getattr(node, "_avikal_board", None)
        parsed_legal_moves = getattr(node, "_avikal_legal_moves", None)
        parsed_move_index = getattr(node, "_avikal_move_index", None)
        if parsed_board is not None and parsed_legal_moves is not None and parsed_move_index is not None:
            board_state = parsed_board.copy()
            legal_moves = parsed_legal_moves
            move_index = parsed_move_index
        else:
            board_state = board.copy() if board is not None else node.board()
            legal_moves = sorted(board_state.legal_moves, key=lambda m: m.uci())
            move_index = {move: index for index, move in enumerate(legal_moves)}

        state = _PositionState(
            node=node,
            legal_moves=legal_moves,
            move_index=move_index,
            board=board_state.copy(),
        )
        self._state_cache[cache_key] = state
        return state
    
    def _decode_mainline(self, game: chess.pgn.Game, mainline_positions: list[_PositionState]) -> tuple[int, int]:
        """Decode mainline moves and capacity from precomputed positions."""
        moves_data = []
        
        for state in mainline_positions:
            if not state.node.variations:
                break
            main_node = state.node.variations[0]
            if not state.legal_moves:
                break
            move = main_node.move
            move_index = state.move_index.get(move)
            if move_index is None:
                raise ValueError(f"Illegal move: {move}")
            
            base = len(state.legal_moves)
            moves_data.append((move_index, base))
        
        if not moves_data:
            raise ValueError("No valid moves")
        
        num = 0
        capacity = 1
        for move_index, base in reversed(moves_data):
            num = num * base + move_index + 1
        for _, base in moves_data:
            capacity *= base
        
        return num, capacity
    
    def _decode_distributed_variations(self, game: chess.pgn.Game) -> int:
        """Decode variations distributed across mainline moves."""
        # Collect all variations in the order they were encoded (ROUND-ROBIN)
        all_variations = self._collect_all_variations(game)
        
        if not all_variations:
            return 0
        
        # Decode in reverse order (last encoded = first decoded)
        total = 0
        for var_info in reversed(all_variations):
            var_num = var_info['num']
            capacity = var_info['capacity']
            total = total * capacity + var_num
        
        return total
    
    def _collect_all_variations(self, game: chess.pgn.Game) -> list:
        """Collect variations in the encoder's recursive order."""
        all_variations = []
        
        # Start recursive collection from mainline (depth 0)
        self._collect_variations_recursive(game, all_variations, depth=0, parent_board=None)
        
        return all_variations
    
    def _collect_variations_recursive(self, parent_node, all_variations: list, depth: int, parent_board):
        """Recursively collect variations at the current depth."""
        # Collect positions at current level
        if depth == 0:
            positions = self._collect_mainline_positions(parent_node, include_forced=False)
        else:
            # For sub-variations, parent_node is the endpoint
            state = self._position_state(parent_node, parent_board)
            if len(state.legal_moves) > 0:
                positions = [state]
            else:
                return
        
        if not positions:
            return
        
        # Find max variations at any position at this level
        max_vars = 0
        for state in positions:
            node = state.node
            num_vars = len(node.variations) - (1 if depth == 0 else 0)  # -1 for mainline at depth 0
            max_vars = max(max_vars, num_vars)
        
        # Collect variations round by round at this level
        var_index = 0
        variation_endpoints = []  # Track endpoints for recursive collection
        
        while var_index < max_vars:
            for state in positions:
                node = state.node
                
                # Get variations at this position
                if depth == 0:
                    mainline_move = node.variations[0].move
                    variations = node.variations[1:]  # Exclude mainline
                else:
                    mainline_move = None
                    variations = node.variations  # All are variations
                
                # Collect N variations from this position in this round
                for i in range(self.variations_per_round):
                    current_var_index = var_index + i
                    
                    if current_var_index < len(variations):
                        var_node = variations[current_var_index]
                        
                        # Decode this variation
                        var_num, capacity, endpoint, endpoint_board = self._decode_single_variation_with_endpoint(
                            state, var_node, mainline_move, current_var_index, depth
                        )
                        
                        all_variations.append({
                            'num': var_num,
                            'capacity': capacity
                        })
                        
                        # Track endpoint for recursive sub-variation collection
                        if endpoint:
                            variation_endpoints.append((endpoint, endpoint_board))
                            self._progress("Decoding recursive PGN variations", min(0.88, 0.35 + (len(all_variations) / 600.0)))
            
            var_index += self.variations_per_round
        
        # Recursively collect sub-variations from endpoints
        for endpoint, endpoint_board in variation_endpoints:
            self._collect_variations_recursive(endpoint, all_variations, depth + 1, endpoint_board)
    
    def _collect_mainline_positions(self, game: chess.pgn.Game, *, include_forced: bool) -> list[_PositionState]:
        """Collect info about all mainline positions."""
        positions = []
        node = game
        board = chess.Board()
        
        while node.variations:
            state = self._position_state(node, board)
            
            if include_forced or len(state.legal_moves) > 1:
                positions.append(state)
            
            board.push(node.variations[0].move)
            node = node.variations[0]
        
        return positions
    
    def _decode_single_variation(self, parent_node: chess.pgn.GameNode,
                                  var_node: chess.pgn.GameNode,
                                  legal_moves: list, mainline_move: chess.Move,
                                  var_round: int, depth: int = 0) -> tuple:
        """Decode a single variation, return (num, capacity)."""
        state = self._position_state(parent_node)
        var_num, capacity, _, _ = self._decode_single_variation_with_endpoint(
            state, var_node, mainline_move, var_round, depth
        )
        return var_num, capacity
    
    def _decode_single_variation_with_endpoint(self, parent_state: _PositionState,
                                               var_node: chess.pgn.GameNode,
                                               mainline_move: chess.Move | None,
                                               var_round: int, depth: int = 0) -> tuple:
        """Decode a single variation and return num, capacity, and endpoint."""
        parent_node = parent_state.node
        legal_moves = parent_state.legal_moves

        # Calculate available moves at the time this variation was added
        if depth == 0:
            # At mainline level, exclude mainline move
            used_moves = {mainline_move}
        else:
            # At sub-variation level, no mainline to exclude
            used_moves = set()
        
        # Exclude all previous variations at this position
        variations = parent_node.variations[1:] if depth == 0 else parent_node.variations
        for i, v in enumerate(variations):
            if i < var_round:
                used_moves.add(v.move)
        
        var_move = var_node.move
        move_index = None
        base = 0
        for move in legal_moves:
            if move in used_moves:
                continue
            if move == var_move:
                move_index = base
            base += 1

        if base == 0 or move_index is None:
            return 0, 1, None, None
        
        branch_board = parent_state.board.copy()
        branch_board.push(var_move)
        branch_num, branch_capacity, endpoint, endpoint_board = self._decode_variation_branch_with_endpoint(var_node, branch_board)
        
        # Total num for this variation
        total_num = branch_num * base + move_index + 1
        total_capacity = base * branch_capacity
        
        return total_num, total_capacity, endpoint, endpoint_board
    
    def _decode_variation_branch(self, node: chess.pgn.GameNode) -> int:
        """Decode a variation branch."""
        board = node.board()
        num, _, _, _ = self._decode_variation_branch_with_endpoint(node, board)
        return num
    
    def _decode_variation_branch_with_endpoint(self, node: chess.pgn.GameNode, board: chess.Board) -> tuple:
        """Decode a variation branch and return num, capacity, endpoint, and endpoint board."""
        moves_data = []
        current = node
        current_board = board.copy()
        ply_count = 1
        
        while current.variations and ply_count < self.MAX_VAR_PLIES:
            next_node = current.variations[0]
            state = self._position_state(current, current_board)
            legal_moves = state.legal_moves
            
            if not legal_moves:
                break
            
            move = next_node.move
            move_index = state.move_index.get(move)
            if move_index is None:
                break
            
            base = len(legal_moves)
            moves_data.append((move_index, base))
            
            current_board.push(move)
            current = next_node
            ply_count += 1
        
        num = 0
        capacity = 1
        for move_index, base in reversed(moves_data):
            num = num * base + move_index + 1
        for _, base in moves_data:
            capacity *= base
        
        return num, max(1, capacity), current, current_board.copy()
    
    def _calculate_mainline_capacity(self, game: chess.pgn.Game) -> int:
        """Calculate encoding capacity of mainline."""
        capacity = 1
        node = game
        board = chess.Board()
        
        while node.variations:
            legal_moves = list(board.legal_moves)
            if not legal_moves:
                break
            
            capacity *= len(legal_moves)
            board.push(node.variations[0].move)
            node = node.variations[0]
        
        return capacity
    
    def _calculate_branch_capacity(self, node: chess.pgn.GameNode) -> int:
        """Calculate capacity of a variation branch."""
        capacity = 1
        current = node
        board = node.board()
        ply_count = 1
        
        while current.variations and ply_count < self.MAX_VAR_PLIES:
            legal_moves = list(board.legal_moves)
            if not legal_moves:
                break
            
            capacity *= len(legal_moves)
            board.push(current.variations[0].move)
            current = current.variations[0]
            ply_count += 1
        
        return max(1, capacity)
