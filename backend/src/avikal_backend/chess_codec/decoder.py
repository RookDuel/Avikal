"""
Chess PGN decoder - UNLIMITED VARIATIONS version for Time Capsule
Handles mainline + distributed variations with NO LIMIT on variations per move.

Mirrors the unlimited encoder's structure exactly.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import io

from .. import chess


class PGNDecoder:
    """Decodes chess PGN with NESTED RECURSIVE variations back to NUM."""
    
    MAX_VAR_PLIES = 40  # Max plies for each variation branch
    
    def __init__(self):
        """Initialize decoder."""
        self.variations_per_round = 1
    
    def decode_from_pgn(self, pgn_text: str) -> int:
        """Decode PGN to NUM."""
        if not pgn_text or not isinstance(pgn_text, str):
            raise ValueError("Invalid PGN")
        
        try:
            pgn_io = io.StringIO(pgn_text.strip())
            game = chess.pgn.read_game(pgn_io)
            
            if game is None:
                raise ValueError("Could not parse PGN")
            
            if not game.variations:
                raise ValueError("Empty game")
            
            # Read variations_per_round from the header, falling back to 1 if absent or invalid.
            self.variations_per_round = 1
            if "VariationsPerRound" in game.headers:
                try:
                    self.variations_per_round = int(game.headers["VariationsPerRound"])
                except (ValueError, TypeError):
                    self.variations_per_round = 1
            
            # Step 1: Decode mainline
            mainline_num = self._decode_mainline(game)
            
            # Step 2: Decode distributed variations (UNLIMITED)
            variation_num = self._decode_distributed_variations(game)
            
            if variation_num > 0:
                mainline_capacity = self._calculate_mainline_capacity(game)
                return mainline_num + variation_num * mainline_capacity
            
            return mainline_num
            
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"PGN parsing failed: {str(e)}")
    
    def _decode_mainline(self, game: chess.pgn.Game) -> int:
        """Decode mainline moves to NUM."""
        moves_data = []
        node = game
        board = chess.Board()
        
        while node.variations:
            main_node = node.variations[0]
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
            
            if not legal_moves:
                break
            
            move = main_node.move
            if move not in legal_moves:
                raise ValueError(f"Illegal move: {move}")
            
            move_index = legal_moves.index(move)
            base = len(legal_moves)
            moves_data.append((move_index, base))
            
            board.push(move)
            node = main_node
        
        if not moves_data:
            raise ValueError("No valid moves")
        
        # Reconstruct NUM
        num = 0
        for move_index, base in reversed(moves_data):
            num = num * base + move_index + 1
        
        return num
    
    def _decode_distributed_variations(self, game: chess.pgn.Game) -> int:
        """
        Decode variations distributed across mainline moves.
        NO LIMIT on variations per position - handles any number.
        """
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
        """
        Collect all variations in NESTED RECURSIVE encoding order.
        
        The encoder creates variations recursively:
        1. Level 0: N variations from each mainline position
        2. Level 1: N sub-variations from end of each level-0 variation
        3. Level 2: N sub-variations from end of each level-1 variation
        ...
        
        We must collect in the same order (depth-first traversal).
        """
        all_variations = []
        
        # Start recursive collection from mainline (depth 0)
        self._collect_variations_recursive(game, all_variations, depth=0)
        
        return all_variations
    
    def _collect_variations_recursive(self, parent_node, all_variations: list, depth: int):
        """
        Recursively collect variations at current depth level.
        
        Args:
            parent_node: Node to collect variations from
            all_variations: List to append variation info to
            depth: Current recursion depth
        """
        # Collect positions at current level
        if depth == 0:
            positions = self._collect_mainline_positions(parent_node)
        else:
            # For sub-variations, parent_node is the endpoint
            board = parent_node.board()
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
            if len(legal_moves) > 0:
                positions = [{
                    'node': parent_node,
                    'legal_moves': legal_moves,
                    'board': board.copy()
                }]
            else:
                return
        
        if not positions:
            return
        
        # Find max variations at any position at this level
        max_vars = 0
        for pos_info in positions:
            node = pos_info['node']
            num_vars = len(node.variations) - (1 if depth == 0 else 0)  # -1 for mainline at depth 0
            max_vars = max(max_vars, num_vars)
        
        # Collect variations round by round at this level
        var_index = 0
        variation_endpoints = []  # Track endpoints for recursive collection
        
        while var_index < max_vars:
            for pos_info in positions:
                node = pos_info['node']
                legal_moves = pos_info['legal_moves']
                
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
                        var_num, capacity, endpoint = self._decode_single_variation_with_endpoint(
                            node, var_node, legal_moves, mainline_move, current_var_index, depth
                        )
                        
                        all_variations.append({
                            'num': var_num,
                            'capacity': capacity
                        })
                        
                        # Track endpoint for recursive sub-variation collection
                        if endpoint:
                            variation_endpoints.append(endpoint)
            
            var_index += self.variations_per_round
        
        # Recursively collect sub-variations from endpoints
        for endpoint in variation_endpoints:
            self._collect_variations_recursive(endpoint, all_variations, depth + 1)
    
    def _collect_mainline_positions(self, game: chess.pgn.Game) -> list:
        """Collect info about all mainline positions."""
        positions = []
        node = game
        board = chess.Board()
        
        while node.variations:
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
            
            if len(legal_moves) > 1:
                positions.append({
                    'node': node,
                    'legal_moves': legal_moves,
                    'board': board.copy()
                })
            
            board.push(node.variations[0].move)
            node = node.variations[0]
        
        return positions
    
    def _decode_single_variation(self, parent_node: chess.pgn.GameNode,
                                  var_node: chess.pgn.GameNode,
                                  legal_moves: list, mainline_move: chess.Move,
                                  var_round: int, depth: int = 0) -> tuple:
        """Decode a single variation, return (num, capacity)."""
        var_num, capacity, _ = self._decode_single_variation_with_endpoint(
            parent_node, var_node, legal_moves, mainline_move, var_round, depth
        )
        return var_num, capacity
    
    def _decode_single_variation_with_endpoint(self, parent_node: chess.pgn.GameNode,
                                               var_node: chess.pgn.GameNode,
                                               legal_moves: list, mainline_move: chess.Move,
                                               var_round: int, depth: int = 0) -> tuple:
        """
        Decode a single variation, return (num, capacity, endpoint).
        
        Args:
            parent_node: Parent node where variation branches from
            var_node: The variation node
            legal_moves: Legal moves at parent position
            mainline_move: The mainline move (None if depth > 0)
            var_round: Which variation this is (for calculating available moves)
            depth: Recursion depth (0 = mainline level)
        
        Returns:
            (num, capacity, endpoint_node)
        """
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
        
        available_moves = [m for m in legal_moves if m not in used_moves]
        
        if not available_moves:
            return 0, 1, None
        
        # Decode the variation move selection
        var_move = var_node.move
        if var_move not in available_moves:
            return 0, 1, None
        
        move_index = available_moves.index(var_move)
        base = len(available_moves)
        
        # Decode the branch and get endpoint
        branch_num, endpoint = self._decode_variation_branch_with_endpoint(var_node)
        branch_capacity = self._calculate_branch_capacity(var_node)
        
        # Total num for this variation
        total_num = branch_num * base + move_index + 1
        total_capacity = base * branch_capacity
        
        return total_num, total_capacity, endpoint
    
    def _decode_variation_branch(self, node: chess.pgn.GameNode) -> int:
        """Decode a variation branch."""
        num, _ = self._decode_variation_branch_with_endpoint(node)
        return num
    
    def _decode_variation_branch_with_endpoint(self, node: chess.pgn.GameNode) -> tuple:
        """
        Decode a variation branch and return (num, endpoint_node).
        
        Returns:
            (num, endpoint) where endpoint is the last node in the branch
        """
        moves_data = []
        current = node
        board = node.board()
        ply_count = 1
        
        while current.variations and ply_count < self.MAX_VAR_PLIES:
            next_node = current.variations[0]
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
            
            if not legal_moves:
                break
            
            move = next_node.move
            if move not in legal_moves:
                break
            
            move_index = legal_moves.index(move)
            base = len(legal_moves)
            moves_data.append((move_index, base))
            
            board.push(move)
            current = next_node
            ply_count += 1
        
        # Reconstruct NUM for this branch
        num = 0
        for move_index, base in reversed(moves_data):
            num = num * base + move_index + 1
        
        return num, current  # Return last node as endpoint
    
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
