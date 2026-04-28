"""
Chess PGN encoder - UNLIMITED VARIATIONS version for Time Capsule
Uses mainline + distributed variations with NO LIMIT on variations per move.

Key improvements:
- Removed MAX_VARIATIONS_PER_MOVE limit
- Round-robin distribution ensures even spread
- Natural limit: stops when all legal moves used
- Keeps MAX_VAR_PLIES = 40 for variation depth

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from .. import chess


class ChessGenerator:
    """Encodes NUM into a single chess game with NESTED RECURSIVE variations."""
    
    MAX_VAR_PLIES = 40  # Max plies for each variation branch (applies to all levels)
    MAX_MAINLINE_PLIES = 250  # Max plies for mainline (forces use of variations)
    VARIATIONS_PER_ROUND = 5  # Number of variations to add per position per round
    MAX_RECURSION_DEPTH = 10  # Maximum nesting depth (only used if USE_DEPTH_LIMIT = True)
    USE_DEPTH_LIMIT = False  # Set to True to enforce MAX_RECURSION_DEPTH, False for unlimited
    
    def __init__(self, variations_per_round: int = 5, use_depth_limit: bool = False):
        """
        Initialize encoder with nested variation support.
        
        Args:
            variations_per_round: Number of variations to add per position per round.
                                 Default is 5.
            use_depth_limit: If True, enforce MAX_RECURSION_DEPTH limit.
                           If False, nest as deep as needed (natural limit: remaining=0).
                           Default is False (unlimited nesting).
        """
        self.variations_per_round = max(1, variations_per_round)
        self.use_depth_limit = use_depth_limit
        
        # Stats tracking
        self.stats = {
            'mainline_plies': 0,
            'variation_plies': 0,
            'total_variations': 0,
            'total_plies': 0,
            'max_variations_at_position': 0,
            'positions_with_variations': 0,
            'max_nesting_depth': 0,  # Track deepest nesting level
            'total_variation_branches': 0  # Track all variation branches at all levels
        }
    
    def get_stats(self) -> dict:
        """Return encoding statistics."""
        return self.stats.copy()
    
    def _reset_stats(self):
        """Reset stats for new encoding."""
        self.stats = {
            'mainline_plies': 0,
            'variation_plies': 0,
            'total_variations': 0,
            'total_plies': 0,
            'max_variations_at_position': 0,
            'positions_with_variations': 0,
            'max_nesting_depth': 0,
            'total_variation_branches': 0
        }
    
    def encode_to_pgn(self, num: int) -> str:
        """Encode NUM into a single chess PGN with unlimited distributed variations."""
        if num < 1:
            raise ValueError("NUM must be >= 1")
        
        self._reset_stats()
        
        game = chess.pgn.Game()
        
        # Set custom PGN headers
        game.headers["Event"] = "Chess PGN Crypto"
        game.headers["Site"] = "Encrypted Data"
        game.headers["Date"] = "????.??.??"
        game.headers["Round"] = "-"
        game.headers["White"] = "RookDuel Encode"
        game.headers["Black"] = "Message"
        game.headers["Result"] = "*"
        game.headers["VariationsPerRound"] = str(self.variations_per_round)  # Store for decoder
        
        # Step 1: Encode mainline first
        remaining = self._encode_mainline(game, num)
        
        # Step 2: If data remains, distribute variations across mainline moves
        # ROUND-ROBIN: Each position gets variations evenly
        if remaining > 0:
            remaining = self._distribute_variations(game, remaining)
        
        if remaining > 0:
            raise ValueError(f"Could not encode all data (remaining: {remaining})")
        
        # Calculate total plies
        self.stats['total_plies'] = self.stats['mainline_plies'] + self.stats['variation_plies']
        
        return str(game)
    
    def _encode_mainline(self, game: chess.pgn.Game, num: int) -> int:
        """
        Encode into mainline with MAX_MAINLINE_PLIES limit.
        
        This ensures balanced usage between mainline and variations.
        After 250 plies, remaining data goes into nested variations.
        """
        node = game
        remaining = num
        
        while remaining > 0 and self.stats['mainline_plies'] < self.MAX_MAINLINE_PLIES:
            board = node.board()
            if board.is_game_over():
                break
            
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
            if not legal_moves:
                break
            
            base = len(legal_moves)
            move_index = (remaining - 1) % base
            remaining = (remaining - 1) // base
            
            node = node.add_variation(legal_moves[move_index])
            self.stats['mainline_plies'] += 1
        
        return remaining
    
    def _distribute_variations(self, game: chess.pgn.Game, num: int) -> int:
        """
        Distribute variations using NESTED RECURSIVE structure.
        
        Algorithm:
        1. Add N variations to each mainline position
        2. If more data remains, recursively add N sub-variations to end of each variation
        3. Continue recursively until data encoded or max depth reached
        
        Structure:
        Mainline → V1, V2, V3, V4, V5
                   ├─ V1 → V1.1, V1.2, V1.3, V1.4, V1.5
                   │       └─ V1.1 → V1.1.1, V1.1.2, ...
                   ├─ V2 → V2.1, V2.2, ...
                   └─ ...
        """
        remaining = num
        
        # Start recursive distribution from mainline (depth 0)
        remaining = self._distribute_variations_recursive(game, remaining, depth=0)
        
        return remaining
    
    def _distribute_variations_recursive(self, parent_node: chess.pgn.Game, 
                                        num: int, depth: int) -> int:
        """
        Recursively distribute variations at current depth level.
        
        Args:
            parent_node: Node to add variations to (could be game or variation)
            num: Remaining data to encode
            depth: Current recursion depth (0 = mainline level)
        
        Returns:
            Remaining data after encoding
        """
        # Natural stopping conditions (always checked)
        if num == 0:
            return num  # No more data to encode
        
        # Optional depth limit (only if USE_DEPTH_LIMIT = True)
        if self.use_depth_limit and depth >= self.MAX_RECURSION_DEPTH:
            return num  # Depth limit reached
        
        remaining = num
        
        # Collect positions at current level
        positions = self._collect_positions_at_level(parent_node, depth)
        
        if not positions:
            return remaining
        
        # Track if we're at mainline level for stats
        is_mainline_level = (depth == 0)
        
        # Round-robin: Add N variations to each position at this level
        round_number = 0
        variation_endpoints = []  # Track endpoints for recursive sub-variations
        
        while remaining > 0:
            made_progress = False
            
            for pos_info in positions:
                if remaining == 0:
                    break
                
                node = pos_info['node']
                legal_moves = pos_info['legal_moves']
                
                # Calculate available moves
                used_moves = {v.move for v in node.variations}
                available_moves = [m for m in legal_moves if m not in used_moves]
                
                if not available_moves:
                    continue
                
                # Add N variations at this position
                for _ in range(self.variations_per_round):
                    if remaining == 0 or not available_moves:
                        break
                    
                    # Add single variation and get its endpoint
                    remaining, endpoint = self._add_single_variation_with_endpoint(
                        node, available_moves, remaining
                    )
                    
                    if endpoint:
                        variation_endpoints.append(endpoint)
                    
                    self.stats['total_variations'] += 1
                    self.stats['total_variation_branches'] += 1
                    made_progress = True
                    
                    # Recalculate available moves
                    used_moves = {v.move for v in node.variations}
                    available_moves = [m for m in legal_moves if m not in used_moves]
            
            if not made_progress:
                break
            
            round_number += 1
        
        # Update stats for mainline level
        if is_mainline_level:
            for pos_info in positions:
                node = pos_info['node']
                num_vars = len(node.variations) - 1
                if num_vars > 0:
                    self.stats['positions_with_variations'] += 1
                self.stats['max_variations_at_position'] = max(
                    self.stats['max_variations_at_position'], 
                    num_vars
                )
        
        # Update max nesting depth
        self.stats['max_nesting_depth'] = max(self.stats['max_nesting_depth'], depth)
        
        # If data remains, recursively add sub-variations to variation endpoints
        # Natural limit: stops when remaining = 0 (no more data)
        # Optional limit: stops when depth limit reached (if USE_DEPTH_LIMIT = True)
        if remaining > 0 and variation_endpoints:
            # Check depth limit only if enabled
            if not self.use_depth_limit or depth + 1 < self.MAX_RECURSION_DEPTH:
                for endpoint in variation_endpoints:
                    if remaining == 0:
                        break
                    remaining = self._distribute_variations_recursive(endpoint, remaining, depth + 1)
        
        return remaining
    
    def _collect_positions_at_level(self, parent_node, depth: int) -> list:
        """
        Collect positions at current level.
        
        For depth 0: Collect mainline positions
        For depth > 0: Parent node is a variation endpoint, return it as single position
        """
        if depth == 0:
            # Mainline level - collect all mainline positions
            return self._collect_mainline_positions(parent_node)
        else:
            # Variation level - parent_node is the endpoint of a variation
            # Return it as a single position to add sub-variations to
            board = parent_node.board()
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
            
            if len(legal_moves) > 0:  # Need at least 1 move for variations
                return [{
                    'node': parent_node,
                    'legal_moves': legal_moves,
                    'board': board.copy()
                }]
            return []
    
    def _collect_mainline_positions(self, game: chess.pgn.Game) -> list:
        """Collect info about all mainline positions."""
        positions = []
        node = game
        board = chess.Board()
        
        while node.variations:
            legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
            
            if len(legal_moves) > 1:  # Need at least 2 moves for variations
                mainline_move = node.variations[0].move
                mainline_index = legal_moves.index(mainline_move)
                
                positions.append({
                    'node': node,
                    'mainline_index': mainline_index,
                    'legal_moves': legal_moves,
                    'board': board.copy()
                })
            
            board.push(node.variations[0].move)
            node = node.variations[0]
        
        return positions
    
    def _add_single_variation(self, node: chess.pgn.GameNode, 
                              available_moves: list, num: int) -> int:
        """Add a single variation at a node, encoding data into it."""
        remaining, _ = self._add_single_variation_with_endpoint(node, available_moves, num)
        return remaining
    
    def _add_single_variation_with_endpoint(self, node: chess.pgn.GameNode, 
                                           available_moves: list, num: int) -> tuple:
        """
        Add a single variation at a node, encoding data into it.
        Returns (remaining, endpoint_node) where endpoint is the last node of the variation.
        """
        if not available_moves or num == 0:
            return num, None
        
        remaining = num
        
        # Select which move to use for this variation
        base = len(available_moves)
        move_index = (remaining - 1) % base
        remaining = (remaining - 1) // base
        
        # Create the variation
        var_node = node.add_variation(available_moves[move_index])
        self.stats['variation_plies'] += 1
        
        # Encode more data along this variation branch (up to MAX_VAR_PLIES)
        remaining, endpoint = self._encode_variation_branch_with_endpoint(var_node, remaining, 1)
        
        return remaining, endpoint
    
    def _encode_variation_branch(self, node: chess.pgn.GameNode, 
                                  num: int, ply_count: int) -> int:
        """Encode data along a variation branch, respecting MAX_VAR_PLIES."""
        remaining, _ = self._encode_variation_branch_with_endpoint(node, num, ply_count)
        return remaining
    
    def _encode_variation_branch_with_endpoint(self, node: chess.pgn.GameNode, 
                                               num: int, ply_count: int) -> tuple:
        """
        Encode data along a variation branch, respecting MAX_VAR_PLIES.
        Returns (remaining, endpoint_node) where endpoint is the last node.
        """
        if num == 0 or ply_count >= self.MAX_VAR_PLIES:
            return num, node  # Return current node as endpoint
        
        board = node.board()
        if board.is_game_over():
            return num, node
        
        legal_moves = sorted(board.legal_moves, key=lambda m: m.uci())
        if not legal_moves:
            return num, node
        
        remaining = num
        base = len(legal_moves)
        move_index = (remaining - 1) % base
        remaining = (remaining - 1) // base
        
        next_node = node.add_variation(legal_moves[move_index])
        self.stats['variation_plies'] += 1
        
        # Continue encoding in this branch
        return self._encode_variation_branch_with_endpoint(next_node, remaining, ply_count + 1)
