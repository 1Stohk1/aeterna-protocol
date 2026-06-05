"""
AETERNA Protocol — Memory Episodica
This module implements the short-term episodic memory buffer, storing recent
dialogue turns and pruning them based on a sliding-window time parameter.
"""

import time
from dataclasses import dataclass
import numpy as np
from typing import List, Optional

@dataclass
class DialogueTurn:
    """
    Represents a single conversational turn in the episodic memory.
    """
    timestamp: float           # Epoch timestamp
    speaker: str               # e.g., "user", "guardian"
    text: str                  # Message text
    embedding_omega: np.ndarray # Projected concept vector in Omega space (D_shared,)

class EpisodicMemory:
    """
    A short-term sliding window dialogue buffer.
    """
    def __init__(self, max_age_days: float = 30.0):
        self.max_age_days = max_age_days
        self.turns: List[DialogueTurn] = []

    def add_turn(self, speaker: str, text: str, embedding_omega: np.ndarray, timestamp: Optional[float] = None):
        """
        Adds a new turn to the episodic memory buffer.
        """
        if timestamp is None:
            timestamp = time.time()
        
        # Ensure flat shape (D_shared,)
        emb = np.array(embedding_omega, dtype=float).flatten()
        self.turns.append(DialogueTurn(
            timestamp=timestamp,
            speaker=speaker,
            text=text,
            embedding_omega=emb
        ))

    def prune_expired(self, current_time: Optional[float] = None):
        """
        Prunes turns older than max_age_days from the current_time (or now).
        """
        if current_time is None:
            current_time = time.time()
        
        cutoff = current_time - (self.max_age_days * 86400.0)
        self.turns = [turn for turn in self.turns if turn.timestamp >= cutoff]

    def get_active_turns(self) -> List[DialogueTurn]:
        """
        Returns all active/unexpired dialogue turns.
        """
        return self.turns
