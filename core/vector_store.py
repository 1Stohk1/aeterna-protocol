"""
AETERNA Protocol — Store Vettoriale Semantico
This module implements a long-term semantic memory vector store in pure numpy,
projecting searches in the shared Omega space.
"""

import numpy as np
from typing import List, Tuple, Dict, Any, Optional
from core.memory import EpisodicMemory

class SemanticMemory:
    """
    A long-term vector store operating in the shared Omega space.
    """
    def __init__(self, shared_dim: int):
        self.shared_dim = shared_dim
        # Rows: number of stored memories, columns: shared_dim
        self.embeddings = np.empty((0, shared_dim), dtype=float)
        self.metadata: List[Dict[str, Any]] = []

    def add_memory(self, text: str, embedding_omega: np.ndarray, metadata: Optional[Dict[str, Any]] = None):
        """
        Adds a semantic memory to the long-term store.
        """
        emb = np.array(embedding_omega, dtype=float).flatten()
        if emb.shape[0] != self.shared_dim:
            raise ValueError(f"Embedding dimensions must match shared_dim ({self.shared_dim}), got {emb.shape[0]}.")

        self.embeddings = np.vstack([self.embeddings, emb])
        
        meta = metadata.copy() if metadata is not None else {}
        meta["text"] = text
        self.metadata.append(meta)

    def search(self, query_vector: np.ndarray, top_k: int = 5) -> List[Tuple[str, float, Dict[str, Any]]]:
        """
        Queries the vector store using cosine similarity.
        Returns a list of tuples: (text, similarity, metadata_dict)
        """
        if self.embeddings.shape[0] == 0:
            return []

        q = np.array(query_vector, dtype=float).flatten()
        if q.shape[0] != self.shared_dim:
            raise ValueError(f"Query vector dimensions must match shared_dim ({self.shared_dim}).")

        norm_q = np.linalg.norm(q)
        if norm_q == 0.0:
            return []

        # Calculate cosine similarities in vectorized form
        # dot(A, q) / (norms(A) * norm_q)
        dots = np.dot(self.embeddings, q)
        norms = np.linalg.norm(self.embeddings, axis=1)
        
        # Avoid division by zero
        norms[norms == 0.0] = 1e-10
        
        similarities = dots / (norms * norm_q)

        # Get indices sorted in descending order
        sorted_indices = np.argsort(similarities)[::-1]

        results = []
        for idx in sorted_indices[:top_k]:
            meta = self.metadata[idx].copy()
            text = meta.pop("text", "")
            results.append((text, float(similarities[idx]), meta))

        return results

    def consolidate_from_episodic(self, episodic_memory: EpisodicMemory):
        """
        Consolidates all current active short-term episodic memories into the long-term semantic store.
        """
        turns = episodic_memory.get_active_turns()
        for turn in turns:
            self.add_memory(
                text=turn.text,
                embedding_omega=turn.embedding_omega,
                metadata={
                    "speaker": turn.speaker,
                    "timestamp": turn.timestamp,
                    "type": "consolidated_episodic"
                }
            )
