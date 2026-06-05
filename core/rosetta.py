"""
AETERNA Protocol — Rosetta Stone (Spazio Latente di Ancoraggio)
This module implements the latent space alignment algorithm to map asymmetric
node representations (different vector space dimensionalities) to a shared
canonical anchoring space (Omega), allowing semantic communication and memory sharing.
"""

import numpy as np

class RosettaAligner:
    """
    Handles local calibration, projection, and reconstruction of vector embeddings
    between a local model's internal space and AETERNA's shared space (Omega).
    """
    def __init__(self, shared_dim: int, local_dim: int):
        """
        Initialize the aligner.
        
        Args:
            shared_dim: Dimensionality of the shared anchor space Omega (D).
            local_dim: Dimensionality of this node's internal model space (d).
        """
        self.shared_dim = shared_dim
        self.local_dim = local_dim
        self.W = None       # Projection matrix: local_dim -> shared_dim
        self.W_pinv = None  # Reconstruction matrix (pseudo-inverse): shared_dim -> local_dim

    def calibrate(self, local_anchors: np.ndarray, shared_anchors: np.ndarray) -> float:
        """
        Calibrates the projection matrix using a set of reference concepts.
        Solves the Procruste/Least Squares problem: local_anchors * W ~= shared_anchors
        
        Args:
            local_anchors: Matrix of shape (N, local_dim) representing reference concepts internally.
            shared_anchors: Matrix of shape (N, shared_dim) representing canonical anchor concepts.
            
        Returns:
            The mean reconstruction error (RMSE) on the calibration set.
        """
        if local_anchors.shape[0] != shared_anchors.shape[0]:
            raise ValueError("Number of calibration anchors must match between spaces.")
            
        # Solve least squares for W (local_dim x shared_dim)
        W, residuals, _, _ = np.linalg.lstsq(local_anchors, shared_anchors, rcond=None)
        self.W = W
        
        # Precompute pseudo-inverse for fast reconstruction back to local space
        self.W_pinv = np.linalg.pinv(self.W)
        
        # Calculate calibration error
        projections = np.dot(local_anchors, self.W)
        rmse = float(np.sqrt(np.mean((projections - shared_anchors) ** 2)))
        return rmse

    def project(self, local_vector: np.ndarray) -> np.ndarray:
        """
        Projects a local space vector into the shared Omega space.
        
        Args:
            local_vector: Vector of shape (local_dim,) or (N, local_dim)
            
        Returns:
            Projected vector of shape (shared_dim,) or (N, shared_dim)
        """
        if self.W is None:
            raise ValueError("Aligner must be calibrated before projecting.")
        return np.dot(local_vector, self.W)

    def reconstruct(self, shared_vector: np.ndarray) -> np.ndarray:
        """
        Reconstructs a shared Omega space vector back into the local space.
        
        Args:
            shared_vector: Vector of shape (shared_dim,) or (N, shared_dim)
            
        Returns:
            Reconstructed vector of shape (local_dim,) or (N, local_dim)
        """
        if self.W_pinv is None:
            raise ValueError("Aligner must be calibrated before reconstructing.")
        return np.dot(shared_vector, self.W_pinv)

    @staticmethod
    def cosine_similarity(v1: np.ndarray, v2: np.ndarray) -> float:
        """
        Computes the cosine similarity between two vectors.
        Handles both 1D vectors and 2D single-row matrices.
        """
        v1_flat = v1.flatten()
        v2_flat = v2.flatten()
        norm1 = np.linalg.norm(v1_flat)
        norm2 = np.linalg.norm(v2_flat)
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return float(np.dot(v1_flat, v2_flat) / (norm1 * norm2))
