"""
AETERNA Protocol — Rosetta Stone (Spazio Latente di Ancoraggio)
This module implements the latent space alignment algorithm to map asymmetric
node representations (different vector space dimensionalities) to a shared
canonical anchoring space (Omega), allowing semantic communication and memory sharing.
It also implements neuroplastic growth: semantic routing and dynamic expert sprouting.
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


class SemanticRouter:
    """
    Manages a dictionary of active experts (LoRA adapters) and routes input vectors
    to the closest expert in the shared Omega space.
    """
    def __init__(self):
        self.experts = {} # Map of expert_id (str) -> centroid vector (np.ndarray)

    def add_expert(self, expert_id: str, centroid: np.ndarray):
        """
        Adds or updates an expert in the router index.
        """
        self.experts[expert_id] = centroid.flatten()

    def route(self, vector_omega: np.ndarray) -> tuple[str, float]:
        """
        Routes the input vector to the closest expert based on cosine similarity.
        
        Returns:
            Tuple of (expert_id, cosine_similarity)
        """
        if not self.experts:
            return "default", 0.0

        v_flat = vector_omega.flatten()
        best_expert = None
        best_similarity = -1.0

        for expert_id, centroid in self.experts.items():
            norm_c = np.linalg.norm(centroid)
            norm_v = np.linalg.norm(v_flat)
            if norm_c == 0 or norm_v == 0:
                sim = 0.0
            else:
                sim = float(np.dot(centroid, v_flat) / (norm_c * norm_v))

            if sim > best_similarity:
                best_similarity = sim
                best_expert = expert_id

        return best_expert, best_similarity


class NeuroplasticNode:
    """
    Represents an active Aeterna cognitive node capable of semantic routing,
    dynamic adaptation (sprouting new experts), and immunological screening.
    """
    def __init__(self, name: str, shared_dim: int, local_dim: int, true_transform: np.ndarray, projection_basis: np.ndarray = None):
        """
        Args:
            name: Node name
            shared_dim: Dimension of Omega (D)
            local_dim: Node's internal dimension (d)
            true_transform: Distortion matrix (D x d)
            projection_basis: Basis matrix of the shared subspace (D_intrinsic x D)
        """
        self.name = name
        self.aligner = RosettaAligner(shared_dim, local_dim)
        self.router = SemanticRouter()
        self.true_transform = true_transform
        self.projection_basis = projection_basis # Orthogonal basis for OOD subspace checking
        
        # History variables to allow recalibration upon sprouting
        self.local_anchors_history = None
        self.shared_anchors_history = None

    def initialize_calibration(self, local_anchors: np.ndarray, shared_anchors: np.ndarray):
        """
        Initial calibration of the aligner. Saves history.
        """
        self.local_anchors_history = local_anchors.copy()
        self.shared_anchors_history = shared_anchors.copy()
        return self.aligner.calibrate(local_anchors, shared_anchors)

    def process_input(self, vector_omega: np.ndarray, threshold: float = 0.35, novelty_threshold: float = 0.75) -> tuple[str, str, float, float]:
        """
        Processes an incoming concept vector from the network.
        Runs immunology check, and either accepts/routes it or triggers sprouting.
        
        Args:
            vector_omega: Input vector in shared Omega space.
            threshold: Immunology PRE threshold (max acceptable reconstruction error).
            novelty_threshold: Similarity threshold below which a concept is sprouted as a new expert.
            
        Returns:
            Tuple: (status, expert_id_or_quarantine, pre_error, metric)
            Status can be: "ROUTE_SUCCESS", "SPROUTED", "REJECTED_SPAM"
        """
        # 1. Compute Projection Reconstruction Error (PRE)
        reconstructed = self.aligner.reconstruct(vector_omega)
        reprojected = self.aligner.project(reconstructed)
        pre = float(np.linalg.norm(vector_omega.flatten() - reprojected.flatten()))

        # 2. Check if PRE is within the accepted alignment manifold (is it clean/valid?)
        if pre <= threshold:
            # Concept is valid. Route to closest expert.
            expert_id, similarity = self.router.route(vector_omega)
            
            # If similarity to nearest expert is high enough, route succeeds.
            if similarity >= novelty_threshold:
                return "ROUTE_SUCCESS", expert_id, pre, similarity
            else:
                # Similarity is low: it's a valid novel concept! Trigger Sprouting!
                expert_id = self.sprout(vector_omega)
                return "SPROUTED", expert_id, pre, similarity

        # 3. Anomaly detected (pre > threshold). Check if it lies in the valid anchor subspace.
        subspace_err = 1.0
        if self.projection_basis is not None:
            # Project vector_omega onto the orthogonal subspace basis (projection_basis is D_intrinsic x D)
            # v_proj = v * basis.T * basis
            v_flat = vector_omega.flatten()
            proj_v = np.dot(np.dot(v_flat, self.projection_basis.T), self.projection_basis)
            subspace_err = float(np.linalg.norm(v_flat - proj_v))

        # If it lies in the valid anchor subspace, it's a valid but OOD concept. Trigger Sprouting!
        if subspace_err <= 0.15:
            expert_id = self.sprout(vector_omega)
            return "SPROUTED", expert_id, pre, subspace_err
        else:
            # High PRE and far from valid anchor subspace: reject as spam/poisoning
            return "REJECTED_SPAM", "quarantine", pre, subspace_err

    def sprout(self, vector_omega: np.ndarray, expert_name: str = None) -> str:
        """
        Sprouts a new expert adapter to capture the new semantic direction.
        Recalibrates the projection matrix W so that future similar concepts are aligned.
        
        Returns:
            The generated or provided expert_id
        """
        if expert_name is None:
            expert_name = f"Expert_{len(self.router.experts) + 1}"

        # 1. Add to the semantic router
        self.router.add_expert(expert_name, vector_omega)

        # 2. Recalibrate projection matrix by adding the concept to our training anchors
        v_flat = vector_omega.reshape(1, -1)
        
        # Simulate local pretraining: generate local representation of the new concept
        local_concept = np.dot(v_flat, self.true_transform) + np.random.normal(0, 0.02, (1, self.aligner.local_dim))
        
        # Append to calibration history
        if self.local_anchors_history is not None:
            self.local_anchors_history = np.vstack([self.local_anchors_history, local_concept])
            self.shared_anchors_history = np.vstack([self.shared_anchors_history, v_flat])
            
            # Recalibrate aligner with expanded anchor set
            self.aligner.calibrate(self.local_anchors_history, self.shared_anchors_history)

        return expert_name
