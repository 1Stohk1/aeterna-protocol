"""
AETERNA Protocol — Ollama Client
This module provides a lightweight client wrapper for a local Ollama daemon
to extract high-dimensional semantic embeddings and perform text generation.
Uses built-in urllib to avoid external request package dependencies.
"""

import json
import urllib.request
import urllib.error
import numpy as np
from typing import List, Dict, Any, Optional

class OllamaClient:
    """
    Client for local Ollama server.
    """
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def is_healthy(self) -> bool:
        """
        Checks if the Ollama daemon is active and running.
        """
        try:
            req = urllib.request.Request(
                f"{self.base_url}/",
                method="GET"
            )
            with urllib.request.urlopen(req, timeout=2.0) as response:
                body = response.read().decode("utf-8")
                return "Ollama is running" in body or response.status == 200
        except Exception:
            return False

    def is_model_available(self) -> bool:
        """
        Checks if the configured model is already pulled in Ollama.
        """
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/tags",
                method="GET"
            )
            with urllib.request.urlopen(req, timeout=3.0) as response:
                data = json.loads(response.read().decode("utf-8"))
                models = data.get("models", [])
                for m in models:
                    name = m.get("name", "")
                    # Check both exact match and prefix match (e.g. llama3.2:latest)
                    if name == self.model or name.startswith(f"{self.model}:"):
                        return True
            return False
        except Exception:
            return False

    def get_embedding(self, text: str) -> np.ndarray:
        """
        Fetches the embedding vector for a single string.
        """
        embeddings = self.get_embeddings([text])
        if len(embeddings) == 0:
            raise RuntimeError("Failed to generate embedding.")
        return embeddings[0]

    def get_embeddings(self, texts: List[str]) -> np.ndarray:
        """
        Fetches the embeddings for a list of strings, automatically falling back
        to the legacy single-vector endpoint if batched embed endpoint is not supported.
        """
        # Try the modern batched API endpoint first (/api/embed)
        try:
            payload = {
                "model": self.model,
                "input": texts
            }
            data_bytes = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/embed",
                data=data_bytes,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15.0) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                embeddings = res_data.get("embeddings", [])
                if embeddings:
                    return np.array(embeddings, dtype=float)
        except urllib.error.HTTPError as e:
            # If 404 (Not Found), 501 (Not Implemented) or 400 (Bad Request), fallback to legacy endpoint
            if e.code not in (404, 501, 400):
                raise
        except Exception:
            # Other errors also trigger legacy fallback or propagate
            pass

        # Legacy fallback (/api/embeddings)
        legacy_embeddings = []
        for text in texts:
            payload = {
                "model": self.model,
                "prompt": text
            }
            data_bytes = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/embeddings",
                data=data_bytes,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10.0) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                emb = res_data.get("embedding")
                if emb is None:
                    raise RuntimeError(f"Ollama legacy embedding endpoint failed to return a vector: {res_data}")
                legacy_embeddings.append(emb)

        return np.array(legacy_embeddings, dtype=float)

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        """
        Generates text completion using the Ollama model.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        if system is not None:
            payload["system"] = system

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=data_bytes,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30.0) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("response", "")
