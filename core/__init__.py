"""
AETERNA Core — Python Sentinel (userland orchestrator).

This package implements the userland orchestrator for a Guardian node. It
speaks UDP gossip to peers, dispatches scientific tasks to the Julia engine
over ZMQ, and — once v0.1.0 is out — asks the Rust Santuario to cryptographically
sign the results over an encrypted Unix Domain Socket (gRPC / Protobuf).

The Sentinel is explicitly NOT the Santuario. It runs with normal user
privileges, touches the network, talks to PyTorch and the GPU, and is
considered the "trusted-but-compromisable" perimeter. Secrets never live here.
"""

__version__ = "0.0.1"
__protocol__ = "AGP-v1"
__codename__ = "Genesis"
