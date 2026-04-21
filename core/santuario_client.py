from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

# Add core directory to sys.path so generated protobufs can import each other.
sys.path.append(str(Path(__file__).parent))

import grpc
import signer_pb2
import signer_pb2_grpc

LOG = logging.getLogger("aeterna.santuario")


class SantuarioUnavailable(RuntimeError):
    """Raised when the Rust signer cannot be reached before the deadline."""


class SantuarioClient:
    """Client wrapper for the Rust Santuario signer, with startup reconnects."""

    def __init__(
        self,
        *,
        target: str | None = None,
        connect_timeout_seconds: float = 30.0,
        retry_interval_seconds: float = 0.5,
        rpc_timeout_seconds: float = 10.0,
    ) -> None:
        self._target = target or self._default_target()
        self._connect_timeout_seconds = connect_timeout_seconds
        self._retry_interval_seconds = retry_interval_seconds
        self._rpc_timeout_seconds = rpc_timeout_seconds
        self._channel: grpc.Channel | None = None
        self._stub: signer_pb2_grpc.SignerStub | None = None
        self._connect()

    @staticmethod
    def _default_target() -> str:
        if "SANTUARIO_PORT" in os.environ:
            port = os.environ["SANTUARIO_PORT"]
            return f"127.0.0.1:{port}"
        
        if sys.platform == "win32":
            return "127.0.0.1:50051"

        socket_path = os.environ.get("SANTUARIO_SOCKET", "/run/aeterna/santuario.sock")
        return f"unix://{socket_path}"

    def _connect(self) -> None:
        deadline = time.monotonic() + self._connect_timeout_seconds
        last_error: Exception | None = None

        while True:
            channel = grpc.insecure_channel(self._target)
            try:
                remaining = max(0.1, deadline - time.monotonic())
                grpc.channel_ready_future(channel).result(timeout=min(1.0, remaining))
            except grpc.FutureTimeoutError as exc:
                last_error = exc
                channel.close()
            else:
                self._channel = channel
                self._stub = signer_pb2_grpc.SignerStub(channel)
                LOG.info("connected to Santuario signer at %s", self._target)
                return

            if time.monotonic() >= deadline:
                raise SantuarioUnavailable(
                    f"Santuario signer unavailable at {self._target}"
                ) from last_error

            time.sleep(self._retry_interval_seconds)

    def _reconnect(self) -> None:
        if self._channel is not None:
            self._channel.close()
        self._connect()

    def _call(self, method_name: str, request: Any) -> Any:
        assert self._stub is not None
        method = getattr(self._stub, method_name)
        try:
            return method(request, timeout=self._rpc_timeout_seconds)
        except grpc.RpcError:
            LOG.warning("Santuario RPC %s failed, reconnecting once", method_name)
            self._reconnect()
            assert self._stub is not None
            method = getattr(self._stub, method_name)
            return method(request, timeout=self._rpc_timeout_seconds)

    def sign(self, payload_hash: bytes) -> bytes:
        if len(payload_hash) != 32:
            raise ValueError("payload_hash must be exactly 32 bytes")

        req = signer_pb2.SignRequest(payload_hash=payload_hash)
        try:
            resp = self._call("Sign", req)
            return resp.signature
        except grpc.RpcError as exc:
            LOG.error("Santuario sign failed: %s", exc)
            raise

    def verify(self, payload_hash: bytes, signature: bytes, public_key: bytes) -> bool:
        if len(payload_hash) != 32:
            return False

        req = signer_pb2.VerifyRequest(
            payload_hash=payload_hash,
            signature=signature,
            public_key=public_key,
        )
        try:
            resp = self._call("Verify", req)
            return bool(resp.valid)
        except grpc.RpcError as exc:
            LOG.error("Santuario verify failed: %s", exc)
            return False

    def get_public_key(self) -> bytes:
        req = signer_pb2.GetPublicKeyRequest()
        try:
            resp = self._call("GetPublicKey", req)
            return resp.public_key
        except grpc.RpcError as exc:
            LOG.error("Santuario get_public_key failed: %s", exc)
            raise

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()
