"""v0.3.0 "Oculus" — War Room operator dashboard.

A Streamlit app that reads the Admin gRPC surface exposed by
``santuario-signer`` and renders signer health, peer gossip, and audit
tail. Read-only by contract. Binds loopback-only by default.

Module layout:
    client.py            — typed wrapper around the Admin gRPC stubs.
    app.py               — single-file Streamlit dashboard.
    admin_pb2.py         — generated protobuf descriptors.
    admin_pb2_grpc.py    — generated gRPC service stubs.
"""
