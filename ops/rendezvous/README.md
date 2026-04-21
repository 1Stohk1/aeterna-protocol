# AETERNA Rendezvous Relay

Phase D fallback relay for NAT traversal. It is intentionally small: it learns
the public UDP endpoint of each registering Guardian and forwards opaque gossip
datagrams to other recently-seen peers.

Run on a VPS:

```bash
python3 ops/rendezvous/server.py --host 0.0.0.0 --port 4450
```

Configure each node in `aeterna.local.toml`:

```toml
[gossip]
rendezvous_hints = ["udp://<vps-ip>:4450"]
```

The relay does not validate AGP payloads. Santuario signatures remain verified
by the receiving Sentinel.
