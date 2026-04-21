import time
import logging

LOG = logging.getLogger("aeterna.peer_table")

class PeerTable:
    """Manages known peers with liveness decay and limits."""
    
    def __init__(self, max_peers: int = 100, max_age_seconds: int = 120):
        self.max_peers = max_peers
        self.max_age_seconds = max_age_seconds
        # dict: (host, port) -> {"guardian_id": str, "last_seen_ts": float}
        self._peers: dict[tuple[str, int], dict] = {}
        
    def add_or_update(self, host: str, port: int, guardian_id: str | None = None) -> None:
        now = time.time()
        peer_key = (host, port)
        
        if peer_key not in self._peers:
            if len(self._peers) >= self.max_peers:
                self._evict_oldest()
            LOG.debug(f"peer added/discovered {host}:{port}")
            
        old_data = self._peers.get(peer_key, {})
        new_guardian_id = guardian_id if guardian_id else old_data.get("guardian_id", "unknown")
            
        self._peers[peer_key] = {
            "guardian_id": new_guardian_id,
            "last_seen_ts": now
        }
        
    def get_active_peers(self) -> list[tuple[str, int]]:
        self._prune()
        return list(self._peers.keys())
        
    def _evict_oldest(self) -> None:
        if not self._peers:
            return
        oldest = min(self._peers.items(), key=lambda x: x[1]["last_seen_ts"])
        del self._peers[oldest[0]]
        
    def _prune(self) -> None:
        now = time.time()
        stale_keys = [
            k for k, v in self._peers.items()
            if now - v["last_seen_ts"] > self.max_age_seconds
        ]
        for k in stale_keys:
            LOG.debug(f"peer evicted due to liveness decay {k[0]}:{k[1]}")
            del self._peers[k]
