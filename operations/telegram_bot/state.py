"""Local-only ack / cursor state for the Telegram operator bot.

The bot itself never mutates signer state (that would violate the
Admin read-only contract). What it DOES track locally:

* ``last_seen_ts_utc``  — the highest ``ts_utc`` from an audit line
  it's already inspected. Without this the poller would re-push every
  alert on every cycle.
* ``acked_ts_utc``      — the latest ``ts_utc`` the operator has
  explicitly acknowledged via ``/ack``. Alerts with
  ``ts_utc <= acked_ts_utc`` are NOT re-pushed even if they would
  otherwise still satisfy the alert-kinds filter.

The file lives under ``operations/telegram_bot/state/ack_state.json``
and is written atomically (write-to-tmp + os.replace) so a SIGTERM
mid-write doesn't leave a half-JSON that crashes the next boot.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("aeterna.telegram.state")


@dataclass(frozen=True)
class AckState:
    """Frozen snapshot of the bot's local cursor/ack state."""

    last_seen_ts_utc: int = 0
    acked_ts_utc: int = 0


class AckStore:
    """Read/write wrapper around ``ack_state.json``.

    Not thread-safe. The bot runs a single asyncio loop; all mutations
    go through the same task, so no locking is needed. If a future
    refactor runs multiple pollers, wrap mutations in a lock.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._state = self._load()

    # --- public API ---

    @property
    def state(self) -> AckState:
        return self._state

    def advance_seen(self, ts_utc: int) -> None:
        """Bump ``last_seen_ts_utc`` if ``ts_utc`` is newer."""
        if ts_utc <= self._state.last_seen_ts_utc:
            return
        self._state = replace(self._state, last_seen_ts_utc=int(ts_utc))
        self._persist()

    def ack(self, ts_utc: Optional[int] = None) -> AckState:
        """Mark ``ts_utc`` (default: last seen) as acknowledged.

        Returns the new :class:`AckState` so callers can echo the value
        into the Telegram reply.
        """
        target = int(ts_utc) if ts_utc is not None else self._state.last_seen_ts_utc
        if target < self._state.acked_ts_utc:
            # /ack never rewinds the ack cursor — re-acking an older
            # timestamp would let old alerts resurface, which is the
            # opposite of what the command means.
            return self._state
        self._state = replace(self._state, acked_ts_utc=target)
        self._persist()
        return self._state

    def should_push(self, ts_utc: int) -> bool:
        """True if a record at ``ts_utc`` has NOT been seen AND NOT been acked."""
        if ts_utc <= self._state.acked_ts_utc:
            return False
        if ts_utc <= self._state.last_seen_ts_utc:
            return False
        return True

    # --- internal ---

    def _load(self) -> AckState:
        if not self._path.is_file():
            return AckState()
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            LOG.warning(
                "ack_state.json unreadable (%s); starting from zero. "
                "A fresh file will be written on the next persist.",
                exc,
            )
            return AckState()
        return AckState(
            last_seen_ts_utc=int(raw.get("last_seen_ts_utc", 0) or 0),
            acked_ts_utc=int(raw.get("acked_ts_utc", 0) or 0),
        )

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: write to a tmp file in the SAME directory so that
        # os.replace is a cross-rename on the same filesystem, then swap
        # it in. This survives SIGTERM between write and rename.
        fd, tmp = tempfile.mkstemp(
            prefix=".ack_state.", suffix=".json.tmp", dir=str(self._path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "last_seen_ts_utc": self._state.last_seen_ts_utc,
                        "acked_ts_utc": self._state.acked_ts_utc,
                    },
                    fh,
                    indent=2,
                )
                fh.write("\n")
            os.replace(tmp, self._path)
        except Exception:
            # Best-effort cleanup of the tmp file on failure. Never raise
            # from inside cleanup — we re-raise the original below.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
