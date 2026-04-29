"""Audit-log alert poller.

Decoupled from the Telegram framework so the core logic (diff the
audit log against the local ack cursor, push the delta, advance the
cursor) is easy to unit-test without spinning up a real bot.

``broadcaster`` is any ``async`` callable that takes a message string
and delivers it to ONE destination (either a single chat for
``/audit_now``, or the allowlisted fan-out for push alerts). Keeping
the recipient selection in the caller makes the poller reusable.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Awaitable, Callable

# Cross-package import — see bot.py for the rationale.
_WAR_ROOM = Path(__file__).resolve().parent.parent / "war_room"
if str(_WAR_ROOM) not in sys.path:
    sys.path.insert(0, str(_WAR_ROOM))

from client import AdminObserver, AuditLogLine, Unreachable  # noqa: E402

from .config import BotConfig  # noqa: E402
from .rendering import render_alert_line  # noqa: E402
from .state import AckStore  # noqa: E402

LOG = logging.getLogger("aeterna.telegram.poller")

BroadcastFn = Callable[[str], Awaitable[None]]


async def run_alert_cycle(
    *,
    observer: AdminObserver,
    store: AckStore,
    cfg: BotConfig,
    broadcaster: BroadcastFn,
) -> list[AuditLogLine]:
    """Single poll pass. Returns the lines that were actually pushed."""
    tail = await asyncio.to_thread(observer.tail_audit_log, cfg.audit_tail_limit)
    if isinstance(tail, Unreachable):
        LOG.warning("alert poll: admin unreachable (%s)", tail.reason)
        return []

    pushed: list[AuditLogLine] = []
    for line in tail.lines:
        if line.record not in cfg.alert_kinds:
            continue
        if not store.should_push(line.ts_utc):
            continue
        await broadcaster(render_alert_line(line.record, line.ts_utc, line.json))
        pushed.append(line)

    # Advance seen cursor to the newest ts_utc we inspected, alert-or-not.
    # Without this the next /audit_now re-scans the same window and the
    # poll loop wastes grpc calls on identical data.
    if tail.lines:
        store.advance_seen(max(l.ts_utc for l in tail.lines))
    return pushed


async def alert_loop(
    observer: AdminObserver,
    store: AckStore,
    cfg: BotConfig,
    broadcaster: BroadcastFn,
) -> None:
    """Long-running task: poll every ``cfg.poll_interval_seconds``."""
    LOG.info(
        "alert loop started: interval=%.1fs kinds=%s",
        cfg.poll_interval_seconds,
        sorted(cfg.alert_kinds),
    )
    while True:
        try:
            await run_alert_cycle(
                observer=observer,
                store=store,
                cfg=cfg,
                broadcaster=broadcaster,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.warning("alert cycle raised (%s); will retry next tick", exc)
        await asyncio.sleep(cfg.poll_interval_seconds)
