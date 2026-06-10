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
    import os
    import json
    import time
    import urllib.request

    LOG.info(
        "alert loop started: interval=%.1fs kinds=%s",
        cfg.poll_interval_seconds,
        sorted(cfg.alert_kinds),
    )

    # State for chain disconnected monitoring
    chain_was_connected = None
    chain_disconnected_since = None
    chain_alert_sent = False

    # State for shipper push failed monitoring
    # Tracks segment_id -> seen_pending_count
    shipper_pending_counts: dict[int, int] = {}
    shipper_alerted_segments: set[int] = set()

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

        # 1. Chain disconnected check
        if "chain_disconnected" in cfg.alert_kinds:
            try:
                req = urllib.request.Request("http://127.0.0.1:1317/status")
                with urllib.request.urlopen(req, timeout=1.0) as response:
                    res = json.loads(response.read().decode("utf-8"))
                is_chain_online = res and "result" in res
            except Exception:
                is_chain_online = False
                
            now = time.time()
            if is_chain_online:
                chain_was_connected = True
                chain_disconnected_since = None
                if chain_alert_sent:
                    await broadcaster(
                        f"🟢 <b>chain_connected</b>\n"
                        f"ts: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}\n"
                        f"REST endpoint at :1317 is back online."
                    )
                    chain_alert_sent = False
            else:
                if chain_was_connected:
                    if chain_disconnected_since is None:
                        chain_disconnected_since = now
                    elif now - chain_disconnected_since > 600: # 10 minutes
                        if not chain_alert_sent:
                            await broadcaster(
                                f"⚠️ <b>chain_disconnected</b>\n"
                                f"ts: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}\n"
                                f"REST endpoint at :1317 has been unreachable for > 10 minutes."
                            )
                            chain_alert_sent = True

        # 2. Shipper push failed check
        if "shipper_push_failed" in cfg.alert_kinds:
            shipper_enabled = False
            audit_dir = "./logs/audit"
            try:
                try:
                    import tomllib
                except ImportError:
                    import tomli as tomllib
                
                config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "aeterna.toml"))
                if os.path.exists(config_path):
                    with open(config_path, "rb") as f:
                        toml_cfg = tomllib.load(f)
                    if "shipper" in toml_cfg:
                        shipper_enabled = toml_cfg["shipper"].get("enabled", False)
                    if "sigillum" in toml_cfg:
                        audit_dir = toml_cfg["sigillum"].get("log_segment_dir", audit_dir)
            except Exception as e:
                LOG.warning("poller: failed to parse aeterna.toml for shipper status (%s)", e)
                
            env_url = os.environ.get("AETERNA_SHIPPER_ENDPOINT", "")
            if env_url:
                shipper_enabled = True
                
            if shipper_enabled:
                resolved_audit_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", audit_dir))
                if os.path.exists(resolved_audit_dir):
                    try:
                        files = os.listdir(resolved_audit_dir)
                        sigillum_files = [f for f in files if f.endswith(".sigillum")]
                        
                        current_pending: set[int] = set()
                        for f in sigillum_files:
                            stem = f[:-9] # strip ".sigillum"
                            try:
                                segment_id = int(stem)
                            except ValueError:
                                continue
                                
                            pushed_file = os.path.join(resolved_audit_dir, f + ".pushed")
                            if not os.path.exists(pushed_file):
                                current_pending.add(segment_id)
                                
                        # Increment count for currently pending segments
                        for seg_id in current_pending:
                            count = shipper_pending_counts.get(seg_id, 0) + 1
                            shipper_pending_counts[seg_id] = count
                            
                            if count >= 3:
                                if seg_id not in shipper_alerted_segments:
                                    now = time.time()
                                    await broadcaster(
                                        f"⚠️ <b>shipper_push_failed</b>\n"
                                        f"ts: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}\n"
                                        f"Segment {seg_id:06} failed to push after 3 consecutive checks."
                                    )
                                    shipper_alerted_segments.add(seg_id)
                                    
                        # Clean up segments that are no longer pending
                        for seg_id in list(shipper_pending_counts.keys()):
                            if seg_id not in current_pending:
                                shipper_pending_counts.pop(seg_id, None)
                                shipper_alerted_segments.discard(seg_id)
                                
                    except Exception as ex:
                        LOG.warning("poller: failed to scan audit directory for shipper status (%s)", ex)

        await asyncio.sleep(cfg.poll_interval_seconds)
