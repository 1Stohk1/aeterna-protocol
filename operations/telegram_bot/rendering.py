"""HTML renderers for Telegram operator messages.

Kept separate from ``bot.py`` so unit tests don't need to import the
full ``python-telegram-bot`` stack just to check message formatting.
Everything here is a pure function of the typed dataclasses from
``operations/war_room/client.py``.

Output is Telegram's HTML parse-mode. We escape every interpolated
signer string with :func:`html.escape` because audit JSON and peer
addresses are untrusted text from the Santuario perspective.
"""
from __future__ import annotations

import html
import sys
import time
from pathlib import Path

# Cross-package import: the typed Admin client lives in the War Room.
# See the longer note in bot.py.
_WAR_ROOM = Path(__file__).resolve().parent.parent / "war_room"
if str(_WAR_ROOM) not in sys.path:
    sys.path.insert(0, str(_WAR_ROOM))

from client import AuditTail, Metrics, PeerList, Unreachable  # noqa: E402


def fmt_ts(ts_utc: int) -> str:
    """UTC ``YYYY-MM-DD HH:MM:SS UTC`` — matches the War Room banner."""
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts_utc))


def render_status(m: Metrics | Unreachable) -> str:
    if isinstance(m, Unreachable):
        return (
            "<b>Signer UNREACHABLE</b>\n"
            f"reason: <code>{html.escape(m.reason)}</code>\n"
            f"elapsed: {m.elapsed_s:.2f}s"
        )
    ready = int(m.gauges.get("santuario_signer_ready", 0)) == 1
    sealed = int(m.gauges.get("santuario_vault_sealed", 1)) == 1
    head = "\u2705" if ready and not sealed else "\u26a0\ufe0f"
    return (
        f"{head} <b>{html.escape(m.node_id)}</b>\n"
        f"ready: <b>{'yes' if ready else 'no'}</b>  |  "
        f"vault sealed: <b>{'yes' if sealed else 'no'}</b>\n"
        f"schema_version: {m.schema_version}  |  window: {m.metric_window_seconds}s\n"
        f"snapshot: {fmt_ts(m.ts_utc)}"
    )


def render_peers(pl: PeerList | Unreachable) -> str:
    if isinstance(pl, Unreachable):
        return f"<b>Peers UNREACHABLE</b>\n<code>{html.escape(pl.reason)}</code>"
    if not pl.peers:
        return "<i>No peers in snapshot.</i>"
    lines = [f"<b>Peers</b>  ({len(pl.peers)}, snapshot {fmt_ts(pl.snapshot_utc)})"]
    for p in pl.peers:
        flag = " [bootstrap]" if p.is_bootstrap else ""
        last = fmt_ts(p.last_seen_utc) if p.last_seen_utc else "never"
        lines.append(
            f"\u2022 <code>{html.escape(p.address)}</code>{flag}\n"
            f"  id: <code>{html.escape(p.node_id or '<unknown>')}</code>  |  "
            f"last seen: {last}  |  rx={p.rx_count} tx={p.tx_count}"
        )
    return "\n".join(lines)


def render_tail(t: AuditTail | Unreachable, limit: int) -> str:
    if isinstance(t, Unreachable):
        return f"<b>Audit UNREACHABLE</b>\n<code>{html.escape(t.reason)}</code>"
    if not t.lines:
        return "<i>Audit log empty.</i>"
    take = t.lines[-limit:]
    head = f"<b>Audit tail</b>  (showing {len(take)} of {len(t.lines)})"
    body = "\n".join(
        f"<code>{fmt_ts(l.ts_utc)}  {html.escape(l.record)}</code>\n"
        f"<pre>{html.escape(l.json)}</pre>"
        for l in take
    )
    return f"{head}\n{body}"


def render_alert_line(record: str, ts_utc: int, raw_json: str) -> str:
    """Single-line push alert — sent at most once per audit record."""
    return (
        f"\u26a0\ufe0f <b>{html.escape(record)}</b>\n"
        f"ts: {fmt_ts(ts_utc)}\n"
        f"<pre>{html.escape(raw_json)}</pre>"
    )
