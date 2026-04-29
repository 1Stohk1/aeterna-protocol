"""Unit tests for the Telegram operator bot — pure-logic modules only.

We intentionally exercise ``rendering``, ``state``, ``config``, and
``poller`` without importing ``bot.py`` or ``python-telegram-bot``.
The refactor that extracted these modules out of ``bot.py`` was done
specifically so the test surface stays lean: if PTB's async stack is
missing from the test venv, these tests still run.

The one piece of ``bot.py`` we DO want coverage on — ``AccessGate`` —
is tested via a thin fake Update/Chat/User trio, again no PTB import.

Fake Admin surface
------------------

``_FakeAdmin`` is a pure-Python stand-in for ``AdminObserver``. The
poller only calls ``tail_audit_log`` / ``get_metrics`` / ``list_peers``
through ``asyncio.to_thread``, so any object with those methods of the
right shape works. This is simpler than spinning up a real in-process
gRPC server (which the War Room tests do) — our target here is the
bot's own logic, not the gRPC plumbing.
"""
from __future__ import annotations

import asyncio
import calendar
import json
import os
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional
from unittest import mock

# The bot package uses a sys.path hack to import the War Room's typed
# dataclasses (Metrics / AuditTail / Unreachable / ...). We replicate
# the same hack here so the test file can import the dataclasses
# directly for building fixtures, without having to import via the
# bot's own modules (which would be a circular smell).
_HERE = Path(__file__).resolve()
_WAR_ROOM = _HERE.parent.parent.parent / "war_room"
if str(_WAR_ROOM) not in sys.path:
    sys.path.insert(0, str(_WAR_ROOM))

from client import (  # noqa: E402
    AuditLogLine,
    AuditTail,
    Metrics,
    Peer,
    PeerList,
    Unreachable,
)

from operations.telegram_bot.config import (  # noqa: E402
    BotConfig,
    ConfigError,
    load_config,
)
from operations.telegram_bot.poller import run_alert_cycle  # noqa: E402
from operations.telegram_bot.rendering import (  # noqa: E402
    fmt_ts,
    render_alert_line,
    render_peers,
    render_status,
    render_tail,
)
from operations.telegram_bot.state import AckState, AckStore  # noqa: E402


# --------------------------------------------------------------------------
# Fakes / helpers
# --------------------------------------------------------------------------


@dataclass
class _FakeAdmin:
    """Drop-in for ``AdminObserver`` — only the three methods the bot uses."""

    metrics: Metrics | Unreachable
    peers: PeerList | Unreachable
    audit: AuditTail | Unreachable
    calls: list[tuple[str, tuple]] = field(default_factory=list)

    def get_metrics(self) -> Metrics | Unreachable:
        self.calls.append(("get_metrics", ()))
        return self.metrics

    def list_peers(self) -> PeerList | Unreachable:
        self.calls.append(("list_peers", ()))
        return self.peers

    def tail_audit_log(self, n: int) -> AuditTail | Unreachable:
        self.calls.append(("tail_audit_log", (n,)))
        return self.audit


def _base_cfg(**overrides) -> BotConfig:
    """A permissive BotConfig used by poller tests (bypasses require_ready)."""
    defaults = dict(
        enabled=True,
        token="stub:token",
        allowed_chat_ids=frozenset({111}),
        admin_target="",
        poll_interval_seconds=5.0,
        alert_kinds=frozenset({"alert", "suspend", "recovery_token_issued"}),
        audit_tail_limit=50,
        rate_limit_per_second=1.0,
        source_path=Path("/tmp/fake-aeterna.toml"),
    )
    defaults.update(overrides)
    return BotConfig(**defaults)


def _collect(recipient: list[str]):
    """Return a broadcaster callable that appends every message to ``recipient``."""

    async def _broadcast(msg: str) -> None:
        recipient.append(msg)

    return _broadcast


# --------------------------------------------------------------------------
# AckStore: persistence + dedup invariant
# --------------------------------------------------------------------------


class AckStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "ack_state.json"

    def test_starts_from_zero_when_file_missing(self) -> None:
        store = AckStore(self.path)
        self.assertEqual(store.state, AckState(0, 0))
        # No file is written just from construction.
        self.assertFalse(self.path.exists())

    def test_advance_seen_persists_atomically(self) -> None:
        store = AckStore(self.path)
        store.advance_seen(1000)

        self.assertTrue(self.path.is_file())
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(raw["last_seen_ts_utc"], 1000)
        self.assertEqual(raw["acked_ts_utc"], 0)

    def test_advance_seen_never_rewinds(self) -> None:
        store = AckStore(self.path)
        store.advance_seen(2000)
        store.advance_seen(1500)  # older — must be ignored
        self.assertEqual(store.state.last_seen_ts_utc, 2000)

    def test_ack_defaults_to_last_seen(self) -> None:
        store = AckStore(self.path)
        store.advance_seen(3000)
        new = store.ack()
        self.assertEqual(new.acked_ts_utc, 3000)

    def test_ack_never_rewinds(self) -> None:
        store = AckStore(self.path)
        store.advance_seen(3000)
        store.ack(3000)
        # Explicit older ack should be a no-op — re-acking older
        # timestamps would let previously-silenced alerts resurface.
        store.ack(1000)
        self.assertEqual(store.state.acked_ts_utc, 3000)

    def test_should_push_respects_seen_and_acked(self) -> None:
        store = AckStore(self.path)
        # Fresh store — everything is pushable.
        self.assertTrue(store.should_push(500))

        store.advance_seen(1000)
        # Anything <= last_seen has already been inspected.
        self.assertFalse(store.should_push(1000))
        self.assertFalse(store.should_push(900))
        self.assertTrue(store.should_push(1001))

        store.ack(1000)
        # Anything <= acked is muted even if not yet seen.
        self.assertFalse(store.should_push(500))
        self.assertFalse(store.should_push(1000))
        self.assertTrue(store.should_push(1001))

    def test_reload_round_trip(self) -> None:
        store = AckStore(self.path)
        store.advance_seen(4242)
        store.ack(4242)

        reborn = AckStore(self.path)
        self.assertEqual(reborn.state.last_seen_ts_utc, 4242)
        self.assertEqual(reborn.state.acked_ts_utc, 4242)

    def test_unreadable_file_falls_back_to_zero(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{not valid json", encoding="utf-8")
        store = AckStore(self.path)
        self.assertEqual(store.state, AckState(0, 0))


# --------------------------------------------------------------------------
# BotConfig.require_ready: zero-trust guard
# --------------------------------------------------------------------------


class RequireReadyTests(unittest.TestCase):
    def test_happy_path(self) -> None:
        _base_cfg().require_ready()  # should not raise

    def test_disabled_flag_blocks_startup(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            _base_cfg(enabled=False).require_ready()
        self.assertIn("enabled = false", str(ctx.exception))

    def test_empty_token_blocks_startup(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            _base_cfg(token="").require_ready()
        self.assertIn("No bot token", str(ctx.exception))

    def test_empty_allowlist_blocks_startup(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            _base_cfg(allowed_chat_ids=frozenset()).require_ready()
        self.assertIn("allowed_chat_ids is empty", str(ctx.exception))

    def test_poll_interval_floor(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            _base_cfg(poll_interval_seconds=1.0).require_ready()
        self.assertIn("poll_interval_seconds", str(ctx.exception))

    def test_all_errors_are_surfaced_together(self) -> None:
        # An operator with a completely pristine toml should see all the
        # hints at once, not one-at-a-time after repeated restarts.
        with self.assertRaises(ConfigError) as ctx:
            _base_cfg(
                enabled=False,
                token="",
                allowed_chat_ids=frozenset(),
                poll_interval_seconds=0,
            ).require_ready()
        msg = str(ctx.exception)
        self.assertIn("enabled = false", msg)
        self.assertIn("No bot token", msg)
        self.assertIn("allowed_chat_ids is empty", msg)
        self.assertIn("poll_interval_seconds", msg)


# --------------------------------------------------------------------------
# load_config: env vars win, TOML parses as expected
# --------------------------------------------------------------------------


class LoadConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.toml = self.root / "aeterna.toml"

    def _write(self, body: str) -> None:
        self.toml.write_text(body, encoding="utf-8")

    def test_env_token_overrides_toml(self) -> None:
        self._write(
            """
[operations.telegram]
enabled = true
token = "from-toml"
allowed_chat_ids = [111]
poll_interval_seconds = 5
"""
        )
        with mock.patch.dict(
            os.environ,
            {
                "AETERNA_TOML": str(self.toml),
                "AETERNA_TELEGRAM_TOKEN": "from-env",
            },
            clear=False,
        ):
            cfg = load_config()
        self.assertEqual(cfg.token, "from-env")

    def test_toml_token_used_when_env_absent(self) -> None:
        self._write(
            """
[operations.telegram]
enabled = true
token = "from-toml"
allowed_chat_ids = [111]
poll_interval_seconds = 5
"""
        )
        with mock.patch.dict(
            os.environ,
            {"AETERNA_TOML": str(self.toml)},
            clear=False,
        ):
            os.environ.pop("AETERNA_TELEGRAM_TOKEN", None)
            cfg = load_config()
        self.assertEqual(cfg.token, "from-toml")

    def test_non_integer_allowlist_entries_are_dropped(self) -> None:
        # Operators hand-editing the TOML occasionally leave a string id
        # by accident — we log and ignore, never raise, because a bad
        # entry shouldn't take down the whole bot.
        self._write(
            """
[operations.telegram]
enabled = true
token = "t"
allowed_chat_ids = [111, "oops", 222]
poll_interval_seconds = 5
"""
        )
        with mock.patch.dict(os.environ, {"AETERNA_TOML": str(self.toml)}, clear=False):
            cfg = load_config()
        self.assertEqual(cfg.allowed_chat_ids, frozenset({111, 222}))

    def test_env_admin_target_overrides_toml(self) -> None:
        self._write(
            """
[operations.telegram]
enabled = true
token = "t"
allowed_chat_ids = [111]
admin_target = "127.0.0.1:50051"
poll_interval_seconds = 5
"""
        )
        with mock.patch.dict(
            os.environ,
            {
                "AETERNA_TOML": str(self.toml),
                "AETERNA_TELEGRAM_ADMIN": "10.0.0.5:50051",
            },
            clear=False,
        ):
            cfg = load_config()
        self.assertEqual(cfg.admin_target, "10.0.0.5:50051")


# --------------------------------------------------------------------------
# Renderers: HTML escaping + branch coverage
# --------------------------------------------------------------------------


class RenderingTests(unittest.TestCase):
    def test_fmt_ts_is_utc(self) -> None:
        # Don't hard-code a Unix timestamp — the formatter's job is "UTC,
        # no local offset", and a literal epoch second is just a setup
        # hazard. Compute both sides from the calendar and compare.
        ts = calendar.timegm((2026, 4, 24, 6, 43, 13, 0, 0, 0))
        self.assertEqual(fmt_ts(ts), "2026-04-24 06:43:13 UTC")

    def test_render_status_ready(self) -> None:
        m = Metrics(
            schema_version=1,
            node_id="Prometheus-1",
            ts_utc=1777617793,
            counters={},
            gauges={"santuario_signer_ready": 1.0, "santuario_vault_sealed": 0.0},
            quantiles={},
            metric_window_seconds=60,
        )
        out = render_status(m)
        self.assertIn("Prometheus-1", out)
        self.assertIn("ready: <b>yes</b>", out)
        self.assertIn("vault sealed: <b>no</b>", out)
        # The green check-mark emoji precedes the node id on happy path.
        self.assertTrue(out.startswith("\u2705"))

    def test_render_status_degraded_uses_warning_glyph(self) -> None:
        m = Metrics(
            schema_version=1,
            node_id="Prometheus-1",
            ts_utc=1777617793,
            counters={},
            gauges={"santuario_signer_ready": 0.0, "santuario_vault_sealed": 1.0},
            quantiles={},
            metric_window_seconds=60,
        )
        out = render_status(m)
        self.assertTrue(out.startswith("\u26a0\ufe0f"))
        self.assertIn("ready: <b>no</b>", out)
        self.assertIn("vault sealed: <b>yes</b>", out)

    def test_render_status_unreachable(self) -> None:
        out = render_status(Unreachable(reason="UNAVAILABLE: <bad>", elapsed_s=0.02))
        self.assertIn("UNREACHABLE", out)
        # Angle brackets in the reason must be escaped — operators paste
        # arbitrary gRPC error strings straight out of the signer.
        self.assertIn("&lt;bad&gt;", out)
        self.assertNotIn("<bad>", out)

    def test_render_peers_empty(self) -> None:
        out = render_peers(PeerList(peers=[], snapshot_utc=1777617793))
        self.assertIn("No peers", out)

    def test_render_peers_escapes_address(self) -> None:
        p = Peer(
            address="<evil>",
            node_id="n1",
            last_seen_utc=1777617793,
            rx_count=1,
            tx_count=2,
            is_bootstrap=True,
        )
        out = render_peers(PeerList(peers=[p], snapshot_utc=1777617793))
        self.assertIn("&lt;evil&gt;", out)
        self.assertIn("[bootstrap]", out)

    def test_render_tail_empty(self) -> None:
        out = render_tail(AuditTail(lines=[]), limit=20)
        self.assertIn("Audit log empty", out)

    def test_render_tail_clamps_and_escapes(self) -> None:
        lines = [
            AuditLogLine(ts_utc=i, record="alert", json='{"v":"<script>"}')
            for i in range(1, 6)
        ]
        out = render_tail(AuditTail(lines=lines), limit=2)
        # Only the last 2 are shown.
        self.assertIn("showing 2 of 5", out)
        # Nasty JSON content is escaped before being wrapped in <pre>.
        self.assertIn("&lt;script&gt;", out)
        self.assertNotIn("<script>", out)

    def test_render_alert_line_escapes_record_and_json(self) -> None:
        out = render_alert_line("al<ert>", 1777617793, '{"k":"<v>"}')
        self.assertIn("al&lt;ert&gt;", out)
        self.assertIn("&lt;v&gt;", out)
        self.assertNotIn("<ert>", out)


# --------------------------------------------------------------------------
# run_alert_cycle: the dedup invariant — at most one push per record
# --------------------------------------------------------------------------


class RunAlertCycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ack_path = Path(self._tmp.name) / "ack_state.json"

    async def test_alert_records_are_pushed_once(self) -> None:
        tail = AuditTail(
            lines=[
                AuditLogLine(ts_utc=1000, record="boot", json="{}"),
                AuditLogLine(ts_utc=1100, record="alert", json='{"k":"v"}'),
                AuditLogLine(ts_utc=1200, record="suspend", json='{"why":"x"}'),
            ]
        )
        admin = _FakeAdmin(
            metrics=Unreachable("unused", 0.0),
            peers=Unreachable("unused", 0.0),
            audit=tail,
        )
        store = AckStore(self.ack_path)
        cfg = _base_cfg()
        msgs: list[str] = []

        pushed = await run_alert_cycle(
            observer=admin, store=store, cfg=cfg, broadcaster=_collect(msgs)
        )

        # Only alert/suspend lines get pushed — "boot" is not in alert_kinds.
        self.assertEqual([p.record for p in pushed], ["alert", "suspend"])
        self.assertEqual(len(msgs), 2)
        # Cursor advanced past the entire window, not just the alert ts.
        self.assertEqual(store.state.last_seen_ts_utc, 1200)

        # Second cycle with the SAME tail must not re-push anything.
        msgs.clear()
        pushed2 = await run_alert_cycle(
            observer=admin, store=store, cfg=cfg, broadcaster=_collect(msgs)
        )
        self.assertEqual(pushed2, [])
        self.assertEqual(msgs, [])

    async def test_ack_suppresses_new_alerts_below_cursor(self) -> None:
        # Tail arrives containing a brand-new alert at ts=900. If the
        # operator already /ack'd up to ts=2000 (e.g. during an incident
        # they cleared everything), any alert whose ts_utc is below that
        # cursor must stay muted — otherwise a late-arriving, backdated
        # line could re-page them after they've closed the incident.
        tail = AuditTail(
            lines=[
                AuditLogLine(ts_utc=900, record="alert", json="{}"),
            ]
        )
        admin = _FakeAdmin(
            metrics=Unreachable("unused", 0.0),
            peers=Unreachable("unused", 0.0),
            audit=tail,
        )
        store = AckStore(self.ack_path)
        store.advance_seen(2000)
        store.ack(2000)

        msgs: list[str] = []
        pushed = await run_alert_cycle(
            observer=admin,
            store=store,
            cfg=_base_cfg(),
            broadcaster=_collect(msgs),
        )
        self.assertEqual(pushed, [])
        self.assertEqual(msgs, [])

    async def test_unreachable_tail_is_soft_failure(self) -> None:
        admin = _FakeAdmin(
            metrics=Unreachable("unused", 0.0),
            peers=Unreachable("unused", 0.0),
            audit=Unreachable("UNAVAILABLE: down", 0.05),
        )
        store = AckStore(self.ack_path)
        msgs: list[str] = []
        pushed = await run_alert_cycle(
            observer=admin,
            store=store,
            cfg=_base_cfg(),
            broadcaster=_collect(msgs),
        )
        self.assertEqual(pushed, [])
        self.assertEqual(msgs, [])
        # Cursor must not move forward on a failed poll — otherwise
        # we'd silently skip alerts that were in fact present on the
        # signer but temporarily unreachable.
        self.assertEqual(store.state.last_seen_ts_utc, 0)

    async def test_new_alert_after_ack_is_still_pushed(self) -> None:
        # Regression guard: the ack cursor must only suppress records at
        # or below it. Fresh records with ts > acked_ts_utc still fire.
        tail_round_1 = AuditTail(
            lines=[AuditLogLine(ts_utc=1000, record="alert", json="{}")]
        )
        tail_round_2 = AuditTail(
            lines=[
                AuditLogLine(ts_utc=1000, record="alert", json="{}"),
                AuditLogLine(ts_utc=2000, record="alert", json="{}"),
            ]
        )
        store = AckStore(self.ack_path)
        cfg = _base_cfg()

        # Round 1: push + ack.
        admin = _FakeAdmin(
            metrics=Unreachable("u", 0.0),
            peers=Unreachable("u", 0.0),
            audit=tail_round_1,
        )
        msgs: list[str] = []
        await run_alert_cycle(
            observer=admin, store=store, cfg=cfg, broadcaster=_collect(msgs)
        )
        self.assertEqual(len(msgs), 1)
        store.ack()  # ack everything seen so far (= 1000)

        # Round 2: a new, strictly-later alert appears. Must push.
        admin.audit = tail_round_2
        msgs.clear()
        pushed = await run_alert_cycle(
            observer=admin, store=store, cfg=cfg, broadcaster=_collect(msgs)
        )
        self.assertEqual([p.ts_utc for p in pushed], [2000])
        self.assertEqual(len(msgs), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
bserver=admin, store=store, cfg=cfg, broadcaster=_collect(msgs)
        )
        self.assertEqual([p.ts_utc for p in pushed], [2000])
        self.assertEqual(len(msgs), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
