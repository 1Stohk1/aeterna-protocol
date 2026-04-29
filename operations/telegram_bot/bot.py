"""AETERNA v0.3.0 'Oculus' — Telegram operator bot (Phase C).

Design invariants:

1. **Read-only on the signer.** The bot calls only the Admin gRPC
   surface the War Room already uses (``GetMetrics`` /
   ``TailAuditLog`` / ``ListPeers``). It NEVER calls the sign path and
   NEVER carries unseal material. A stolen bot token must not be able
   to mutate signer state.
2. **Zero-trust allowlist.** Every incoming chat id is checked against
   ``operations.telegram.allowed_chat_ids`` in ``aeterna.toml``.
   Unauthorized messages are silently dropped (no reply to the wrong
   chat — we don't want to confirm the bot's existence to a scan) and
   logged on stderr so the operator can whitelist themselves via the
   "log & restart" flow in README.md.
3. **Per-chat rate limit.** Even an allowlisted chat gets a token
   bucket (default 1 cmd/s) so a compromised account can't DoS the
   admin surface by flooding ``/status``.
4. **Alert push with local ack.** The poller watches the audit log
   for new ``alert`` / ``suspend`` / ``recovery_token_issued`` lines
   and pushes them to every allowlisted chat. ``/ack`` is a LOCAL
   bookkeeping op — it doesn't touch signer state, only suppresses
   re-notification of already-seen alerts during the same incident
   (see state.py).

Cross-package import note:

The typed Admin client (``AdminObserver`` + pb2 stubs) lives in
``operations/war_room/``. The bot imports it via sys.path rather than
vendoring a second copy, so a proto regeneration feeds both surfaces.
If either directory moves, update the ``_WAR_ROOM`` path in
``rendering.py`` and ``poller.py``.
"""
from __future__ import annotations

import argparse
import asyncio
import html
import logging
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

# Path-massage for the sibling War Room import MUST happen before the
# 'client' import below. rendering.py and poller.py do the same dance
# — keeping it here too means `python -m operations.telegram_bot.bot`
# works regardless of which module gets imported first.
_WAR_ROOM = Path(__file__).resolve().parent.parent / "war_room"
if str(_WAR_ROOM) not in sys.path:
    sys.path.insert(0, str(_WAR_ROOM))

from client import AdminObserver  # noqa: E402

from telegram import Update  # noqa: E402
from telegram.constants import ParseMode  # noqa: E402
from telegram.ext import (  # noqa: E402
    Application,
    ApplicationBuilder,
    ApplicationHandlerStop,
    CommandHandler,
    ContextTypes,
    TypeHandler,
)

from .config import BotConfig, ConfigError, load_config  # noqa: E402
from .poller import alert_loop, run_alert_cycle  # noqa: E402
from .rendering import (  # noqa: E402
    fmt_ts,
    render_peers,
    render_status,
    render_tail,
)
from .state import AckStore  # noqa: E402

LOG = logging.getLogger("aeterna.telegram.bot")


# --- allowlist + rate limit -------------------------------------------------


class AccessGate:
    """Silently drop messages from non-allowlisted chats; rate-limit the rest."""

    def __init__(self, cfg: BotConfig) -> None:
        self._allowed = cfg.allowed_chat_ids
        self._min_interval = (
            1.0 / cfg.rate_limit_per_second if cfg.rate_limit_per_second > 0 else 0.0
        )
        self._last_cmd_ts: dict[int, float] = defaultdict(float)

    async def guard(self, update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        chat = update.effective_chat
        if chat is None:
            return

        if chat.id not in self._allowed:
            # Intentional: no reply. We don't confirm the bot exists.
            user = update.effective_user
            uname = f"@{user.username}" if user and user.username else "(no username)"
            print(
                f"[UNAUTHORIZED] Tentativo di accesso dal chat-id: {chat.id} "
                f"({uname}). Se sei l'operatore, aggiungi questo ID ad "
                f"aeterna.toml e riavvia.",
                file=sys.stderr,
                flush=True,
            )
            raise ApplicationHandlerStop()

        if self._min_interval > 0:
            now = time.monotonic()
            last = self._last_cmd_ts[chat.id]
            if now - last < self._min_interval:
                LOG.warning(
                    "rate-limit: dropping cmd from chat %s (%.2fs since last)",
                    chat.id,
                    now - last,
                )
                raise ApplicationHandlerStop()
            self._last_cmd_ts[chat.id] = now


# --- command handlers -------------------------------------------------------


def _make_handlers(
    observer: AdminObserver, cfg: BotConfig, store: AckStore
) -> list[CommandHandler]:
    async def start(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await update.effective_chat.send_message(
            "AETERNA War Room bot — read-only operator surface.\n"
            "Commands: /status /peers /tail [N] /audit_now /ack /help",
            parse_mode=ParseMode.HTML,
        )

    async def help_cmd(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await update.effective_chat.send_message(
            "<b>Read-only operator bot</b>\n"
            "/status      current signer readiness + vault state\n"
            "/peers       gossip peer list\n"
            "/tail [N]    last N audit log lines (default 20, max "
            f"{cfg.audit_tail_limit})\n"
            "/audit_now   force an immediate alert poll cycle\n"
            "/ack         suppress re-notification of current incident\n"
            "/help        this message",
            parse_mode=ParseMode.HTML,
        )

    async def status(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        m = await asyncio.to_thread(observer.get_metrics)
        await update.effective_chat.send_message(render_status(m), parse_mode=ParseMode.HTML)

    async def peers(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        pl = await asyncio.to_thread(observer.list_peers)
        await update.effective_chat.send_message(render_peers(pl), parse_mode=ParseMode.HTML)

    async def tail(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        args = ctx.args or []
        try:
            req_n = int(args[0]) if args else 20
        except ValueError:
            await update.effective_chat.send_message(
                "Usage: /tail [N]  (N is an integer, default 20)"
            )
            return
        n = max(1, min(req_n, cfg.audit_tail_limit))
        t = await asyncio.to_thread(observer.tail_audit_log, n)
        await update.effective_chat.send_message(render_tail(t, n), parse_mode=ParseMode.HTML)

    async def ack(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        new = store.ack()
        ts_str = fmt_ts(new.acked_ts_utc) if new.acked_ts_utc else "(nothing to ack)"
        await update.effective_chat.send_message(
            f"ack cursor advanced to <code>{html.escape(ts_str)}</code>\n"
            f"<i>(local bot state only — signer was not modified)</i>",
            parse_mode=ParseMode.HTML,
        )

    async def audit_now(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        async def reply_broadcaster(msg: str) -> None:
            await update.effective_chat.send_message(msg, parse_mode=ParseMode.HTML)

        pushed = await run_alert_cycle(
            observer=observer, store=store, cfg=cfg, broadcaster=reply_broadcaster
        )
        if not pushed:
            await update.effective_chat.send_message(
                "<i>No new alert-worthy audit lines since last poll.</i>",
                parse_mode=ParseMode.HTML,
            )

    return [
        CommandHandler("start", start),
        CommandHandler("help", help_cmd),
        CommandHandler("status", status),
        CommandHandler("peers", peers),
        CommandHandler("tail", tail),
        CommandHandler("ack", ack),
        CommandHandler("audit_now", audit_now),
    ]


# --- app wiring -------------------------------------------------------------


def build_application(
    cfg: BotConfig,
    *,
    observer: AdminObserver | None = None,
    store: AckStore | None = None,
    application_builder: ApplicationBuilder | None = None,
) -> Application:
    observer = observer or AdminObserver(target=cfg.admin_target or None)
    state_dir = Path(__file__).resolve().parent / "state"
    store = store or AckStore(state_dir / "ack_state.json")
    gate = AccessGate(cfg)

    builder = application_builder or ApplicationBuilder().token(cfg.token)
    app = builder.build()

    async def _gate_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await gate.guard(update, ctx)

    app.add_handler(TypeHandler(Update, _gate_handler), group=-1)
    for h in _make_handlers(observer, cfg, store):
        app.add_handler(h)

    async def _post_init(a: Application) -> None:
        async def fanout(msg: str) -> None:
            for cid in cfg.allowed_chat_ids:
                try:
                    await a.bot.send_message(cid, msg, parse_mode=ParseMode.HTML)
                except Exception as exc:
                    LOG.warning("failed to push alert to chat %s: %s", cid, exc)

        a.bot_data["_alert_task"] = asyncio.create_task(
            alert_loop(observer, store, cfg, fanout)
        )

    async def _post_shutdown(a: Application) -> None:
        task = a.bot_data.get("_alert_task")
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    app.post_init = _post_init
    app.post_shutdown = _post_shutdown
    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AETERNA Telegram operator bot")
    parser.add_argument(
        "--log-level",
        default=os.environ.get("AETERNA_LOG_LEVEL", "INFO"),
        help="Python logging level (default: INFO)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        cfg = load_config()
        cfg.require_ready()
    except ConfigError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        return 2

    LOG.info(
        "starting bot: toml=%s allowlist=%d admin_target=%s",
        cfg.source_path,
        len(cfg.allowed_chat_ids),
        cfg.admin_target or "<default>",
    )

    app = build_application(cfg)
    app.run_polling(allowed_updates=Update.ALL_TYPES)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
