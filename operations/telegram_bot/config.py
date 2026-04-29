"""Parse ``aeterna.toml`` [operations.telegram] + env overrides.

Precedence (highest wins):

1. Environment variables:
   - ``AETERNA_TELEGRAM_TOKEN``    — bot token from @BotFather
   - ``AETERNA_TELEGRAM_ADMIN``    — admin gRPC target (overrides toml + default)
   - ``AETERNA_TOML``              — path to a non-default aeterna.toml

2. aeterna.toml file under the repo root (auto-discovered by walking
   parents of this file until one contains an ``aeterna.toml``).

3. Hard-coded defaults that keep the bot refusing to start unless
   explicitly provisioned — zero-trust posture.

A :class:`BotConfig` is a frozen dataclass so command handlers can pass
it around without accidentally mutating the allowlist at runtime.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

LOG = logging.getLogger("aeterna.telegram.config")


class ConfigError(RuntimeError):
    """Raised when the loaded config would let the bot start unsafely."""


@dataclass(frozen=True)
class BotConfig:
    """Immutable runtime configuration for the Telegram operator bot."""

    enabled: bool
    token: str
    allowed_chat_ids: frozenset[int]
    admin_target: str
    poll_interval_seconds: float
    alert_kinds: frozenset[str]
    audit_tail_limit: int
    rate_limit_per_second: float
    source_path: Path  # Where the aeterna.toml was read from — for log context.

    def require_ready(self) -> None:
        """Fail-fast guard. Call once at bot startup.

        The bot must NOT accept the default zero-trust posture at boot:
        an operator that forgot to flip ``enabled = true`` or populate
        ``allowed_chat_ids`` would otherwise run a dead bot burning
        quota at BotFather with zero benefit. We refuse to start and
        point at the README's provisioning checklist.
        """
        errors = []
        if not self.enabled:
            errors.append(
                "operations.telegram.enabled = false in aeterna.toml — "
                "flip it to true after you've provisioned the token AND "
                "at least one chat_id."
            )
        if not self.token:
            errors.append(
                "No bot token set. Provide it via $AETERNA_TELEGRAM_TOKEN "
                "(preferred in production) or operations.telegram.token in "
                "aeterna.toml. See README.md §BotFather for the procedure."
            )
        if not self.allowed_chat_ids:
            errors.append(
                "allowed_chat_ids is empty. The bot ignores every message "
                "from a non-allowlisted chat; without entries here, the bot "
                "has no one to talk to. First-run flow: start the bot with "
                "an empty allowlist, DM the bot from your phone once, read "
                "the stderr line '[UNAUTHORIZED] ...' and copy the chat id "
                "into aeterna.toml, then restart."
            )
        if self.poll_interval_seconds < 2:
            errors.append(
                "poll_interval_seconds must be >= 2 to avoid hammering the "
                "signer's Admin surface."
            )
        if errors:
            raise ConfigError(
                "Telegram bot refusing to start (zero-trust defaults):\n  - "
                + "\n  - ".join(errors)
            )


def _find_aeterna_toml(start: Path) -> Path:
    """Walk parents of ``start`` until a sibling ``aeterna.toml`` is found."""
    override = os.environ.get("AETERNA_TOML")
    if override:
        p = Path(override)
        if not p.is_file():
            raise ConfigError(f"$AETERNA_TOML points at '{p}' which is not a file")
        return p

    here = start.resolve()
    for candidate_dir in [here, *here.parents]:
        candidate = candidate_dir / "aeterna.toml"
        if candidate.is_file():
            return candidate
    raise ConfigError(
        f"Could not find aeterna.toml by walking parents of {start}. "
        f"Set $AETERNA_TOML to override."
    )


def load_config(search_from: Optional[Path] = None) -> BotConfig:
    """Read aeterna.toml + env overrides into an immutable :class:`BotConfig`."""
    search_from = search_from or Path(__file__).resolve().parent
    toml_path = _find_aeterna_toml(search_from)

    with toml_path.open("rb") as fh:
        doc = tomllib.load(fh)

    tg = (doc.get("operations", {}) or {}).get("telegram", {}) or {}

    enabled = bool(tg.get("enabled", False))

    token_env = os.environ.get("AETERNA_TELEGRAM_TOKEN", "").strip()
    token = token_env or str(tg.get("token", "")).strip()

    raw_ids = tg.get("allowed_chat_ids", []) or []
    chat_ids: list[int] = []
    for entry in raw_ids:
        try:
            chat_ids.append(int(entry))
        except (TypeError, ValueError):
            LOG.warning(
                "Ignoring non-integer allowlist entry %r in %s", entry, toml_path
            )
    allowed = frozenset(chat_ids)

    admin_env = os.environ.get("AETERNA_TELEGRAM_ADMIN", "").strip()
    admin_target = admin_env or str(tg.get("admin_target", "")).strip()

    poll_interval = float(tg.get("poll_interval_seconds", 5))
    audit_limit = int(tg.get("audit_tail_limit", 50))
    rate_limit = float(tg.get("rate_limit_per_second", 1))
    kinds = frozenset(
        str(k) for k in tg.get("alert_kinds", ["alert", "suspend"])
    )

    return BotConfig(
        enabled=enabled,
        token=token,
        allowed_chat_ids=allowed,
        admin_target=admin_target,
        poll_interval_seconds=poll_interval,
        alert_kinds=kinds,
        audit_tail_limit=audit_limit,
        rate_limit_per_second=rate_limit,
        source_path=toml_path,
    )
