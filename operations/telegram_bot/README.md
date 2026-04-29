# AETERNA Telegram Operator Bot — v0.3.0 "Oculus"

Read-only Telegram companion to the War Room. Same Admin gRPC surface
(`GetMetrics` / `TailAuditLog` / `ListPeers`) — no new capability,
no sign path, no unseal path. If the bot token is stolen the worst
an attacker can do is *watch* your signer. Every other safety property
is preserved by the same invariants that hold for the War Room.

The bot lives in its own Python package (`operations/telegram_bot/`)
but **shares the typed Admin client with `operations/war_room/`** via
a sibling-import hack — one proto regeneration feeds both surfaces.
If you move either directory, update the `_WAR_ROOM` path at the top
of `bot.py`.

---

## 1. Provisioning: create a bot with @BotFather

The Telegram-side identity of the bot is a long-lived token issued
by the official `@BotFather` account. AETERNA never talks to anything
else during the handshake.

1. Open Telegram on any client and DM [`@BotFather`](https://t.me/BotFather).
2. Send `/newbot`. BotFather will prompt for:
   - **A display name**: e.g. `AETERNA Prometheus-1 Ops`. Shown in the
     chat header — keep it recognisable for late-night pages.
   - **A unique username**: must end in `bot` (e.g. `aeterna_prom1_ops_bot`).
3. BotFather replies with a line of the form:
   ```
   Use this token to access the HTTP API:
   123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
   ```
   **This token is a credential.** Treat it like an SSH private key.

4. Feed the token to the bot. Two options:
   - **Production (recommended):** environment variable.
     ```bash
     export AETERNA_TELEGRAM_TOKEN='123456789:AA...'
     ```
     The env var wins over `aeterna.toml`, so secrets never enter the
     repo's config audit trail.
   - **Dev only:** paste it into `aeterna.toml` under
     `[operations.telegram] token = "…"`. Do NOT commit if you go this
     route — add a local override in `aeterna.local.toml` (gitignored)
     instead.

5. **Register the slash-command menu.** Still inside `@BotFather`,
   send `/setcommands`, pick your new bot, and paste:
   ```
   status - signer readiness + vault state snapshot
   peers - gossip peer list
   tail - last N audit log lines (default 20)
   audit_now - force an immediate alert poll
   ack - suppress re-notification of current incident
   help - command reference
   ```
   This is what makes the commands tap-selectable on mobile. Skip it
   and the bot still works but the operator has to type every command
   by hand during an incident — bad UX when fingers are shaking.

---

## 2. Allowlist: the "log & restart" zero-trust flow

The bot refuses to reply to any chat id that isn't in
`operations.telegram.allowed_chat_ids`. It does **not** expose a
`/whitelist_me` command — self-registration would defeat the point.
The provisioning flow is intentionally operator-driven:

1. Leave `allowed_chat_ids = []` in `aeterna.toml` on first run.
2. Set `enabled = true` and provide the token.
3. Start the bot. It will log
   ```
   [FATAL] Telegram bot refusing to start (zero-trust defaults):
     - allowed_chat_ids is empty. ...
   ```
   and exit. **This is expected.** Temporarily comment out the empty
   check (or add a single throwaway chat id) to get past the gate for
   the discovery step, then follow this procedure to find your id:

4. Alternative (cleaner) — use `@userinfobot` on Telegram: it replies
   with your numeric chat id without any AETERNA code running. Copy
   the id into `allowed_chat_ids = [123456789]`, flip `enabled = true`,
   and restart. This is the recommended path for the first operator.

5. For additional operators later on, keep the bot up and just DM it
   from the new account. You'll see on the bot's stderr:
   ```
   [UNAUTHORIZED] Tentativo di accesso dal chat-id: 987654321
     (@some_username). Se sei l'operatore, aggiungi questo ID ad
     aeterna.toml e riavvia.
   ```
   Add `987654321` to `allowed_chat_ids`, SIGTERM the bot, relaunch.

**The bot never replies to an unauthorized chat.** We don't want a
port-scan-equivalent probe to confirm that a Telegram bot exists at
this account at all.

---

## 3. Install

The bot lives in its own virtualenv (same PEP 668 rationale as the
War Room). From the repo root:

**Linux / macOS / WSL:**

```bash
python3 -m venv operations/telegram_bot/.venv
operations/telegram_bot/.venv/bin/pip install -r \
    operations/telegram_bot/requirements.txt
```

**Windows PowerShell 5.1:**

```powershell
# If a WSL-built .venv exists at the same path, remove it first:
Remove-Item -Recurse -Force operations\telegram_bot\.venv -ErrorAction SilentlyContinue

python -m venv operations\telegram_bot\.venv
operations\telegram_bot\.venv\Scripts\pip install -r operations\telegram_bot\requirements.txt
```

The `requirements.txt` pins `grpcio` and `protobuf` to the same range
as the War Room — the two surfaces import the same generated stubs,
so they must agree on wire format. Do NOT upgrade one without
regenerating the other.

---

## 4. Run

**Linux / macOS / WSL:**

```bash
AETERNA_TELEGRAM_TOKEN='123456789:AA...' \
    bash operations/telegram_bot/launch.sh
```

**Windows PowerShell:**

```powershell
$env:AETERNA_TELEGRAM_TOKEN = '123456789:AA...'
powershell -ExecutionPolicy Bypass -File operations\telegram_bot\launch.ps1
```

On first successful boot the bot logs:

```
aeterna.telegram.bot: starting bot: toml=.../aeterna.toml allowlist=1 admin_target=<default>
aeterna.telegram.bot: alert loop started: interval=5.0s kinds=['alert', 'recovery_token_issued', 'suspend'] recipients=1
```

and then waits for your first `/status` DM.

### Admin gRPC target override

```bash
AETERNA_TELEGRAM_ADMIN='127.0.0.1:50052' bash operations/telegram_bot/launch.sh
```

Equivalent to the War Room's sidebar override. Defaults to whatever
`core/santuario_client.py` resolves (`$SANTUARIO_PORT` → Windows TCP
→ Unix UDS).

---

## 5. What happens when the signer dies

Identical to the War Room: every handler returns `Unreachable` instead
of raising, and the alert loop logs a warning and retries next tick.
`/status` during an outage replies with:

```
Signer UNREACHABLE
reason: UNAVAILABLE: failed to connect to all addresses; ...
elapsed: 0.02s
```

If the outage coincides with a signer-side integrity alert (the signer
writes the audit line BEFORE self-suspending), the bot will push the
alert at least once — audit writes are append-only and survive the
self-suspend path by design.

---

## 6. Tests

```bash
cd operations/telegram_bot
.venv/bin/python -m unittest tests.test_bot -v
```

The tests stub `python-telegram-bot` and dial a fake Admin gRPC server
in-process. They cover:

- `/status` roundtrip through the HTML renderer
- `/tail N` with limit clamping
- Alert push + `/ack` suppression (the dedup invariant)
- Unauthorized chat ids are silently dropped and logged

---

## 7. Security checklist

Before flipping `enabled = true` in `aeterna.toml`:

- [ ] Token is in `$AETERNA_TELEGRAM_TOKEN`, not committed.
- [ ] `allowed_chat_ids` contains only the operator(s) you expect.
- [ ] Bot is on a machine that can already read the Admin gRPC socket
  (same host, or a host in your ops VLAN). The bot is NOT a tunnel.
- [ ] BotFather commands registered via `/setcommands`.
- [ ] `poll_interval_seconds >= 2` in `aeterna.toml`.
- [ ] Nothing in `alert_kinds` matches a record your signer emits at
  high cardinality — this would spam you.
