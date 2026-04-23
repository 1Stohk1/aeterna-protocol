# Sprint Plan — AETERNA v0.3.0 "Oculus"

**Status:** proposed by the Terminale di Comando on 2026-04-23.
**Predecessor:** v0.2.0 "Custos" — sovereignty-grade Santuario kernel
(TPM2 vault, seccomp-bpf, deterministic critic, α/β/γ watchdog,
Dilithium-5 recovery).
**Successor target:** v0.4.0 "Sigillum" — log confidentiality
(ChaCha20-Poly1305 audit log, HKDF/Double-Ratchet gossip key rotation).

---

## 1. Sprint goal (one sentence)

> **Make the Custos kernel legible to its operator without weakening
> any of its guarantees.**

v0.2.0 hardened the node: the Santuario refuses to sign when integrity,
isolation, or axioms are violated. But the operator only sees that
through `santuarioctl status`, a single line of text on a terminal.
v0.3.0 turns that one line into a control surface — a real-time
dashboard, a phone-side alerting bot, and a metrics endpoint another
machine can scrape — so a degraded node never goes unnoticed and a
healthy one can be inspected at a glance.

If at the end of this sprint you cannot, from a phone in a different
room, see that a peer has tripped β and command its acknowledgement
without ever opening an SSH session, the sprint has failed regardless
of how many widgets the dashboard ships with.

## 2. Scope rationale

v0.2.0 answered "is the node hard to compromise?" v0.3.0 answers "can
the operator see and act on what the node is doing?" Three operator
scenarios drive the scope:

1. **Single-node operator at the desk.** Wants a one-pane dashboard:
   vault state, signer verdict, integrity green/red, last 20 audit-log
   records, current peer set. Read-only is fine — write actions stay
   on `santuarioctl`. Defense against drift: surface the same fields
   the gRPC `GetStatus` already exposes; do not invent new state.
2. **Multi-node operator on the move.** Phone-only access. Needs push
   alerts on α/β/γ trips, vault unseal events, and signer suspensions.
   Must be able to query `status` and trigger `audit --now` from a
   chat. No write keys ever leave the node — recovery (`resume`) stays
   local; the bot only lobs read-only RPCs and admin commands the
   operator pre-authorised.
3. **Fleet operator integrating with existing observability.** Has
   Prometheus, Grafana, and PagerDuty already wired. Wants AETERNA
   metrics in a `/metrics` text endpoint they can scrape. Defense
   against scope creep: ship the exporter, do not ship dashboards
   (Grafana JSON is a community contribution, not a release artifact).

Everything not mapped to those three scenarios is deferred. In
particular **log confidentiality** (ChaCha20, HKDF, Double-Ratchet) is
v0.4.0 territory — it makes the trail unreadable to a thief, not more
readable to the operator, and this sprint is about visibility, not
secrecy.

## 3. Phased deliverables

Five phases, binary pass/fail demos. Do not start phase N+1 until
phase N's demo is green.

### Phase A — Admin gRPC surface

The signer already speaks `GetStatus`. v0.3.0 needs three more
read-only RPCs: `GetMetrics` (counters/gauges in a serialisable form),
`TailAuditLog` (last N records), and `ListPeers` (snapshot of the
gossip view). All three are pure observers — they do not unseal,
do not sign, do not mutate state.

| Deliverable | Path | Owner |
|---|---|---|
| Proto extensions for `GetMetrics`, `TailAuditLog`, `ListPeers` | `santuario/signer/proto/santuario_signer.proto` | Rust |
| Server impls — strictly read-only, behind the same UDS | `santuario/signer/src/admin.rs` | Rust |
| Sentinel-side metrics provider — counters wired into existing loop | `core/sentinel.py` (new `metrics.py` mixin) | Python |
| `santuarioctl metrics`, `santuarioctl tail`, `santuarioctl peers` | `santuario/signer/src/bin/santuarioctl.rs` | Rust |
| Conformance test — every new RPC callable in osservatore tier | `santuario/signer/tests/admin_api.rs` | Test |

**Phase A demo:** with the signer running, every new RPC returns a
shape-stable JSON payload via `santuarioctl <cmd> --json`. The same
RPCs called against a *suspended* signer return their data anyway
(observers do not gate on signer verdict).

### Phase B — Streamlit War Room

A single-file Streamlit app under `operations/war_room/app.py`. Reads
exclusively through the new admin RPCs (no direct disk peek, no
sub-shelling `santuarioctl`). Refreshes on a timer, never writes.
Auth is HTTP Basic over loopback by default; an explicit
`--public-bind` flag is required to expose beyond `127.0.0.1` and
prints a loud warning.

| Deliverable | Path | Owner |
|---|---|---|
| Streamlit app — single file, no extra framework | `operations/war_room/app.py` | Python |
| Admin RPC client — typed dataclass wrappers | `operations/war_room/client.py` | Python |
| Status panel — vault/seccomp/critic/integrity/signer banner | `operations/war_room/app.py` | Python |
| Peer panel — live gossip view, last-seen ages | `operations/war_room/app.py` | Python |
| Audit panel — paginated tail of audit.log.jsonl via RPC | `operations/war_room/app.py` | Python |
| Quickstart — `make war-room` target invokes Streamlit | `Makefile` | Ops |
| Smoke test — Playwright headless screenshot of the three panels | `operations/war_room/tests/screenshot.py` | Test |

**Phase B demo:** `make war-room` opens `localhost:8501` in the
operator's browser. All three panels render against a healthy node
within 2s. Killing `santuario-signer` flips the status banner to red
within one refresh cycle without the dashboard crashing.

### Phase C — Telegram operator bot

A long-poll bot under `operations/telegram_bot/`. Speaks to the
operator over a private chat keyed by their Telegram user-id (an
allowlist in `aeterna.toml → [operations.telegram]`). Reads via the
admin RPCs; never writes to the vault. The bot is a *messenger* — it
relays alerts the integrity loop already produces and forwards a
small set of operator commands back to `santuarioctl`.

| Deliverable | Path | Owner |
|---|---|---|
| Bot runner — `python -m operations.telegram_bot` | `operations/telegram_bot/__main__.py` | Python |
| Alert subscriber — tails the audit log, pushes α/β/γ + suspends | `operations/telegram_bot/alerts.py` | Python |
| Command router — `/status`, `/tail`, `/peers`, `/audit_now` | `operations/telegram_bot/commands.py` | Python |
| Authz — operator allowlist + per-command rate limits | `operations/telegram_bot/auth.py` | Python |
| Bootstrap doc — how to mint a bot token and wire the chat-id | `operations/telegram_bot/README.md` | Docs |
| Integration test — mock Telegram API, assert end-to-end roundtrip | `operations/telegram_bot/tests/e2e.py` | Test |

**Phase C demo:** with the bot running, manually corrupt
`MANIFESTO.md` on disk. Within 60s the operator's Telegram chat shows
the α-alert. The operator types `/status` from their phone and
receives the live banner.

### Phase D — Prometheus exporter

A second loopback HTTP endpoint, `:9477/metrics`, serving Prometheus
text-exposition format. Backed by the same admin RPC `GetMetrics`
introduced in Phase A. Never serves anything except metrics — no
debug pages, no service discovery.

| Deliverable | Path | Owner |
|---|---|---|
| Exporter binary — `santuario-exporter`, calls `GetMetrics` and renders | `santuario/exporter/src/main.rs` | Rust |
| Metric definitions — counters/gauges in a stable namespace | `santuario/exporter/src/metrics.rs` | Rust |
| systemd unit + bootstrap.sh wiring | `santuario/exporter/aeterna-exporter.service` | Ops |
| Conformance test — `promtool check metrics` clean | `santuario/exporter/tests/promtool.sh` | Test |
| Grafana JSON sample (community asset, NOT a release gate) | `operations/grafana/aeterna-overview.json` | Docs |

**Phase D demo:** `curl http://127.0.0.1:9477/metrics | promtool check
metrics` exits 0. A Prometheus instance scrapes the endpoint and
recognises every metric without a parsing error. The operator can
load the sample Grafana dashboard and see the same numbers as the War
Room, side by side.

### Phase E — Operator UX polish

Cross-cutting work that is too small to be its own phase but too
important to slip into v0.4.0. Mostly hardening and documentation.

| Deliverable | Path | Owner |
|---|---|---|
| HTTP Basic auth for War Room with bcrypted password | `operations/war_room/auth.py` | Python |
| Bot token + Telegram secrets stored via `vaultctl wrap-dek` | `operations/telegram_bot/secrets.py` | Python |
| Operator runbook — what every alert means, what to do | `docs/OPERATOR-RUNBOOK.md` | Docs |
| Onboarding script — `make operator-setup` provisions War Room + bot | `Makefile` | Ops |
| README v0.3.0 row marked ✅, v0.4.0 row added | `README.md` | Docs |

**Phase E demo:** a fresh operator on a fresh laptop runs
`make operator-setup`, follows the prompts (Telegram token, bcrypt
password), and within 10 minutes has both the dashboard and the bot
working without ever editing a config file by hand.

## 4. Acceptance criteria (sprint-level)

All simultaneously for v0.3.0 to ship:

1. The three new admin RPCs (`GetMetrics`, `TailAuditLog`,
   `ListPeers`) are callable from `santuarioctl` and return shape-
   stable JSON when invoked with `--json`.
2. The War Room dashboard renders all five panels (status, peers,
   audit, metrics, integrity) on `localhost:8501` within 2s of cold
   start, against an idle node.
3. The Telegram bot pushes an α/β/γ alert to the operator chat within
   60s of the integrity loop firing it, and serves `/status`,
   `/tail`, `/peers`, `/audit_now` correctly to allowlisted users.
4. The Prometheus exporter at `127.0.0.1:9477/metrics` passes
   `promtool check metrics` with zero warnings, and at least 12
   distinct AETERNA metrics are exposed (signer state, vault state,
   integrity verdict, peer counts, gossip rates, audit-log size,
   sign rate, sign latency p50/p99, suspension count, recovery
   count, α-alert count, β/γ alert counts).
5. No new code in the *signing* path. The Santuario gRPC handlers
   for `Sign` / `Verify` / `Resume` are untouched. New RPCs live in
   a separate `admin` service descriptor and a separate Rust module.
6. Running `santuarioctl status --tail 5 --peers` prints the v0.2.0
   banner plus the last five audit records and the current peer
   table, in a single command.
7. `docs/OPERATOR-RUNBOOK.md` exists and documents at least one
   recovery procedure for every alert kind in the audit log.
8. A solo operator with no SSH access can, from a phone, observe and
   acknowledge an α alert end-to-end.

## 5. Out of scope — deferred to v0.4.0 or later

Reminder for the periphery chats. Any suggestion on this list this
sprint is scope drift.

**v0.4.0 "Sigillum" — log confidentiality** owns:

- ChaCha20-Poly1305 encryption of the audit log on disk.
- HKDF-derived per-session keys for the gossip channel.
- Double-Ratchet key rotation between operator endpoints.
- Tail/replay tooling that decrypts on the fly given an operator key.
- Optional remote log shipper (encrypted, append-only).

**v0.5.0+ — consensus & storage** owns (unchanged):

- Cosmos SDK `x/guardian` module and `aeterna_oracle` CosmWasm contract.
- IPFS cold storage for checkpoints and model weights.
- zk-SNARK PoC circuits.
- Full stealth migration on γ trip.

**v1.0.0 "Sovereign" — production hardening** owns (unchanged):

- gVisor / Firecracker isolation replacing seccomp.
- Windows and macOS support.
- Formal external security audit.

## 6. Risks and mitigations

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| War Room exposed beyond loopback by a sleepy operator | High | High | Default bind `127.0.0.1`; `--public-bind` mandatory and prints a 5-line warning + waits 3s before binding |
| Telegram bot token leaked from `aeterna.toml` | High | Medium | Token stored as a wrapped-DEK via `vaultctl wrap-dek`; never written to TOML; only the wrapped blob is committed |
| Operator floods bot with `/audit_now` and DOSes integrity loop | Medium | Medium | Per-command rate limit (1 audit per 5 min) + bot-side cooldown table |
| Prometheus exporter accidentally scraped over public network | Medium | Medium | Listens on `127.0.0.1` only; exposing it to a network requires an explicit reverse-proxy step documented in OPERATOR-RUNBOOK.md |
| Streamlit version churn breaks the dashboard between releases | Medium | Low | Pin Streamlit in `requirements-operations.txt`; smoke test renders three known panels and grep-asserts the banner string |
| Scope creep pulling v0.4.0 cripto forward | High | Medium | Terminale di Comando gates all PRs; anything touching `santuario/secure_log/` or `core/ratchet*.py` is auto-rejected this sprint |
| Solo-dev fatigue after a heavy v0.2.0 | Medium | Medium | Phase A is shippable as v0.2.1 if the sprint stalls; Phase B alone unlocks 80% of operator value |

## 7. Executive decisions needed before coding starts

Five micro-questions gate Phase A. Decide now, log here, don't re-open.

1. **Admin RPC isolation.** Same gRPC service as `Sign`/`Verify`, or
   a dedicated `Admin` service descriptor on the same UDS?
   *Proposal:* **dedicated `Admin` service.** Keeps the signing surface
   minimal (the Santuario refuses every non-`Signer` method on the
   same descriptor), and lets operations evolve without touching the
   signer's proto file. Cost: a second `tonic::include_proto!` line.

2. **War Room framework.** Streamlit, Gradio, plain Flask+HTMX, or a
   React SPA?
   *Proposal:* **Streamlit, with deployment guard-rails.** Single-file,
   zero JS toolchain, idiomatic Python, and the operator audience
   already runs Python locally for the Sentinel. React would buy
   nothing and double the bundle work. Streamlit's known weak spot is
   hot-reload + reverse-proxy flakiness, so we sidestep it by contract:
   the dashboard runs **loopback only**, the `make war-room` target
   passes `--server.fileWatcherType=none --server.runOnSave=false` to
   kill hot-reload in operator runs, and any reverse-proxy deployment
   is documented as out-of-scope for v0.3.0 (operators who want it
   bring their own nginx config and accept the support burden).

3. **Bot framework.** `python-telegram-bot`, `aiogram`, or hand-rolled
   long-poll?
   *Proposal:* **`python-telegram-bot` v21+.** Mature, async-first,
   well-typed, and the rate-limiter / conversation-handler surface
   maps cleanly onto our authz needs.

4. **Metrics namespace.** `aeterna_*`, `santuario_*`, or split
   (`aeterna_*` for Sentinel, `santuario_*` for signer)?
   *Proposal:* **split.** Mirrors the codebase split. `santuario_*`
   metrics ship with the signer's `GetMetrics`; `aeterna_*` metrics
   ship with the Sentinel's runtime. Operators reading a Grafana panel
   can tell at a glance which subsystem produced a number.

5. **Default bot privacy mode.** Allow group chats, or DMs only?
   *Proposal:* **DMs only.** A group with multiple members is an
   ambient leak of audit-log fragments. Operators who genuinely need
   shared visibility can rotate one chat-id between two phones.

If Christian disagrees with any of these, say so before Phase A
starts. Otherwise they're locked at Phase A kickoff.

## 8. Release checklist

When all phase demos are green:

- [ ] Bump `aeterna.toml → sentinel.sentinel_version` to `0.3.0`.
- [ ] Add `[operations]` section to `aeterna.toml` with War Room bind,
      Telegram allowlist, Prometheus port, all defaulting to safe
      loopback values.
- [ ] Tag `v0.3.0-oculus` on the main branch, signed by the active
      Santuario signer.
- [ ] Publish the operator runbook at `docs/OPERATOR-RUNBOOK.md`.
- [ ] Update the README roadmap table — v0.3.0 row to ✅, add v0.4.0
      "Sigillum" row.
- [ ] Ship the sample Grafana dashboard JSON under
      `operations/grafana/` clearly marked "community asset, no SLA".
- [ ] File a public postmortem on any operator-UX surprises
      encountered during Phase B/C, so downstream deployments can
      tune their bind policy and alert thresholds.

## 9. What comes after

v0.4.0 "Sigillum" — log confidentiality. Now that the operator can
read the trail, the trail itself becomes an attack surface. ChaCha20-
Poly1305 over the audit log on disk, HKDF-derived per-session keys
for gossip, Double-Ratchet rotation between operator endpoints. No
new visibility primitives; only confidentiality on top of the ones
this sprint exposes.

v0.5.0+ — consensus & storage. Cosmos SDK modules, CosmWasm oracle,
IPFS cold storage, the first zk-SNARK circuits.

v1.0.0 "Sovereign" — production. External audit, gVisor/Firecracker,
multi-OS, formal threat model.

---

*See also:*
[`docs/SPRINT-v0.2.0.md`](./SPRINT-v0.2.0.md) — prior sprint, the
Custos kernel this sprint observes,
[`docs/AGP-v1.md`](./AGP-v1.md) — payload format the audit panel
displays,
[`docs/CONSENSUS.md`](./CONSENSUS.md) — pipeline whose health the
War Room dashboards,
[`ETHICS.md`](../ETHICS.md) — the rules the critic enforces and the
operator surveys.
