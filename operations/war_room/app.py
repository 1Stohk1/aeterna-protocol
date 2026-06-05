"""AETERNA v0.3.0 "Oculus" — Streamlit War Room.

Single-file operator dashboard. Reads the signer's Admin gRPC surface
(admin.proto v1) and renders four panels: Status, Metrics, Peers, Audit.

Contract:
    * Read-only. No RPC in this process can mutate the signer's state.
    * Loopback-only by default. The ``launch.ps1`` / ``launch.sh``
      wrappers pin ``--server.address=127.0.0.1``; a sleepy operator
      exposing this to the LAN would violate SPRINT-v0.3.0 §6 Risk #1.
    * Hot-reload disabled. The wrappers pin
      ``--server.fileWatcherType=none --server.runOnSave=false`` to
      avoid restarts in the middle of a shift.
    * Signer state is inferred from the ``santuario_signer_ready`` and
      ``santuario_vault_sealed`` gauges + the audit log tail. There is
      no ``GetStatus`` equivalent on the Admin surface by design
      (admin.proto §header — "strictly an observer").

Run via::

    pwsh operations/war_room/launch.ps1        # Windows
    bash operations/war_room/launch.sh         # Linux/macOS
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
import time
from typing import Optional

import streamlit as st
from streamlit_autorefresh import st_autorefresh

# Ensure root directory is in path for core imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from core.llm_client import OllamaClient

from client import (  # type: ignore[import-not-found]
    AdminObserver,
    AuditTail,
    Metrics,
    PeerList,
    Unreachable,
)

# --- constants -------------------------------------------------------------

POLL_MS_DEFAULT = 2_000
POLL_MS_MIN = 500
POLL_MS_MAX = 15_000
AUDIT_TAIL_DEFAULT = 20
AUDIT_TAIL_MAX = 200

# Gauges whose presence in `GetMetrics.gauges` tells us whether the
# signer is ready / whether the vault is sealed. Keys pinned by the
# admin.proto "namespace" rule — santuario_* from Rust-side registry.
GAUGE_SIGNER_READY = "santuario_signer_ready"
GAUGE_VAULT_SEALED = "santuario_vault_sealed"


# --- streamlit page setup --------------------------------------------------

st.set_page_config(
    page_title="AETERNA War Room",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get help": "https://github.com/ChristianPeluso/AETERNA",
        "About": (
            "AETERNA v0.3.0 'Oculus' — War Room.\n\n"
            "Read-only operator dashboard over the Admin gRPC surface.\n"
            "Binds loopback-only by contract."
        ),
    },
)


# --- session-wide observer (one gRPC channel per browser session) ---------


@st.cache_resource(show_spinner=False)
def _observer(target: Optional[str]) -> AdminObserver:
    """Cache one ``AdminObserver`` per (session, target) tuple."""
    return AdminObserver(target=target or None)


def _fmt_duration_s(seconds: int) -> str:
    if seconds <= 0:
        return "—"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3_600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    if seconds < 86_400:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86_400}d"


def _fmt_utc(ts_utc: int) -> str:
    if ts_utc <= 0:
        return "—"
    try:
        return (
            _dt.datetime.fromtimestamp(ts_utc, tz=_dt.timezone.utc)
            .strftime("%Y-%m-%d %H:%M:%S")
            + " UTC"
        )
    except (OverflowError, OSError, ValueError):
        return str(ts_utc)


# --- sidebar ---------------------------------------------------------------

with st.sidebar:
    st.title("War Room")
    st.caption("v0.3.0 Oculus — read-only")

    default_target = os.environ.get("SANTUARIO_ADMIN_TARGET", "")
    target = st.text_input(
        "Admin gRPC target",
        value=default_target,
        placeholder="leave empty for auto",
        help=(
            "Override the default target. Auto-discovery falls back to "
            "`$SANTUARIO_PORT` → `127.0.0.1:50051` (Windows) → "
            "`unix:///run/aeterna/santuario.sock` (Unix)."
        ),
    ).strip()

    poll_ms = st.slider(
        "Refresh (ms)",
        min_value=POLL_MS_MIN,
        max_value=POLL_MS_MAX,
        value=POLL_MS_DEFAULT,
        step=500,
        help="How often to re-poll GetMetrics/ListPeers/TailAuditLog.",
    )

    tail_limit = st.slider(
        "Audit lines",
        min_value=5,
        max_value=AUDIT_TAIL_MAX,
        value=AUDIT_TAIL_DEFAULT,
        step=5,
    )

    paused = st.toggle("Pause polling", value=False)

    st.divider()
    st.caption(
        "Bind: loopback (127.0.0.1) — exposing to a LAN requires "
        "`--public-bind` on the launch script (see README)."
    )


# --- poll loop -------------------------------------------------------------

obs = _observer(target)

if not paused:
    # Redraws the whole page on a timer. No websockets, no custom JS.
    st_autorefresh(interval=poll_ms, key="war_room_poll")


# Fetch all three endpoints. Each one degrades independently — if the
# signer is suspended the Admin surface still returns, by contract
# (admin.proto §header).
metrics_r = obs.get_metrics()
peers_r = obs.list_peers()
audit_r = obs.tail_audit_log(limit=tail_limit)


# --- banner ----------------------------------------------------------------

def _render_banner() -> None:
    if isinstance(metrics_r, Unreachable):
        st.error(
            f"Signer unreachable at `{obs.target}` — {metrics_r.reason}. "
            "Admin service may be down or the bind address is wrong.",
            icon="⛔",
        )
        return

    m: Metrics = metrics_r
    ready = m.gauges.get(GAUGE_SIGNER_READY, 0.0) > 0.5
    sealed = m.gauges.get(GAUGE_VAULT_SEALED, 0.0) > 0.5

    left, mid, right = st.columns([2, 1, 1])
    with left:
        if ready and not sealed:
            st.success(
                f"**{m.node_id}** — Ready. Vault unsealed. Snapshot "
                f"{_fmt_utc(m.ts_utc)}.",
                icon="✅",
            )
        elif sealed:
            st.warning(
                f"**{m.node_id}** — Vault SEALED. Signer refuses new work "
                "until `vaultctl unseal`.",
                icon="🔒",
            )
        else:
            st.error(
                f"**{m.node_id}** — Signer NOT ready. Check the audit tail "
                "below for the suspend reason.",
                icon="🚨",
            )
    with mid:
        st.metric("Signer ready", "yes" if ready else "no")
    with right:
        st.metric("Vault sealed", "yes" if sealed else "no")


_render_banner()


# --- tabs ------------------------------------------------------------------

tab_metrics, tab_peers, tab_audit, tab_chat = st.tabs(["Metrics", "Peers", "Audit", "Model Chat"])


# --- Metrics tab -----------------------------------------------------------

with tab_metrics:
    if isinstance(metrics_r, Unreachable):
        st.warning(
            f"GetMetrics degraded — {metrics_r.reason} "
            f"(after {metrics_r.elapsed_s:.2f}s)"
        )
    else:
        m = metrics_r
        st.caption(
            f"schema_version={m.schema_version} · "
            f"window={m.metric_window_seconds}s · "
            f"snapshot={_fmt_utc(m.ts_utc)}"
        )

        # Split by namespace so the Rust-side and Sentinel-side signals
        # are visually distinct. Disjoint-by-contract (admin.proto §7.2).
        col_a, col_b = st.columns(2)

        def _render_kv(title: str, items: dict, caption: str) -> None:
            st.subheader(title)
            st.caption(caption)
            if not items:
                st.info("No entries yet.")
                return
            rows = [{"key": k, "value": v} for k, v in sorted(items.items())]
            st.dataframe(rows, use_container_width=True, hide_index=True)

        with col_a:
            rust_counters = {
                k: v for k, v in m.counters.items() if k.startswith("santuario_")
            }
            rust_gauges = {
                k: v for k, v in m.gauges.items() if k.startswith("santuario_")
            }
            _render_kv(
                "santuario_* counters",
                rust_counters,
                "Rust-side signer signals (sign path, reject buckets).",
            )
            _render_kv(
                "santuario_* gauges",
                rust_gauges,
                "Instantaneous Rust-side state gauges.",
            )

        with col_b:
            sentinel_counters = {
                k: v for k, v in m.counters.items() if k.startswith("aeterna_")
            }
            sentinel_gauges = {
                k: v for k, v in m.gauges.items() if k.startswith("aeterna_")
            }
            _render_kv(
                "aeterna_* counters",
                sentinel_counters,
                "Python Sentinel signals (gossip, block tx, task queue).",
            )
            _render_kv(
                "aeterna_* gauges",
                sentinel_gauges,
                "Instantaneous Sentinel-side gauges.",
            )

        if m.quantiles:
            st.subheader("Latency quantiles (seconds)")
            st.dataframe(
                [
                    {
                        "metric": k,
                        "p50": q.p50,
                        "p90": q.p90,
                        "p99": q.p99,
                    }
                    for k, q in sorted(m.quantiles.items())
                ],
                use_container_width=True,
                hide_index=True,
            )


# --- Peers tab -------------------------------------------------------------

with tab_peers:
    if isinstance(peers_r, Unreachable):
        st.warning(
            f"ListPeers degraded — {peers_r.reason} "
            f"(after {peers_r.elapsed_s:.2f}s)"
        )
    else:
        p: PeerList = peers_r
        now = int(time.time())
        st.caption(
            f"Snapshot {_fmt_utc(p.snapshot_utc)} · "
            f"{len(p.peers)} peer{'s' if len(p.peers) != 1 else ''}"
        )
        if not p.peers:
            st.info(
                "No peers seen yet. Bootstrap list is loaded from "
                "`aeterna.toml [gossip].bootstrap_peers` — if it's empty "
                "the Sentinel has nowhere to gossip to."
            )
        else:
            rows = []
            for peer in p.peers:
                age = (now - peer.last_seen_utc) if peer.last_seen_utc > 0 else -1
                rows.append(
                    {
                        "address": peer.address,
                        "node_id": peer.node_id or "—",
                        "bootstrap": "✓" if peer.is_bootstrap else "",
                        "last_seen": _fmt_duration_s(age) if age >= 0 else "never",
                        "rx": peer.rx_count,
                        "tx": peer.tx_count,
                    }
                )
            st.dataframe(rows, use_container_width=True, hide_index=True)


# --- Audit tab -------------------------------------------------------------

with tab_audit:
    if isinstance(audit_r, Unreachable):
        st.warning(
            f"TailAuditLog degraded — {audit_r.reason} "
            f"(after {audit_r.elapsed_s:.2f}s)"
        )
    else:
        a: AuditTail = audit_r
        st.caption(
            f"{len(a.lines)} record{'s' if len(a.lines) != 1 else ''} — "
            "oldest first, raw JSON preserved byte-for-byte from disk."
        )
        if not a.lines:
            st.info(
                "No audit records yet. Every α/β/γ alert, signer "
                "self-suspend, operator resume, and baseline seal lands "
                "here."
            )
        else:
            # Show newest-at-top for scanning; the wire order is
            # oldest-first per admin.proto §TailAuditLog.
            for line in reversed(a.lines):
                ts = _fmt_utc(line.ts_utc)
                kind = line.record or "unknown"
                icon = {
                    "alert": "🚨",
                    "signer_suspend": "⏸️",
                    "signer_resume": "▶️",
                    "baseline_sealed": "📦",
                }.get(kind, "·")
                with st.expander(f"{icon} [{ts}] {kind}", expanded=False):
                    # Pretty-print for readability; the underlying
                    # `.json` field is the on-disk bytes.
                    try:
                        pretty = json.dumps(
                            json.loads(line.json), indent=2, ensure_ascii=False
                        )
                    except (ValueError, TypeError):
                        pretty = line.json
                    st.code(pretty, language="json")


# --- Model Chat tab --------------------------------------------------------

with tab_chat:
    st.subheader("💬 AETERNA Local Model Chat")
    st.caption(
        "Interazione diretta con il modello LLM locale di AETERNA (llama3.2). "
        "Consigliato: attiva il toggle 'Pause polling' nella barra laterale per evitare interruzioni."
    )

    client = OllamaClient(base_url="http://localhost:11434", model="llama3.2")

    if not client.is_healthy():
        st.error(
            "Il demone Ollama non risponde all'indirizzo http://localhost:11434.",
            icon="🔌"
        )
        st.markdown(
            "### Come avviare Ollama:\n"
            "1. Assicurati che Ollama sia installato sul tuo sistema.\n"
            "2. Apri un terminale ed esegui:\n"
            "   ```powershell\n"
            "   ollama serve\n"
            "   ```\n"
            "3. Ricarica questa pagina."
        )
    elif not client.is_model_available():
        st.warning(
            f"Il modello '{client.model}' non è caricato/scaricato in Ollama.",
            icon="⚠️"
        )
        st.markdown(
            f"### Come scaricare il modello:\n"
            f"1. Apri un terminale ed esegui:\n"
            f"   ```powershell\n"
            f"   ollama pull {client.model}\n"
            f"   ```\n"
            f"2. Attendi il completamento del download e ricarica questa pagina."
        )
    else:
        col_system, col_clear = st.columns([4, 1])
        with col_system:
            system_prompt = st.text_input(
                "System Prompt di AETERNA",
                value="Sei AETERNA, un'intelligenza artificiale cooperativa per l'analisi dei dati scientifici e crittografici.",
                help="Configura il comportamento e le istruzioni di sistema per il modello."
            )
        with col_clear:
            st.write("") # Spacer to align button
            st.write("") # Spacer to align button
            if st.button("Clear History", use_container_width=True):
                st.session_state.chat_messages = []
                st.rerun()

        # Initialize chat history
        if "chat_messages" not in st.session_state:
            st.session_state.chat_messages = []

        # Display chat messages from history on app rerun
        for msg in st.session_state.chat_messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        # React to user input
        if user_prompt := st.chat_input("Scrivi un messaggio per AETERNA..."):
            # Display user message in chat message container
            st.chat_message("user").markdown(user_prompt)
            # Add user message to chat history
            st.session_state.chat_messages.append({"role": "user", "content": user_prompt})

            # Display assistant response in chat message container
            with st.chat_message("assistant"):
                with st.spinner("Generazione risposta in corso..."):
                    try:
                        response = client.generate(prompt=user_prompt, system=system_prompt)
                        st.markdown(response)
                        # Add assistant response to chat history
                        st.session_state.chat_messages.append({"role": "assistant", "content": response})
                    except Exception as e:
                        st.error(f"Errore durante la generazione della risposta: {e}")
            st.rerun()
