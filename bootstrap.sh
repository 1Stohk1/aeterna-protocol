#!/usr/bin/env bash
# =============================================================================
#  AETERNA Protocol — Genesis Boot v0.0.1
#  Script: bootstrap.sh
#
#  Starts the three cooperating processes that constitute a v0.1.0 Guardian node:
#    0. Rust Santuario signer     (santuario/signer - gRPC signer)
#
#    1. Julia scientific engine   (scientific/zmq_server.jl — ZMQ REP on :5555)
#    2. Python Sentinel           (core/sentinel.py — ZMQ REQ + UDP gossip :4444)
#
#  Out of scope for v0.0.1 (per roadmap in README.md):
#    - Streamlit "War Room" dashboard    → v0.2.0
#    - Telegram bot + encrypted audit    → v0.1.0 alongside Santuario
#    - Key rotation / Ratchet            → v0.5.0
#
#  v0.1.0 proves the signed Sentinel/Santuario/Julia loop on Missione Alpha.
#  Hardening and operator dashboards remain later releases.
#
#  Usage:
#      ./bootstrap.sh                   start the node
#      ./bootstrap.sh --install-deps    install python + julia deps first
#      ./bootstrap.sh --help            show this help
# =============================================================================

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

LOG_DIR="$HERE/logs"
mkdir -p "$LOG_DIR"
JULIA_LOG="$LOG_DIR/julia.log"
SENTINEL_LOG="$LOG_DIR/sentinel.log"
SANTUARIO_LOG="$LOG_DIR/santuario.log"

# ---- colors (TTY only) ------------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'
  CYN=$'\033[36m'; DIM=$'\033[2m';  RST=$'\033[0m'
else
  RED=; GRN=; YEL=; CYN=; DIM=; RST=
fi

banner() {
  printf '%s' "$CYN"
  cat <<'EOF'
     _     _____ _____ _____ ____  _   _    _
    / \   | ____|_   _| ____|  _ \| \ | |  / \
   / _ \  |  _|   | | |  _| | |_) |  \| | / _ \
  / ___ \ | |___  | | | |___|  _ <| |\  |/ ___ \
 /_/   \_\|_____| |_| |_____|_| \_\_| \_/_/   \_\
EOF
  printf '%s' "$RST"
  printf '  %sv0.0.1 "Genesis" — Prometheus-0%s\n\n' "$DIM" "$RST"
}

info() { printf '%s[bootstrap]%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s[bootstrap]%s %s\n' "$YEL" "$RST" "$1"; }
die()  { printf '%s[bootstrap] %s%s\n'   "$RED" "$1"  "$RST" >&2; exit 1; }

# ---- argument handling ------------------------------------------------------
install_deps=0
for arg in "${@:-}"; do
  case "$arg" in
    --install-deps) install_deps=1 ;;
    --help|-h)
      sed -n '3,20p' "$0"; exit 0 ;;
    "") ;;
    *) die "unknown argument: $arg (use --help)" ;;
  esac
done

# ---- pre-flight -------------------------------------------------------------
check_files() {
  [[ -f aeterna.toml ]]                || die "aeterna.toml missing"
  [[ -f MANIFESTO.md ]]                || die "MANIFESTO.md missing — Axiom I violation: refuse to boot"
  [[ -f core/sentinel.py ]]            || die "core/sentinel.py missing"
  [[ -f scientific/zmq_server.jl ]]    || die "scientific/zmq_server.jl missing"
  [[ -f scientific/Project.toml ]]     || die "scientific/Project.toml missing"
  [[ -d santuario ]]                   || die "santuario workspace missing"
}

check_python() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
  local ver
  ver="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
  info "python $ver detected"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' \
    || warn "python < 3.11 — core/sentinel.py will fall back to the 'tomli' package"
}

check_julia() {
  command -v julia >/dev/null 2>&1 || die "julia not found on PATH (install Julia ≥ 1.10)"
  local ver
  ver="$(julia -e 'print(VERSION)')"
  info "julia $ver detected"
}

# ---- optional: install deps -------------------------------------------------
if [[ $install_deps -eq 1 ]]; then
  info "installing python deps from core/requirements.txt…"
  python3 -m pip install -r core/requirements.txt --break-system-packages
  info "instantiating julia project at scientific/Project.toml…"
  julia --project=scientific -e 'using Pkg; Pkg.instantiate(); Pkg.precompile()'
fi

# Santuario runtime paths. Operators can override both before invoking the
# script; defaults avoid privileged /run writes on regular user sessions.
export SANTUARIO_KEYS_DIR="${SANTUARIO_KEYS_DIR:-$HERE/santuario/keys}"
if [[ -z "${SANTUARIO_SOCKET:-}" ]]; then
  if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
    export SANTUARIO_SOCKET="$XDG_RUNTIME_DIR/aeterna/santuario.sock"
  else
    export SANTUARIO_SOCKET="/tmp/aeterna-${UID:-user}/santuario.sock"
  fi
fi

# ---- child-process management ----------------------------------------------
JULIA_PID=""
SANTUARIO_PID=""
cleanup() {
  local code=$?
  if [[ -n "$JULIA_PID" ]] && kill -0 "$JULIA_PID" 2>/dev/null; then
    info "stopping julia engine (pid $JULIA_PID)"
    kill "$JULIA_PID" 2>/dev/null || true
    wait "$JULIA_PID" 2>/dev/null || true
  fi
  if [[ -n "$SANTUARIO_PID" ]] && kill -0 "$SANTUARIO_PID" 2>/dev/null; then
    info "stopping santuario signer (pid $SANTUARIO_PID)"
    kill "$SANTUARIO_PID" 2>/dev/null || true
    wait "$SANTUARIO_PID" 2>/dev/null || true
  fi
  info "shutdown complete (exit $code)"
  exit "$code"
}
trap cleanup EXIT INT TERM

# ---- wait-for-port helper ---------------------------------------------------
wait_for_port() {
  local port="$1" timeout="$2"
  local child_pid="${3:-$JULIA_PID}"
  local deadline=$(( SECONDS + timeout ))
  while (( SECONDS < deadline )); do
    if command -v ss >/dev/null 2>&1; then
      ss -ltn 2>/dev/null | grep -q ":${port}[[:space:]]" && return 0
    elif command -v lsof >/dev/null 2>&1; then
      lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    elif command -v netstat >/dev/null 2>&1; then
      netstat -ltn 2>/dev/null | grep -q ":${port}[[:space:]]" && return 0
    else
      # No introspection tool available — best effort, assume ready after 3 s.
      sleep 3; return 0
    fi
    # Bail out if the child exited early.
    [[ -z "$child_pid" ]] || kill -0 "$child_pid" 2>/dev/null || return 1
    sleep 0.5
  done
  return 1
}

wait_for_socket() {
  local path="$1" timeout="$2" child_pid="$3"
  local deadline=$(( SECONDS + timeout ))
  while (( SECONDS < deadline )); do
    [[ -S "$path" ]] && return 0
    kill -0 "$child_pid" 2>/dev/null || return 1
    sleep 0.5
  done
  return 1
}

# ---- boot -------------------------------------------------------------------
banner
info "working directory: $HERE"
check_files
check_python
check_julia

info "launching julia scientific engine → $JULIA_LOG"
julia --project=scientific scientific/zmq_server.jl >"$JULIA_LOG" 2>&1 &
JULIA_PID=$!
info "  julia pid=$JULIA_PID"

# Force WSL to use TCP because of tonic/grpcio HTTP/2 UDS bugs
if [[ "$(uname -s)" =~ ^(MINGW|MSYS|CYGWIN) ]] || [[ "$(uname -r)" =~ WSL ]]; then
  export SANTUARIO_PORT="50051"
fi

info "launching santuario signer (Dilithium-5) → $SANTUARIO_LOG"
# Attempt to run it via cargo. In a production environment without cargo, this would just be `./santuario-signer`.
if command -v cargo >/dev/null 2>&1; then
  (cd santuario/signer && cargo run --bin santuario-signer > "$SANTUARIO_LOG" 2>&1) &
  SANTUARIO_PID=$!
  info "  santuario pid=$SANTUARIO_PID"
else
  warn "cargo not found, skipping Santuario signer startup (Python sentinel may fail if it cannot connect to gRPC)"
fi

if [[ -n "$SANTUARIO_PID" ]]; then
  if [[ -n "${SANTUARIO_PORT:-}" ]]; then
    info "waiting for Santuario TCP :$SANTUARIO_PORT (timeout 60s)..."
    if ! wait_for_port "$SANTUARIO_PORT" 60 "$SANTUARIO_PID"; then
      warn "santuario did not bind within 60s - last 40 lines of its log:"
      tail -n 40 "$SANTUARIO_LOG" || true
      die "aborting"
    fi
  else
    info "waiting for Santuario UDS $SANTUARIO_SOCKET (timeout 60s)..."
    if ! wait_for_socket "$SANTUARIO_SOCKET" 60 "$SANTUARIO_PID"; then
      warn "santuario did not bind within 60s - last 40 lines of its log:"
      tail -n 40 "$SANTUARIO_LOG" || true
      die "aborting"
    fi
  fi
  info "santuario signer ready"
fi

info "waiting for ZMQ REP to bind on :5555 (timeout 60s)…"
if ! wait_for_port 5555 60; then
  warn "julia did not bind within 60s — last 40 lines of its log:"
  tail -n 40 "$JULIA_LOG" || true
  die "aborting"
fi
info "julia engine ready"

info "launching python sentinel — Ctrl-C stops the whole node"
info "  sentinel log → $SENTINEL_LOG"
# Sentinel runs in the foreground so Ctrl-C flows through to cleanup().
python3 -m core.sentinel --config aeterna.toml 2>&1 | tee "$SENTINEL_LOG"
