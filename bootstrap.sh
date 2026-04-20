#!/usr/bin/env bash
# =============================================================================
#  AETERNA Protocol — Genesis Boot v0.0.1
#  Script: bootstrap.sh
#
#  Starts the two cooperating processes that constitute a v0.0.1 Guardian node:
#
#    1. Julia scientific engine   (scientific/zmq_server.jl — ZMQ REP on :5555)
#    2. Python Sentinel           (core/sentinel.py — ZMQ REQ + UDP gossip :4444)
#
#  Out of scope for v0.0.1 (per roadmap in README.md):
#    - Rust Santuario gRPC server        → v0.1.0
#    - Streamlit "War Room" dashboard    → v0.2.0
#    - Telegram bot + encrypted audit    → v0.1.0 alongside Santuario
#    - Key rotation / Ratchet            → v0.5.0
#
#  This script intentionally does NOT start any of the above. v0.0.1 proves the
#  Sentinel↔Julia loop on Missione Alpha. Everything else is a later release.
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

# ---- child-process management ----------------------------------------------
JULIA_PID=""
cleanup() {
  local code=$?
  if [[ -n "$JULIA_PID" ]] && kill -0 "$JULIA_PID" 2>/dev/null; then
    info "stopping julia engine (pid $JULIA_PID)"
    kill "$JULIA_PID" 2>/dev/null || true
    wait "$JULIA_PID" 2>/dev/null || true
  fi
  info "shutdown complete (exit $code)"
  exit "$code"
}
trap cleanup EXIT INT TERM

# ---- wait-for-port helper ---------------------------------------------------
wait_for_port() {
  local port="$1" timeout="$2"
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
    kill -0 "$JULIA_PID" 2>/dev/null || return 1
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
