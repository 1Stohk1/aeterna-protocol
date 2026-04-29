#!/usr/bin/env bash
# AETERNA v0.3.0 "Oculus" — War Room launcher (Linux/macOS).
#
# See launch.ps1 for the full guard-rail rationale. This is the POSIX
# equivalent — same flags, same defaults.
#
# Usage:
#   bash operations/war_room/launch.sh
#   PORT=8502 bash operations/war_room/launch.sh
#   PUBLIC_BIND=1 bash operations/war_room/launch.sh      # ⚠️ LAN-visible
#
# On first run, install deps with:
#   pip install -r operations/war_room/requirements.txt

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

PORT="${PORT:-8501}"
BIND="127.0.0.1"

if [[ "${PUBLIC_BIND:-0}" == "1" ]]; then
    cat <<'EOF' >&2
╔════════════════════════════════════════════════════════════╗
║  WARNING — BINDING WAR ROOM ON 0.0.0.0                     ║
║  The dashboard will be visible to every host on this LAN.  ║
║  The Admin surface is READ-ONLY, but the operator view is  ║
║  sensitive. Put a reverse proxy with auth in front of it,  ║
║  OR abort now (Ctrl+C) within 3 seconds.                   ║
╚════════════════════════════════════════════════════════════╝
EOF
    sleep 3
    BIND="0.0.0.0"
fi

if [[ -n "${ADMIN_TARGET:-}" ]]; then
    export SANTUARIO_ADMIN_TARGET="${ADMIN_TARGET}"
fi

echo "AETERNA War Room — starting on http://${BIND}:${PORT}" >&2

# Run from the war_room dir so the sibling `client.py` / `admin_pb2*.py`
# modules resolve without a PYTHONPATH dance.
cd "${SCRIPT_DIR}"

# Prefer the local venv if it exists. PEP 668 ("externally managed"
# environments, default on Debian/Ubuntu 23.04+) forbids system pip,
# so the install instructions in README.md bootstrap the dashboard
# inside `.venv`. Auto-activate it here so `bash launch.sh` works with
# no extra ceremony.
if [[ -x "${SCRIPT_DIR}/.venv/bin/python" ]]; then
    PYTHON="${SCRIPT_DIR}/.venv/bin/python"
elif [[ -x "${SCRIPT_DIR}/.venv/Scripts/python.exe" ]]; then
    # Windows-style venv layout, in case someone created it from PowerShell.
    PYTHON="${SCRIPT_DIR}/.venv/Scripts/python.exe"
else
    PYTHON="python3"
fi

exec "${PYTHON}" -m streamlit run app.py \
    --server.address="${BIND}" \
    --server.port="${PORT}" \
    --server.fileWatcherType=none \
    --server.runOnSave=false \
    --server.headless=true \
    --browser.gatherUsageStats=false
