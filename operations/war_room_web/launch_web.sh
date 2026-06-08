#!/usr/bin/env bash
# AETERNA v0.3.0 "Oculus" — Web HUD Dashboard Launcher (Linux/macOS).
#
# Usage:
#   bash operations/war_room_web/launch_web.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

# Resolve Python from the existing war_room virtual environment
if [[ -x "${SCRIPT_DIR}/../war_room/.venv/bin/python" ]]; then
    PYTHON="${SCRIPT_DIR}/../war_room/.venv/bin/python"
elif [[ -x "${SCRIPT_DIR}/../war_room/.venv/Scripts/python.exe" ]]; then
    PYTHON="${SCRIPT_DIR}/../war_room/.venv/Scripts/python.exe"
else
    PYTHON="python3"
fi

# Trap exits to kill background processes cleanly
cleanup() {
    echo ""
    echo ">>> Stopping API Backend (PID ${BACKEND_PID})..."
    kill "${BACKEND_PID}" 2>/dev/null || true
    echo ">>> AETERNA Web Dashboard stopped."
}
trap cleanup EXIT

# Start backend Python API server on port 8000
echo ""
echo ">>> Starting AETERNA Backend API Server on http://127.0.0.1:8000..."
cd "${SCRIPT_DIR}"
"${PYTHON}" server.py &
BACKEND_PID=$!

# Give the backend server a second to start
sleep 1

# Start frontend dev server
echo ">>> Starting Vite/React Frontend Server..."
cd "${SCRIPT_DIR}/frontend"
npm run dev
