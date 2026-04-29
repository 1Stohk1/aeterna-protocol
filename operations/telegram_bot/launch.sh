#!/usr/bin/env bash
# AETERNA v0.3.0 "Oculus" — Telegram operator bot launcher (Linux/macOS).
#
# Usage:
#   bash operations/telegram_bot/launch.sh
#   AETERNA_TELEGRAM_TOKEN=XXX bash operations/telegram_bot/launch.sh
#   AETERNA_LOG_LEVEL=DEBUG bash operations/telegram_bot/launch.sh
#
# Provisioning (one-time): see operations/telegram_bot/README.md.
#
# On first run, install deps with:
#   python3 -m venv operations/telegram_bot/.venv
#   operations/telegram_bot/.venv/bin/pip install -r \
#       operations/telegram_bot/requirements.txt

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd)"

# Prefer the local venv. PEP 668 ("externally managed" environments,
# default on Debian/Ubuntu 23.04+) forbids system pip; the README
# bootstraps deps inside .venv.
if [[ -x "${SCRIPT_DIR}/.venv/bin/python" ]]; then
    PYTHON="${SCRIPT_DIR}/.venv/bin/python"
elif [[ -x "${SCRIPT_DIR}/.venv/Scripts/python.exe" ]]; then
    PYTHON="${SCRIPT_DIR}/.venv/Scripts/python.exe"
else
    PYTHON="python3"
fi

# Run from the repo root so aeterna.toml is auto-discovered by config.py.
cd "${REPO_ROOT}"

echo "AETERNA Telegram bot -- launching from ${REPO_ROOT}" >&2
exec "${PYTHON}" -m operations.telegram_bot.bot "$@"
