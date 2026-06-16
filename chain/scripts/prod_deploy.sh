#!/bin/bash
# Production Deployment Script for AETERNA AppChain (CometBFT & Cosmovisor)
# Unix/WSL/macOS version.

set -e

# Stop any running aeternad or cosmovisor instances
echo "Stopping any running aeternad and cosmovisor instances..."
pkill aeternad || true
pkill cosmovisor || true

# Setup home folders
HOME1="$HOME/.aeternad_prometheus-1"
HOME2="$HOME/.aeternad_prometheus-2"

# Clean old state
echo "Cleaning up old state in home directories..."
rm -rf "$HOME1" "$HOME2"

# Check directories
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CHAIN_DIR="$SCRIPT_DIR/.."

# 1. Compile aeternad
echo "Compiling aeternad..."
(cd "$CHAIN_DIR" && go build -o aeternad ./cmd/aeternad/)

# 2. Check and locate cosmovisor
COSMOVISOR_PATH="$CHAIN_DIR/cosmovisor"
if [ ! -f "$COSMOVISOR_PATH" ]; then
    GO_BIN_COSMOVISOR="$HOME/go/bin/cosmovisor"
    if [ -f "$GO_BIN_COSMOVISOR" ]; then
        echo "Found cosmovisor in $GO_BIN_COSMOVISOR. Copying..."
        cp "$GO_BIN_COSMOVISOR" "$COSMOVISOR_PATH"
    else
        echo "cosmovisor not found. Installing..."
        (cd "$CHAIN_DIR" && go install cosmossdk.io/tools/cosmovisor/cmd/cosmovisor@v1.5.0)
        if [ -f "$GO_BIN_COSMOVISOR" ]; then
            cp "$GO_BIN_COSMOVISOR" "$COSMOVISOR_PATH"
        else
            echo "Failed to install cosmovisor"
            exit 1
        fi
    fi
fi

# 3. Setup Cosmovisor directories for Node 1 and Node 2
echo "Setting up Cosmovisor directories..."
DAEMON_BIN1="$HOME1/cosmovisor/genesis/bin"
DAEMON_BIN2="$HOME2/cosmovisor/genesis/bin"

mkdir -p "$DAEMON_BIN1" "$HOME1/cosmovisor/upgrades" "$HOME1/backup"
mkdir -p "$DAEMON_BIN2" "$HOME2/cosmovisor/upgrades" "$HOME2/backup"

# Copy binary to Cosmovisor folders
cp "$CHAIN_DIR/aeternad" "$DAEMON_BIN1/aeternad"
cp "$CHAIN_DIR/aeternad" "$DAEMON_BIN2/aeternad"

# Create symlinks for cosmovisor/current pointing to cosmovisor/genesis
echo "Creating symlinks for current..."
ln -sf genesis "$HOME1/cosmovisor/current"
ln -sf genesis "$HOME2/cosmovisor/current"

# 4. Initialize nodes to generate config and validator keys
echo "Initializing Node 1 (prometheus-1)..."
"$DAEMON_BIN1/aeternad" init --moniker prometheus-1 --home "$HOME1"

echo "Initializing Node 2 (prometheus-2)..."
"$DAEMON_BIN2/aeternad" init --moniker prometheus-2 --home "$HOME2"

# 5. Generate unified genesis.json
echo "Merging validator keys and generating unified genesis.json..."
GENESIS_TEMPLATE="$SCRIPT_DIR/genesis.json"
python3 "$SCRIPT_DIR/generate_genesis.py" "$HOME1" "$HOME2" "$GENESIS_TEMPLATE"

# 6. Read Node IDs using show-node-id command
echo "Reading Node IDs..."
NODE_ID1=$("$DAEMON_BIN1/aeternad" show-node-id --home "$HOME1")
NODE_ID2=$("$DAEMON_BIN2/aeternad" show-node-id --home "$HOME2")

echo "  - Node 1 ID: $NODE_ID1"
echo "  - Node 2 ID: $NODE_ID2"

# 7. Start both nodes under Cosmovisor in the background
echo "Starting Node 1 under Cosmovisor in background..."
export DAEMON_NAME=aeternad
export DAEMON_HOME="$HOME1"
export DAEMON_ALLOW_START_KEY_MIGRATION=true
export DAEMON_DATA_BACKUP_DIR="$HOME1/backup"

nohup "$COSMOVISOR_PATH" run start \
    --rpc-addr 127.0.0.1:26657 \
    --rest-addr 127.0.0.1:1317 \
    --p2p-addr tcp://0.0.0.0:26656 \
    --peers "$NODE_ID2@127.0.0.1:26659" \
    --moniker prometheus-1 \
    --home "$HOME1" > "$HOME1/cosmovisor.log" 2>&1 &

echo "Starting Node 2 under Cosmovisor in background..."
export DAEMON_NAME=aeternad
export DAEMON_HOME="$HOME2"
export DAEMON_ALLOW_START_KEY_MIGRATION=true
export DAEMON_DATA_BACKUP_DIR="$HOME2/backup"

nohup "$COSMOVISOR_PATH" run start \
    --rpc-addr 127.0.0.1:26658 \
    --rest-addr 127.0.0.1:1318 \
    --p2p-addr tcp://0.0.0.0:26659 \
    --peers "$NODE_ID1@127.0.0.1:26656" \
    --moniker prometheus-2 \
    --home "$HOME2" > "$HOME2/cosmovisor.log" 2>&1 &

echo ""
echo "AETERNA production nodes successfully launched under Cosmovisor!"
echo "  - Node 1: REST http://127.0.0.1:1317 | RPC http://127.0.0.1:26657 | Logs: $HOME1/cosmovisor.log"
echo "  - Node 2: REST http://127.0.0.1:1318 | RPC http://127.0.0.1:26658 | Logs: $HOME2/cosmovisor.log"
echo ""
