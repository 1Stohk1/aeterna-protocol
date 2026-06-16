#!/bin/bash
# Stop any running aeternad instances
pkill aeternad || true

# Setup home folders
HOME1="$HOME/.aeternad_prometheus-1"
HOME2="$HOME/.aeternad_prometheus-2"

# Clean old state
rm -rf "$HOME1" "$HOME2"

# Check binary
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BINARY_PATH="$SCRIPT_DIR/../aeternad"

if [ ! -f "$BINARY_PATH" ]; then
    echo "aeternad binary not found. Building..."
    (cd "$SCRIPT_DIR/.." && go build -o aeternad ./cmd/aeternad/)
fi

# Initialize nodes
echo "Initializing Node 1 (prometheus-1)..."
"$BINARY_PATH" init --moniker prometheus-1 --home "$HOME1"

echo "Initializing Node 2 (prometheus-2)..."
"$BINARY_PATH" init --moniker prometheus-2 --home "$HOME2"

# Inject custom genesis containing pre-minted SBTs
echo "Injecting pre-minted SBT genesis configuration..."
cp "$SCRIPT_DIR/genesis.json" "$HOME1/config/genesis.json"
cp "$SCRIPT_DIR/genesis.json" "$HOME2/config/genesis.json"

# Start nodes in background with redirected output logs and --home flag
echo "Starting Node 1 on RPC :26657, REST :1317..."
nohup "$BINARY_PATH" start --rpc-addr 127.0.0.1:26657 --rest-addr 127.0.0.1:1317 --moniker prometheus-1 --home "$HOME1" > "$HOME1/aeternad.log" 2>&1 &

echo "Starting Node 2 on RPC :26658, REST :1318..."
nohup "$BINARY_PATH" start --rpc-addr 127.0.0.1:26658 --rest-addr 127.0.0.1:1318 --moniker prometheus-2 --home "$HOME2" > "$HOME2/aeternad.log" 2>&1 &

echo "Local 2-node devnet launched successfully:"
echo "  - Node 1 (prometheus-1): http://127.0.0.1:1317 (REST) / http://127.0.0.1:26657 (RPC) with home $HOME1"
echo "  - Node 2 (prometheus-2): http://127.0.0.1:1318 (REST) / http://127.0.0.1:26658 (RPC) with home $HOME2"
