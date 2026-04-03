#!/usr/bin/env bash
# Start OpenBao in non-dev (production-like) mode with file storage.
# This tests the plugin under real init/unseal/auth conditions.
# Usage: ./start-prod.sh [--no-build] [--fresh]
set -euo pipefail

source "$(dirname "$0")/common.env"

# Parse args
SKIP_BUILD=false
FRESH=false
for arg in "$@"; do
    case "$arg" in
        --no-build) SKIP_BUILD=true ;;
        --fresh)    FRESH=true ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

# Stop any existing instance
stop_server

# Optionally wipe all state for a clean start
if [ "$FRESH" = true ]; then
    echo "Wiping data and init state..."
    rm -rf "$DATA_DIR"/*
    rm -f "$INIT_FILE"
fi

# Build plugin
if [ "$SKIP_BUILD" = false ]; then
    build_plugin
fi

# Start server with file storage config
echo "Starting OpenBao server (non-dev mode)..."
cd "$INSTANCE_DIR"
"$BAO" server -config=config.hcl \
    > "$LOG_DIR/server.log" 2>&1 &
echo $! > "$PIDFILE"
echo "  PID: $(cat "$PIDFILE")"
echo "  Log: $LOG_DIR/server.log"
cd - > /dev/null

# Wait for listener (server starts sealed, so `bao status` returns exit 2)
echo -n "Waiting for listener"
for i in $(seq 1 15); do
    if "$BAO" status >/dev/null 2>&1 || [ $? -eq 2 ]; then
        echo " up."
        break
    fi
    echo -n "."
    sleep 1
done

# Init if needed
if [ ! -f "$INIT_FILE" ]; then
    echo "Initializing vault (1 key, threshold 1)..."
    "$BAO" operator init \
        -key-shares=1 \
        -key-threshold=1 \
        -format=json > "$INIT_FILE"
    echo "  Init data saved to: $INIT_FILE"
fi

# Extract unseal key and root token
UNSEAL_KEY=$(jq -r '.unseal_keys_b64[0]' "$INIT_FILE")
ROOT_TOKEN=$(jq -r '.root_token' "$INIT_FILE")

# Unseal
echo "Unsealing..."
"$BAO" operator unseal "$UNSEAL_KEY" > /dev/null

# Authenticate
export BAO_TOKEN="$ROOT_TOKEN"

wait_for_server

# Register and mount plugin (idempotent — skip if already mounted)
if "$BAO" secrets list 2>/dev/null | grep -q "^gpg/"; then
    echo "Plugin already mounted at gpg/."
else
    register_and_mount_plugin
fi

echo ""
echo "=== Non-dev instance ready ==="
echo "  BAO_ADDR=$BAO_ADDR"
echo "  BAO_TOKEN=$ROOT_TOKEN"
echo "  Unseal key: $UNSEAL_KEY"
echo "  Mode: non-dev (file storage at $DATA_DIR)"
echo ""
echo "Run tests:  BAO_TOKEN=$ROOT_TOKEN bash $(dirname "$0")/run-cross-checks.sh"
echo "Stop:       bash $(dirname "$0")/stop.sh"
