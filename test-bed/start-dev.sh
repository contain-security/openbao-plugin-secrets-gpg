#!/usr/bin/env bash
# Start OpenBao in dev mode with the GPG plugin built, registered, and mounted.
# Usage: ./start-dev.sh [--no-build]
set -euo pipefail

source "$(dirname "$0")/common.env"

# Parse args
SKIP_BUILD=false
for arg in "$@"; do
    case "$arg" in
        --no-build) SKIP_BUILD=true ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

# Stop any existing instance
stop_server

# Build plugin
if [ "$SKIP_BUILD" = false ]; then
    build_plugin
fi

# Start dev server
echo "Starting OpenBao dev server..."
"$BAO" server -dev \
    -dev-root-token-id=root \
    -dev-plugin-dir="$PLUGIN_DIR" \
    -dev-listen-address="127.0.0.1:8200" \
    > "$LOG_DIR/server.log" 2>&1 &
echo $! > "$PIDFILE"
echo "  PID: $(cat "$PIDFILE")"
echo "  Log: $LOG_DIR/server.log"

export BAO_TOKEN=root
wait_for_server

# Register and mount
register_and_mount_plugin

echo ""
echo "=== Dev instance ready ==="
echo "  BAO_ADDR=$BAO_ADDR"
echo "  BAO_TOKEN=root"
echo ""
echo "Run tests:  bash $(dirname "$0")/run-cross-checks.sh"
echo "Stop:       bash $(dirname "$0")/stop.sh"
