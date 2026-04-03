#!/usr/bin/env bash
# Register and mount the GPG plugin in a running OpenBao instance.
# Usage: ./scripts/register.sh <path-to-binary> [mount-path]
set -euo pipefail

BINARY=${1:?Usage: register.sh <binary> [mount-path]}
MOUNT=${2:-gpg}
PLUGIN_NAME=openbao-plugin-secrets-gpg

# Determine plugin directory from OpenBao config, fallback to default
PLUGIN_DIR=${BAO_PLUGIN_DIR:-/etc/openbao/plugins}

cp "$BINARY" "$PLUGIN_DIR/$PLUGIN_NAME"
chmod 755 "$PLUGIN_DIR/$PLUGIN_NAME"

SHASUM=$(sha256sum "$PLUGIN_DIR/$PLUGIN_NAME" | awk '{print $1}')

bao plugin register -sha256="$SHASUM" secret "$PLUGIN_NAME"
echo "Registered plugin: $PLUGIN_NAME (sha256=$SHASUM)"

bao secrets enable -path="$MOUNT" -plugin-name="$PLUGIN_NAME" plugin
echo "Mounted at: $MOUNT/"
