#!/usr/bin/env bash
# Stop a running test-bed OpenBao instance.
set -euo pipefail

source "$(dirname "$0")/common.env"

stop_server
