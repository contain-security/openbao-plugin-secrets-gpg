#!/usr/bin/env bash
# Common test framework for the GPG plugin regression suite.
# Source this file from individual test scripts.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TESTS_DIR/.." && pwd)"

export BAO_ADDR=${BAO_ADDR:-http://192.168.1.101:8200}
export BAO_TOKEN=${BAO_TOKEN:-root}
BAO=${BAO_BIN:-"$ROOT_DIR/openbao/bin/bao"}

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Counters
_PASS=0
_FAIL=0
_SKIP=0
_TEST_NAME=""

# Test lifecycle
begin_test() {
    _TEST_NAME="$1"
    echo "TEST: $1"
}

pass() {
    local msg="${1:-$_TEST_NAME}"
    echo "  PASS: $msg"
    _PASS=$((_PASS + 1))
}

fail() {
    local msg="${1:-$_TEST_NAME}"
    echo "  FAIL: $msg"
    _FAIL=$((_FAIL + 1))
}

skip() {
    local msg="${1:-$_TEST_NAME}"
    echo "  SKIP: $msg"
    _SKIP=$((_SKIP + 1))
}

# Assert helpers
assert_eq() {
    local expected="$1" actual="$2" msg="${3:-assertion}"
    if [ "$expected" = "$actual" ]; then
        pass "$msg"
    else
        fail "$msg (expected: '$expected', got: '$actual')"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" msg="${3:-assertion}"
    if echo "$haystack" | grep -q "$needle"; then
        pass "$msg"
    else
        fail "$msg (expected to contain: '$needle')"
    fi
}

assert_not_empty() {
    local value="$1" msg="${2:-assertion}"
    if [ -n "$value" ]; then
        pass "$msg"
    else
        fail "$msg (expected non-empty value)"
    fi
}

assert_cmd_succeeds() {
    local msg="${1:-command should succeed}"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$msg"
    else
        fail "$msg"
    fi
}

assert_cmd_fails() {
    local msg="${1:-command should fail}"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$msg"
    else
        pass "$msg"
    fi
}

# Print summary and exit with appropriate code
print_summary() {
    echo ""
    echo "============================================="
    echo "  Results: $_PASS passed, $_FAIL failed, $_SKIP skipped"
    echo "============================================="
    [ $_FAIL -eq 0 ] && exit 0 || exit 1
}

# Ensure server is reachable
check_server() {
    if ! curl -sf "$BAO_ADDR/v1/sys/health" >/dev/null 2>&1; then
        echo "ERROR: OpenBao server not reachable at $BAO_ADDR"
        echo "Start it with: cd test-bed/openbao-instance && ../../openbao/bin/bao server -dev -dev-root-token-id=root -dev-listen-address=192.168.1.101:8200 -dev-plugin-dir=./plugins"
        exit 1
    fi
}

# Ensure the gpg plugin is mounted
check_plugin() {
    if ! $BAO secrets list 2>/dev/null | grep -q "^gpg/"; then
        echo "ERROR: GPG plugin not mounted at gpg/"
        echo "Mount it with: bao secrets enable -path=gpg -plugin-name=openbao-plugin-secrets-gpg plugin"
        exit 1
    fi
}

# Create a key if it doesn't already exist
ensure_key() {
    local name="$1" real_name="${2:-Test Key}" email="${3:-test@example.com}" extra="${4:-}"
    if ! $BAO read "gpg/keys/$name" >/dev/null 2>&1; then
        $BAO write "gpg/keys/$name" real_name="$real_name" email="$email" generate=true key_bits=2048 $extra >/dev/null 2>&1
    fi
}

# Delete a key (ignore errors if it doesn't exist)
delete_key() {
    local name="$1"
    $BAO delete "gpg/keys/$name" >/dev/null 2>&1 || true
}
