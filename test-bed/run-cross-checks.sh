#!/usr/bin/env bash
# Cross-check test suite for openbao-plugin-secrets-gpg
#
# Validates interoperability between the OpenBao GPG plugin and GnuPG CLI.
#
# Prerequisites:
#   - OpenBao dev server running at BAO_ADDR with root token
#   - GPG plugin registered and mounted at gpg/
#   - GnuPG installed
#   - Test PGP keys in test-bed/test-pgp-keys/ (alice + bob .asc files)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export BAO_ADDR=${BAO_ADDR:-http://127.0.0.1:8200}

# =============================================
#  Prerequisite checks — bail early if not met
# =============================================

echo "Checking prerequisites..."

# Required tools (check these first — jq is needed for token auto-detection below)
MISSING=()
command -v jq >/dev/null 2>&1 || MISSING+=("jq")
command -v gpg >/dev/null 2>&1 || MISSING+=("gpg")
command -v curl >/dev/null 2>&1 || MISSING+=("curl")
command -v base64 >/dev/null 2>&1 || MISSING+=("base64")
if [ ${#MISSING[@]} -gt 0 ]; then
    echo "ERROR: Required tools not found: ${MISSING[*]}"
    exit 1
fi

# Locate bao binary: BAO_BIN env > PATH
if [ -n "${BAO_BIN:-}" ]; then
    BAO="$BAO_BIN"
elif command -v bao >/dev/null 2>&1; then
    BAO="$(command -v bao)"
else
    echo "ERROR: bao binary not found."
    echo "  Set BAO_BIN=/path/to/bao or add bao to PATH."
    exit 1
fi

# Auto-detect token: BAO_TOKEN env > init.json (non-dev) > "root" (dev)
if [ -z "${BAO_TOKEN:-}" ]; then
    INIT_FILE="$SCRIPT_DIR/openbao-instance/init.json"
    if [ -f "$INIT_FILE" ]; then
        export BAO_TOKEN=$(jq -r '.root_token' "$INIT_FILE")
    else
        export BAO_TOKEN=root
    fi
fi

# Temp directories and cleanup
TMPDIR=$(mktemp -d)
export GNUPGHOME=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR" "$GNUPGHOME"; }
trap cleanup EXIT

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# Server reachable
if ! curl -sf "$BAO_ADDR/v1/sys/health" >/dev/null 2>&1; then
    echo "ERROR: OpenBao server not reachable at $BAO_ADDR"
    echo "  Start it with: bash test-bed/start-dev.sh"
    exit 1
fi

# Plugin mounted
if ! "$BAO" secrets list 2>/dev/null | grep -q "^gpg/"; then
    echo "ERROR: GPG plugin not mounted at gpg/"
    echo "  Start the dev server with: bash test-bed/start-dev.sh"
    exit 1
fi

# Test PGP key files exist
TEST_KEYS_DIR="$SCRIPT_DIR/test-pgp-keys"
for keyfile in alice-private.asc alice-public.asc bob-private.asc bob-public.asc; do
    if [ ! -f "$TEST_KEYS_DIR/$keyfile" ]; then
        echo "ERROR: Missing test key: $TEST_KEYS_DIR/$keyfile"
        exit 1
    fi
done

# =============================================
#  GPG keyring setup
# =============================================
# GNUPGHOME is an isolated temp directory (created above).
# Import alice and bob test keys fresh each run.

echo "Setting up GPG keyring..."
gpg --batch --pinentry-mode loopback --passphrase '' --import "$TEST_KEYS_DIR/alice-private.asc" 2>/dev/null
gpg --batch --pinentry-mode loopback --passphrase '' --import "$TEST_KEYS_DIR/bob-private.asc" 2>/dev/null

# Verify imports
if ! gpg --list-secret-keys "alice@test.local" >/dev/null 2>&1; then
    echo "ERROR: Failed to import Alice test key into GPG keyring"
    exit 1
fi
if ! gpg --list-secret-keys "bob@test.local" >/dev/null 2>&1; then
    echo "ERROR: Failed to import Bob test key into GPG keyring"
    exit 1
fi

echo "Prerequisites OK."
echo ""

echo "============================================="
echo "  OpenBao GPG Plugin Cross-Check Test Suite"
echo "============================================="
echo ""

# --- Test 1: Key CRUD ---
echo "TEST 1: Key CRUD"

$BAO delete gpg/keys/crud-test >/dev/null 2>&1 || true
$BAO write gpg/keys/crud-test real_name="CRUD Test" generate=true key_bits=2048 exportable=true >/dev/null 2>&1
$BAO read -field=fingerprint gpg/keys/crud-test >/dev/null 2>&1 && pass "create + read" || fail "create + read"

$BAO list gpg/keys 2>/dev/null | grep -q crud-test && pass "list" || fail "list"

$BAO delete gpg/keys/crud-test >/dev/null 2>&1
$BAO read gpg/keys/crud-test >/dev/null 2>&1 && fail "delete (key still exists)" || pass "delete"

echo ""

# --- Setup keys for remaining tests ---
$BAO delete gpg/keys/test-key >/dev/null 2>&1 || true
$BAO delete gpg/keys/signer-key >/dev/null 2>&1 || true
$BAO delete gpg/keys/alice-imported >/dev/null 2>&1 || true
$BAO delete gpg/keys/bob-imported >/dev/null 2>&1 || true

$BAO write gpg/keys/test-key real_name="Test Key" email="test@example.com" generate=true key_bits=2048 exportable=true >/dev/null 2>&1
$BAO write gpg/keys/signer-key real_name="Signer Key" email="signer@example.com" generate=true key_bits=2048 >/dev/null 2>&1

# Import plugin test-key public key into gpg
PUBKEY=$($BAO read -field=public_key gpg/keys/test-key)
echo "$PUBKEY" | gpg --batch --import 2>/dev/null

# Export plugin test-key private key into gpg (for decrypt tests)
PRIVKEY=$($BAO read -field=key gpg/export/test-key 2>&1)
echo "$PRIVKEY" | gpg --batch --pinentry-mode loopback --passphrase '' --import 2>/dev/null

# --- Test 2: Sign via plugin, verify with gpg ---
echo "TEST 2: Sign via plugin, verify with gpg"

PAYLOAD="Hello from OpenBao GPG plugin"
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64)
SIGNATURE=$($BAO write -field=signature gpg/sign/test-key input="$PAYLOAD_B64" format=ascii-armor 2>&1)
echo -n "$PAYLOAD" > "$TMPDIR/payload.txt"
echo "$SIGNATURE" > "$TMPDIR/sig.asc"
gpg --verify "$TMPDIR/sig.asc" "$TMPDIR/payload.txt" 2>/dev/null && pass "sign → gpg verify" || fail "sign → gpg verify"

echo ""

# --- Test 3: Sign with gpg, verify via plugin ---
echo "TEST 3: Sign with gpg, verify via plugin"

# Import Alice's key into plugin
ALICE_PRIVKEY=$(cat "$TEST_KEYS_DIR/alice-private.asc")
$BAO write gpg/keys/alice-imported generate=false key="$ALICE_PRIVKEY" >/dev/null 2>&1

PAYLOAD="Message signed by GnuPG Alice"
echo -n "$PAYLOAD" > "$TMPDIR/gpg_payload.txt"
gpg --batch --pinentry-mode loopback --passphrase '' --detach-sign --armor -u "alice@test.local" "$TMPDIR/gpg_payload.txt" 2>/dev/null
GPG_SIG=$(cat "$TMPDIR/gpg_payload.txt.asc")
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64)
VALID=$($BAO write -field=valid gpg/verify/alice-imported input="$PAYLOAD_B64" signature="$GPG_SIG" format=ascii-armor 2>&1)
[ "$VALID" = "true" ] && pass "gpg sign → plugin verify" || fail "gpg sign → plugin verify"

echo ""

# --- Test 4: Encrypt via plugin, decrypt with gpg ---
echo "TEST 4: Encrypt via plugin, decrypt with gpg"

PLAINTEXT="Secret message encrypted by OpenBao plugin"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)
CIPHERTEXT=$($BAO write -field=ciphertext gpg/encrypt/test-key plaintext="$PLAINTEXT_B64" format=ascii-armor 2>&1)
echo "$CIPHERTEXT" > "$TMPDIR/enc4.asc"
RECOVERED=$(gpg --batch --pinentry-mode loopback --passphrase '' --decrypt "$TMPDIR/enc4.asc" 2>/dev/null)
[ "$RECOVERED" = "$PLAINTEXT" ] && pass "plugin encrypt → gpg decrypt" || fail "plugin encrypt → gpg decrypt"

echo ""

# --- Test 5: Encrypt with gpg, decrypt via plugin ---
echo "TEST 5: Encrypt with gpg, decrypt via plugin"

FINGERPRINT=$($BAO read -field=fingerprint gpg/keys/test-key)
PLAINTEXT="Message encrypted by GnuPG for the plugin"
echo -n "$PLAINTEXT" | gpg --batch --trust-model always --encrypt --armor --recipient "$FINGERPRINT" > "$TMPDIR/enc5.asc" 2>/dev/null
CIPHERTEXT=$(cat "$TMPDIR/enc5.asc")
RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/test-key ciphertext="$CIPHERTEXT" format=ascii-armor 2>&1)
RECOVERED=$(echo "$RECOVERED_B64" | base64 -d)
[ "$RECOVERED" = "$PLAINTEXT" ] && pass "gpg encrypt → plugin decrypt" || fail "gpg encrypt → plugin decrypt"

echo ""

# --- Test 6: Encrypt+sign round-trip via plugin ---
echo "TEST 6: Encrypt+sign round-trip via plugin"

PLAINTEXT="Signed and encrypted round-trip"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)
CIPHERTEXT=$($BAO write -field=ciphertext gpg/encrypt/test-key/sign/signer-key plaintext="$PLAINTEXT_B64" format=ascii-armor 2>&1)
RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/test-key/sign/signer-key ciphertext="$CIPHERTEXT" format=ascii-armor 2>&1)
RECOVERED=$(echo "$RECOVERED_B64" | base64 -d)
[ "$RECOVERED" = "$PLAINTEXT" ] && pass "encrypt+sign → decrypt+verify" || fail "encrypt+sign → decrypt+verify"

# Wrong signer should fail
if $BAO write gpg/decrypt/test-key/sign/test-key ciphertext="$CIPHERTEXT" format=ascii-armor >/dev/null 2>&1; then
    fail "wrong signer accepted"
else
    pass "wrong signer rejected"
fi

echo ""

# --- Test 7: Key import from gpg into plugin ---
echo "TEST 7: Key import (gpg → plugin)"

BOB_PRIVKEY=$(cat "$TEST_KEYS_DIR/bob-private.asc")
$BAO write gpg/keys/bob-imported generate=false key="$BOB_PRIVKEY" exportable=true >/dev/null 2>&1
PAYLOAD="Signed by imported Bob key"
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64)
SIGNATURE=$($BAO write -field=signature gpg/sign/bob-imported input="$PAYLOAD_B64" format=ascii-armor 2>&1)
echo -n "$PAYLOAD" > "$TMPDIR/bob_payload.txt"
echo "$SIGNATURE" > "$TMPDIR/bob_sig.asc"
gpg --verify "$TMPDIR/bob_sig.asc" "$TMPDIR/bob_payload.txt" 2>/dev/null && pass "imported key sign → gpg verify" || fail "imported key sign → gpg verify"

echo ""

# --- Test 8: Export key from plugin, use in gpg ---
echo "TEST 8: Export key from plugin, use in gpg"

EXPORT_GNUPGHOME="$TMPDIR/export-gnupghome"
mkdir -p "$EXPORT_GNUPGHOME"
PRIVKEY=$($BAO read -field=key gpg/export/test-key 2>&1)
echo "$PRIVKEY" | GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --import 2>/dev/null

PAYLOAD="Signed using exported key"
echo -n "$PAYLOAD" > "$TMPDIR/exp_payload.txt"
GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --detach-sign --armor "$TMPDIR/exp_payload.txt" 2>/dev/null
EXP_SIG=$(cat "$TMPDIR/exp_payload.txt.asc")
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64)
VALID=$($BAO write -field=valid gpg/verify/test-key input="$PAYLOAD_B64" signature="$EXP_SIG" format=ascii-armor 2>&1)
[ "$VALID" = "true" ] && pass "exported key sign → plugin verify" || fail "exported key sign → plugin verify"

echo ""

# --- Cleanup ---
$BAO delete gpg/keys/test-key >/dev/null 2>&1 || true
$BAO delete gpg/keys/signer-key >/dev/null 2>&1 || true
$BAO delete gpg/keys/alice-imported >/dev/null 2>&1 || true
$BAO delete gpg/keys/bob-imported >/dev/null 2>&1 || true

# --- Summary ---
echo "============================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================="

[ $FAIL -eq 0 ] && exit 0 || exit 1
