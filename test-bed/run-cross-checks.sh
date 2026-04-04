#!/usr/bin/env bash
# Cross-check test suite for openbao-plugin-secrets-gpg
# Prerequisites:
#   - OpenBao dev server running at BAO_ADDR with root token
#   - GPG plugin registered and mounted at gpg/
#   - GnuPG installed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export BAO_ADDR=${BAO_ADDR:-http://127.0.0.1:8200}
export GNUPGHOME="$SCRIPT_DIR/test-pgp-keys"

# Auto-detect token: use BAO_TOKEN env, fall back to init.json (non-dev), fall back to "root" (dev)
if [ -z "${BAO_TOKEN:-}" ]; then
    INIT_FILE="$SCRIPT_DIR/openbao-instance/init.json"
    if [ -f "$INIT_FILE" ]; then
        export BAO_TOKEN=$(jq -r '.root_token' "$INIT_FILE")
    else
        export BAO_TOKEN=root
    fi
fi

# Auto-detect bao binary
BAO=${BAO_BIN:-"$SCRIPT_DIR/../openbao/bin/bao"}

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "============================================="
echo "  OpenBao GPG Plugin Cross-Check Test Suite"
echo "============================================="
echo ""

# --- Test 1: Key CRUD ---
echo "TEST 1: Key CRUD"

$BAO write gpg/keys/crud-test real_name="CRUD Test" generate=true key_bits=2048 exportable=true >/dev/null 2>&1
$BAO read -field=fingerprint gpg/keys/crud-test >/dev/null 2>&1 && pass "create + read" || fail "create + read"

$BAO list gpg/keys 2>/dev/null | grep -q crud-test && pass "list" || fail "list"

$BAO delete gpg/keys/crud-test >/dev/null 2>&1
$BAO read gpg/keys/crud-test >/dev/null 2>&1 && fail "delete (key still exists)" || pass "delete"

echo ""

# --- Setup keys for remaining tests ---
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
ALICE_PRIVKEY=$(cat "$SCRIPT_DIR/test-pgp-keys/alice-private.asc")
$BAO write gpg/keys/alice-imported generate=false key="$ALICE_PRIVKEY" >/dev/null 2>&1 || true

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

BOB_PRIVKEY=$(cat "$SCRIPT_DIR/test-pgp-keys/bob-private.asc")
$BAO write gpg/keys/bob-imported generate=false key="$BOB_PRIVKEY" exportable=true >/dev/null 2>&1 || true
PAYLOAD="Signed by imported Bob key"
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64)
SIGNATURE=$($BAO write -field=signature gpg/sign/bob-imported input="$PAYLOAD_B64" format=ascii-armor 2>&1)
echo -n "$PAYLOAD" > "$TMPDIR/bob_payload.txt"
echo "$SIGNATURE" > "$TMPDIR/bob_sig.asc"
gpg --verify "$TMPDIR/bob_sig.asc" "$TMPDIR/bob_payload.txt" 2>/dev/null && pass "imported key sign → gpg verify" || fail "imported key sign → gpg verify"

echo ""

# --- Test 8: Export key from plugin, use in gpg ---
echo "TEST 8: Export key from plugin, use in gpg"

EXPORT_GNUPGHOME=$(mktemp -d)
PRIVKEY=$($BAO read -field=key gpg/export/test-key 2>&1)
echo "$PRIVKEY" | GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --import 2>/dev/null

PAYLOAD="Signed using exported key"
echo -n "$PAYLOAD" > "$TMPDIR/exp_payload.txt"
GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --detach-sign --armor "$TMPDIR/exp_payload.txt" 2>/dev/null
EXP_SIG=$(cat "$TMPDIR/exp_payload.txt.asc")
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64)
VALID=$($BAO write -field=valid gpg/verify/test-key input="$PAYLOAD_B64" signature="$EXP_SIG" format=ascii-armor 2>&1)
[ "$VALID" = "true" ] && pass "exported key sign → plugin verify" || fail "exported key sign → plugin verify"

rm -rf "$EXPORT_GNUPGHOME"

echo ""

# --- Summary ---
echo "============================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================="

[ $FAIL -eq 0 ] && exit 0 || exit 1
