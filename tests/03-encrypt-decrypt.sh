#!/usr/bin/env bash
# Test: Encrypt and Decrypt operations (non-streaming)
source "$(dirname "$0")/common.sh"
check_server
check_plugin

echo "============================================="
echo "  03 - Encrypt & Decrypt (Non-Streaming)"
echo "============================================="
echo ""

ensure_key "enc-test" "Encrypt Test" "enc@test.com" "exportable=true"
ensure_key "signer-test" "Signer Test" "signer@test.com"

PLAINTEXT="Confidential data for encrypt/decrypt test"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)

# --- Encrypt + decrypt base64 ---
begin_test "Encrypt + decrypt (base64)"
CIPHERTEXT=$($BAO write -field=ciphertext gpg/encrypt/enc-test plaintext="$PLAINTEXT_B64" format=base64 2>&1)
assert_not_empty "$CIPHERTEXT" "ciphertext returned"

RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/enc-test ciphertext="$CIPHERTEXT" format=base64 2>&1)
RECOVERED=$(echo "$RECOVERED_B64" | base64 -d)
assert_eq "$PLAINTEXT" "$RECOVERED" "decrypt matches original (base64)"

# --- Encrypt + decrypt ascii-armor ---
begin_test "Encrypt + decrypt (ascii-armor)"
CIPHERTEXT=$($BAO write -field=ciphertext gpg/encrypt/enc-test plaintext="$PLAINTEXT_B64" format=ascii-armor 2>&1)
assert_contains "$CIPHERTEXT" "BEGIN PGP MESSAGE" "ciphertext is armored"

RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/enc-test ciphertext="$CIPHERTEXT" format=ascii-armor 2>&1)
RECOVERED=$(echo "$RECOVERED_B64" | base64 -d)
assert_eq "$PLAINTEXT" "$RECOVERED" "decrypt matches original (ascii-armor)"

# --- Encrypt + sign, decrypt + verify ---
begin_test "Encrypt+sign → decrypt+verify"
CIPHERTEXT=$($BAO write -field=ciphertext gpg/encrypt/enc-test/sign/signer-test plaintext="$PLAINTEXT_B64" format=base64 2>&1)
RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/enc-test/sign/signer-test ciphertext="$CIPHERTEXT" format=base64 2>&1)
RECOVERED=$(echo "$RECOVERED_B64" | base64 -d)
assert_eq "$PLAINTEXT" "$RECOVERED" "signed encrypt/decrypt round-trip"

# --- Wrong signer rejected ---
begin_test "Decrypt with wrong signer fails"
assert_cmd_fails "wrong signer rejected" \
    $BAO write gpg/decrypt/enc-test/sign/enc-test ciphertext="$CIPHERTEXT" format=base64

# --- Decrypt with wrong key fails ---
begin_test "Decrypt with wrong key fails"
CIPHERTEXT=$($BAO write -field=ciphertext gpg/encrypt/enc-test plaintext="$PLAINTEXT_B64" format=base64 2>&1)
assert_cmd_fails "wrong key rejected" \
    $BAO write gpg/decrypt/signer-test ciphertext="$CIPHERTEXT" format=base64

# --- Encrypt with non-existent key ---
begin_test "Encrypt with non-existent key fails"
assert_cmd_fails "non-existent key rejected" \
    $BAO write gpg/encrypt/no-such-key plaintext="$PLAINTEXT_B64"

# --- GnuPG interop: plugin encrypt, gpg decrypt ---
begin_test "GnuPG interop: plugin encrypt, gpg decrypt"
EXPORT_GNUPGHOME=$(mktemp -d)
PRIVKEY=$($BAO read -field=key gpg/export/enc-test 2>&1)
echo "$PRIVKEY" | GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --import 2>/dev/null

CIPHERTEXT=$($BAO write -field=ciphertext gpg/encrypt/enc-test plaintext="$PLAINTEXT_B64" format=ascii-armor 2>&1)
echo "$CIPHERTEXT" > "$TMPDIR/enc.asc"
RECOVERED=$(GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --decrypt "$TMPDIR/enc.asc" 2>/dev/null)
assert_eq "$PLAINTEXT" "$RECOVERED" "plugin encrypt → gpg decrypt"

# --- GnuPG interop: gpg encrypt, plugin decrypt ---
begin_test "GnuPG interop: gpg encrypt, plugin decrypt"
FP=$($BAO read -field=fingerprint gpg/keys/enc-test)
echo -n "$PLAINTEXT" | GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --trust-model always --encrypt --armor --recipient "$FP" > "$TMPDIR/gpg_enc.asc" 2>/dev/null
GPG_CIPHERTEXT=$(cat "$TMPDIR/gpg_enc.asc")
RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/enc-test ciphertext="$GPG_CIPHERTEXT" format=ascii-armor 2>&1)
RECOVERED=$(echo "$RECOVERED_B64" | base64 -d)
assert_eq "$PLAINTEXT" "$RECOVERED" "gpg encrypt → plugin decrypt"

rm -rf "$EXPORT_GNUPGHOME"

# --- Cleanup ---
delete_key "enc-test"
delete_key "signer-test"

print_summary
