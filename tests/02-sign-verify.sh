#!/usr/bin/env bash
# Test: Sign and Verify operations (non-streaming)
source "$(dirname "$0")/common.sh"
check_prerequisites

echo "============================================="
echo "  02 - Sign & Verify (Non-Streaming)"
echo "============================================="
echo ""

ensure_key "sign-test" "Sign Test" "sign@test.com" "exportable=true"

PAYLOAD="Hello from the sign/verify regression test"
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64)

# --- Sign ascii-armor ---
begin_test "Sign (ascii-armor)"
SIG_ARMOR=$($BAO write -field=signature gpg/sign/sign-test input="$PAYLOAD_B64" format=ascii-armor 2>&1)
assert_contains "$SIG_ARMOR" "BEGIN PGP SIGNATURE" "signature is armored"

# --- Verify ascii-armor ---
begin_test "Verify (ascii-armor)"
VALID=$($BAO write -field=valid gpg/verify/sign-test input="$PAYLOAD_B64" signature="$SIG_ARMOR" format=ascii-armor 2>&1)
assert_eq "true" "$VALID" "signature valid"

# --- Sign base64 ---
begin_test "Sign (base64)"
SIG_B64=$($BAO write -field=signature gpg/sign/sign-test input="$PAYLOAD_B64" format=base64 2>&1)
assert_not_empty "$SIG_B64" "base64 signature returned"

# --- Verify base64 ---
begin_test "Verify (base64)"
VALID=$($BAO write -field=valid gpg/verify/sign-test input="$PAYLOAD_B64" signature="$SIG_B64" format=base64 2>&1)
assert_eq "true" "$VALID" "base64 signature valid"

# --- Tampered data ---
begin_test "Verify tampered data fails"
TAMPERED_B64=$(echo -n "TAMPERED DATA" | base64)
VALID=$($BAO write -field=valid gpg/verify/sign-test input="$TAMPERED_B64" signature="$SIG_ARMOR" format=ascii-armor 2>&1)
assert_eq "false" "$VALID" "tampered data rejected"

# --- Different hash algorithms ---
for algo in sha2-224 sha2-256 sha2-384 sha2-512; do
    begin_test "Sign + verify with $algo"
    SIG=$($BAO write -field=signature gpg/sign/sign-test input="$PAYLOAD_B64" algorithm="$algo" format=ascii-armor 2>&1)
    VALID=$($BAO write -field=valid gpg/verify/sign-test input="$PAYLOAD_B64" signature="$SIG" format=ascii-armor 2>&1)
    assert_eq "true" "$VALID" "$algo round-trip"
done

# --- Sign with non-existent key ---
begin_test "Sign with non-existent key fails"
assert_cmd_fails "non-existent key rejected" \
    $BAO write gpg/sign/no-such-key input="$PAYLOAD_B64"

# --- GnuPG interop: sign via plugin, verify with gpg ---
begin_test "GnuPG interop: plugin sign, gpg verify"
EXPORT_GNUPGHOME=$(mktemp -d)
PRIVKEY=$($BAO read -field=key gpg/export/sign-test 2>&1)
echo "$PRIVKEY" | GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --import 2>/dev/null
echo -n "$PAYLOAD" > "$TMPDIR/payload.txt"
echo "$SIG_ARMOR" > "$TMPDIR/sig.asc"
if GNUPGHOME="$EXPORT_GNUPGHOME" gpg --verify "$TMPDIR/sig.asc" "$TMPDIR/payload.txt" 2>/dev/null; then
    pass "plugin sign → gpg verify"
else
    fail "plugin sign → gpg verify"
fi
rm -rf "$EXPORT_GNUPGHOME"

# --- Cleanup ---
delete_key "sign-test"

print_summary
