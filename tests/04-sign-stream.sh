#!/usr/bin/env bash
# Test: Streaming sign operations
source "$(dirname "$0")/common.sh"
check_prerequisites

echo "============================================="
echo "  04 - Streaming Sign"
echo "============================================="
echo ""

ensure_key "stream-sign-test" "Stream Sign" "streamsign@test.com" "exportable=true"

# --- Basic streaming sign round-trip ---
begin_test "Streaming sign: start → update → finalize → verify"

# Generate a test file (~100KB)
dd if=/dev/urandom bs=1024 count=100 of="$TMPDIR/testfile.bin" 2>/dev/null

# Start session
START_RESP=$($BAO write -format=json gpg/sign-stream/stream-sign-test/start \
    algorithm=sha2-256 format=ascii-armor 2>&1)
SESSION_ID=$(echo "$START_RESP" | jq -r '.data.session_id')
assert_not_empty "$SESSION_ID" "session_id returned"

ALGO=$(echo "$START_RESP" | jq -r '.data.algorithm')
assert_eq "sha2-256" "$ALGO" "algorithm echoed back"

# Send file in 16KB chunks using @file syntax to avoid arg-list-too-long
CHUNK_SIZE=16384
FILE_SIZE=$(stat -c%s "$TMPDIR/testfile.bin")
OFFSET=0

while [ $OFFSET -lt $FILE_SIZE ]; do
    REMAINING=$((FILE_SIZE - OFFSET))
    READ_SIZE=$CHUNK_SIZE
    [ $REMAINING -lt $READ_SIZE ] && READ_SIZE=$REMAINING

    dd if="$TMPDIR/testfile.bin" bs=1 skip=$OFFSET count=$READ_SIZE 2>/dev/null | base64 -w0 > "$TMPDIR/chunk.b64"
    $BAO write gpg/sign-stream/stream-sign-test/update \
        session_id="$SESSION_ID" input=@"$TMPDIR/chunk.b64" >/dev/null 2>&1
    OFFSET=$((OFFSET + READ_SIZE))
done

# Finalize
FIN_RESP=$($BAO write -format=json gpg/sign-stream/stream-sign-test/finalize \
    session_id="$SESSION_ID" 2>&1)
SIGNATURE=$(echo "$FIN_RESP" | jq -r '.data.signature')
assert_contains "$SIGNATURE" "BEGIN PGP SIGNATURE" "ascii-armor signature returned"

# Verify via plugin (use @file for large input)
base64 -w0 "$TMPDIR/testfile.bin" > "$TMPDIR/input.b64"
echo "$SIGNATURE" > "$TMPDIR/sig_verify.asc"
VALID=$($BAO write -field=valid gpg/verify/stream-sign-test \
    input=@"$TMPDIR/input.b64" signature=@"$TMPDIR/sig_verify.asc" format=ascii-armor 2>&1)
assert_eq "true" "$VALID" "plugin verify of streaming signature"

# --- GnuPG verify of streaming signature ---
begin_test "GnuPG verifies streaming signature"
EXPORT_GNUPGHOME=$(mktemp -d)
PRIVKEY=$($BAO read -field=key gpg/export/stream-sign-test 2>&1)
echo "$PRIVKEY" | GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --import 2>/dev/null
echo "$SIGNATURE" > "$TMPDIR/stream_sig.asc"
if GNUPGHOME="$EXPORT_GNUPGHOME" gpg --verify "$TMPDIR/stream_sig.asc" "$TMPDIR/testfile.bin" 2>/dev/null; then
    pass "gpg verify of streaming signature"
else
    fail "gpg verify of streaming signature"
fi
rm -rf "$EXPORT_GNUPGHOME"

# --- Streaming vs non-streaming consistency ---
begin_test "Streaming vs non-streaming sign consistency"
SMALL_DATA="consistent test data for both methods"
echo -n "$SMALL_DATA" | base64 > "$TMPDIR/small.b64"

# Non-streaming
NS_SIG=$($BAO write -field=signature gpg/sign/stream-sign-test \
    input=@"$TMPDIR/small.b64" algorithm=sha2-256 format=ascii-armor 2>&1)

# Streaming
START_RESP=$($BAO write -format=json gpg/sign-stream/stream-sign-test/start \
    algorithm=sha2-256 format=ascii-armor 2>&1)
SID=$(echo "$START_RESP" | jq -r '.data.session_id')
$BAO write gpg/sign-stream/stream-sign-test/update \
    session_id="$SID" input=@"$TMPDIR/small.b64" >/dev/null 2>&1
S_SIG=$($BAO write -field=signature gpg/sign-stream/stream-sign-test/finalize \
    session_id="$SID" 2>&1)

# Both should verify
for label in non-stream stream; do
    if [ "$label" = "non-stream" ]; then SIG="$NS_SIG"; else SIG="$S_SIG"; fi
    echo "$SIG" > "$TMPDIR/verify_${label}.asc"
    VALID=$($BAO write -field=valid gpg/verify/stream-sign-test \
        input=@"$TMPDIR/small.b64" signature=@"$TMPDIR/verify_${label}.asc" format=ascii-armor 2>&1)
    assert_eq "true" "$VALID" "$label signature verifies"
done

# --- Base64 output format ---
begin_test "Streaming sign with base64 format"
START_RESP=$($BAO write -format=json gpg/sign-stream/stream-sign-test/start \
    algorithm=sha2-256 format=base64 2>&1)
SID=$(echo "$START_RESP" | jq -r '.data.session_id')
$BAO write gpg/sign-stream/stream-sign-test/update \
    session_id="$SID" input=@"$TMPDIR/small.b64" >/dev/null 2>&1
B64_SIG=$($BAO write -field=signature gpg/sign-stream/stream-sign-test/finalize \
    session_id="$SID" 2>&1)
assert_not_empty "$B64_SIG" "base64 signature returned"

echo "$B64_SIG" > "$TMPDIR/b64sig.txt"
VALID=$($BAO write -field=valid gpg/verify/stream-sign-test \
    input=@"$TMPDIR/small.b64" signature=@"$TMPDIR/b64sig.txt" format=base64 2>&1)
assert_eq "true" "$VALID" "base64 streaming signature verifies"

# --- SHA-512 hash algorithm ---
begin_test "Streaming sign with sha2-512"
START_RESP=$($BAO write -format=json gpg/sign-stream/stream-sign-test/start \
    algorithm=sha2-512 format=ascii-armor 2>&1)
SID=$(echo "$START_RESP" | jq -r '.data.session_id')
$BAO write gpg/sign-stream/stream-sign-test/update \
    session_id="$SID" input=@"$TMPDIR/small.b64" >/dev/null 2>&1
SIG=$($BAO write -field=signature gpg/sign-stream/stream-sign-test/finalize \
    session_id="$SID" 2>&1)
echo "$SIG" > "$TMPDIR/sha512sig.asc"
VALID=$($BAO write -field=valid gpg/verify/stream-sign-test \
    input=@"$TMPDIR/small.b64" signature=@"$TMPDIR/sha512sig.asc" format=ascii-armor 2>&1)
assert_eq "true" "$VALID" "sha2-512 streaming signature verifies"

# --- Error: double finalize ---
begin_test "Double finalize fails"
START_RESP=$($BAO write -format=json gpg/sign-stream/stream-sign-test/start \
    algorithm=sha2-256 format=base64 2>&1)
SID=$(echo "$START_RESP" | jq -r '.data.session_id')
$BAO write gpg/sign-stream/stream-sign-test/update \
    session_id="$SID" input=@"$TMPDIR/small.b64" >/dev/null 2>&1
$BAO write gpg/sign-stream/stream-sign-test/finalize session_id="$SID" >/dev/null 2>&1
assert_cmd_fails "double finalize rejected" \
    $BAO write gpg/sign-stream/stream-sign-test/finalize session_id="$SID"

# --- Error: non-existent session ---
begin_test "Update non-existent session fails"
assert_cmd_fails "non-existent session rejected" \
    $BAO write gpg/sign-stream/stream-sign-test/update session_id="fake-session" input=@"$TMPDIR/small.b64"

# --- Cleanup ---
delete_key "stream-sign-test"

print_summary
