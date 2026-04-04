#!/usr/bin/env bash
# Test: Streaming decrypt operations
source "$(dirname "$0")/common.sh"
check_server
check_plugin

echo "============================================="
echo "  06 - Streaming Decrypt"
echo "============================================="
echo ""

ensure_key "stream-dec-test" "Stream Dec" "streamdec@test.com"
ensure_key "stream-dec-signer" "Stream Dec Signer" "decsigner@test.com"

PLAINTEXT="Streaming decryption test data for the regression suite"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)

# Helper: non-streaming encrypt → binary ciphertext file
plugin_encrypt_to_file() {
    local key="$1" plaintext_b64="$2" outfile="$3" signer="${4:-}"
    local enc_path="gpg/encrypt/$key"
    [ -n "$signer" ] && enc_path="gpg/encrypt/$key/sign/$signer"

    echo -n "$plaintext_b64" > "$TMPDIR/_pt.b64"
    local ct_b64
    ct_b64=$($BAO write -field=ciphertext "$enc_path" plaintext=@"$TMPDIR/_pt.b64" format=base64 2>&1)
    echo -n "$ct_b64" | base64 -d > "$outfile"
}

# Helper: stream encrypt → binary ciphertext file
stream_encrypt_to_file() {
    local key="$1" infile="$2" outfile="$3" chunk_size="${4:-8192}"

    local start_resp sid
    start_resp=$($BAO write -force -format=json "gpg/encrypt-stream/$key/start" 2>&1)
    sid=$(echo "$start_resp" | jq -r '.data.session_id')
    echo -n "$(echo "$start_resp" | jq -r '.data.data')" | base64 -d > "$outfile"

    local file_size offset
    file_size=$(stat -c%s "$infile")
    offset=0
    while [ $offset -lt $file_size ]; do
        local remaining=$((file_size - offset))
        local read_size=$chunk_size
        [ $remaining -lt $read_size ] && read_size=$remaining
        dd if="$infile" bs=1 skip=$offset count=$read_size 2>/dev/null | base64 -w0 > "$TMPDIR/_chunk.b64"
        local resp
        resp=$($BAO write -format=json "gpg/encrypt-stream/session/$sid/update" data=@"$TMPDIR/_chunk.b64" 2>&1)
        echo -n "$(echo "$resp" | jq -r '.data.data')" | base64 -d >> "$outfile"
        offset=$((offset + read_size))
    done

    local fin_resp
    fin_resp=$($BAO write -force -format=json "gpg/encrypt-stream/session/$sid/finalize" 2>&1)
    echo -n "$(echo "$fin_resp" | jq -r '.data.data')" | base64 -d >> "$outfile"
}

# Helper: stream decrypt a binary ciphertext file → plaintext file
# Returns the finalize JSON response on stdout for inspection.
stream_decrypt_file() {
    local key="$1" infile="$2" outfile="$3" signer="${4:-}" chunk_size="${5:-8192}"

    local file_size first_chunk_end
    file_size=$(stat -c%s "$infile")
    first_chunk_end=$chunk_size
    [ $first_chunk_end -gt $file_size ] && first_chunk_end=$file_size

    dd if="$infile" bs=1 count=$first_chunk_end 2>/dev/null | base64 -w0 > "$TMPDIR/_first.b64"

    local start_path="gpg/decrypt-stream/$key/start"
    [ -n "$signer" ] && start_path="gpg/decrypt-stream/$key/sign/$signer/start"

    local start_resp sid
    start_resp=$($BAO write -format=json "$start_path" data=@"$TMPDIR/_first.b64" 2>&1)
    sid=$(echo "$start_resp" | jq -r '.data.session_id')
    echo -n "$(echo "$start_resp" | jq -r '.data.data')" | base64 -d > "$outfile"

    local offset=$first_chunk_end
    while [ $offset -lt $file_size ]; do
        local remaining=$((file_size - offset))
        local read_size=$chunk_size
        [ $remaining -lt $read_size ] && read_size=$remaining
        dd if="$infile" bs=1 skip=$offset count=$read_size 2>/dev/null | base64 -w0 > "$TMPDIR/_chunk.b64"
        local resp
        resp=$($BAO write -format=json "gpg/decrypt-stream/session/$sid/update" data=@"$TMPDIR/_chunk.b64" 2>&1)
        echo -n "$(echo "$resp" | jq -r '.data.data')" | base64 -d >> "$outfile"
        offset=$((offset + read_size))
    done

    local fin_resp
    fin_resp=$($BAO write -force -format=json "gpg/decrypt-stream/session/$sid/finalize" 2>&1)
    echo -n "$(echo "$fin_resp" | jq -r '.data.data')" | base64 -d >> "$outfile"

    # Return finalize response for caller to inspect
    echo "$fin_resp"
}

# --- Non-stream encrypt → stream decrypt ---
begin_test "Non-stream encrypt → stream decrypt"
echo -n "$PLAINTEXT_B64" > "$TMPDIR/_pt.b64"
CT_B64=$($BAO write -field=ciphertext gpg/encrypt/stream-dec-test \
    plaintext=@"$TMPDIR/_pt.b64" format=base64 2>&1)
echo -n "$CT_B64" | base64 -d > "$TMPDIR/ct1.bin"

FIN=$(stream_decrypt_file "stream-dec-test" "$TMPDIR/ct1.bin" "$TMPDIR/pt1.bin")
RECOVERED=$(cat "$TMPDIR/pt1.bin")
assert_eq "$PLAINTEXT" "$RECOVERED" "stream decrypt matches original"

# --- Stream encrypt → stream decrypt (full round-trip) ---
begin_test "Stream encrypt → stream decrypt round-trip"
echo -n "$PLAINTEXT" > "$TMPDIR/pt_in.bin"
stream_encrypt_to_file "stream-dec-test" "$TMPDIR/pt_in.bin" "$TMPDIR/ct2.bin" 4096
FIN=$(stream_decrypt_file "stream-dec-test" "$TMPDIR/ct2.bin" "$TMPDIR/pt2.bin")
RECOVERED=$(cat "$TMPDIR/pt2.bin")
assert_eq "$PLAINTEXT" "$RECOVERED" "full stream round-trip"

# --- Larger file (~50KB) ---
begin_test "Stream decrypt of 50KB file"
dd if=/dev/urandom bs=1024 count=50 of="$TMPDIR/large_pt.bin" 2>/dev/null
ORIGINAL_HASH=$(sha256sum "$TMPDIR/large_pt.bin" | awk '{print $1}')

stream_encrypt_to_file "stream-dec-test" "$TMPDIR/large_pt.bin" "$TMPDIR/large_ct.bin" 8192
FIN=$(stream_decrypt_file "stream-dec-test" "$TMPDIR/large_ct.bin" "$TMPDIR/large_recovered.bin" "" 8192)
RECOVERED_HASH=$(sha256sum "$TMPDIR/large_recovered.bin" | awk '{print $1}')
assert_eq "$ORIGINAL_HASH" "$RECOVERED_HASH" "50KB file SHA-256 match"

# --- With signer verification ---
begin_test "Stream decrypt with signer verification"
echo -n "$PLAINTEXT_B64" > "$TMPDIR/_pt.b64"
CT_B64=$($BAO write -field=ciphertext gpg/encrypt/stream-dec-test/sign/stream-dec-signer \
    plaintext=@"$TMPDIR/_pt.b64" format=base64 2>&1)
echo -n "$CT_B64" | base64 -d > "$TMPDIR/ct_signed.bin"

FIN=$(stream_decrypt_file "stream-dec-test" "$TMPDIR/ct_signed.bin" "$TMPDIR/pt_signed.bin" "stream-dec-signer")
RECOVERED=$(cat "$TMPDIR/pt_signed.bin")
assert_eq "$PLAINTEXT" "$RECOVERED" "signed decrypt matches original"

SIG_VALID=$(echo "$FIN" | jq -r '.data.signature_valid')
assert_eq "true" "$SIG_VALID" "signature_valid=true"

# --- All ciphertext in start (no update needed) ---
begin_test "All ciphertext in start request"
echo -n "$PLAINTEXT_B64" > "$TMPDIR/_pt.b64"
CT_B64=$($BAO write -field=ciphertext gpg/encrypt/stream-dec-test \
    plaintext=@"$TMPDIR/_pt.b64" format=base64 2>&1)
echo -n "$CT_B64" | base64 -d > "$TMPDIR/ct_small.bin"

# Send all ciphertext in start
base64 -w0 "$TMPDIR/ct_small.bin" > "$TMPDIR/_all.b64"
START_RESP=$($BAO write -format=json gpg/decrypt-stream/stream-dec-test/start data=@"$TMPDIR/_all.b64" 2>&1)
SID=$(echo "$START_RESP" | jq -r '.data.session_id')
echo -n "$(echo "$START_RESP" | jq -r '.data.data')" | base64 -d > "$TMPDIR/pt_fromstart.bin"

FIN_RESP=$($BAO write -force -format=json "gpg/decrypt-stream/session/$SID/finalize" 2>&1)
echo -n "$(echo "$FIN_RESP" | jq -r '.data.data')" | base64 -d >> "$TMPDIR/pt_fromstart.bin"

RECOVERED=$(cat "$TMPDIR/pt_fromstart.bin")
assert_eq "$PLAINTEXT" "$RECOVERED" "start-only decrypt works"

# --- Error: missing initial data ---
begin_test "Start without data fails"
assert_cmd_fails "missing initial data rejected" \
    $BAO write gpg/decrypt-stream/stream-dec-test/start

# --- Error: non-existent session ---
begin_test "Update non-existent session fails"
echo "dGVzdA==" > "$TMPDIR/_junk.b64"
assert_cmd_fails "non-existent session rejected" \
    $BAO write gpg/decrypt-stream/session/fakeid/update data=@"$TMPDIR/_junk.b64"

# --- Cleanup ---
delete_key "stream-dec-test"
delete_key "stream-dec-signer"

print_summary
