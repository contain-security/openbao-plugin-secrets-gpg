#!/usr/bin/env bash
# Test: Streaming encrypt operations
source "$(dirname "$0")/common.sh"
check_server
check_plugin

echo "============================================="
echo "  05 - Streaming Encrypt"
echo "============================================="
echo ""

ensure_key "stream-enc-test" "Stream Enc" "streamenc@test.com" "exportable=true"
ensure_key "stream-signer" "Stream Signer" "streamsigner@test.com"

# Helper: stream encrypt a file, output binary ciphertext to a file
# Usage: stream_encrypt <key> <infile> <outfile> [chunk_size]
stream_encrypt_file() {
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

# Helper: stream encrypt with signer
stream_encrypt_file_signed() {
    local key="$1" infile="$2" outfile="$3" signer="$4" chunk_size="${5:-8192}"

    local start_resp sid
    start_resp=$($BAO write -format=json "gpg/encrypt-stream/$key/start" signer_key_name="$signer" 2>&1)
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

PLAINTEXT="Streaming encryption test data with enough content to be meaningful"

# --- Basic streaming encrypt → non-streaming decrypt ---
begin_test "Stream encrypt → non-stream decrypt"
echo -n "$PLAINTEXT" > "$TMPDIR/pt_in.txt"
stream_encrypt_file "stream-enc-test" "$TMPDIR/pt_in.txt" "$TMPDIR/ct1.bin"

base64 -w0 "$TMPDIR/ct1.bin" > "$TMPDIR/ct1.b64"
RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/stream-enc-test \
    ciphertext=@"$TMPDIR/ct1.b64" format=base64 2>&1)
RECOVERED=$(echo "$RECOVERED_B64" | base64 -d)
assert_eq "$PLAINTEXT" "$RECOVERED" "decrypt matches original"

# --- Chunked streaming encrypt (~50KB file) ---
begin_test "Chunked stream encrypt of 50KB file"
dd if=/dev/urandom bs=1024 count=50 of="$TMPDIR/enc_testfile.bin" 2>/dev/null
ORIGINAL_HASH=$(sha256sum "$TMPDIR/enc_testfile.bin" | awk '{print $1}')

stream_encrypt_file "stream-enc-test" "$TMPDIR/enc_testfile.bin" "$TMPDIR/enc_chunks.bin" 8192

base64 -w0 "$TMPDIR/enc_chunks.bin" > "$TMPDIR/enc_chunks.b64"
RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/stream-enc-test \
    ciphertext=@"$TMPDIR/enc_chunks.b64" format=base64 2>&1)
echo -n "$RECOVERED_B64" | base64 -d > "$TMPDIR/enc_recovered.bin"
RECOVERED_HASH=$(sha256sum "$TMPDIR/enc_recovered.bin" | awk '{print $1}')
assert_eq "$ORIGINAL_HASH" "$RECOVERED_HASH" "50KB file SHA-256 match"

# --- Stream encrypt with signer ---
begin_test "Stream encrypt with signer → decrypt with signer verify"
echo -n "$PLAINTEXT" > "$TMPDIR/pt_signed.txt"
stream_encrypt_file_signed "stream-enc-test" "$TMPDIR/pt_signed.txt" "$TMPDIR/ct_signed.bin" "stream-signer"

base64 -w0 "$TMPDIR/ct_signed.bin" > "$TMPDIR/ct_signed.b64"
RECOVERED_B64=$($BAO write -field=plaintext gpg/decrypt/stream-enc-test \
    ciphertext=@"$TMPDIR/ct_signed.b64" format=base64 signer_key_name=stream-signer 2>&1)
RECOVERED=$(echo "$RECOVERED_B64" | base64 -d)
assert_eq "$PLAINTEXT" "$RECOVERED" "signed stream encrypt round-trip"

# --- GnuPG decrypt of stream-encrypted data ---
begin_test "GnuPG decrypts stream-encrypted data"
EXPORT_GNUPGHOME=$(mktemp -d)
PRIVKEY=$($BAO read -field=key gpg/export/stream-enc-test 2>&1)
echo "$PRIVKEY" | GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --import 2>/dev/null

echo -n "$PLAINTEXT" > "$TMPDIR/pt_gpg.txt"
stream_encrypt_file "stream-enc-test" "$TMPDIR/pt_gpg.txt" "$TMPDIR/gpg_test_enc.gpg"

RECOVERED=$(GNUPGHOME="$EXPORT_GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase '' --decrypt "$TMPDIR/gpg_test_enc.gpg" 2>/dev/null)
assert_eq "$PLAINTEXT" "$RECOVERED" "gpg decrypts stream-encrypted data"
rm -rf "$EXPORT_GNUPGHOME"

# --- Error: double finalize ---
begin_test "Double finalize fails"
START_RESP=$($BAO write -force -format=json gpg/encrypt-stream/stream-enc-test/start 2>&1)
SID=$(echo "$START_RESP" | jq -r '.data.session_id')
$BAO write -force "gpg/encrypt-stream/session/$SID/finalize" >/dev/null 2>&1
assert_cmd_fails "double finalize rejected" \
    $BAO write -force "gpg/encrypt-stream/session/$SID/finalize"

# --- Error: non-existent key ---
begin_test "Non-existent key fails"
assert_cmd_fails "non-existent key rejected" \
    $BAO write gpg/encrypt-stream/nokey/start

# --- Cleanup ---
delete_key "stream-enc-test"
delete_key "stream-signer"

print_summary
