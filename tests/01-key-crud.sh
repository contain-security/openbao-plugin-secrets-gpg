#!/usr/bin/env bash
# Test: Key CRUD operations
source "$(dirname "$0")/common.sh"
check_prerequisites

echo "============================================="
echo "  01 - Key CRUD Operations"
echo "============================================="
echo ""

# --- Create ---
begin_test "Create a generated key (exportable)"
delete_key "crud-test"
assert_cmd_succeeds "create key" \
    $BAO write gpg/keys/crud-test real_name="CRUD Test" email="crud@test.com" generate=true key_bits=2048 exportable=true

begin_test "Read key metadata"
FP=$($BAO read -field=fingerprint gpg/keys/crud-test 2>&1)
assert_not_empty "$FP" "fingerprint is returned"

begin_test "Read public key"
PUBKEY=$($BAO read -field=public_key gpg/keys/crud-test 2>&1)
assert_contains "$PUBKEY" "BEGIN PGP PUBLIC KEY BLOCK" "public key is armored"

# --- List ---
begin_test "List keys"
LIST=$($BAO list gpg/keys 2>&1)
assert_contains "$LIST" "crud-test" "key appears in list"

# --- Config endpoint ---
begin_test "Config endpoint accepts valid key"
# Config is a stub — just validates key exists. Pass any data to satisfy bao write.
if $BAO write gpg/keys/crud-test/config >/dev/null 2>&1; then
    pass "config endpoint works"
else
    # Some versions of bao return non-zero for empty responses; check via API
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Vault-Token: $BAO_TOKEN" \
        --data '{}' \
        "$BAO_ADDR/v1/gpg/keys/crud-test/config")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        pass "config endpoint works (via API)"
    else
        fail "config endpoint works (HTTP $HTTP_CODE)"
    fi
fi

# --- Export ---
begin_test "Export key"
PRIVKEY=$($BAO read -field=key gpg/export/crud-test 2>&1)
assert_contains "$PRIVKEY" "BEGIN PGP PRIVATE KEY BLOCK" "private key is armored"

# --- Export non-exportable key ---
begin_test "Export non-exportable key fails"
ensure_key "noexport-test" "NoExport" "noexport@test.com"
assert_cmd_fails "export non-exportable key" \
    $BAO read gpg/export/noexport-test

# --- Duplicate create ---
begin_test "Duplicate key create fails"
assert_cmd_fails "duplicate key rejected" \
    $BAO write gpg/keys/crud-test real_name="Dupe" generate=true key_bits=2048

# --- Delete ---
begin_test "Delete key"
assert_cmd_succeeds "delete key" \
    $BAO delete gpg/keys/crud-test

begin_test "Read deleted key fails"
assert_cmd_fails "deleted key not readable" \
    $BAO read gpg/keys/crud-test

# --- Cleanup ---
delete_key "noexport-test"

print_summary
