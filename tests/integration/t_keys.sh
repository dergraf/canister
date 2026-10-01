#!/usr/bin/env bash
# ============================================================================
# t_keys.sh — `can keygen` / `can pubkey` (ADR-0021)
#
# No sandbox is launched: these commands only touch a key file, so they
# run anywhere the binary does.
# ============================================================================

source "$(dirname "$0")/lib.sh"
header "Signing keys: keygen and pubkey"

KEY_DIR=$(mktemp -d)
trap 'rm -rf "$KEY_DIR"' EXIT
KEY="${KEY_DIR}/seal.key"

begin_test "can keygen writes a key and prints its public key"
run_can keygen "$KEY"
assert_exit_code 0 "$RUN_EXIT"
GENERATED_PUBKEY="$RUN_STDOUT"

begin_test "the public key is 64 lowercase hex characters"
assert_match "$GENERATED_PUBKEY" '^[0-9a-f]{64}$'

begin_test "the key file is mode 0600"
assert_eq "600" "$(stat -c '%a' "$KEY")"

begin_test "the key file holds the seed as 64 hex characters"
assert_match "$(cat "$KEY")" '^[0-9a-f]{64}$'

begin_test "the seed never reaches stdout"
assert_not_contains "$GENERATED_PUBKEY" "$(cat "$KEY")"

begin_test "can pubkey exits 0"
run_can pubkey "$KEY"
assert_exit_code 0 "$RUN_EXIT"

begin_test "can pubkey prints the same public key keygen printed"
assert_eq "$GENERATED_PUBKEY" "$RUN_STDOUT"

begin_test "can keygen refuses to overwrite an existing key"
run_can keygen "$KEY"
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "overwrote an existing key"
else
    assert_contains "$RUN_STDERR" "--force"
fi

begin_test "the refused overwrite left the key unchanged"
run_can pubkey "$KEY"
assert_eq "$GENERATED_PUBKEY" "$RUN_STDOUT"

begin_test "can keygen --force exits 0"
run_can keygen --force "$KEY"
assert_exit_code 0 "$RUN_EXIT"

begin_test "can keygen --force replaces the key"
assert_neq "$GENERATED_PUBKEY" "$RUN_STDOUT"

# RFC 8032, section 7.1, TEST 1: the seed and the public key it derives.
begin_test "can pubkey derives the RFC 8032 public key from an openssl-style hex seed"
echo "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" > "${KEY_DIR}/rfc8032.key"
run_can pubkey "${KEY_DIR}/rfc8032.key"
assert_eq "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" "$RUN_STDOUT"

begin_test "can pubkey rejects a malformed key file"
echo "not a key" > "${KEY_DIR}/bad.key"
run_can pubkey "${KEY_DIR}/bad.key"
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "accepted a malformed key"
else
    pass
fi

summary
