#!/usr/bin/env bash
# ============================================================================
# t_profiles.sh — Seccomp profile selection and listing
#
# Tests:
#   1. can profiles shows all built-in profiles with counts
#   2. --profile flag selects the right profile
#   3. Profile override via CLI takes precedence over config
#   4. Invalid profile name is rejected
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Seccomp profile selection"

# ---- Test 1: Profiles listing shows counts ----
begin_test "can profiles shows allow and deny counts"
run_can profiles
assert_exit_code 0 "$RUN_EXIT"
# Should show both allowed and denied counts
assert_contains "$RUN_STDOUT" "generic"
assert_contains "$RUN_STDOUT" "python"
assert_contains "$RUN_STDOUT" "node"
assert_contains "$RUN_STDOUT" "elixir"
# Check that counts are shown (format: "N allowed, M denied")
assert_contains "$RUN_STDOUT" "allowed"
assert_contains "$RUN_STDOUT" "denied"

# ---- Test 2: --profile flag works ----
begin_test "--profile python runs with python profile"
run_can run --profile python -- echo "profile test"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "profile test" "$RUN_STDOUT"

# ---- Test 3: --profile overrides config ----
begin_test "--profile overrides config file profile"
TMPCONF=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]
[network]
deny_all = true
[profile]
name = "node"
EOF
)
_TMPFILES+=("$TMPCONF")
# Config says "node" but CLI says "generic"
run_can run --profile generic --config "$TMPCONF" -- echo "override"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "override" "$RUN_STDOUT"

# ---- Test 4: Invalid profile rejected ----
begin_test "invalid profile name is rejected"
run_can run --profile nonexistent -- echo "should fail"
assert_neq 0 "$RUN_EXIT" "invalid profile should be rejected"

summary
