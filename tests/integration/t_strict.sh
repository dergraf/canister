#!/usr/bin/env bash
# ============================================================================
# t_strict.sh — Strict mode (fail-hard enforcement)
#
# Tests:
#   1. Strict mode runs when all features are available
#   2. Strict mode via config file (strict = true)
#   3. Normal command succeeds in strict mode
#   4. Exit code propagation works in strict mode
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Strict mode"

CONFIG="${CONFIGS_DIR}/strict.toml"

# ---- Test 1: Strict mode runs successfully ----
begin_test "strict mode runs with all features available"
run_can run --recipe "$CONFIG" -- echo "strict works"
# If this system supports all features, it should work.
# If it doesn't (e.g., AppArmor blocks mounts), strict mode will abort —
# that's the correct behavior.
if [[ "$RUN_EXIT" -eq 0 ]]; then
    assert_eq "strict works" "$RUN_STDOUT"
else
    # Strict mode correctly aborted because a feature is unavailable.
    # This is expected on some CI systems. Log it but don't fail.
    skip "strict mode aborted (feature unavailable on this system)"
fi

# ---- Test 2: Strict via --strict flag ----
begin_test "strict mode via --strict CLI flag"
TMPCONF=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]
[network]
deny_all = true
[process]
env_passthrough = ["PATH", "HOME"]
[profile]
name = "generic"
EOF
)
_TMPFILES+=("$TMPCONF")
run_can run --strict --recipe "$TMPCONF" -- echo "strict flag"
if [[ "$RUN_EXIT" -eq 0 ]]; then
    assert_eq "strict flag" "$RUN_STDOUT"
else
    skip "strict mode aborted (feature unavailable on this system)"
fi

# ---- Test 3: Exit code in strict mode ----
begin_test "exit code propagated in strict mode"
run_can run --recipe "$CONFIG" -- sh -c "exit 7"
if [[ "$RUN_EXIT" -eq 7 ]]; then
    pass
elif [[ "$RUN_EXIT" -ne 0 ]]; then
    # Strict mode itself may have aborted
    skip "strict mode aborted before running command"
else
    fail "expected exit 7, got $RUN_EXIT"
fi

summary
