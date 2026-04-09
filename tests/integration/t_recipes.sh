#!/usr/bin/env bash
# ============================================================================
# t_recipes.sh — Recipe system integration tests
#
# Tests:
#   1. can recipe list lists discovered recipes
#   2. can recipe list shows default baseline info
#   3. --recipe flag works (loads a recipe TOML)
#   4. Recipe with [syscalls] allow_extra works
#   5. Recipe with unknown fields is rejected (deny_unknown_fields)
#   6. Plain policy (no [recipe] section) works via --recipe
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Recipe system"

# ---- Test 1: can recipe list lists discovered recipes ----
begin_test "can recipe list lists discovered recipes"
run_can recipe list
assert_exit_code 0 "$RUN_EXIT"
# Should find the example recipes in ./recipes/
assert_contains "$RUN_STDOUT" "Discovered recipes"

# ---- Test 2: can recipe list shows default baseline ----
begin_test "can recipe list shows default baseline info"
assert_contains "$RUN_STDOUT" "Default baseline"
assert_contains "$RUN_STDOUT" "allowed"
assert_contains "$RUN_STDOUT" "denied"

# ---- Test 3: --recipe flag works ----
begin_test "--recipe loads a recipe TOML file"
TMPRECIPE=$(tmpconfig <<'EOF'
[recipe]
name = "test-recipe"
description = "Integration test recipe"

[network]
deny_all = true
EOF
)
_TMPFILES+=("$TMPRECIPE")
run_can run --recipe "$TMPRECIPE" -- echo "recipe works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "recipe works" "$RUN_STDOUT"

# ---- Test 4: Recipe with [syscalls] allow_extra ----
begin_test "recipe with [syscalls] allow_extra works"
TMPRECIPE2=$(tmpconfig <<'EOF'
[recipe]
name = "syscall-test"
description = "Tests allow_extra override"

[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]

[network]
deny_all = true

[syscalls]
allow_extra = ["ptrace", "personality"]
EOF
)
_TMPFILES+=("$TMPRECIPE2")
run_can run --recipe "$TMPRECIPE2" -- echo "allow_extra works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "allow_extra works" "$RUN_STDOUT"

# ---- Test 5: Unknown fields rejected (migration guard) ----
begin_test "recipe with unknown fields is rejected"
TMPBAD=$(tmpconfig <<'EOF'
[recipe]
name = "bad-recipe"
baseline = "python"
EOF
)
_TMPFILES+=("$TMPBAD")
run_can run --recipe "$TMPBAD" -- echo "should fail"
assert_neq 0 "$RUN_EXIT" "unknown field 'baseline' should be rejected"

# ---- Test 6: Plain policy without [recipe] section works ----
begin_test "plain policy (no [recipe] section) works via --recipe"
TMPPLAIN=$(tmpconfig <<'EOF'
[network]
deny_all = true
[syscalls]
EOF
)
_TMPFILES+=("$TMPPLAIN")
run_can run --recipe "$TMPPLAIN" -- echo "plain works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "plain works" "$RUN_STDOUT"

summary
