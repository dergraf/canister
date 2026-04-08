#!/usr/bin/env bash
# ============================================================================
# t_recipes.sh — Recipe system integration tests
#
# Tests:
#   1. can recipes lists discovered recipes
#   2. can recipes lists built-in baselines
#   3. --recipe flag works (loads a recipe TOML)
#   4. --recipe with --profile overrides baseline
#   5. Recipe with unknown baseline is rejected
#   6. Plain policy (no [recipe] section) works via --recipe
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Recipe system"

# ---- Test 1: can recipes lists discovered recipes ----
begin_test "can recipes lists discovered recipes"
run_can recipes
assert_exit_code 0 "$RUN_EXIT"
# Should find the example recipes in ./recipes/
assert_contains "$RUN_STDOUT" "Discovered recipes"

# ---- Test 2: can recipes lists baselines ----
begin_test "can recipes lists built-in baselines"
assert_contains "$RUN_STDOUT" "Built-in baselines"
assert_contains "$RUN_STDOUT" "generic"
assert_contains "$RUN_STDOUT" "python"
assert_contains "$RUN_STDOUT" "node"
assert_contains "$RUN_STDOUT" "elixir"

# ---- Test 3: --recipe flag works ----
begin_test "--recipe loads a recipe TOML file"
TMPRECIPE=$(tmpconfig <<'EOF'
[recipe]
name = "test-recipe"
description = "Integration test recipe"
baseline = "generic"

[network]
deny_all = true
EOF
)
_TMPFILES+=("$TMPRECIPE")
run_can run --recipe "$TMPRECIPE" -- echo "recipe works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "recipe works" "$RUN_STDOUT"

# ---- Test 4: --recipe with --profile overrides baseline ----
begin_test "--profile overrides recipe baseline"
TMPRECIPE2=$(tmpconfig <<'EOF'
[recipe]
name = "override-test"
baseline = "python"
EOF
)
_TMPFILES+=("$TMPRECIPE2")
# Recipe says "python" but --profile says "generic"
run_can run --recipe "$TMPRECIPE2" --profile generic -- echo "override"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "override" "$RUN_STDOUT"

# ---- Test 5: Unknown baseline is rejected ----
begin_test "recipe with unknown baseline is rejected"
TMPBAD=$(tmpconfig <<'EOF'
[recipe]
baseline = "nonexistent"
EOF
)
_TMPFILES+=("$TMPBAD")
run_can run --recipe "$TMPBAD" -- echo "should fail"
assert_neq 0 "$RUN_EXIT" "unknown baseline should be rejected"
assert_contains "$RUN_STDERR" "nonexistent"

# ---- Test 6: Plain policy without [recipe] section works ----
begin_test "plain policy (no [recipe] section) works via --recipe"
TMPPLAIN=$(tmpconfig <<'EOF'
[network]
deny_all = true
[profile]
name = "generic"
EOF
)
_TMPFILES+=("$TMPPLAIN")
run_can run --recipe "$TMPPLAIN" -- echo "plain works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "plain works" "$RUN_STDOUT"

summary
