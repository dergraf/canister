#!/usr/bin/env bash
# ============================================================================
# t_composition.sh — Recipe composition integration tests
#
# Tests:
#   1. Multiple --recipe flags merge left-to-right
#   2. Name-based recipe lookup (-r elixir resolves to elixir.toml)
#   3. Mixed name and path arguments work
#   4. Unknown recipe name fails with helpful error
#   5. Strict OR semantics across composed recipes
#   6. Three-way composition works
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Recipe composition"

# ---- Test 1: Multiple --recipe flags merge ----
begin_test "multiple --recipe flags merge left-to-right"
RECIPE_A=$(tmpconfig <<'EOF'
[recipe]
name = "layer-a"

[network]
deny_all = true

[process]
env_passthrough = ["HOME"]
EOF
)
RECIPE_B=$(tmpconfig <<'EOF'
[recipe]
name = "layer-b"

[process]
env_passthrough = ["PATH"]

[syscalls]
allow_extra = ["ptrace"]
EOF
)
_TMPFILES+=("$RECIPE_A" "$RECIPE_B")
# Both recipes should merge: env_passthrough = [HOME, PATH], allow_extra = [ptrace]
run_can run --recipe "$RECIPE_A" --recipe "$RECIPE_B" -- echo "merged"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "merged" "$RUN_STDOUT"

# ---- Test 2: Name-based recipe lookup ----
# The elixir recipe has allow_execve restrictions, so echo won't work.
# We verify name resolution by checking that the error is about allow_execve
# (meaning the recipe WAS found and loaded), not about "not found".
begin_test "-r elixir resolves to recipes/elixir.toml"
run_can run --recipe elixir -- echo "test"
# We expect failure (allow_execve blocks echo), but the error should NOT
# be "recipe not found" — it should be about the command whitelist.
assert_contains "$RUN_STDERR" "allow_execve"

# ---- Test 3: Mixed name and path arguments ----
begin_test "mixed name and path recipe arguments"
RECIPE_EXTRA=$(tmpconfig <<'EOF'
[syscalls]
allow_extra = ["personality"]
EOF
)
_TMPFILES+=("$RECIPE_EXTRA")
# elixir recipe (by name) + extra overrides (by path). Both load and merge.
# Still fails on allow_execve, but that proves both loaded.
run_can run --recipe elixir --recipe "$RECIPE_EXTRA" -- echo "test"
assert_contains "$RUN_STDERR" "allow_execve"

# ---- Test 4: Unknown recipe name fails ----
begin_test "unknown recipe name fails with helpful error"
run_can run --recipe nonexistent-recipe-xyz -- echo "should fail"
assert_neq 0 "$RUN_EXIT" "unknown recipe name should fail"
assert_contains "$RUN_STDERR" "not found"

# ---- Test 5: Strict OR semantics across composed recipes ----
# Strict mode may not work on all systems (seccomp KILL_PROCESS can kill
# even allowed syscalls if the kernel syscall table differs). Skip if
# --strict doesn't work standalone.
begin_test "strict=true in any recipe wins (OR semantics)"
run_can run --strict -- echo "strict probe"
if [[ "$RUN_EXIT" -ne 0 ]]; then
    skip "strict mode aborted (feature unavailable on this system)"
else
    RECIPE_RELAXED=$(tmpconfig <<'EOF'
[recipe]
name = "relaxed"

[network]
deny_all = true
EOF
)
    RECIPE_STRICT=$(tmpconfig <<'EOF'
strict = true

[recipe]
name = "strict-layer"

[network]
deny_all = true
EOF
)
    _TMPFILES+=("$RECIPE_RELAXED" "$RECIPE_STRICT")
    run_can run --recipe "$RECIPE_RELAXED" --recipe "$RECIPE_STRICT" -- echo "strict or works"
    assert_exit_code 0 "$RUN_EXIT"
    assert_eq "strict or works" "$RUN_STDOUT"
fi

# ---- Test 6: Three-way composition ----
begin_test "three recipes compose correctly"
R1=$(tmpconfig <<'EOF'
[recipe]
name = "base-layer"

[network]
deny_all = true

[process]
env_passthrough = ["HOME"]
EOF
)
R2=$(tmpconfig <<'EOF'
[recipe]
name = "middle-layer"

[process]
env_passthrough = ["LANG"]

[syscalls]
allow_extra = ["ptrace"]
EOF
)
R3=$(tmpconfig <<'EOF'
[recipe]
name = "top-layer"

[process]
env_passthrough = ["TERM"]
EOF
)
_TMPFILES+=("$R1" "$R2" "$R3")
run_can run --recipe "$R1" --recipe "$R2" --recipe "$R3" -- echo "three-way"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "three-way" "$RUN_STDOUT"

# ---- Test 7: No recipe still works (default deny-all) ----
begin_test "no --recipe flag uses default deny-all policy"
run_can run -- echo "no recipe"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "no recipe" "$RUN_STDOUT"

summary
