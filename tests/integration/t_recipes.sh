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
#   7. Name lookup recurses into category subdirs
#   8. Missing name reports the search path
#   9. Name collision within one search dir is reported
#  10. recipe explain shows filesystem paths and env vars
#  11. recipe explain with direct file path works
#  12. recipe list groups output by category
#  13. recipe suggest matches recipe by basename
#  14. recipe suggest with unknown binary suggests nothing
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Recipe system"

# ---- Test 1: can recipe list lists discovered recipes ----
begin_test "can recipe list lists discovered recipes"
run_can recipe list
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "Recipes:"

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
egress = "proxy-only"
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
egress = "proxy-only"

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
egress = "proxy-only"
[syscalls]
EOF
)
_TMPFILES+=("$TMPPLAIN")
run_can run --recipe "$TMPPLAIN" -- echo "plain works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "plain works" "$RUN_STDOUT"

# ============================================================================
# Recursive name lookup
#
# Recipes live in category subdirectories under the recipe search path.
# Name lookup walks the tree, so a project-local recipe under any depth
# resolves the same way as one at the search-dir root.
# ============================================================================

PROJDIR=$(mktemp -d)
_TMPFILES+=("$PROJDIR")
mkdir -p "$PROJDIR/.canister/extras"
cat >"$PROJDIR/.canister/extras/example.toml" <<'EOF'
[recipe]
name = "example"
description = "Test fixture for recursive name resolution"
version = "1"

[filesystem]
allow = ["/tmp/example-marker-path"]

[process]
env_passthrough = ["EXAMPLE_TEST_VAR"]
EOF

# ---- Test 7: name lookup recurses into category subdirs ----
begin_test "bare-name lookup resolves from .canister/extras/example.toml"
pushd "$PROJDIR" >/dev/null
run_can recipe show -r example
popd >/dev/null
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *"/tmp/example-marker-path"* ]]; then
    fail "expected the fixture's allow path in the merged output; got: ${RUN_STDOUT:0:200}"
else
    pass
fi

# ---- Test 8: missing recipe reports searched path ----
begin_test "missing recipe reports recursive search path"
run_can recipe show -r definitely-no-such-recipe
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "expected non-zero exit on missing recipe"
elif [[ "$RUN_STDERR" != *"definitely-no-such-recipe.toml"* ]] && \
     [[ "$RUN_STDOUT" != *"definitely-no-such-recipe.toml"* ]]; then
    fail "expected filename in error; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDERR" != *"recursively"* ]] && [[ "$RUN_STDOUT" != *"recursively"* ]]; then
    fail "expected 'recursively' hint; stderr: ${RUN_STDERR}"
else
    pass
fi

# ---- Test 9: name collision within one search dir is reported ----
DUPDIR=$(mktemp -d)
_TMPFILES+=("$DUPDIR")
mkdir -p "$DUPDIR/.canister/catA" "$DUPDIR/.canister/catB"
cat >"$DUPDIR/.canister/catA/dup.toml" <<'EOF'
[recipe]
name = "dup"
EOF
cat >"$DUPDIR/.canister/catB/dup.toml" <<'EOF'
[recipe]
name = "dup"
EOF
begin_test "name collision across category dirs is reported"
pushd "$DUPDIR" >/dev/null
run_can recipe show -r dup
popd >/dev/null
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "expected non-zero exit on ambiguous recipe"
elif [[ "$RUN_STDERR" != *"ambiguous"* ]] && [[ "$RUN_STDOUT" != *"ambiguous"* ]]; then
    fail "expected 'ambiguous' in error; stderr: ${RUN_STDERR}"
else
    pass
fi

# ============================================================================
# recipe explain / list / suggest subcommands
# ============================================================================

# ---- Test 10: recipe explain shows filesystem and env sections ----
begin_test "recipe explain shows filesystem paths and env vars"
pushd "$PROJDIR" >/dev/null
run_can recipe explain -r example
popd >/dev/null
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *"/tmp/example-marker-path"* ]]; then
    fail "expected marker path in explain output; got: ${RUN_STDOUT:0:300}"
elif [[ "$RUN_STDOUT" != *"EXAMPLE_TEST_VAR"* ]]; then
    fail "expected env var in explain output; got: ${RUN_STDOUT:0:300}"
elif [[ "$RUN_STDOUT" != *"read-only"* ]]; then
    fail "expected 'read-only' label in explain output; got: ${RUN_STDOUT:0:300}"
else
    pass
fi

# ---- Test 11: recipe explain with file path works ----
begin_test "recipe explain with direct file path"
run_can recipe explain -r "$PROJDIR/.canister/extras/example.toml"
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *"example"* ]]; then
    fail "expected recipe name in output; got: ${RUN_STDOUT:0:200}"
else
    pass
fi

# ---- Test 12: recipe list groups output by category ----
begin_test "recipe list groups output by category"
pushd "$PROJDIR" >/dev/null
run_can recipe list
popd >/dev/null
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *"[extras]"* ]]; then
    fail "expected category header '[extras]'; got: ${RUN_STDOUT:0:500}"
elif [[ "$RUN_STDOUT" != *"example"* ]]; then
    fail "expected fixture recipe 'example' in listing; got: ${RUN_STDOUT:0:500}"
else
    pass
fi

# ---- Test 13: recipe suggest with known binary matches recipe by basename ----
FAKEBIN=$(mktemp -d)
_TMPFILES+=("$FAKEBIN")
touch "$FAKEBIN/example"
chmod +x "$FAKEBIN/example"
begin_test "recipe suggest matches recipe by basename"
pushd "$PROJDIR" >/dev/null
PATH="$FAKEBIN:$PATH" run_can recipe suggest example
popd >/dev/null
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *'recipes = ["example"]'* ]]; then
    fail "expected recipes = [\"example\"]; got: ${RUN_STDOUT}"
else
    pass
fi

# ---- Test 14: recipe suggest with unknown binary suggests nothing ----
begin_test "recipe suggest with unknown binary"
run_can recipe suggest no-such-binary-ever
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *"No matching recipes"* ]]; then
    fail "expected 'No matching recipes'; got: ${RUN_STDOUT}"
else
    pass
fi

summary
