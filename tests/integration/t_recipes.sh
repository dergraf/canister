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
#   7. tool:NAME resolves to <search-path>/tools/NAME.toml
#   8. tool:nonexistent fails with `can init` hint
#   9. tool: (bare) fails with a clear error
#  10. tool:foo/bar fails with "bare identifier" error (no slashes)
#  11. recipe explain shows filesystem paths and env vars
#  12. recipe explain with direct file path works
#  13. recipe list groups tool shortcuts separately
#  14. recipe suggest matches tool recipe by basename
#  15. recipe suggest with unknown binary suggests nothing
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Recipe system"

# ---- Test 1: can recipe list lists discovered recipes ----
begin_test "can recipe list lists discovered recipes"
run_can recipe list
assert_exit_code 0 "$RUN_EXIT"
# Should find the example recipes in ./recipes/
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
# tool: namespace resolution
#
# These tests pin the resolver behaviour for tool-prefixed recipes. They
# use a temp `.canister/tools/<name>.toml` so the search-path lookup is
# exercised end-to-end without depending on `can init` having populated
# ~/.config/canister/recipes/.
# ============================================================================

TOOLDIR=$(mktemp -d)
_TMPFILES+=("$TOOLDIR")
mkdir -p "$TOOLDIR/.canister/tools"
cat >"$TOOLDIR/.canister/tools/example.toml" <<'EOF'
[recipe]
name = "tool:example"
description = "Test fixture for tool: namespace resolution"
version = "1"

[filesystem]
allow = ["/tmp/example-marker-path"]

[process]
env_passthrough = ["EXAMPLE_TEST_VAR"]
EOF

# ---- Test 7: tool:NAME resolves via tools/ subdirectory ----
begin_test "tool:example resolves to .canister/tools/example.toml"
pushd "$TOOLDIR" >/dev/null
run_can recipe show -r tool:example
popd >/dev/null
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *"/tmp/example-marker-path"* ]]; then
    fail "expected the fixture's allow path in the merged output; got: ${RUN_STDOUT:0:200}"
else
    pass
fi

# ---- Test 8: tool:<missing> fails with init hint ----
begin_test "tool:does-not-exist fails with 'can init' hint"
pushd "$TOOLDIR" >/dev/null
run_can recipe show -r tool:does-not-exist
popd >/dev/null
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "expected non-zero exit on missing tool recipe"
elif [[ "$RUN_STDERR" != *"can init"* ]] && [[ "$RUN_STDOUT" != *"can init"* ]]; then
    fail "expected 'can init' hint in error output; stderr: ${RUN_STDERR}"
else
    pass
fi

# ---- Test 9: bare tool: rejected ----
begin_test "bare 'tool:' rejected with clear error"
run_can recipe show -r "tool:"
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "expected non-zero exit on bare 'tool:'"
elif [[ "$RUN_STDERR" != *"bare 'tool:'"* ]] && [[ "$RUN_STDOUT" != *"bare 'tool:'"* ]]; then
    fail "expected 'bare tool:' error; stderr: ${RUN_STDERR}; stdout: ${RUN_STDOUT}"
else
    pass
fi

# ---- Test 10: tool name with slash rejected ----
begin_test "tool:foo/bar rejected (no slashes in tool names)"
run_can recipe show -r "tool:foo/bar"
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "expected non-zero exit on tool:foo/bar"
elif [[ "$RUN_STDERR" != *"bare identifier"* ]] && [[ "$RUN_STDOUT" != *"bare identifier"* ]]; then
    fail "expected 'bare identifier' error; stderr: ${RUN_STDERR}"
else
    pass
fi

# ============================================================================
# recipe explain / suggest subcommands
# ============================================================================

# ---- Test 11: recipe explain shows filesystem and env sections ----
begin_test "recipe explain shows filesystem paths and env vars"
pushd "$TOOLDIR" >/dev/null
run_can recipe explain -r tool:example
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

# ---- Test 12: recipe explain with file path works ----
begin_test "recipe explain with direct file path"
run_can recipe explain -r "$TOOLDIR/.canister/tools/example.toml"
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *"tool:example"* ]]; then
    fail "expected recipe name in output; got: ${RUN_STDOUT:0:200}"
else
    pass
fi

# ---- Test 13: recipe list groups tool shortcuts separately ----
begin_test "recipe list groups tool shortcuts"
pushd "$TOOLDIR" >/dev/null
run_can recipe list
popd >/dev/null
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *"Tool shortcuts:"* ]]; then
    fail "expected 'Tool shortcuts:' heading; got: ${RUN_STDOUT:0:500}"
elif [[ "$RUN_STDOUT" != *"tool:example"* ]]; then
    fail "expected tool:example in tool shortcuts section; got: ${RUN_STDOUT:0:500}"
else
    pass
fi

# ---- Test 14: recipe suggest with known binary matches tool recipe ----
# Create a fake binary so `which`-style resolution finds it by basename.
FAKEBIN=$(mktemp -d)
_TMPFILES+=("$FAKEBIN")
touch "$FAKEBIN/example"
chmod +x "$FAKEBIN/example"
begin_test "recipe suggest matches tool recipe by basename"
pushd "$TOOLDIR" >/dev/null
PATH="$FAKEBIN:$PATH" run_can recipe suggest example
popd >/dev/null
if [[ "$RUN_EXIT" -ne 0 ]]; then
    fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
elif [[ "$RUN_STDOUT" != *'tools = ["example"]'* ]]; then
    fail "expected tools = [\"example\"]; got: ${RUN_STDOUT}"
else
    pass
fi

# ---- Test 15: recipe suggest with unknown binary suggests nothing ----
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
