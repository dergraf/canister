#!/usr/bin/env bash
# ============================================================================
# t_env_expansion.sh — Environment variable expansion in recipes
#
# Verifies that $VAR, ${VAR}, and $$ patterns in recipe TOML files are
# expanded before being applied as sandbox policy. Expansion happens at
# config resolution time (in the host process), so host env vars are used.
#
# Tests:
#   1. $VAR in allow_execve is expanded (positive match)
#   2. Unexpanded $VAR would NOT match (proves expansion is needed)
#   3. ${BRACED} syntax works
#   4. $$ escapes to literal $
#   5. Multiple env vars in filesystem paths
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Environment variable expansion in recipes"

# ---- Test 1: env var in allow_execve enables the right binary ----
# Set a custom env var to /usr/bin, then use it in allow_execve.
# If expansion works, echo is allowed. If not, it would look for
# a literal "$_CANISTER_BINDIR/echo" which doesn't exist → denied.
begin_test "env var in allow_execve is expanded (command succeeds)"
export _CANISTER_BINDIR="/usr/bin"
RECIPE=$(tmpconfig <<'EOF'
[recipe]
name = "env-execve-test"

[process]
allow_execve = ["$_CANISTER_BINDIR/echo"]
EOF
)
_TMPFILES+=("$RECIPE")
run_can run --recipe "$RECIPE" -- echo "expanded"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "expanded" "$RUN_STDOUT"
unset _CANISTER_BINDIR

# ---- Test 2: without the env var set, same recipe fails ----
# Proves that the literal string "$_CANISTER_BINDIR/echo" would not match.
begin_test "unset env var causes allow_execve mismatch (command denied)"
unset _CANISTER_BINDIR 2>/dev/null || true
RECIPE2=$(tmpconfig <<'EOF'
[recipe]
name = "env-execve-unset"

[process]
allow_execve = ["$_CANISTER_BINDIR/echo"]
EOF
)
_TMPFILES+=("$RECIPE2")
run_can run --recipe "$RECIPE2" -- echo "should fail"
assert_neq 0 "$RUN_EXIT"
assert_contains "$RUN_STDERR" "allow_execve"

# ---- Test 3: ${BRACED} syntax in allow_execve ----
begin_test "\${BRACED} syntax expands correctly in allow_execve"
export _CANISTER_BINDIR2="/usr/bin"
RECIPE3=$(tmpconfig <<'EOF'
[recipe]
name = "env-braced-test"

[process]
allow_execve = ["${_CANISTER_BINDIR2}/echo"]
EOF
)
_TMPFILES+=("$RECIPE3")
run_can run --recipe "$RECIPE3" -- echo "braced ok"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "braced ok" "$RUN_STDOUT"
unset _CANISTER_BINDIR2

# ---- Test 4: $$ produces literal dollar sign ----
# allow_execve = ["/usr/bin/echo"] combined with $$ in a path won't
# affect allow_execve, but we can test $$ in filesystem.allow.
# A recipe with filesystem.allow = ["/tmp/$$test"] should expand to
# "/tmp/$test". Since this is a harmless extra mount, the sandbox
# still runs. We verify indirectly that $$ doesn't break parsing.
begin_test "\$\$ escape does not break recipe loading"
RECIPE4=$(tmpconfig <<'EOF'
[recipe]
name = "dollar-escape-test"

[filesystem]
allow = ["/tmp/$$literal-path"]
EOF
)
_TMPFILES+=("$RECIPE4")
run_can run --recipe "$RECIPE4" -- echo "dollar ok"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "dollar ok" "$RUN_STDOUT"

# ---- Test 5: $HOME in filesystem.allow ----
# Use $HOME in filesystem.allow. The sandbox should start fine.
# We just verify the recipe loads and the sandbox runs — the
# actual mount may be a no-op if the dir doesn't exist.
begin_test "\$HOME in filesystem.allow does not break sandbox"
RECIPE5=$(tmpconfig <<'EOF'
[recipe]
name = "home-fs-test"

[filesystem]
allow = ["$HOME/.config/canister"]
deny = ["$HOME/.ssh"]
EOF
)
_TMPFILES+=("$RECIPE5")
run_can run --recipe "$RECIPE5" -- echo "home fs ok"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "home fs ok" "$RUN_STDOUT"

summary
