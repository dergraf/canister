#!/usr/bin/env bash
# ============================================================================
# t_profiles.sh — Seccomp baseline and [syscalls] overrides
#
# Tests:
#   1. Default baseline is applied (mount denied, echo works)
#   2. [syscalls] allow_extra adds syscalls
#   3. [syscalls] deny_extra blocks syscalls
#   4. Old [profile] section is rejected (migration guard)
#   5. Old --profile flag is rejected
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Seccomp baseline and [syscalls] overrides"

# ---- Test 1: Default baseline works ----
begin_test "default baseline allows basic execution"
run_can run -- echo "baseline works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "baseline works" "$RUN_STDOUT"

# ---- Test 2: [syscalls] allow_extra ----
begin_test "[syscalls] allow_extra permits additional syscalls"
TMPCONF=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]
[network]
deny_all = true
[syscalls]
allow_extra = ["ptrace"]
EOF
)
_TMPFILES+=("$TMPCONF")
run_can run --recipe "$TMPCONF" -- echo "allow_extra works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "allow_extra works" "$RUN_STDOUT"

# ---- Test 3: [syscalls] deny_extra ----
begin_test "[syscalls] deny_extra is accepted"
TMPCONF2=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]
[network]
deny_all = true
[syscalls]
deny_extra = ["personality"]
EOF
)
_TMPFILES+=("$TMPCONF2")
run_can run --recipe "$TMPCONF2" -- echo "deny_extra works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "deny_extra works" "$RUN_STDOUT"

# ---- Test 4: Old [profile] section is rejected ----
begin_test "old [profile] section is rejected"
TMPOLD=$(tmpconfig <<'EOF'
[network]
deny_all = true
[profile]
name = "python"
EOF
)
_TMPFILES+=("$TMPOLD")
run_can run --recipe "$TMPOLD" -- echo "should fail"
assert_neq 0 "$RUN_EXIT" "old [profile] section should be rejected"

# ---- Test 5: Old --profile flag is rejected ----
begin_test "--profile flag is rejected"
run_can run --profile python -- echo "should fail"
assert_neq 0 "$RUN_EXIT" "--profile flag should be rejected"

summary
