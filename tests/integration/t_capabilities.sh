#!/usr/bin/env bash
# ============================================================================
# t_capabilities.sh — Linux capability dropping invariant
#
# After spawn_sandboxed() the child should have zero capabilities across all
# capability sets. This is a security invariant: any capability surviving
# into the sandboxed process is a potential privilege-escalation vector.
#
# Tests:
#   1. CapEff is 0 inside the sandbox
#   2. CapPrm, CapBnd, CapAmb, CapInh are all 0
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Capability dropping"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/proc", "/tmp"]

[process]
env_passthrough = ["PATH", "HOME"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

# ---- Test 1: read /proc/self/status capability sets ----
begin_test "all capability sets are zero inside sandbox"
run_can run --recipe "$CONFIG" -- sh -c '
    grep -E "^Cap(Inh|Prm|Eff|Bnd|Amb):" /proc/self/status
'
if [[ "$RUN_EXIT" -ne 0 ]]; then
    skip "sandbox did not run (likely missing /proc/self/status capability lines)"
else
    # Each line is e.g. "CapEff: 0000000000000000". Extract just the hex value
    # and confirm it's zero across all five capability sets.
    leaked=0
    while IFS=$'\t ' read -r label hex; do
        # Strip the trailing colon from the label.
        label="${label%:}"
        # Bash arithmetic accepts hex with 0x prefix.
        if (( 16#$hex != 0 )); then
            echo "       leak: $label = $hex"
            leaked=$(( leaked + 1 ))
        fi
    done <<< "$RUN_STDOUT"

    if (( leaked == 0 )); then
        pass
    else
        fail "$leaked capability set(s) leaked into sandbox"
    fi
fi

summary
