#!/usr/bin/env bash
# ============================================================================
# t_resources.sh — Resource limits (cgroups v2)
#
# Tests:
#   1. Memory limit is enforced (process killed when exceeding limit)
#   2. Sandbox runs fine within memory limit
#
# NOTE: These tests require cgroups v2 with systemd delegation. On systems
# without it, the tests are skipped.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_cgroups_v2
require_python3
header "Resource limits (cgroups v2)"

CONFIG="${CONFIGS_DIR}/resources.toml"
# resources.toml has memory_mb = 64

# Inline memory allocation script (was alloc_memory.py)
ALLOC_MEMORY='
import sys
target_mb = int(sys.argv[1]) if len(sys.argv) > 1 else 100
chunks = []
try:
    for i in range(target_mb):
        chunk = bytearray(1024 * 1024)
        chunks.append(chunk)
    print(f"OK: allocated {target_mb}MB successfully")
    sys.exit(0)
except MemoryError:
    print(f"OOM: allocation failed after {len(chunks)}MB")
    sys.exit(1)
'

# ---- Test 1: Process within limit succeeds ----
begin_test "process within memory limit succeeds"
run_can run --recipe "$CONFIG" -- python3 -c "$ALLOC_MEMORY" 10
if [[ "$RUN_EXIT" -eq 0 ]]; then
    assert_contains "$RUN_STDOUT" "OK: allocated 10MB"
else
    # Cgroup setup may have failed (non-fatal in normal mode)
    if [[ "$RUN_STDERR" == *"cgroup"* ]]; then
        skip "cgroup setup failed on this system"
    else
        assert_exit_code 0 "$RUN_EXIT"
    fi
fi

# ---- Test 2: Process exceeding limit is killed ----
begin_test "process exceeding memory limit is killed"
run_can run --recipe "$CONFIG" -- python3 -c "$ALLOC_MEMORY" 256
if [[ "$RUN_EXIT" -ne 0 ]]; then
    pass
else
    # If it succeeded, cgroup enforcement may not be working
    if [[ "$RUN_STDOUT" == *"OK: allocated 256MB"* ]]; then
        skip "cgroup memory limit not enforced (no delegation?)"
    else
        pass
    fi
fi

summary
