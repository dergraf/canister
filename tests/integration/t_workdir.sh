#!/usr/bin/env bash
# ============================================================================
# t_workdir.sh — The working directory's access (ADR-0024)
#
# Tests:
#   1. By default the working directory is writable
#   2. workdir = "read" makes it read-only
#   3. A write entry inside a read-only working directory stays writable
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Working directory access"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; cleanup' EXIT
mkdir -p "$WORK/notes"
cd "$WORK" || exit 1

# ---- Test 1: writable by default ----
begin_test "the working directory is writable by default"
run_can run -- sh -c 'echo x > default.txt && echo wrote'
assert_eq "wrote" "$RUN_STDOUT"

# ---- Test 2: read-only ----
READ_ONLY=$(tmpconfig <<'TOML'
[filesystem]
workdir = "read"
TOML
)
_TMPFILES+=("$READ_ONLY")

begin_test "workdir = read makes the working directory read-only"
run_can run --recipe "$READ_ONLY" -- sh -c 'echo x > blocked.txt 2>/dev/null && echo wrote || echo refused'
assert_eq "refused" "$RUN_STDOUT"

# ---- Test 3: a write entry inside it ----
WITH_NOTES=$(tmpconfig <<TOML
[filesystem]
workdir = "read"
write = ["$WORK/notes"]
TOML
)
_TMPFILES+=("$WITH_NOTES")

begin_test "a write entry inside a read-only working directory stays writable"
run_can run --recipe "$WITH_NOTES" -- sh -c 'echo x > notes/n.txt && echo wrote'
assert_eq "wrote" "$RUN_STDOUT"

summary
