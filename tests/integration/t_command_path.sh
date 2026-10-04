#!/usr/bin/env bash
# ============================================================================
# t_command_path.sh — How the command is found and what it sees as argv[0]
#
# Tests:
#   1. A relative path with a slash runs from the working directory
#   2. A symlinked command sees argv[0] as written, not its target
#   3. A Python virtualenv's interpreter finds its own prefix
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Command path and argv[0]"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; cleanup' EXIT
mkdir -p "$WORK/bin"
cd "$WORK" || exit 1

printf '#!/bin/sh\necho relative-ok\n' > bin/hello
chmod +x bin/hello
ln -s "$(command -v sh)" bin/mysh

# ---- Test 1: relative path ----
begin_test "a relative command runs from the working directory"
run_can run -- bin/hello
assert_eq "relative-ok" "$RUN_STDOUT"

# ---- Test 2: argv[0] as written ----
begin_test "a symlinked command sees argv[0] as written"
run_can run -- ./bin/mysh -c 'echo "$0"'
assert_eq "./bin/mysh" "$RUN_STDOUT"

# ---- Test 3: a virtualenv ----
if has_python3; then
    begin_test "a virtualenv's interpreter finds its own prefix"
    python3 -m venv --without-pip venv >/dev/null 2>&1
    run_can run -- venv/bin/python -c 'import sys; print(sys.prefix)'
    assert_eq "$WORK/venv" "$RUN_STDOUT"
else
    begin_test "a virtualenv's interpreter finds its own prefix"
    skip "python3 not available"
fi

summary
