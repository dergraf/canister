#!/usr/bin/env bash
# ============================================================================
# t_workdir.sh — The working directory's access (ADR-0024)
#
# Tests:
#   1. By default the working directory is writable
#   2. workdir = "read" makes it read-only
#   3. A write entry inside a read-only working directory stays writable
#   4. workdir = "listed" shows only the listed entries: no .git, no other file
#   5. ... a listed write entry stays writable, and its changes reach the host
#   6. ... nothing else in the working directory can be created
#   7. ... and the command still starts in the working directory
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

# ---- Tests 4-7: listed (ADR-0032) ----
mkdir -p src .git
echo "the app" > src/app.txt
echo "SECRET=1" > secret.env
echo "[remote]" > .git/config
LISTED=$(tmpconfig <<TOML
[filesystem]
workdir = "listed"
read = ["$WORK/src"]
write = ["$WORK/notes"]
TOML
)
_TMPFILES+=("$LISTED")

begin_test "workdir = listed shows only the listed entries"
run_can run --recipe "$LISTED" -- sh -c 'cat src/app.txt; for p in .git secret.env blocked.txt; do [ -e "$p" ] && echo "visible: $p"; done; true'
assert_eq "the app" "$RUN_STDOUT"

begin_test "a listed write entry stays writable, and its changes reach the host"
run_can run --recipe "$LISTED" -- sh -c 'echo listed > notes/listed.txt && echo wrote'
assert_eq "wrote" "$RUN_STDOUT"
assert_eq "listed" "$(cat notes/listed.txt 2>/dev/null)"

begin_test "nothing else in a listed working directory can be created"
run_can run --recipe "$LISTED" -- sh -c 'echo x > new.txt 2>/dev/null && echo wrote || echo refused; mkdir newdir 2>/dev/null && echo made || echo refused'
assert_eq "refused
refused" "$RUN_STDOUT"
if [ -e new.txt ] || [ -e newdir ]; then fail "created on the host"; else pass; fi

begin_test "the command still starts in a listed working directory"
run_can run --recipe "$LISTED" -- pwd
assert_eq "$WORK" "$RUN_STDOUT"

summary
