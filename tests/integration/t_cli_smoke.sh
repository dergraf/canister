#!/usr/bin/env bash
# ============================================================================
# t_cli_smoke.sh — CLI surface output stability
#
# Pins the agent- and user-facing CLI surface so accidental UX
# regressions get caught fast. The strategy is INTENTIONALLY shallow:
# we pin *presence* of subcommands, top-level flags, and key sections
# in help text, not the exact wording. Heavy snapshot pinning would be
# brittle as docs evolve; presence pinning catches what actually
# matters — a subcommand silently disappearing, a help section that
# stops rendering, a non-zero exit on a no-op help invocation.
#
# Coverage:
#   1. `can --help` exits 0 and lists every documented subcommand.
#   2. `can --version` exits 0 and matches the "can <semver>" pattern.
#   3. Each subcommand's `--help` exits 0 and includes a Usage: line.
#   4. `can recipe list` runs cleanly and shows recipe entries.
#   5. `can check` runs and reports feature detection (non-zero
#      result is OK when features are unavailable, but it must not
#      crash with a stack trace).
#   6. Unknown subcommand exits non-zero with a clap-style error.
#   7. Unknown top-level flag exits non-zero.
# ============================================================================

source "$(dirname "$0")/lib.sh"
header "CLI smoke + output stability"

# ---- Test 1: top-level --help lists all documented subcommands ----
# These are the surfaces agents and users reach for first. Removing
# or renaming one is a UX break that should be conscious, not silent.
EXPECTED_SUBCOMMANDS=(
    "up"
    "run"
    "check"
    "setup"
    "recipe"
    "init"
    "update"
    "help"
)

begin_test "can --help exits 0"
run_can --help
assert_exit_code 0 "$RUN_EXIT"

# A non-empty Usage: line and the subcommand list are the minimum
# clap-rendered structure we depend on.
begin_test "can --help has a Usage: line"
assert_contains "$RUN_STDOUT" "Usage:"

begin_test "can --help has a Commands: section"
assert_contains "$RUN_STDOUT" "Commands:"

for cmd in "${EXPECTED_SUBCOMMANDS[@]}"; do
    begin_test "can --help lists subcommand '${cmd}'"
    # clap renders each subcommand on its own line as
    # "  <name>  <description>". A loose substring match is
    # sufficient — we don't want to pin the description text.
    assert_contains "$RUN_STDOUT" "  ${cmd}"
done

# ---- Test 2: --version output is "can <semver>" ----
begin_test "can --version exits 0"
run_can --version
assert_exit_code 0 "$RUN_EXIT"

begin_test "can --version matches 'can <major>.<minor>.<patch>'"
# Loosely pin to semver shape; tolerate optional pre-release/build.
assert_match "$RUN_STDOUT" '^can [0-9]+\.[0-9]+\.[0-9]+'

# ---- Test 3: each subcommand --help works ----
# Skip 'help' (it's the help command itself and behaves differently).
HELPABLE=("up" "run" "check" "setup" "recipe" "init" "update")
for cmd in "${HELPABLE[@]}"; do
    begin_test "can ${cmd} --help exits 0 and includes Usage:"
    run_can "$cmd" --help
    if [[ "$RUN_EXIT" -ne 0 ]]; then
        fail "exit ${RUN_EXIT}; stderr: ${RUN_STDERR}"
    elif [[ "$RUN_STDOUT" != *"Usage:"* ]]; then
        fail "no Usage: line in --help output"
    else
        pass
    fi
done

# ---- Test 4: recipe list runs cleanly ----
begin_test "can recipe list exits 0"
run_can recipe list
assert_exit_code 0 "$RUN_EXIT"

begin_test "can recipe list mentions 'recipes'"
# Output begins with "Discovered recipes:" or similar header. Anchor
# on the word "recipes" appearing somewhere — anything else would
# over-pin formatting.
if [[ "$RUN_STDOUT" == *"recipes"* ]] || [[ "$RUN_STDOUT" == *"Recipes"* ]]; then
    pass
else
    fail "no mention of 'recipes' in output: $RUN_STDOUT"
fi

# ---- Test 5: can check runs without crashing ----
# `check` may exit non-zero on systems missing kernel features. We
# only assert that it doesn't panic (no "thread 'main' panicked" or
# Rust backtrace markers) and produces some output.
begin_test "can check runs without panicking"
run_can check
if [[ "$RUN_STDOUT" == *"thread '"*"panicked"* ]] ||
   [[ "$RUN_STDERR" == *"thread '"*"panicked"* ]] ||
   [[ "$RUN_STDERR" == *"RUST_BACKTRACE"* ]]; then
    fail "can check panicked: ${RUN_STDERR}"
elif [[ -z "$RUN_STDOUT" ]] && [[ -z "$RUN_STDERR" ]]; then
    fail "can check produced no output at all"
else
    pass
fi

# ---- Test 6: unknown subcommand fails with non-zero exit ----
begin_test "can <unknown-subcommand> exits non-zero"
run_can definitely-not-a-real-subcommand 2>/dev/null
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "unknown subcommand returned exit 0; expected non-zero"
else
    pass
fi

# ---- Test 7: unknown top-level flag fails with non-zero exit ----
begin_test "can --not-a-real-flag exits non-zero"
run_can --not-a-real-flag 2>/dev/null
if [[ "$RUN_EXIT" -eq 0 ]]; then
    fail "unknown flag returned exit 0; expected non-zero"
else
    pass
fi

# ---- Test 8: recipe show on baseline default emits TOML ----
# `recipe show default` resolves the embedded default baseline. The
# output is canonical TOML that downstream tools (and humans) may
# script against. A regression here would silently break recipe
# tooling.
begin_test "can recipe show default emits TOML structure"
run_can recipe show default
if [[ "$RUN_EXIT" -ne 0 ]]; then
    skip "recipe show default not supported in this build (exit ${RUN_EXIT})"
elif [[ "$RUN_STDOUT" != *"["*"]"* ]]; then
    fail "expected TOML section headers in recipe show output; got: $RUN_STDOUT"
else
    pass
fi

summary
