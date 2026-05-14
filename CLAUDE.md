# Canister — Claude Code orientation

A Rust workspace implementing `can`, a single-binary unprivileged Linux sandbox.
This file orients agents. The README is for users; this is for the next
contributor (human or AI) who needs to navigate or change code quickly.

## What it does

Runs an arbitrary command inside layered Linux isolation: user/mount/PID/network
namespaces, seccomp BPF (default-deny allow list), USER_NOTIF supervisor for
argument-level filtering, capability dropping, cgroups v2 limits, /proc
hardening, and an L7 egress proxy with Wasm filters. No root, no daemon, no
external runtime. Targets Linux 5.6+ (USER_NOTIF supervisor needs 5.9+).

## Crate map

| Crate | Role | First-look files |
|---|---|---|
| `crates/can-cli` | Binary `can`; clap subcommands; manifest discovery; recipe download | `main.rs`, `commands.rs` (currently monolithic — see Phase 4) |
| `crates/can-sandbox` | Core runtime: namespaces, mounts, seccomp, supervisor | `lib.rs`, `namespace.rs` (fork/ns protocol), `notifier.rs` (USER_NOTIF) |
| `crates/can-policy` | TOML recipes, merge semantics, manifest, env expansion | `lib.rs`, `config.rs` (RecipeFile::merge), `manifest.rs` |
| `crates/can-proxy` | L7 egress proxy with Wasm via Extism | `server.rs` (entrypoint), `wasm.rs`, `egress.rs`, `policy.rs`, `ca.rs` |
| `crates/can-net` | Netns setup, pasta integration, DNS cache | `pasta.rs`, `netns.rs`, `dns_cache.rs` |
| `crates/can-log` | TTY-aware tracing init | `lib.rs` (small) |
| `crates/can-docgen` | mdBook reference generation; runs `can --help` | `main.rs` |

Recipes live in `recipes/`. `base.toml` (essential OS mounts) and `default.toml`
(seccomp baseline ~187 allowed syscalls) are **embedded via `include_str!`** in
`can-policy/src/profile.rs` and also overridable on disk. `default.toml` is the
canonical source of truth for the baseline.

## Where to look first

| Question | Start here |
|---|---|
| "Why is this syscall blocked / which baseline allows it?" | `recipes/default.toml`, then `crates/can-sandbox/src/seccomp.rs` |
| "How does USER_NOTIF arg-level filtering decide?" | `crates/can-sandbox/src/notifier.rs` (one of ~13 `evaluate_*` fns) |
| "How does the fork/ns/pivot dance work?" | `crates/can-sandbox/src/namespace.rs` (`spawn_sandboxed`) — **do not reorder steps**, the parent↔child pipe protocol is order-sensitive |
| "Why is this recipe field merged that way?" | `crates/can-policy/src/config.rs` (`RecipeFile::merge`) |
| "What does `can up <name>` do?" | `crates/can-cli/src/commands.rs` (`up` command) → `can-policy/src/manifest.rs::discover_manifest` |
| "Proxy / Wasm filter behavior?" | `crates/can-proxy/src/server.rs` (`handle_inner_request`), `wasm.rs` (plugin invocation) |
| "How is the egress mode decided?" | `crates/can-policy/src/config.rs` `NetworkConfig::egress` (`none`/`proxy-only`/`direct`), unified in commit 6f81746 |

## Build / test / lint

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check     # check
cargo fmt --all             # fix
./ci/verify.sh              # mirrors core CI checks (fmt + clippy + tests for proxy/sandbox/net)
./tests/integration/run.sh  # bash integration suite; requires unprivileged user namespaces
```

`ci/verify.sh` currently runs unit tests only for `can-proxy`, `can-sandbox`,
`can-net`. `can-cli` and `can-policy` are also unit-tested; expanding
`verify.sh` to include them is Phase 2 work.

## Conventions

- **Error handling.** Library crates use `thiserror` typed errors (see
  `SandboxError`, `NetError`, `ConfigError`). The `anyhow` dependency belongs to
  `can-cli` only. Do not add `anyhow` to library crates.
- **No `.unwrap()` in production paths.** Existing offenders are tracked for
  audit in `docs/guardrails-agentic-development-plan.md` PR 3. Annotate
  unavoidable `expect("...")` with a domain-meaningful message. Tests can
  unwrap freely.
- **Terminology.** Use "allow list" / "deny list", not whitelist/blacklist
  (refactored in commit 30d686e — keep it consistent).
- **Commit messages.** Conventional commits:
  `feat|fix|refactor|docs|test|chore|perf|ci|style:`. Keep commits atomic.
- **Tests.** Library code: unit tests live `#[cfg(test)] mod tests` in the same
  file. Integration tests: bash scripts in `tests/integration/t_*.sh` plus
  helpers in `tests/integration/lib.sh`. New `t_*.sh` files must be registered
  in `tests/integration/run.sh`.
- **Recipe schema is strict** (`#[serde(deny_unknown_fields)]`). Unknown fields
  fail parsing. When adding a recipe field, update both the struct and the
  `merge()` implementation in `can-policy/src/config.rs`.

## Critical gotchas

- `spawn_sandboxed` in `namespace.rs` is a state machine driven by pipes
  between parent and child. The order of operations (write UID/GID maps,
  signal network ready, etc.) is load-bearing. Read the comment block at the
  top of the function before changing anything mid-sequence.
- `notifier.rs` runs the supervisor as PID 1 in its own PID namespace and
  reads child memory through `/proc/<pid>/mem`. Cannot use `ptrace` due to
  USER_NOTIF restrictions.
- The seccomp filter validates CPU architecture to prevent x32 ABI bypass —
  do not remove the arch check in `seccomp.rs`.
- `pasta` (from passt) is required for filtered network mode. The path can be
  overridden via `--pasta-path`. The default lookup tries common locations.
- Recipes are merged left-to-right: `base.toml` (always) → auto-detected
  (via `match_prefix`) → explicit `-r` flags. `Vec` fields union, `strict`
  ORs (never downgrades), `egress` is last-wins.

## Repo layout — scratch vs. real

Real code lives under `crates/`, `recipes/`, `tests/`, `docs/`, `ci/`,
`.github/`. Everything else at the repo root is dev detritus and is
gitignored. If you see `refactor*.py`, `rewrite_*.py`, `test_*.rs`,
`test-*.toml`, `*.orig`, `*.rej`, `--out-dir/`, `.local/`, `.nvimlog`,
`erl_crash.dump`, `strace-*.log`, `my_test_app/`, or similar at the root —
that's noise, not source. Do not edit, do not reference.

## Known monoliths (Phase 4 will split these)

`notifier.rs` (~2000 lines), `config.rs` (~1500), `namespace.rs` (~1450),
`seccomp.rs` (~1000), `commands.rs` (~1000), `server.rs` (~830). Adding to
these is fine; large refactors should ride along with the planned splits in
`/home/graf/.claude/plans/please-familiarize-with-this-cozy-lake.md`.

## Useful entry points to read once

- `docs/ARCHITECTURE.md` — design and execution flow
- `docs/CONFIGURATION.md` — full recipe and manifest reference
- `docs/SECCOMP.md` — baseline and filtering model
- `docs/adr/0001-…` through `0005-…` — accepted ADRs (egress unification and
  proxy/Wasm work are not yet ADR'd; see Phase 5 of the plan)
- `docs/guardrails-agentic-development-plan.md` — 5-PR plan for CI guardrails
- `docs/wasm-abi.md` — ExtProc-style Wasm filter ABI
