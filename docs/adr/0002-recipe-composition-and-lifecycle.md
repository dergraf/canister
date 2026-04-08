# ADR-0002: Recipe Composition, Auto-Detection, and Lifecycle

## Status
Accepted

## Date
2026-04-08

## Context

ADR-0001 established external TOML recipes as the single policy entry point, replacing
built-in profiles. Phase 1 delivered `--recipe PATH`, `can recipes`, and `[syscalls]`
overrides. However, several limitations remained:

1. **No composition.** Users running `nix`-installed Elixir tools needed a single recipe
   that combined Nix store mounts, Elixir-specific syscalls, and base OS paths. This led
   to large, duplicative recipe files.

2. **Hardcoded infrastructure.** Essential OS bind mounts (`/bin`, `/usr/lib`, `/etc/resolv.conf`,
   etc.) were hardcoded in Rust (`ESSENTIAL_BIND_MOUNTS`). Package manager detection
   (`detect_command_prefix()`) was also hardcoded, matching path prefixes like `/nix/store`
   and `/home/linuxbrew` in Rust code. Neither was auditable or customizable.

3. **No recipe lifecycle.** Users had to manually create recipe files. There was no way to
   download community recipes or keep them updated.

4. **No environment variable support.** Recipes with `$HOME/.cargo` in filesystem paths
   were not possible — paths were treated as literals.

## Options Considered

### Option 1: Monolithic recipes with includes
**Description**: Add an `include = ["base.toml", "nix.toml"]` directive to recipes. The
included files are inlined before parsing.
**Pros**: Familiar pattern (like Nginx includes); explicit composition
**Cons**: Creates dependency graphs; ordering is implicit; harder to override; doesn't
solve auto-detection
**Estimated effort**: Medium

### Option 2: CLI-driven composition with layered merge (chosen)
**Description**: Multiple `--recipe` flags on the CLI, merged left-to-right with defined
semantics per field type. Auto-detection via `match_prefix` in recipe metadata. Essential
mounts extracted to `base.toml`.
**Pros**: Explicit composition order; no dependency graphs; auto-detection replaces
hardcoded prefix matching; infrastructure recipes become auditable TOML; simple mental
model (layers stacked left to right)
**Cons**: Merge semantics must be well-defined per field type; auto-detection adds implicit
behavior
**Estimated effort**: Medium

### Option 3: Policy inheritance with override chains
**Description**: Recipes declare `extends = "nix"` to inherit from another recipe, with
field-level overrides.
**Pros**: Familiar OOP-style inheritance
**Cons**: Diamond inheritance problems; harder to reason about final state; ordering
ambiguity with multiple parents; over-engineered for the use case
**Estimated effort**: High

## Decision

**Option 2: CLI-driven composition with layered merge.** This provides explicit, predictable
composition without the complexity of dependency graphs or inheritance chains.

### Composition order

```
base.toml → auto-detected recipes → explicit --recipe args
```

1. **`base.toml`** — always loaded first. Provides essential OS bind mounts. Embedded in the
   binary with the same embed+override pattern as `default.toml` (ADR-0001).
2. **Auto-detected recipes** — scanned from the recipe search path. Each recipe declares
   `match_prefix` patterns in `[recipe]` metadata. When the resolved command binary path
   matches a prefix, the recipe is automatically composed into the stack.
3. **Explicit `--recipe` args** — user-specified recipes, merged left-to-right.

The seccomp baseline (`default.toml`) remains separate — it is resolved by the seccomp
layer, not the composition stack.

### Merge semantics

| Field type | Strategy | Rationale |
|---|---|---|
| `Vec<T>` (paths, domains, syscalls, env vars) | Union (deduplicated, first-occurrence order) | Additive — each layer contributes its needs |
| `strict` (`Option<bool>`) | OR — any `Some(true)` wins | Security: strict mode can never be loosened by composition |
| `deny_all` (`Option<bool>`) | Last-`Some`-wins | Network policy is a deliberate choice per layer |
| `seccomp_mode` (`Option<SeccompMode>`) | Last-`Some`-wins | Mode is a global setting, last layer decides |
| Numeric (`max_pids`, `memory_mb`, `cpu_percent`) | Last-`Some`-wins | Resource limits are contextual |
| `RecipeMeta` | Overlay (non-empty fields win) | Metadata is informational |

The `Option<T>` wrapping is key: fields default to `None` in recipes, meaning "I have no
opinion." Only fields with `Some(value)` participate in merging. This lets a recipe add
filesystem paths without affecting network policy.

### Auto-detection via `match_prefix`

Recipes declare path prefixes they care about:

```toml
[recipe]
name = "nix"
match_prefix = ["/nix/store"]

[filesystem]
allow = ["/nix/store"]
```

Before entering the sandbox, the CLI resolves the command binary to its canonical path
(following symlinks), then scans all recipes for matching prefixes. This replaces the
hardcoded `detect_command_prefix()` function and its `ESSENTIAL_PREFIXES` constant.

Environment variables in `match_prefix` are expanded (`$HOME/.cargo` → `/home/user/.cargo`),
enabling user-local package manager detection.

### `base.toml` — auditable essential mounts

The hardcoded `ESSENTIAL_BIND_MOUNTS` array is extracted to `recipes/base.toml`:

```toml
[filesystem]
allow = ["/bin", "/sbin", "/lib", "/lib64", "/usr/bin", ...]
deny = ["/etc/shadow", "/etc/gshadow"]
```

This provides:
- **Auditability**: security teams can review exactly what's mounted
- **Customizability**: organizations can override via `$XDG_CONFIG_HOME/canister/recipes/base.toml`
- **Consistency**: same embed+override pattern as `default.toml`

### Package manager recipes

Six package manager recipes replace the hardcoded prefix detection:

| Recipe | `match_prefix` | Replaces |
|---|---|---|
| `nix.toml` | `/nix/store` | `detect_command_prefix()` Nix case |
| `homebrew.toml` | `/opt/homebrew`, `/home/linuxbrew/.linuxbrew` | Homebrew case |
| `cargo.toml` | `$HOME/.cargo`, `$HOME/.rustup` | Cargo case |
| `snap.toml` | `/snap` | Snap case |
| `flatpak.toml` | `/var/lib/flatpak`, `$HOME/.local/share/flatpak` | Flatpak case |
| `gnu-store.toml` | `/gnu/store` | GNU Guix case |

### Recipe lifecycle: `can init` / `can update`

Recipes are distributed from the main canister GitHub repository
(`canister-sandbox/canister`), which already contains a `recipes/` directory.

- `can init` shallow-clones the repository via `git`, copies `.toml` files from
  `recipes/`, validates each as a `RecipeFile`, and writes to
  `$XDG_CONFIG_HOME/canister/recipes/`.
- `can update` is identical — re-clones and overwrites all recipes.
- `default.toml` and `base.toml` are skipped (infrastructure recipes embedded in binary).
- Custom `--repo` and `--branch` flags support alternative recipe sources.
- If `git` is not available, manual download instructions are printed.

No additional Rust dependencies are needed — `git` is expected on developer machines.

### Environment variable expansion

Recipe paths support `$NAME`, `${NAME}`, and `$$` (escape). Expansion happens at
`into_sandbox_config()` time — the `RecipeFile` stores raw strings, `SandboxConfig`
stores expanded paths. Unset variables expand to empty string.

## Consequences

### Positive
- `can run -r nix -r elixir -- mix test` composes two recipes cleanly
- Package manager detection is now auditable TOML, not hidden Rust code
- Essential mounts are reviewable in `base.toml`
- Auto-detection is opt-in per recipe (only recipes with `match_prefix` participate)
- Community recipes can be shared, versioned, and downloaded via `can init`
- Adding support for a new package manager is "write a .toml file" not "modify Rust code"

### Negative
- Auto-detection adds implicit behavior (mitigated: `RUST_LOG=info` logs every auto-detected
  recipe with its match reason)
- Merge semantics must be learned (mitigated: documented in this ADR and help text)
- `can init`/`can update` require `git` on the host (mitigated: manual download
  instructions printed when git is absent)

### Neutral
- `default.toml` stays separate from the composition stack (seccomp baseline != sandbox policy)
- The `RecipeFile` → `SandboxConfig` conversion boundary remains clean
- Existing recipes continue to work unchanged

## Follow-up Actions
- [x] Implement `RecipeFile::merge()` with layered semantics
- [x] Implement environment variable expansion (`expand_env_vars()`)
- [x] Extract `base.toml` and embed with override pattern
- [x] Create 6 package manager recipes with `match_prefix`
- [x] Implement `discover_auto_recipes()` in CLI commands
- [x] Remove hardcoded `ESSENTIAL_BIND_MOUNTS`, `detect_command_prefix()`, etc.
- [x] Implement `can init` and `can update` with git clone
- [x] Integration tests for composition, env expansion, auto-detection, and registry
- [ ] Recipe signing/verification (future ADR)
- [ ] `can init --generate` from `--monitor` output (future ADR)
