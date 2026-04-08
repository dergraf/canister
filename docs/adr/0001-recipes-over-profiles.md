# ADR-0001: Replace built-in profiles with external recipes

## Status
Accepted

## Date
2026-04-08

## Context

Canister ships 4 hardcoded seccomp profiles (`generic`, `python`, `node`, `elixir`) defined
as Rust code in `can-policy/src/profile.rs`. Each profile is a set of ~170 allowed syscalls
built from a shared `ALLOW_BASE` (~130 syscalls) plus per-profile additions/removals.

Users select a profile via `--profile NAME` or `[profile] name = "..."` in TOML config.

**Problems with this approach:**

1. **Too coarse.** "Python" encompasses `pip install`, script execution, pytest, Django — each
   with very different syscall and filesystem needs. One profile cannot serve all.

2. **Ages silently.** New runtimes, new syscalls, and new package manager behaviors mean built-in
   profiles become too permissive or too restrictive without users noticing.

3. **False sense of security.** Users see `--profile python` and assume their workload is secured.
   In reality the profile may allow far more than needed.

4. **Maintenance burden.** Every ecosystem-specific bug becomes Canister's responsibility. This
   doesn't scale beyond a handful of languages.

5. **No composition.** Profiles are monolithic — there's no way to take a base and add filesystem
   rules, network policies, or environment filtering without writing a full config.

## Options Considered

### Option 1: Expand built-in profiles
**Description**: Add more profiles (python-pip, python-script, node-build, node-runtime, etc.)
**Pros**: No new concepts; no migration
**Cons**: Combinatorial explosion; still ages; still our maintenance burden; still hardcoded
**Estimated effort**: Low

### Option 2: External recipes (TOML files composing over baselines)
**Description**: Introduce "recipes" as external TOML files that are complete sandbox policies.
Recipes optionally reference a "baseline" (the old profiles, demoted to low-level syscall sets).
Users create, version, and share recipes as files.
**Pros**: Context-specific; versionable; auditable; shareable; scales with ecosystem; minimal
maintenance burden on Canister core
**Cons**: New concept to learn; slightly more complex CLI; migration friction
**Estimated effort**: Medium

### Option 3: Full policy DSL
**Description**: Design a custom policy language with composition, conditionals, and inheritance.
**Pros**: Maximum flexibility
**Cons**: High complexity; learning curve; parser maintenance; overkill for Phase 1
**Estimated effort**: High

## Decision

**Option 2: External recipes.** This is the right abstraction level — concrete enough to implement
in a week, abstract enough to become an ecosystem primitive later.

### Key design decisions:

**Recipe format:** A recipe TOML file defines a complete sandbox policy. It contains an optional
`[recipe]` metadata section with `name`, `description`, `version`, and `baseline` fields, plus
the standard sandbox policy sections (`[profile]`, `[filesystem]`, `[network]`, `[process]`,
`[resources]`).

**Baselines vs recipes:** Baselines (the 4 existing profiles) become low-level syscall sets — internal
building blocks, not user-facing. Recipes are the user-facing concept. A recipe references a baseline
via `recipe.baseline = "python"` to get its syscall set, then layers filesystem/network/process/resource
policies on top.

**Resolution order:**
1. `--recipe PATH` loads a recipe TOML file
2. `--profile NAME` overrides the baseline from the file
3. No `--recipe` flag: default deny-all policy with generic baseline

**Recipe discovery:** `can recipes` searches `./recipes/`, `$XDG_CONFIG_HOME/canister/recipes/`,
and `/etc/canister/recipes/`. The `--recipe` flag takes a file path (not a name). Name-based
lookup is deferred to Phase 2.

**Phase 1 scope (this ADR):**
- `RecipeFile` + `RecipeMeta` structs in `can-policy`
- `--recipe` CLI flag on `can run`
- `can recipes` list command
- Example recipes shipped in `recipes/` directory
- `--profile` continues working as a baseline override

**Explicitly NOT in Phase 1:**
- Recipe composition (`include` / layering between recipes)
- Name-based recipe lookup (`--recipe elixir-dev` without a path)
- Custom syscall lists in recipes (`[syscalls]` section)
- Remote recipe registries
- Recipe signing/verification
- Recipe generation from `--monitor` output

## Consequences

### Positive
- Users get context-specific, auditable policies instead of vague profile names
- The recipe format is simple TOML — no new DSL to learn
- `--recipe` is the single, clear entry point for loading sandbox policies
- Recipes are portable files — easy to version control, share, review
- Foundation for an ecosystem: community recipes, org registries, CI templates

### Negative
- Users must learn the distinction between baselines and recipes (mitigated by docs)
- `can profiles` command becomes less prominent (kept as alias for baseline listing)

### Neutral
- Profile Rust code stays as-is (just renamed conceptually to "baselines")
- Seccomp BPF generation is unchanged
- Existing test configs continue to work

## Follow-up Actions
- [x] Implement `RecipeFile` / `RecipeMeta` in `can-policy/src/config.rs`
- [x] Add `--recipe` flag and `can recipes` command to CLI
- [x] Ship example recipes in `recipes/` directory
- [x] Update `docs/CONFIGURATION.md` and `docs/PROFILES.md`
- [x] Remove `--config` backward compatibility — `--recipe` is the only way
- [x] Phase 2 ADR: recipe composition, name-based lookup, remote registries → ADR-0002
- [ ] Phase 3 ADR: versioning, signing

## Amendments

### 2026-04-08: Remove backward compatibility

The original decision planned for a migration period where `--config` and `--recipe` coexisted.
After implementation, we decided to skip the migration period entirely and remove `--config`
immediately. Rationale:

- Canister is pre-1.0 with no external users relying on `--config`
- Two flags doing the same thing creates confusion, not compatibility
- Cleaner codebase: no mutual-exclusion logic, no deprecation warnings, no dead code paths
- `--recipe` is strictly better (same format, plus optional `[recipe]` metadata)

### 2026-04-08: Collapse 4 profiles into single default baseline

The original design kept 4 built-in profiles (`generic`, `python`, `node`, `elixir`) as
"baselines" that recipes could reference. After implementation and analysis, we collapsed them
into a single default baseline with per-recipe `[syscalls]` overrides. Rationale:

- **Python and Node profiles were literally identical** — same allow list, same deny list
- The total delta across all 4 profiles was only **6 syscalls**: `ptrace`, `personality`,
  `seccomp`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`
- The 4-profile taxonomy gave a false sense of specificity — "I'm using the Python profile"
  told you almost nothing about what was actually allowed

**What changed:**
- `--profile` CLI flag removed entirely
- `can profiles` command removed
- `[profile]` section in TOML rejected by `deny_unknown_fields` (migration guard)
- `baseline = "..."` in `[recipe]` rejected by `deny_unknown_fields`
- New `[syscalls]` section: `allow_extra`, `deny_extra`, `seccomp_mode`
- Single `SeccompProfile::default_baseline()` replaces 4 profile constructors
- `SeccompProfile::apply_overrides()` merges recipe overrides onto the baseline
- `can recipes` shows `+syscall` / `-syscall` annotations per recipe

### 2026-04-08: External default.toml baseline (Phase 2)

The single default baseline was originally defined as Rust constants (`ALLOW_BASE` and
`DENY_ALWAYS` arrays in `profile.rs`). Phase 2 moved the baseline to an external
`recipes/default.toml` TOML file, removing all hardcoded syscall lists from Rust code.

**What changed:**
- `recipes/default.toml` is the single source of truth for the baseline (~130 allow, 16 deny)
- The file is embedded in the binary via `include_str!()` as a compile-time fallback
- At runtime, Canister searches `./recipes/`, `$XDG_CONFIG_HOME/canister/recipes/`, and
  `/etc/canister/recipes/` for an external `default.toml`. External file takes precedence.
- `SyscallConfig` now has absolute `allow`/`deny` fields (used only by `default.toml`) in
  addition to the relative `allow_extra`/`deny_extra` (used by regular recipes). The two
  pairs are mutually exclusive — enforced by `validate()`.
- `ALLOW_BASE` and `DENY_ALWAYS` Rust constants removed from `profile.rs`
- `SeccompProfile::resolve_baseline()` implements the embed+override search
- `can recipes` shows the baseline source (embedded vs external path)

**Rationale:**
- Users can pin/audit/version-control the exact baseline without recompiling
- The baseline is human-readable TOML, not buried in Rust arrays
- The embed+override pattern ensures the binary always works standalone
- Organizations can deploy a custom `default.toml` to `/etc/canister/recipes/`
  for fleet-wide baseline policy
