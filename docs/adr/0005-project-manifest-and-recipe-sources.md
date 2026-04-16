# ADR-0005: Project Manifest (`canister.toml`) and Recipe Sources

## Status
Accepted

## Date
2026-04-14

## Context

ADR-0002 established CLI-driven recipe composition (`can run -r A -r B -- cmd`).
This works well for ad-hoc use, but breaks down as complexity grows:

### The combinatorial problem

Real-world development environments combine multiple orthogonal concerns:

- **Editors**: neovim, helix, emacs, vscode, zed
- **Languages**: elixir, rust, go, python, node, ruby, zig, java, ...
- **Package managers**: nix, homebrew, apt/dnf (system), cargo, snap, flatpak, ...

With N editors × M languages × K package managers, users must discover and
manually stack the right `-r` flags. Each project's sandbox requirements are
implicit knowledge — they live in developers' heads, not in the repository.

### The auditability problem

Auto-detection via `match_prefix` (ADR-0002) silently activates recipes based
on the command binary path. This has two issues:

1. **Only matches the top-level binary.** Running `nvim` (from `/usr/bin/`) does
   not trigger `nix.toml` even though neovim will spawn Nix-installed LSP servers.

2. **Host-dependent behavior.** A broader auto-detection (e.g., activating
   `nix.toml` whenever `/nix/store` exists) would mount more than necessary —
   if nix, homebrew, and cargo are all installed but only nix is needed, the
   sandbox exposes excessive filesystem surface. A security auditor cannot
   determine the effective sandbox policy without knowing the host state.

### The reproducibility problem

When multiple developers work on the same project, each may have different
canister versions with different recipe versions. There is no mechanism to
ensure all developers run identical sandboxes.

### Guiding principle: least privilege

The sandbox should expose the **minimum** needed for the task. Silent
auto-detection of all installed package managers contradicts this. The user
(or project) must explicitly declare what the sandbox needs.

## Options Considered

### Option 1: Enhanced auto-detection (`match_path_exists`)
**Description**: Extend `match_prefix` with `match_path_exists` — recipes
activate when a path exists on the host, regardless of the command binary.
**Pros**: Zero configuration; "just works" for common cases
**Cons**: Violates least privilege (mounts everything detected on host);
not auditable (effective policy depends on host state); no reproducibility
across machines
**Estimated effort**: Low

### Option 2: `includes` field for recipe dependencies
**Description**: Add `includes = ["nix", "elixir"]` to recipe metadata,
creating a recipe dependency graph.
**Pros**: Explicit composition declared in recipes
**Cons**: Cubic complexity — each editor×language×package-manager combination
needs a recipe or include chain; dependency graphs add resolution complexity;
ordering ambiguity; diamond dependency problems
**Estimated effort**: Medium

### Option 3: Project manifest with named sandboxes (chosen)
**Description**: A `canister.toml` file at the project root defines named
sandboxes, each composing recipes with project-specific overrides. A lockfile
pins recipe versions for reproducibility. Future phases add remote recipe
sources.
**Pros**: Explicit and auditable; no combinatorial explosion (composition
is per-project, not per-recipe); reproducible via lockfile; scales to teams;
familiar model (like `flake.nix`, `docker-compose.yml`, `.tool-versions`)
**Cons**: Requires a manifest file; new CLI command (`can up`); more complex
than pure `-r` stacking
**Estimated effort**: Medium (Phase 1), High (all phases)

## Decision

**Option 3: Project manifest with named sandboxes**, implemented in three
phases. Each phase is independently useful.

### Phase 1: Project manifest and `can up` (this implementation)

A `canister.toml` file at the project root defines named sandboxes:

```toml
# canister.toml

[sandbox.dev]
description = "Neovim + Elixir development"
recipes = ["neovim", "elixir", "nix"]
command = "nvim"

[sandbox.dev.filesystem]
allow_write = ["$HOME/.local/share/nvim"]

[sandbox.dev.network]
allow_domains = ["api.myproject.dev"]

[sandbox.test]
description = "Mix test runner"
recipes = ["elixir", "nix"]
command = "mix test"

[sandbox.test.network]
deny_all = true

[sandbox.ci]
description = "CI — strict, no network"
recipes = ["elixir", "nix", "generic-strict"]
command = "mix test --cover"
strict = true

[sandbox.ci.resources]
memory_mb = 2048
cpu_percent = 100
```

Usage:

```bash
can up              # Run the default (first-defined) sandbox
can up dev          # Run a named sandbox
can up test         # Run the test sandbox
can up --dry-run ci # Preview the resolved policy without running
```

**Manifest structure:**

Each `[sandbox.<name>]` section contains:

| Field | Type | Description |
|---|---|---|
| `description` | `Option<String>` | Human-readable description |
| `recipes` | `Vec<String>` | Recipe names, resolved via search path |
| `command` | `String` | Command to run (may include arguments) |
| `strict` | `Option<bool>` | Override strict mode |

Each sandbox may also contain override sub-tables that merge on top of the
composed recipes using the same merge semantics from ADR-0002:

| Sub-table | Description |
|---|---|
| `[sandbox.<name>.filesystem]` | Additional paths, writable mounts |
| `[sandbox.<name>.network]` | Additional domains, IPs, deny_all override |
| `[sandbox.<name>.process]` | Additional env vars, execve rules |
| `[sandbox.<name>.resources]` | Resource limit overrides |
| `[sandbox.<name>.syscalls]` | Additional allow_extra / deny_extra |

**Composition order:**

```
base.toml
  → auto-detected recipes (match_prefix against command binary, as today)
  → recipes listed in manifest (left to right)
  → manifest overrides ([sandbox.<name>.filesystem], etc.)
  = final SandboxConfig
```

Auto-detection remains for backward compatibility with `can run`. For
`can up`, the manifest is the primary composition mechanism — auto-detection
still runs but the manifest's explicit recipe list is the intended way to
declare dependencies.

**Recipe resolution:**

Recipe names in `recipes = [...]` resolve through the existing search path
(ADR-0002):

1. `./.canister/` — project-local recipes (a project can ship custom recipes)
2. `$XDG_CONFIG_HOME/canister/recipes/` — user-installed recipes
3. Embedded fallbacks in the binary (base.toml, default.toml)

This means a project can override a shipped recipe by placing a modified
version in its `./.canister/` directory — useful for security-hardened variants.

**Manifest discovery:**

`can up` searches for `canister.toml` in the current directory and its
parents (like `.gitignore`, `Cargo.toml`, etc.). The first match wins.
This allows running `can up` from any subdirectory of the project.

**Relationship to `can run`:**

| Command | Config source | Use case |
|---|---|---|
| `can up [name]` | `canister.toml` | Project workflows |
| `can run -r ... -- cmd` | CLI args | Ad-hoc, one-off, no manifest |

Both produce the same `SandboxConfig` internally. `can up` reads composition
from a file; `can run` reads it from CLI arguments.

### Phase 2: Lockfile (future)

A `canister.lock` file pins the exact recipe versions used:

```toml
# canister.lock — auto-generated by 'can lock', checked into git

[meta]
canister_version = "0.5.0"
generated_at = "2026-04-14T12:00:00Z"

[recipes]
"base" = { sha256 = "a1b2c3..." }
"default" = { sha256 = "d4e5f6..." }
"neovim" = { version = "1", sha256 = "789abc..." }
"elixir" = { version = "1", sha256 = "def012..." }
"nix" = { version = "1", sha256 = "345678..." }
```

Workflow:

- `can lock` resolves all recipes referenced by `canister.toml`, computes
  checksums, writes `canister.lock`.
- `can up` checks the lockfile. If a recipe's checksum doesn't match, it
  warns (or fails with `--strict-lock`).
- `can lock --update` refreshes the lockfile after recipe updates.
- The lockfile is checked into version control so all developers get the
  same sandbox policy.

### Phase 3: Remote recipe sources (future)

Inspired by Nix flake inputs, `canister.toml` gains a `[sources]` section
for declaring remote recipe repositories:

```toml
[sources]
official = { github = "dergraf/canister", path = "recipes", tag = "v0.5.0" }
team = { github = "myorg/canister-recipes", ref = "main" }
hardened = { github = "security-team/canister-hardened", tag = "2026.1" }

[sandbox.dev]
recipes = [
    "official/neovim",
    "official/elixir",
    "official/nix",
    "team/internal-api",
]
command = "nvim"
```

The lockfile (Phase 2) extends to pin git revisions per source:

```toml
[sources.official]
github = "dergraf/canister"
rev = "abc123def456789..."

[sources.team]
github = "myorg/canister-recipes"
rev = "789abc012345678..."
```

This enables:
- Teams publishing shared recipe repositories
- Security teams maintaining hardened recipe variants
- Reproducible builds via pinned git revisions + file checksums
- Multiple recipe ecosystems without forking the canister project

### Recipe cleanup (prerequisite for all phases)

For composition to work cleanly, shipped recipes must be **single-purpose**.
Each recipe should contribute only its specific concern without duplicating
paths or settings from other recipes.

Current problems and fixes:

| Recipe | Problem | Fix |
|---|---|---|
| `base.toml` | Missing common system paths | Add `/usr/lib`, `/usr/bin`, `/usr/local/lib`, `/usr/local/bin`, `/lib`, `/tmp` |
| `neovim.toml` | Duplicates `/usr/lib`, `/usr/bin`, `/lib`, `/tmp` from base | Remove — base provides these |
| `elixir.toml` | Hardcodes `/usr/lib`, `/usr/bin`, `/tmp/workspace` | Remove — base provides system paths; `/tmp/workspace` is project-specific |
| `node-build.toml` | Likely duplicates system paths | Audit and remove |
| `nix.toml` | Only `/nix/store` — already single-purpose | No change needed |
| `cargo.toml` | Only cargo/rustup paths — already single-purpose | No change needed |

After cleanup, each layer has a clear responsibility:

- **`base.toml`**: OS essentials — binaries, libraries, certs, DNS, tmp
- **Package manager recipes** (`nix`, `homebrew`, `cargo`, etc.): Store paths only
- **Language recipes** (`elixir`, `python-pip`, `node-build`): Syscalls, network, env vars
- **Application recipes** (`neovim`, `opencode`): App-specific mounts, domains, settings

## Consequences

### Positive
- A project's sandbox requirements are declared in version control, not in
  developers' heads
- Security auditors read `canister.toml` + referenced recipes to understand
  the effective policy
- No combinatorial explosion — composition is per-project, not per-recipe
- Named sandboxes support different environments (dev/test/ci) from one file
- `can up` is simpler than remembering multiple `-r` flags
- Lockfile (Phase 2) ensures reproducibility across machines
- Remote sources (Phase 3) enable recipe distribution without forking

### Negative
- Another config file in the project root (mitigated: optional — `can run`
  still works without it)
- Manifest format must be learned (mitigated: simple TOML, good error
  messages, `can up --dry-run` for preview)
- Three-phase rollout means some features come later (mitigated: each phase
  is independently useful)

### Neutral
- `can run -r ...` remains fully functional for ad-hoc use
- Auto-detection via `match_prefix` continues to work for both `can run`
  and `can up`
- The merge semantics from ADR-0002 are unchanged
- `default.toml` (seccomp baseline) stays separate from the composition stack

## Follow-up Actions
- [ ] Clean up shipped recipes to be single-purpose (expand base.toml, remove
      duplicated paths from language/application recipes)
- [ ] Implement `canister.toml` parsing and manifest data structures
- [ ] Implement `can up` command with manifest discovery and named sandboxes
- [ ] Add `can up --dry-run` for policy preview
- [ ] Update CONFIGURATION.md and ARCHITECTURE.md
- [ ] Phase 2: `can lock` command and lockfile verification
- [ ] Phase 3: `[sources]` with remote git repositories
- [ ] Phase 3: Namespaced recipe references (`source/recipe`)
