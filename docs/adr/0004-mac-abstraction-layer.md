# ADR-0004: Mandatory Access Control Abstraction Layer

## Status
Accepted

## Date
2026-04-12

## Context

Canister currently has hard-coded AppArmor support. On Ubuntu 24.04+ the kernel
sets `apparmor_restrict_unprivileged_userns=1`, which blocks mount/pivot_root
inside user namespaces unless a dedicated AppArmor profile grants the
capabilities. Canister ships a two-profile AppArmor setup (`canister` +
`canister_sandboxed`) that solves this.

However, this approach has three problems:

1. **Fedora/RHEL are unsupported.** Fedora 41+ restricts unprivileged user
   namespaces via SELinux (the `user_namespace create` permission), analogous
   to Ubuntu's AppArmor restriction. Canister cannot run on these systems
   without SELinux policy modules.

2. **Distros with no MAC are handled poorly.** Systems running neither AppArmor
   nor SELinux (Arch, Void, Gentoo, minimal containers) work fine with
   Canister, but `can check` and `can setup` only speak AppArmor and give
   confusing output on these systems.

3. **The code conflates detection, policy generation, and installation.** The
   `setup.rs` module mixes AppArmor profile templates, binary path resolution,
   status detection, and installation commands. Adding SELinux alongside it
   would create an unmaintainable tangle.

The goal is trustworthiness: users on any major Linux distribution should be
able to run `can setup` and get a correctly configured MAC policy, or be
clearly told that no MAC policy is needed.

## Options Considered

### Option 1: Add SELinux code alongside AppArmor in setup.rs

**Description**: Keep the flat module structure, add SELinux functions next to
the AppArmor ones, and use if/else branches throughout.

**Pros**:
- Minimal file changes
- No new abstractions to learn

**Cons**:
- `setup.rs` would grow to ~1000+ lines mixing two unrelated MAC systems
- Every call site needs `if apparmor { ... } else if selinux { ... } else { ... }`
- Adding a third MAC system (e.g., Landlock, Smack) would be painful
- Hard to test each backend in isolation

**Estimated effort**: Low initially, high maintenance cost

### Option 2: Trait-based MAC abstraction with module-per-backend (chosen)

**Description**: Define a `MACBackend` trait with operations common to all MAC
systems (detect, check status, install, remove, generate policy). Each backend
(AppArmor, SELinux) implements the trait in its own module. A detection function
returns the active backend (or `None` for no-MAC systems). The CLI code
operates on `&dyn MACBackend` exclusively.

**Pros**:
- Clean separation of concerns — each backend is self-contained
- Adding new backends requires only a new module implementing the trait
- Call sites are MAC-agnostic (one code path for all systems)
- Each backend is independently testable
- `None` backend cleanly handles no-MAC systems

**Cons**:
- More upfront refactoring (moving setup.rs into mac/apparmor.rs)
- Trait design requires careful thought about the right abstraction level
- Dynamic dispatch (minor, `setup` is not a hot path)

**Estimated effort**: Medium

### Option 3: Compile-time feature flags per MAC system

**Description**: Use Cargo features (`--features apparmor`, `--features selinux`)
to conditionally compile MAC support.

**Pros**:
- Zero overhead for unused backends
- Clear dependency boundaries

**Cons**:
- Users must know which MAC their system uses at compile time
- Pre-built binaries would need separate builds per MAC system
- Cannot detect and handle the active MAC at runtime
- Contradicts the "single binary works everywhere" design goal

**Estimated effort**: Medium, with distribution complexity

## Decision

**Option 2: Trait-based MAC abstraction.** The `setup.rs` module is refactored
into a `mac/` module tree with a shared trait. This provides clean runtime
detection, per-backend isolation, and trivially extensible architecture.

### Module Structure

```
crates/can-sandbox/src/
  mac/
    mod.rs          — MACBackend trait, MACSystem enum, detect_active()
    apparmor.rs     — AppArmor implementation (refactored from setup.rs)
    selinux.rs      — SELinux implementation (new)
  setup.rs          — REMOVED (replaced by mac/)
```

### Trait Definition

```rust
pub trait MACBackend {
    /// Human-readable name: "AppArmor", "SELinux"
    fn name(&self) -> &'static str;

    /// Whether this MAC system is active on the running kernel.
    fn is_active(&self) -> bool;

    /// Whether this MAC system restricts unprivileged user namespaces.
    fn restricts_userns(&self) -> bool;

    /// Current status of the canister policy.
    fn policy_status(&self) -> PolicyStatus;

    /// Generate the policy content for the given binary path.
    fn generate_policy(&self, bin_path: &str) -> String;

    /// Install the policy. Returns NeedsSudo if permissions are insufficient.
    fn install_policy(&self, bin_path: &str) -> Result<(), SetupError>;

    /// Remove the policy.
    fn remove_policy(&self) -> Result<(), SetupError>;
}
```

### Detection Logic

```
1. Check /sys/module/apparmor/parameters/enabled == "Y"
   → AppArmor is active
2. Check /sys/fs/selinux/enforce exists
   → SELinux is active
3. Neither → no MAC system (canister works without profiles)
```

### Interactive Setup

The `can setup` command gains interactive behavior when stdout is a terminal:

1. Show the generated policy content
2. If updating an existing policy, show a unified diff
3. Ask for confirmation before writing (`Install this policy? [Y/n]`)
4. Non-interactive mode (piped/CI) writes without prompting

This uses no external crates — just `std::io::IsTerminal` (already used in
can-log) and simple stdin line reading.

### SELinux Policy Architecture

SELinux requires three files:
- `canister.te` — type enforcement rules (types, transitions, permissions)
- `canister.fc` — file contexts (maps binary path to `canister_t` domain)
- `canister.if` — interface definitions (empty for our purposes)

Installation flow:
1. Generate `.te` + `.fc` with correct binary path
2. `checkmodule -M -m -o canister.mod canister.te`
3. `semodule_package -o canister.pp -m canister.mod -f canister.fc`
4. `semodule -i canister.pp`
5. `restorecon -v <bin_path>`

The SELinux policy grants `canister_t`:
- `user_namespace { create }` — create user namespaces
- `cap_userns { sys_admin sys_ptrace net_admin sys_chroot }` — capabilities in userns
- `mount`, `pivot_root` permissions on filesystem types
- Transition to `pasta_t` for the pasta binary (if pasta has a policy)
- Transition to `canister_sandboxed_t` for child processes

## Consequences

### Positive
- Canister works correctly on Ubuntu (AppArmor), Fedora/RHEL (SELinux),
  and Arch/Void/Gentoo (no MAC)
- `can check` gives accurate, system-specific guidance on any distro
- `can setup` is interactive when appropriate, scriptable when not
- Adding future MAC backends (Smack, TOMOYO) is straightforward
- Each backend can be tested independently

### Negative
- Refactoring `setup.rs` touches several call sites (capabilities.rs,
  commands.rs, namespace.rs)
- SELinux policy compilation requires `checkmodule` and `semodule_package`
  tools, which may not be installed even on SELinux systems
- SELinux enforcement testing requires a Fedora VM (compile-testing is
  possible in containers)

### Neutral
- The `setup.rs` public API (`ProfileStatus`, `detect_profile_status()`,
  `install_profile()`, `remove_profile()`) is replaced by the trait methods
  with equivalent semantics
- No backward compatibility needed (per project policy)

## Follow-up Actions
- [ ] Create `mac/` module with `MACBackend` trait and detection
- [ ] Refactor `setup.rs` → `mac/apparmor.rs`
- [ ] Implement `mac/selinux.rs`
- [ ] Update `capabilities.rs` to use MAC abstraction
- [ ] Add interactive prompts to `can setup`
- [ ] Update `can check` for multi-MAC output
- [ ] CI: AppArmor compile-test (Ubuntu), SELinux compile-test (Fedora container)
- [ ] Update ARCHITECTURE.md, README.md, CONFIGURATION.md
