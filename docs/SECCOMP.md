# Seccomp Filtering

Canister uses seccomp BPF to restrict which Linux syscalls the sandboxed
process can invoke. This document explains how the default baseline works,
how recipes customize it, and the enforcement modes available.

## Table of Contents

- [How Seccomp Works in Canister](#how-seccomp-works-in-canister)
- [Default Baseline](#default-baseline)
- [Customizing via Recipes](#customizing-via-recipes)
- [Always-Denied Syscalls](#always-denied-syscalls)
- [Deny Action: Errno vs Kill](#deny-action-errno-vs-kill)
- [Monitor Mode and SECCOMP_RET_LOG](#monitor-mode-and-seccomp_ret_log)
- [Architecture Validation](#architecture-validation)
- [Inspecting the Baseline](#inspecting-the-baseline)

---

## How Seccomp Works in Canister

Canister generates a classic BPF (Berkeley Packet Filter) program at runtime
and loads it via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` right before
`execve()`.

### Two enforcement modes

| Mode | Default action | Listed syscalls | Config value |
|------|---------------|-----------------|--------------|
| **Allow-list** (default) | DENY | Only listed syscalls permitted | `seccomp_mode = "allow-list"` |
| **Deny-list** | ALLOW | Only listed syscalls blocked | `seccomp_mode = "deny-list"` |

**Allow-list mode** (recommended, default) inverts the security model:
every syscall not explicitly in the baseline (plus `allow_extra`) is denied.
This provides a much smaller kernel attack surface.

**Deny-list mode** is the permissive fallback: everything is allowed except
the syscalls in the deny list (plus `deny_extra`). Use this when you need
maximum compatibility with unknown workloads, at the cost of a larger
attack surface.

The filter cannot be removed or modified after loading. The `PR_SET_NO_NEW_PRIVS`
flag is set first, which is required for unprivileged seccomp and also prevents
the sandboxed process from gaining new privileges via `execve` of setuid
binaries.

---

## Default Baseline

Canister ships a single default seccomp baseline defined in
`recipes/default.toml`. The baseline is embedded in the binary at compile
time via `include_str!()`, so it always works standalone. At runtime, the
search path is checked for an external override:

1. `./recipes/default.toml` (project-local)
2. `$XDG_CONFIG_HOME/canister/recipes/default.toml` (per-user)
3. `/etc/canister/recipes/default.toml` (system-wide)
4. Embedded fallback (compiled into the binary)

This lets teams pin, audit, or version-control the baseline independently
of the binary.

The baseline provides:

- **~130 allowed syscalls** — the common syscalls needed by most programs
  (read, write, open, mmap, clone, futex, etc.)
- **~16 always-denied syscalls** — dangerous operations that no sandboxed
  process should ever need (reboot, kexec_load, mount, etc.)

The `default.toml` uses absolute `[syscalls] allow = [...]` and `deny = [...]`
fields. Regular recipes use the relative `allow_extra` / `deny_extra` fields
to layer overrides on top. These two modes are **mutually exclusive** — a
recipe either IS the baseline (uses `allow`/`deny`) or EXTENDS it (uses
`allow_extra`/`deny_extra`).

The baseline was derived by analyzing the syscall needs of Python, Node.js,
Elixir/BEAM, and general-purpose binaries. The old 4-profile system (generic,
python, node, elixir) was collapsed into this single baseline because:

1. **Python and Node were literally identical** — same allow list, same deny list.
2. The total delta across all 4 profiles was only **6 syscalls**: `ptrace`,
   `personality`, `seccomp`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`.
3. The 4-profile taxonomy gave a false sense of specificity.

Recipes that need syscalls beyond the baseline use `[syscalls] allow_extra`.
Recipes that want tighter restrictions use `[syscalls] deny_extra`.

---

## Customizing via Recipes

The `[syscalls]` section in a recipe TOML customizes the baseline:

```toml
[syscalls]
allow_extra = ["ptrace"]           # add to the allow list
deny_extra  = ["personality"]      # add to deny list AND remove from allow list
seccomp_mode = "allow-list"        # default; or "deny-list"
```

**How overrides work:**

1. Start with the default baseline (ALLOW_BASE + DENY_ALWAYS).
2. Add `allow_extra` syscalls to the allow list (deduplicated).
3. Add `deny_extra` syscalls to the deny list.
4. Remove `deny_extra` syscalls from the allow list (deny takes precedence).
5. Generate the BPF filter from the final lists.

**Common recipes:**

| Workload | `allow_extra` | `deny_extra` | Why |
|----------|--------------|-------------|-----|
| Python scripts | (none) | — | Default baseline is sufficient |
| Node.js builds | (none) | — | Default baseline is sufficient |
| Elixir/BEAM | `["ptrace"]` | — | BEAM tools (`:observer`, `:dbg`, `recon`) need ptrace |
| Generic (permissive) | `["ptrace", "personality", "seccomp", "io_uring_setup", "io_uring_enter", "io_uring_register"]` | — | Maximum compatibility |
| Hardened | — | `["personality"]` | Block multilib/personality switching |

---

## Always-Denied Syscalls

The default baseline includes ~16 syscalls that are **always denied**.
These are dangerous kernel-level operations that a sandboxed process should
never need:

| Syscall | Why it's blocked |
|---------|-----------------|
| `reboot` | Reboots the system |
| `kexec_load` | Loads a new kernel |
| `init_module` | Loads a kernel module |
| `finit_module` | Loads a kernel module (from fd) |
| `delete_module` | Unloads a kernel module |
| `swapon` | Enables swap space |
| `swapoff` | Disables swap space |
| `acct` | Enables/disables process accounting |
| `mount` | Mounts a filesystem |
| `umount2` | Unmounts a filesystem |
| `pivot_root` | Changes the root filesystem |
| `chroot` | Changes the root directory |
| `syslog` | Reads/controls kernel message buffer |
| `settimeofday` | Changes the system clock |
| `unshare` | Creates new namespaces (escape vector) |
| `setns` | Joins existing namespaces (escape vector) |

These are blocked because they represent operations that only system
administrators should perform, and a sandboxed process has no legitimate
reason to invoke them.

---

## Deny Action: Errno, Kill, and Strict Mode

Canister supports three deny actions depending on the mode:

| Mode | Deny action | Behavior |
|------|-------------|----------|
| **Normal** | `SECCOMP_RET_ERRNO \| EPERM` | Denied syscall returns -1 with `errno = EPERM`. Process survives. |
| **Strict** (`--strict`) | `SECCOMP_RET_KILL_PROCESS` | Process is immediately terminated with `SIGSYS`. |
| **Monitor** (`--monitor`) | `SECCOMP_RET_LOG` | Syscall is allowed but logged to kernel audit. |

**Normal mode** (default) uses Errno because:

1. Most programs check return values and can handle `EPERM` gracefully.
2. Kill mode makes debugging harder (process just dies with no error message).
3. The denied syscalls are operations that programs generally don't invoke
   accidentally -- if a program calls `reboot()`, it's intentional and
   getting EPERM back is the right response.

**Strict mode** (`--strict`) uses Kill because:

1. In CI/production, a denied syscall indicates a policy violation or attack.
2. Immediate termination prevents any further execution after a violation.
3. The process cannot observe or react to the denial (no information leak).

The architecture validation check (wrong CPU architecture) always uses
`SECCOMP_RET_KILL_PROCESS` regardless of mode, since an architecture
mismatch indicates an actual attack (e.g., x32 ABI bypass attempt).

---

## Monitor Mode and SECCOMP_RET_LOG

When running with `--monitor`, the seccomp filter uses `SECCOMP_RET_LOG`
(`0x7ffc0000`) instead of `SECCOMP_RET_ERRNO`. This is a third deny action
mode:

| Mode | Return value | Behavior |
|------|-------------|----------|
| **Errno** | `SECCOMP_RET_ERRNO \| EPERM` | Denied syscall returns EPERM |
| **Kill** | `SECCOMP_RET_KILL_PROCESS` | Process killed immediately |
| **Log** | `SECCOMP_RET_LOG` | Syscall is **allowed** but logged to kernel audit |

In Log mode, the BPF filter structure is identical to Errno mode — same
architecture check, same deny list, same jump offsets. Only the return value
for matched syscalls changes. This means the filter accurately reflects what
*would* be blocked in enforcement mode.

**Viewing logged syscalls:**

```bash
# After running with --monitor
journalctl -k | grep seccomp
# or
dmesg | grep seccomp
```

Each log line shows the syscall number, PID, and other context. Map syscall
numbers back to names with `ausyscall` (from the `auditd` package):

```bash
ausyscall --dump | grep <number>
```

`SECCOMP_RET_LOG` is available since Linux 4.14 (well within the 5.6+
minimum kernel requirement).

---

## Architecture Validation

The BPF filter's first check validates that the syscall comes from the
expected CPU architecture:

- **x86_64:** `AUDIT_ARCH_X86_64` (0xC000003E)
- **aarch64:** `AUDIT_ARCH_AARCH64` (0xC00000B7)

If the architecture doesn't match, the process is killed immediately
(`SECCOMP_RET_KILL_PROCESS`).

**Why this matters:** On x86_64, the kernel also supports the x32 ABI (a
32-bit ABI with 64-bit pointers). x32 syscalls use different numbers than
native x86_64. Without this check, an attacker could invoke x32 syscalls
to bypass the filter (since the BPF checks are against x86_64 numbers).

---

## Inspecting the Baseline

List discovered recipes and the default baseline:

```
$ can recipes
Discovered recipes:

  elixir               Elixir/Erlang (BEAM VM) — mix, iex, Phoenix
                       +ptrace                        recipes/elixir.toml
  ...

Default baseline: ~130 allowed, ~16 denied syscalls
  Customize per-recipe with [syscalls] allow_extra / deny_extra
```

To see exactly which syscalls the baseline allows/blocks, open
`recipes/default.toml`. The `[syscalls] allow` array is the allow set,
`[syscalls] deny` is the deny set. The file is the single source of truth —
it is embedded into the binary at compile time via `include_str!()` and can
be overridden by placing a `default.toml` in the recipe search path
(`./recipes/`, `$XDG_CONFIG_HOME/canister/recipes/`, `/etc/canister/recipes/`).

`SeccompProfile::apply_overrides()` merges per-recipe `allow_extra` /
`deny_extra` customizations on top of this baseline.
