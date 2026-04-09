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
- [USER_NOTIF Supervisor](#user_notif-supervisor)
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

- **~170 allowed syscalls** — the common syscalls needed by most programs
  (read, write, open, mmap, clone, futex, getpgrp, etc.)
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

## USER_NOTIF Supervisor

Classic BPF can only inspect the syscall number and architecture (`seccomp_data.nr`
and `seccomp_data.arch`). It cannot inspect syscall **arguments** — for pointer-based
arguments like `connect()`'s `sockaddr` or `execve()`'s pathname, the BPF filter
only sees the raw pointer value, not the data it points to.

Canister uses `SECCOMP_RET_USER_NOTIF` (Linux 5.9+) to bridge this gap. When the
child invokes a syscall that requires argument inspection, the kernel suspends the
calling thread and delivers a notification to a supervisor thread running in the
parent process. The supervisor reads the actual argument data (from `/proc/<pid>/mem`),
makes a policy decision, and sends an ALLOW or DENY verdict back to the kernel.

### How it works

```
  Child (sandboxed)                    Parent (supervisor)
  ──────────────────                   ────────────────────
  1. seccomp(SET_MODE_FILTER,          4. Receive notifier fd via
     NEW_LISTENER, &bpf_prog)             Unix socket (SCM_RIGHTS)
     → returns notifier fd
  2. Send notifier fd to parent        5. Spawn supervisor thread
     via Unix socket (SCM_RIGHTS)
  3. Install main BPF filter           6. Loop:
     (prctl PR_SET_SECCOMP)               a. ioctl(NOTIF_RECV) → read notification
  ... execve() target command ...         b. Read /proc/<pid>/mem for arguments
                                          c. Evaluate against policy
                                          d. ioctl(NOTIF_ID_VALID) → TOCTOU check
                                          e. ioctl(NOTIF_SEND) → verdict
```

The notifier filter is installed **before** the main seccomp filter. The child
sends the notification fd to the parent via an anonymous Unix socket pair created
before `fork()`, using `SCM_RIGHTS` ancillary data. After the parent receives the
fd, it spawns a dedicated supervisor thread that blocks on `ioctl(NOTIF_RECV)`.

### Two-filter architecture

The child installs two seccomp filters:

1. **Notifier filter** (installed first via `seccomp()` syscall with
   `SECCOMP_FILTER_FLAG_NEW_LISTENER`): Returns `SECCOMP_RET_USER_NOTIF` for the
   six intercepted syscalls (`connect`, `clone`, `clone3`, `socket`, `execve`,
   `execveat`). All other syscalls return `SECCOMP_RET_ALLOW`.

2. **Main filter** (installed second via `prctl(PR_SET_SECCOMP)`): The existing
   allow-list or deny-list BPF filter. Returns `SECCOMP_RET_ERRNO`,
   `SECCOMP_RET_KILL_PROCESS`, or `SECCOMP_RET_LOG` depending on mode.

The kernel evaluates filters in reverse install order, but `SECCOMP_RET_USER_NOTIF`
takes special precedence — when any filter returns USER_NOTIF, the kernel always
delivers the notification to the supervisor, regardless of what other filters return.

### Intercepted syscalls

| Syscall | Argument inspected | Policy |
|---------|-------------------|--------|
| `connect()` | `sockaddr` (destination address) | Allow only IPs from pre-resolved `allow_domains` and explicit `allow_ips`. Loopback and Unix domain sockets always allowed. |
| `clone()` | `flags` (register value) | Deny namespace-creating flags: `CLONE_NEWNS`, `CLONE_NEWCGROUP`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET` |
| `clone3()` | `clone_args.flags` (read from userspace struct) | Same flag check as `clone()`, read from the `clone_args` struct via `/proc/<pid>/mem` |
| `socket()` | `domain`, `type` (register values) | Deny `AF_NETLINK` (domain 16) and `SOCK_RAW` (type 3). Normal TCP/UDP/Unix sockets allowed. |
| `execve()` | `pathname` (read from userspace string) | Validate against `allow_execve` paths. If `allow_execve` is empty, allow all. |
| `execveat()` | `pathname` (read from userspace string) | Same as `execve()`. Resolves the path relative to the `dirfd` argument. |

### TOCTOU protection

A time-of-check-time-of-use race exists: a multi-threaded sandboxed process
could modify the memory that the supervisor reads between the read and the
verdict. Canister mitigates this with `SECCOMP_IOCTL_NOTIF_ID_VALID`:

1. Read notification (gets syscall args and a unique notification ID).
2. Read memory from `/proc/<pid>/mem` for pointer-based arguments.
3. Evaluate policy.
4. Call `ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID, &id)` — if the kernel returns
   an error (`ENOENT`), the syscall was interrupted (the thread exited or
   the memory was unmapped) and the notification is stale. The supervisor
   skips sending a verdict.
5. Send verdict.

This is the standard mitigation recommended by the `seccomp_unotify(2)` man page.
It is not airtight against a determined attacker with precise timing, but it
eliminates the most common race windows.

### CIDR matching

For `connect()` filtering, the supervisor supports both exact IP matches and CIDR
range matches (e.g., `10.0.0.0/8`, `2606:2800:220:1::/64`). The resolved IPs from
`allow_domains` are combined with any `allow_ips` CIDR ranges from the config to
build the allowlist. Loopback addresses (`127.0.0.0/8`, `::1`) and `AF_UNIX`
sockets are always permitted.

### DNS proxy integration

When the notifier is active, a DNS proxy is started inside the sandbox (listening
on `10.0.2.3:53`). DNS queries from the sandboxed process are intercepted by the
proxy, which only resolves domains in the `allow_domains` list. This prevents
DNS-based information exfiltration and ensures the sandbox can only resolve
whitelisted domains.

### Configuration

The notifier is controlled by the `notifier` field in `[syscalls]`:

```toml
[syscalls]
notifier = true     # force on
notifier = false    # force off
# omit             → auto-detect (default)
```

**Auto-detection logic:**

1. If `notifier` is explicitly set in the config, that value is used.
2. If running in monitor mode, the notifier is disabled (monitor mode uses
   `SECCOMP_RET_LOG`, which is incompatible with `SECCOMP_RET_USER_NOTIF`).
3. Otherwise, the notifier is enabled if the kernel version is 5.9 or later
   (the minimum version that supports all required `seccomp_unotify` ioctls).

Kernel version detection reads `/proc/sys/kernel/osrelease` and parses the
major.minor version.

### Requirements

- **Linux 5.9+** — for `SECCOMP_IOCTL_NOTIF_RECV`, `SECCOMP_IOCTL_NOTIF_SEND`,
  and `SECCOMP_IOCTL_NOTIF_ID_VALID`.
- **`PR_SET_NO_NEW_PRIVS`** must be set before installing the filter (already done
  by both the notifier and main filter installation paths).
- **`/proc/<pid>/mem`** must be readable by the parent (always true since the parent
  has the same UID as the child).

---

## Inspecting the Baseline

List discovered recipes and the default baseline:

```
$ can recipes
Discovered recipes:

  elixir               Elixir/Erlang (BEAM VM) — mix, iex, Phoenix
                       +ptrace                        recipes/elixir.toml
  ...

Default baseline: ~170 allowed, ~16 denied syscalls
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
