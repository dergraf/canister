# Architecture

This document describes the internal design of Canister, the execution flow
of a sandboxed process, and the security properties of each isolation layer.

## Table of Contents

- [Design Principles](#design-principles)
- [Crate Structure](#crate-structure)
- [Execution Flow](#execution-flow)
- [Isolation Layers](#isolation-layers)
  - [User Namespaces](#1-user-namespaces)
  - [Mount Namespace + pivot_root](#2-mount-namespace--pivot_root)
  - [Network Namespace](#3-network-namespace)
  - [Seccomp BPF](#4-seccomp-bpf)
  - [Process Control](#5-process-control)
  - [Monitor Mode](#6-monitor-mode)
- [Parent-Child Protocol](#parent-child-protocol)
- [AppArmor Interaction](#apparmor-interaction)
- [Known Limitations](#known-limitations)

---

## Design Principles

1. **Unprivileged by default.** No root, no suid, no capabilities. Everything
   runs as the calling user using unprivileged user namespaces.

2. **Defense in depth.** Five independent isolation mechanisms. Bypassing one
   layer does not compromise the others.

3. **Fail closed.** When a feature cannot be set up (e.g., AppArmor blocks
   mounts), Canister either falls back to reduced isolation with clear
   warnings or fails entirely. It never silently runs without protection.

4. **Single binary.** No runtime dependencies beyond the Linux kernel (and
   optionally slirp4netns for filtered networking). No dynamic linking to
   external libraries.

5. **One-shot execution.** Fork, isolate, exec, wait, exit. No daemon, no
   long-running supervisor process. The sandbox lifetime equals the command
   lifetime.

---

## Crate Structure

```
canister/
├── can-cli        CLI binary. Argument parsing (clap), dispatches to
│                  can-sandbox. No business logic.
│
├── can-sandbox    Core runtime. Orchestrates the fork/unshare/exec
│                  sequence. Contains the namespace, overlay, and
│                  seccomp modules.
│
├── can-policy     Policy engine. TOML config parsing, whitelist
│                  enforcement (path, domain, IP/CIDR), seccomp
│                  profile definitions. No Linux-specific code.
│
├── can-net        Network isolation. Network namespace setup,
│                  loopback interface, slirp4netns integration,
│                  DNS proxy with domain filtering.
│
└── can-log        Logging setup. TTY detection, human vs JSON
                   output selection, monitor-mode event types
                   and summary output.
```

Dependencies flow downward: `can-cli` -> `can-sandbox` -> `can-policy`,
`can-net`. `can-policy` and `can-log` have no internal dependencies.

---

## Execution Flow

The complete lifecycle of `can run --config example.toml -- python3 script.py`:

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. CLI SETUP                                                        │
│    Parse args, load TOML config, resolve + canonicalize command     │
│    path (following all symlinks), validate against allow_execve,    │
│    determine network mode from config                               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────────┐
│ 2. FORK                                                             │
│    Create two pipes (child_ready, parent_done).                     │
│    Capture UID/GID. Call fork().                                    │
└──────────┬──────────────────────────────────────┬───────────────────┘
           │                                      │
    ┌──────▼──────┐                        ┌──────▼──────┐
    │   PARENT    │                        │    CHILD    │
    │             │                        │             │
    │             │                        │ 3. UNSHARE  │
    │             │                        │    Atomic:  │
    │             │                        │    USER+MNT │
    │             │                        │    +PID     │
    │             │                        │    [+NET]   │
    │             │    "ready" ◄────────── │             │
    │             │                        │             │
    │ 4. UID/GID  │                        │   (blocks)  │
    │    MAPPING   │                        │             │
    │    Write     │                        │             │
    │    /proc/    │                        │             │
    │    <pid>/    │                        │             │
    │    uid_map   │                        │             │
    │    gid_map   │                        │             │
    │             │                        │             │
    │ 5. NETWORK  │                        │             │
    │    Start    │                        │             │
    │    slirp4   │                        │             │
    │    netns    │                        │             │
    │    (if      │                        │             │
    │    filtered)│                        │             │
    │             │                        │             │
    │             │ ──────────► "done"     │             │
    │             │                        │             │
    │             │                        │ 6. PID NS   │
    │             │                        │    Inner    │
    │             │                        │    fork()   │
    │             │                        │    (PID 1)  │
    │             │                        │             │
    │             │                        │ 6b. PREFIX  │
    │             │                        │    Detect   │
    │             │                        │    pkg mgr  │
    │             │                        │    prefix   │
    │             │                        │             │
    │             │                        │ 7. OVERLAY  │
    │             │                        │    tmpfs    │
    │             │                        │    root,    │
    │             │                        │    bind     │
    │             │                        │    mounts   │
    │             │                        │    +prefix, │
    │             │                        │    pivot_   │
    │             │                        │    root     │
    │             │                        │             │
    │             │                        │ 8. NET      │
    │             │                        │    SETUP    │
    │             │                        │    loopback │
    │             │                        │    or log   │
    │             │                        │             │
    │             │                        │ 9. PROCESS  │
    │             │                        │    RLIMIT   │
    │             │                        │    NPROC    │
    │             │                        │             │
    │             │                        │ 10. SECCOMP │
    │             │                        │    Load BPF │
    │             │                        │    filter   │
    │             │                        │             │
    │             │                        │ 11. ENV     │
    │             │                        │    Filter   │
    │             │                        │    env vars │
    │             │                        │             │
    │             │                        │ 12. EXEC    │
    │             │                        │    execve() │
    │             │                        │             │
    │ 13. WAIT   │                        │  (running)  │
    │     waitpid │                        │             │
    │             │                        │ (exits)     │
    │             │                        └─────────────┘
    │ 14. CLEANUP│
    │    Kill     │
    │    slirp    │
    │    Return   │
    │    exit code│
    └─────────────┘
```

**Critical ordering constraints:**

- `unshare()` must be a single atomic call. Splitting `CLONE_NEWUSER` and
  `CLONE_NEWNS` into separate calls fails under AppArmor.
- UID/GID maps must be written from the **parent** process. The child cannot
  write its own maps after `unshare(CLONE_NEWUSER)`.
- slirp4netns must be started after the child creates `CLONE_NEWNET` but
  before the child tries to use the network.
- The inner fork for PID namespace must happen before filesystem setup so
  `/proc` mount reflects the new PID namespace.
- Command prefix detection must happen after PID namespace entry but before
  overlay setup, so the prefix can be bind-mounted into the new root.
- `RLIMIT_NPROC` must be set before seccomp (which blocks `prctl`).
- Seccomp must be loaded **after** all setup is complete, right before exec.
- Environment filtering happens at exec time — `execve()` receives the
  filtered environment directly.

---

## Isolation Layers

### 1. User Namespaces

**Syscall:** `unshare(CLONE_NEWUSER)`

The child process gets a new user namespace where it is mapped as UID 0 / GID 0.
This gives it "root inside the namespace" which is required for mount
operations, but grants **zero real privileges** on the host.

The parent writes the mapping:

```
/proc/<pid>/setgroups → "deny"
/proc/<pid>/uid_map   → "0 <host_uid> 1"
/proc/<pid>/gid_map   → "0 <host_gid> 1"
```

**Security property:** The child appears to be root but cannot affect any
resources outside its namespace. All privilege checks are scoped to the
namespace.

### 2. Mount Namespace + pivot_root

**Syscall:** `unshare(CLONE_NEWNS)` + `pivot_root()`

The child gets its own mount table. The setup sequence:

```
1.  mount("", "/", MS_SLAVE | MS_REC)     # stop propagation to host
2.  mount("tmpfs", new_root)               # empty tmpfs as new root
3.  mkdir skeleton dirs                     # /bin, /lib, /usr, /proc, /dev, /tmp, ...
4.  bind-mount essentials (read-only)       # /bin, /sbin, /usr/bin, /usr/sbin, /lib, ...
5.  bind-mount whitelisted paths (RO)       # from config [filesystem].allow
5b. bind-mount command prefix (RO)          # auto-detected package-manager root (see below)
6.  mount /tmp (read-write)                 # ephemeral writable space
7.  mount /proc                             # needed by many programs
8.  set up /dev                             # null, zero, urandom, tty, fd symlinks
9.  pivot_root(new_root, old_root)          # swap filesystem root
10. umount(old_root, MNT_DETACH)           # detach host filesystem entirely
```

**Command prefix auto-detection (step 5b):**

When the command binary lives outside standard FHS paths (e.g., under
`/nix/store`, `/opt/homebrew`, `/home/user/.cargo`), the sandbox would fail
with ENOENT after `pivot_root` since the binary's path doesn't exist in the
new root.

Canister handles this generically:

1. **Canonicalize** the command path at startup (`std::fs::canonicalize`),
   resolving all symlinks. This is critical for package managers like Nix
   that use multi-hop symlink chains (e.g., `~/.nix-profile/bin/iex` →
   `/nix/store/<hash>-elixir/bin/iex`).

2. **Detect** the package-manager prefix from the canonical path:

   | Command path                           | Detected prefix      |
   |----------------------------------------|----------------------|
   | `/nix/store/<hash>-elixir/bin/iex`     | `/nix/store`         |
   | `/gnu/store/<hash>-guile/bin/guile`    | `/gnu/store`         |
   | `/opt/homebrew/bin/python3`            | `/opt/homebrew`      |
   | `/snap/core22/current/usr/bin/hello`   | `/snap`              |
   | `/var/lib/flatpak/app/.../bin/foo`     | `/var/lib/flatpak`   |
   | `/home/user/.cargo/bin/rg`            | `/home/user/.cargo`  |
   | `/usr/bin/python3`                     | None (essential)     |

3. **Bind-mount** the entire prefix tree read-only. For content-addressed
   stores like `/nix/store`, this is the only practical approach — binaries
   reference sibling store entries freely, making individual-entry mounting
   an unbounded dependency chase.

4. **Log a warning** telling the user to add the prefix to
   `[filesystem] allow` to silence it.

The prefix mount is skipped if:
- The path is under an essential mount (e.g., `/usr/bin`)
- The prefix is already covered by the user's `[filesystem] allow` list
- The prefix is in the `[filesystem] deny` list

**Security model:** Filesystem visibility does not equal execution permission.
The prefix mount makes files *visible* inside the sandbox, but `allow_execve`
(and future `SECCOMP_RET_USER_NOTIF`-based enforcement) controls what can
actually be *executed*.

**Security property:** The process cannot see or access any host path that
was not explicitly bind-mounted or auto-detected as a command prefix. All
writes go to tmpfs and are discarded when the process exits.

**Degraded mode:** When AppArmor blocks mount operations (Ubuntu 24.04+),
all mount steps are skipped. The process runs with the full host filesystem.
A clear warning is logged.

### 3. Network Namespace

**Syscall:** `unshare(CLONE_NEWNET)` + slirp4netns

Three modes, determined from config:

**None mode:** The sandbox has an empty network namespace with only loopback.
No external connectivity.

**Filtered mode:** The parent starts `slirp4netns --configure --mtu=65520
--disable-host-loopback` which creates a TAP interface (`tap0`) inside the
child's network namespace and provides user-mode TCP/IP:

```
┌──────────────────────────────────┐
│         Host network             │
│                                  │
│   slirp4netns ◄──── TAP fd      │
│       │                          │
│       │  user-mode TCP/IP        │
│       │                          │
└───────┼──────────────────────────┘
        │
┌───────┼──────────────────────────┐
│       ▼      Sandbox network     │
│   tap0 (10.0.2.100)             │
│   gateway: 10.0.2.2             │
│   DNS:     10.0.2.3             │
│                                  │
│   ┌─────────────────────────┐    │
│   │   sandboxed process     │    │
│   └─────────────────────────┘    │
└──────────────────────────────────┘
```

Whitelisted domains are pre-resolved to IP addresses at startup (from the
parent, which still has host DNS access). These resolved IPs are intended
for future connect() syscall filtering via `SECCOMP_RET_USER_NOTIF`.

**Full mode:** No `CLONE_NEWNET`. The sandbox shares the host network.

**Security property:** In None mode, the process has zero network access.
In Filtered mode, it has connectivity through slirp4netns (full IP-level
filtering of connect() is planned for a future phase). In Full mode, there
is no network isolation.

### 4. Seccomp BPF

**Syscall:** `prctl(PR_SET_NO_NEW_PRIVS)` + `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`

A classic BPF program is loaded right before `execve()`. The filter is
generated at runtime from the selected profile's deny-list.

**BPF program structure:**

```
Instruction  What it does
─────────────────────────────────────────────────
[0]          Load seccomp_data.arch
[1]          If arch == x86_64: skip to [3]
[2]          Return KILL_PROCESS (wrong architecture)
[3]          Load seccomp_data.nr (syscall number)
[4]          If nr == denied_0: jump to [DENY]
[5]          If nr == denied_1: jump to [DENY]
...
[N]          If nr == denied_K: jump to [DENY]
[N+1]        Return ALLOW (no match → permitted)
[N+2]        Return ERRNO(EPERM) (match → denied)
```

**Architecture validation:** The first check rejects any syscall from a
non-native architecture. On x86_64, this prevents bypass via the x32 ABI
(which shares the kernel but uses different syscall numbers).

**Deny action:** Canister uses `SECCOMP_RET_ERRNO | EPERM` rather than
`SECCOMP_RET_KILL_PROCESS`. This allows the sandboxed process to handle
denied syscalls gracefully (e.g., catch the error and continue) rather than
being killed immediately.

**Security property:** Even if a process escapes all namespace isolation,
it cannot invoke denied syscalls. The filter is enforced by the kernel and
cannot be removed or modified by the filtered process (loading new filters
is blocked since `seccomp` is in the deny list for python/node profiles).

### 5. Process Control

**Modules:** `process.rs` (environment filtering, PID namespace, RLIMIT_NPROC,
allow_execve validation)

Process control enforces the `[process]` config section:

**PID Namespace** (`CLONE_NEWPID` + inner fork):

The child calls `unshare(CLONE_NEWPID)` atomically with the other namespace
flags. Since `CLONE_NEWPID` affects children of the calling process (not the
caller itself), the child forks once more. The inner child becomes PID 1 in
the new PID namespace. The intermediate parent waits and propagates the exit
code.

```
  Outer child (after unshare)
       │
       ├── fork()
       │     │
       │     ├── Inner child (PID 1 in new ns)
       │     │     ├── setup overlay, network, seccomp
       │     │     └── execve()
       │     │
       │     └── (intermediate parent waits, exits with child's code)
```

**Security property:** The sandboxed process tree is completely isolated. It
cannot see or signal host processes via /proc or kill().

**Environment Filtering** (`env_passthrough`):

Before `execve()`, the environment is reconstructed from scratch. Only
variables listed in `env_passthrough` are kept. If the list is empty, the
process starts with a completely clean environment (zero host leakage).

A minimal `PATH` is injected if not explicitly passed through, to prevent
the sandbox from being unable to find executables.

Uses `execve()` instead of `execvp()` to pass the filtered environment
explicitly.

**Security property:** Sensitive environment variables (API keys, tokens,
credentials in `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc.) are never
leaked to the sandbox unless explicitly whitelisted.

**`max_pids`** (`RLIMIT_NPROC`):

Sets `RLIMIT_NPROC` via `setrlimit()` to cap the number of processes the
sandbox can create. This is a per-UID limit — effective because the sandbox
runs as UID 0 in its own user namespace, mapped to the host user.

**Security property:** Prevents fork bombs. A process that exceeds the limit
gets `EAGAIN` from `fork()`.

**`allow_execve`** (pre-exec validation):

The resolved command path is checked against the `allow_execve` whitelist
before forking. If the command is not in the list (and the list is non-empty),
execution is rejected immediately.

**Limitation:** This only validates the *initial* command. Child processes
spawned inside the sandbox can exec arbitrary binaries. Full ongoing execve
enforcement requires `SECCOMP_RET_USER_NOTIF` with a supervisor thread
(planned for a future phase).

### 6. Monitor Mode

**Flag:** `--monitor`

Monitor mode runs the sandbox with all namespace isolation active (for accurate
observation) but relaxes policy enforcement. Each enforcement point logs what
*would* have been blocked without actually blocking it.

**Enforcement points and their monitor-mode behavior:**

| Enforcement point | Normal mode | Monitor mode |
|-------------------|-------------|--------------|
| `allow_execve` | Rejects unlisted commands | Logs warning, allows through |
| `env_passthrough` | Strips unlisted env vars | Logs what would be stripped, passes full env |
| `max_pids` | Sets `RLIMIT_NPROC` | Logs the limit, skips `setrlimit()` |
| Seccomp BPF | `SECCOMP_RET_ERRNO` (EPERM) | `SECCOMP_RET_LOG` (allowed but kernel-logged) |
| Filesystem isolation | Full overlay + pivot_root | Full overlay + pivot_root (unchanged) |
| Network isolation | Namespace + slirp4netns | Namespace + slirp4netns (unchanged) |

**Key design decisions:**

1. **Namespaces stay active.** Monitor mode does NOT skip namespace creation.
   This ensures the process runs in the same environment it would in enforced
   mode, so observations are accurate. If namespaces were disabled, the process
   might behave differently (different PIDs, different filesystem view, etc.).

2. **`SECCOMP_RET_LOG` for syscalls.** Instead of returning EPERM, denied
   syscalls are allowed through but logged to the kernel audit subsystem.
   View these with `journalctl -k | grep seccomp`. This uses a real BPF
   filter (same structure as enforcement mode) so the observation is exact.

3. **Pre-run policy preview.** Before forking, the CLI prints a summary of
   the active policy so the user knows what enforcement points will be
   observed.

4. **Post-run summary.** After the sandboxed process exits, the CLI prints
   a summary with the exit code and hints for reviewing the monitor output.

**Intended workflow:**

```bash
# 1. Run with monitor to see what the policy would block
can run --monitor --config my_policy.toml -- ./my_program

# 2. Review MONITOR: lines in output and seccomp audit logs
journalctl -k | grep seccomp

# 3. Adjust policy based on observations

# 4. Run with enforcement
can run --config my_policy.toml -- ./my_program
```

**Security property:** Monitor mode provides NO security guarantees. It is
a development/debugging tool for iterating on sandbox policies.

---

## Parent-Child Protocol

The parent and child synchronize via two anonymous pipes:

```
Pipe 1: child_ready (child → parent)
Pipe 2: parent_done (parent → child)

Timeline:
  Child: unshare()
  Child: write(child_ready, 0x00)       ← "namespaces created"
  Child: read(parent_done)              ← blocks

  Parent: read(child_ready)             ← unblocks
  Parent: write uid_map, gid_map
  Parent: start slirp4netns (if needed)
  Parent: write(parent_done, 0x00)      ← "maps written, network ready"

  Child: read(parent_done)              ← unblocks
  Child: setup overlay, network, seccomp
  Child: execve()
```

This protocol is necessary because:

1. **UID/GID maps must be written from outside the namespace.** The kernel
   requires an external process to write `/proc/<pid>/uid_map`.

2. **slirp4netns needs the child's PID and network namespace.** It must be
   started after the child creates `CLONE_NEWNET` but before the child tries
   to use the network.

3. **Mount operations need mapped UIDs.** The child cannot mount anything
   until its UID is mapped (otherwise the kernel rejects it).

---

## AppArmor Interaction

Ubuntu 24.04+ sets `kernel.apparmor_restrict_unprivileged_userns=1` by default.
When a process calls `unshare(CLONE_NEWUSER)`, AppArmor transitions it to the
`unprivileged_userns` profile which denies:

- All mount operations (mount, umount, pivot_root)
- All capabilities (CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, etc.)
- Module loading

**Impact on Canister:**

| Feature | With AppArmor restriction | Without |
|---------|--------------------------|---------|
| User namespace | Works | Works |
| Mount namespace | Created but mounts fail | Works |
| Filesystem isolation | **Degraded** (host FS visible) | Full |
| Network namespace | Works | Works |
| Loopback bring-up | Fails (no CAP_NET_ADMIN) | Works |
| slirp4netns | Works (runs in parent) | Works |
| Seccomp | Works | Works |

**Detection:** `can check` reads
`/sys/kernel/security/apparmor/policy/unprivileged_userns` and
`/proc/sys/kernel/apparmor_restrict_unprivileged_userns` to detect the
restriction and report it clearly.

**Fix:** The `canister.apparmor` file provides a local override that grants
mount and umount permissions to processes in the `unprivileged_userns` profile.

---

## Known Limitations

### Not yet implemented

- **IP-level connect() filtering.** Whitelisted domains are pre-resolved but
  the resolved IPs are not used to filter actual connections. Requires
  `SECCOMP_RET_USER_NOTIF` with a supervisor thread.

- **Ongoing execve enforcement.** `allow_execve` validates the initial command
  but child processes inside the sandbox can exec arbitrary binaries.
  Requires `SECCOMP_RET_USER_NOTIF` for path-based argument inspection.

- **Resource limits.** `memory_mb` and `cpu_percent` require cgroups v2
  delegation (Phase 7).

### Fundamental limitations

- **Kernel exploits.** No userspace sandbox can protect against kernel
  vulnerabilities. Seccomp reduces the attack surface but cannot eliminate it.

- **Side channels.** Timing attacks, cache attacks, and speculative execution
  attacks are out of scope.

- **RLIMIT_NPROC is per-UID.** The max_pids limit applies to the user's total
  process count, not just the sandbox. Inside a user namespace this is usually
  fine (the sandbox runs as a mapped UID), but if multiple sandboxes share
  a UID they share the limit.

- **DNS resolution timing.** Domain pre-resolution happens at sandbox startup.
  If DNS records change during execution, the resolved IP set becomes stale.
  TTL-aware re-resolution is not implemented.
