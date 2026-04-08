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
  - [Cgroups v2](#6-cgroups-v2)
  - [/proc Hardening](#7-proc-hardening)
  - [Monitor Mode](#8-monitor-mode)
  - [Strict Mode](#9-strict-mode)
- [Parent-Child Protocol](#parent-child-protocol)
- [AppArmor Interaction](#apparmor-interaction)
- [Known Limitations](#known-limitations)

---

## Design Principles

1. **Unprivileged by default.** No root, no suid, no capabilities. Everything
   runs as the calling user using unprivileged user namespaces.

2. **Defense in depth.** Seven independent isolation mechanisms. Bypassing one
   layer does not compromise the others.

3. **Fail closed.** When a feature cannot be set up (e.g., AppArmor blocks
   mounts), Canister either falls back to reduced isolation with clear
   warnings or fails entirely. In strict mode (`--strict`), all degradation
   is fatal — the sandbox runs at full strength or not at all.

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

The complete lifecycle of `can run --recipe example.toml -- python3 script.py`:

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
    │             │                        │ 7b. PROC    │
    │             │                        │    HARDEN   │
    │             │                        │    Mask     │
    │             │                        │    /proc/*  │
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
    │             │                        │ 9b. CGROUP  │
    │             │                        │    memory   │
    │             │                        │    .max +   │
    │             │                        │    cpu.max  │
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
- /proc hardening must happen after overlay + /proc mount but before seccomp.
- `RLIMIT_NPROC` must be set before seccomp (which blocks `prctl`).
- Cgroups v2 setup must happen after RLIMIT but before seccomp, because
  creating cgroups requires write access to the cgroup filesystem.
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
generated at runtime from the default baseline defined in
`recipes/default.toml` plus any `[syscalls]` overrides (`allow_extra` /
`deny_extra`).

The baseline is embedded in the binary via `include_str!()` so it works
standalone. At runtime, Canister searches for an external `default.toml` in
`./recipes/`, `$XDG_CONFIG_HOME/canister/recipes/`, and
`/etc/canister/recipes/`. If found, the external file takes precedence over
the embedded copy. This lets users pin, audit, or version-control the
baseline without recompiling.

**Two modes — allow-list (default) and deny-list:**

| Mode | Default action | Listed syscalls | Recommended for |
|------|---------------|-----------------|-----------------|
| **Allow-list** (default) | DENY | Permitted | Production, CI |
| **Deny-list** | ALLOW | Blocked | Compatibility, unknown workloads |

Allow-list mode is the default and recommended mode. It inverts the
security model: only syscalls explicitly listed in the profile are
permitted; everything else is denied. This provides a much smaller attack
surface than a deny-list.

**BPF program structure (allow-list mode):**

```
Instruction  What it does
─────────────────────────────────────────────────
[0]          Load seccomp_data.arch
[1]          If arch == x86_64: skip to [3]
[2]          Return KILL_PROCESS (wrong architecture)
[3]          Load seccomp_data.nr (syscall number)
[4]          If nr == allowed_0: jump to [ALLOW]
[5]          If nr == allowed_1: jump to [ALLOW]
...
[N]          If nr == allowed_K: jump to [ALLOW]
[N+1]        Return ERRNO(EPERM) (no match → denied)
[N+2]        Return ALLOW (match → permitted)
```

**BPF program structure (deny-list mode):**

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

The mode is selected via `[syscalls] seccomp_mode` in the config file
(default: `"allow-list"`).

**Architecture validation:** The first check rejects any syscall from a
non-native architecture. On x86_64, this prevents bypass via the x32 ABI
(which shares the kernel but uses different syscall numbers).

**Deny action:** In normal mode, Canister uses `SECCOMP_RET_ERRNO | EPERM`
which allows the sandboxed process to handle denied syscalls gracefully. In
**strict mode** (`--strict`), it uses `SECCOMP_RET_KILL_PROCESS` — the
process is killed immediately on any denied syscall.

**Security property:** Even if a process escapes all namespace isolation,
it cannot invoke unlisted syscalls. The filter is enforced by the kernel and
cannot be removed or modified by the filtered process (loading new seccomp
filters is blocked by the default baseline's deny list).

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

### 6. Cgroups v2

**Files:** `cgroups.rs`

Cgroups v2 enforces resource limits (memory and CPU) without requiring root.
It leverages systemd's per-user cgroup delegation, which is available on any
modern system running systemd (Ubuntu 22.04+, Fedora 36+, etc.).

**Setup sequence:**

1. **Detect** the current cgroup by reading `/proc/self/cgroup`.
2. **Create** a child cgroup at `<parent>/canister-<pid>`.
3. **Write** `memory.max` (bytes) and `cpu.max` (quota/period) to the child
   cgroup's control files.
4. **Move** the sandboxed process into the child cgroup by writing its PID
   to `cgroup.procs`.

**CPU limiting:** `cpu_percent = 50` translates to `cpu.max = "50000 100000"`
(50ms quota per 100ms period), effectively capping the process to 50% of
one CPU core.

**Memory limiting:** `memory_mb = 512` translates to `memory.max = 536870912`
(512 * 1024 * 1024 bytes). When exceeded, the kernel OOM-kills the process.

**Cleanup:** Child cgroups are removed when the sandboxed process exits (the
kernel removes empty cgroups automatically).

**Failure handling:** In normal mode, cgroup setup failure is non-fatal (a
warning is logged). In strict mode, cgroup failure aborts the sandbox.

**Security property:** The sandboxed process cannot consume unbounded memory
or CPU. The limits are enforced by the kernel's cgroup controller and cannot
be modified by the sandboxed process (which has no write access to the
cgroup filesystem after seccomp is loaded).

### 7. /proc Hardening

**Files:** `overlay.rs` (mount_proc function)

After mounting `/proc` inside the sandbox, Canister masks sensitive paths
following Docker's default behavior:

**Masked files** (bind-mount `/dev/null` over them):
- `/proc/kcore` — physical memory access
- `/proc/keys` — kernel keyring contents
- `/proc/sysrq-trigger` — kernel SysRq commands
- `/proc/timer_list` — timer details (information leak)
- `/proc/latency_stats` — latency statistics

**Masked directories** (mount empty read-only tmpfs over them):
- `/proc/acpi` — ACPI interface
- `/proc/scsi` — SCSI device interface

**Read-only remount:**
- `/proc/sys` — prevents writing to sysctl tunables

**Failure handling:** Individual mask failures are logged at debug level and
are non-fatal. The sandbox continues with whatever masking succeeded.

**Security property:** The sandboxed process cannot read sensitive kernel
information from /proc, trigger SysRq commands, or modify sysctl values.

### 8. Monitor Mode

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
can run --monitor --recipe my_policy.toml -- ./my_program

# 2. Review MONITOR: lines in output and seccomp audit logs
journalctl -k | grep seccomp

# 3. Adjust policy based on observations

# 4. Run with enforcement
can run --recipe my_policy.toml -- ./my_program
```

**Security property:** Monitor mode provides NO security guarantees. It is
a development/debugging tool for iterating on sandbox policies.

**Warning:** A malicious process can detect monitor mode (e.g., by
attempting a denied syscall and observing it succeeds) and behave
differently. Always validate policies with enforcement enabled.

### 9. Strict Mode

**Flag:** `--strict` (or `strict = true` in config)

Strict mode is the inverse of monitor mode: instead of relaxing
enforcement, it tightens it. Every point where normal mode gracefully
degrades becomes a hard failure in strict mode.

**Changes in strict mode:**

| Enforcement point | Normal mode | Strict mode |
|-------------------|-------------|-------------|
| Filesystem isolation | Falls back if AppArmor blocks mounts | **Aborts** |
| Network setup | Logs warning on failure | **Aborts** |
| Loopback bring-up | Skips with warning | **Aborts** |
| Seccomp deny action | `SECCOMP_RET_ERRNO` (EPERM) | `SECCOMP_RET_KILL_PROCESS` |
| Cgroup setup | Logs warning on failure | **Aborts** |

**Mutual exclusion:** `--strict` and `--monitor` cannot be used together.
This is enforced at the CLI level.

**Recommended for:** CI pipelines, production deployments, and any
environment where reduced isolation is worse than no execution.

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
  the resolved IPs are not used to filter actual connections. The sandbox in
  "filtered" network mode can connect to any IP reachable via slirp4netns.
  Requires `SECCOMP_RET_USER_NOTIF` with a supervisor thread to intercept
  `connect()` syscalls and validate the target IP against the whitelist.

- **Ongoing execve enforcement.** `allow_execve` validates the initial command
  but child processes inside the sandbox can exec arbitrary binaries that are
  visible in the mount namespace. Requires `SECCOMP_RET_USER_NOTIF` for
  path-based argument inspection of every `execve()` call.

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
