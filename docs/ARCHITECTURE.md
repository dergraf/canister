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
  - [Seccomp USER_NOTIF Supervisor](#4b-seccomp-user_notif-supervisor)
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
   mounts), Canister aborts. All setup failures are fatal in both normal and
   strict mode — the sandbox runs at full strength or not at all.

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
├── can-cli        CLI binary. Argument parsing (clap), recipe
│                  resolution (name-based lookup, auto-detection
│                  via match_prefix), composition chain assembly,
│                  `can recipe show` (emit resolved policy as TOML),
│                  can init / can update lifecycle commands.
│
├── can-sandbox    Core runtime. Orchestrates the fork/unshare/exec
│                  sequence. Contains the namespace, overlay, and
│                  seccomp modules.
│
├── can-policy     Policy engine. TOML config parsing, RecipeFile
│                  merge logic, environment variable expansion
│                  ($HOME, $USER, etc.), whitelist enforcement
│                  (path, domain, IP/CIDR), seccomp profile
│                  definitions. No Linux-specific code.
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

The complete lifecycle of `can run -r nix -r elixir -- mix test`:

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. CLI SETUP                                                        │
│    a. Parse args, resolve + canonicalize command path               │
│    b. Load base.toml (embedded, overridable)                        │
│    c. Auto-detect recipes: match resolved binary path against       │
│       match_prefix in all discovered recipe files                   │
│    d. Load explicit --recipe args (name-based lookup or file path)  │
│    e. Merge recipe chain: base → auto-detected → explicit (L-to-R) │
│    f. Expand env vars ($HOME, $USER, etc.) in merged config         │
│    g. Validate allow_execve, determine network mode                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────────┐
│ 1b. NOTIFIER SETUP (before fork)                                     │
│    a. Resolve notifier_enabled (config override / monitor mode /    │
│       kernel version auto-detect)                                   │
│    b. If enabled: create anonymous Unix socket pair for fd passing  │
│       (parent_sock, child_sock)                                     │
│    c. Pre-resolve allowed domains to IPs (already done in network   │
│       setup — IPs stored for building notifier policy)              │
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
     │             │                        │    First    │
     │             │                        │    fork()   │
     │             │                        │    (creates │
     │             │                        │    new PID  │
     │             │                        │    ns)      │
     │             │                        │             │
     │             │                        │    Interme- │
     │             │                        │    diate:   │
     │             │                        │    waitpid  │
     │             │                        │    + exit   │
     │             │                        │             │
     │             │                        │ 6a. SECOND  │
     │             │                        │    FORK     │
     │             │                        │    (when    │
     │             │                        │    notifier │
     │             │                        │    enabled) │
     │             │                        │             │
     │             │                        │   ┌─ PID 1: │
     │             │                        │   │  SUPER- │
     │             │                        │   │  VISOR  │
     │             │                        │   │  unshare│
     │             │                        │   │  NEWNS  │
     │             │                        │   │  mount  │
     │             │                        │   │  /proc  │
     │             │                        │   │  recv   │
     │             │                        │   │  notif  │
     │             │                        │   │  fd via │
     │             │                        │   │  SCM_   │
     │             │                        │   │  RIGHTS │
     │             │                        │   │  poll + │
     │             │                        │   │  waitpid│
     │             │                        │   │  loop   │
     │             │                        │   │         │
     │             │                        │   └─ PID 2: │
     │             │                        │      WORKER │
     │             │                        │      setsid │
    │             │                        │             │
    │             │                        │ 6b. CGROUP  │
    │             │                        │    Create   │
    │             │                        │    child    │
    │             │                        │    cgroup,  │
    │             │                        │    write    │
    │             │                        │    memory   │
    │             │                        │    .max +   │
    │             │                        │    cpu.max  │
    │             │                        │    (before  │
    │             │                        │    pivot_   │
    │             │                        │    root)    │
    │             │                        │             │
    │             │                        │ 7. OVERLAY  │
    │             │                        │    tmpfs    │
    │             │                        │    root,    │
    │             │                        │    bind     │
    │             │                        │    mounts   │
    │             │                        │    (from    │
    │             │                        │    merged   │
    │             │                        │    config), │
    │             │                        │    CWD bind │
    │             │                        │    mount    │
    │             │                        │    (RW),    │
    │             │                        │    pivot_   │
    │             │                        │    root,    │
    │             │                        │    chdir()  │
    │             │                        │             │
    │             │                        │ 7b. PROC    │
    │             │                        │    HARDEN   │
    │             │                        │    Mask     │
    │             │                        │    /proc/*  │
    │             │                        │             │
    │             │                        │ 8. NET      │
    │             │                        │    SETUP    │
    │             │                        │    loopback │
    │             │                        │    resolv.  │
    │             │                        │    conf     │
    │             │                        │             │
    │             │                        │ 9. PROCESS  │
    │             │                        │    RLIMIT   │
    │             │                        │    NPROC    │
    │             │                        │             │
     │             │                        │ 10. NOTIF   │
     │             │                        │    FILTER   │
     │             │                        │    Worker   │
     │             │                        │    installs │
     │             │                        │    USER_    │
     │             │                        │    NOTIF    │
     │             │                        │    BPF,     │
     │             │                        │    sends fd │
     │             │                        │    to PID 1 │
     │             │                        │    (super-  │
     │             │                        │    visor)   │
     │             │                        │    via SCM_ │
     │             │                        │    RIGHTS   │
     │             │                        │             │
     │             │                        │ 11. SECCOMP │
    │             │                        │    Load     │
    │             │                        │    main BPF │
    │             │                        │    filter   │
    │             │                        │             │
    │             │                        │ 12. ENV     │
    │             │                        │    Filter   │
    │             │                        │    env vars │
    │             │                        │             │
    │             │                        │ 13. EXEC    │
    │             │                        │    execve() │
    │             │                        │             │
    │ 14. WAIT   │                        │  (running)  │
    │     waitpid │                        │             │
    │             │                        │ (exits)     │
    │             │                        └─────────────┘
     │ 15. CLEANUP│
     │    Kill     │
     │    slirp    │
     │    Stop DNS │
     │    proxy    │
     │    Return   │
     │    exit code│
     └─────────────┘
```

**Critical ordering constraints:**

- Recipe composition (load, merge, env expansion) happens entirely in the
  CLI layer **before** forking. The child receives an already-resolved
  `SandboxConfig`.
- `unshare()` must be a single atomic call. Splitting `CLONE_NEWUSER` and
  `CLONE_NEWNS` into separate calls fails under AppArmor.
- UID/GID maps must be written from the **parent** process. The child cannot
  write its own maps after `unshare(CLONE_NEWUSER)`.
- slirp4netns must be started after the child creates `CLONE_NEWNET` but
  before the child tries to use the network.
- The inner fork for PID namespace must happen before filesystem setup so
  `/proc` mount reflects the new PID namespace.
- `setsid()` must be called after the inner PID namespace fork. PID 1
  inherits an invisible session/process-group from the parent namespace;
  without `setsid()`, bash's job control initialization fails (`getpgrp`
  returns the parent-namespace group).
- /proc hardening must happen after overlay + /proc mount but before seccomp.
- `RLIMIT_NPROC` must be set before seccomp (which blocks `prctl`).
- Cgroups v2 setup must happen **before** `pivot_root`, because the cgroup
  filesystem (`/sys/fs/cgroup`) is on the host and becomes inaccessible after
  the root is swapped. This is step 6b in the execution flow.
- The CWD bind-mount must happen during overlay setup (step 7), before
  `pivot_root`. The host's current working directory is captured before
  `unshare()` and bind-mounted writable into the new root. After
  `pivot_root`, the child calls `chdir()` to the mounted CWD path.
- The notifier filter must be installed **before** the main seccomp filter.
  The `seccomp()` syscall with `SECCOMP_FILTER_FLAG_NEW_LISTENER` returns
  the notification fd. The worker (PID 2) sends this fd to PID 1 (supervisor)
  via SCM_RIGHTS, then installs the main filter via `prctl(PR_SET_SECCOMP)`.
- PID 1 (the supervisor) must receive the notifier fd and begin its poll loop
  before the worker calls `execve()`, so the supervisor is ready to handle
  notifications from the target program.
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
4.  bind-mount essentials (read-only)       # from base.toml: /bin, /sbin, /usr/bin, ...
5.  bind-mount whitelisted paths (RO)       # from merged [filesystem].allow (all recipes)
5b. bind-mount CWD (read-write)            # host working directory, always mounted
6.  mount /tmp (read-write)                 # ephemeral writable space
7.  mount /proc                             # needed by many programs
8.  set up /dev                             # null, zero, urandom, tty, fd symlinks
9.  pivot_root(new_root, old_root)          # swap filesystem root
10. umount(old_root, MNT_DETACH)           # detach host filesystem entirely
11. chdir(cwd_path)                         # restore working directory inside new root
```

**Recipe-based mount resolution:**

The paths visible inside the sandbox come from the merged recipe chain
(`base.toml` → auto-detected → explicit). There is no hardcoded prefix
detection at runtime. Instead:

1. **`base.toml`** defines essential OS bind mounts (`/bin`, `/sbin`,
   `/usr/bin`, `/usr/sbin`, `/lib`, `/lib64`, `/usr/lib`, `/etc`). It is
   embedded in the binary via `include_str!()` and overridable on disk,
   following the same pattern as `default.toml`.

2. **Auto-detected recipes** provide package-manager mounts. Each recipe
   declares `match_prefix` patterns in its `[recipe]` metadata. During CLI
   setup (before fork), the resolved binary path is matched against all
   discovered recipes. Matching recipes are merged into the chain, bringing
   their `[filesystem].allow` paths with them:

   | Recipe | `match_prefix` | Adds to `allow` |
   |--------|---------------|-----------------|
   | `nix.toml` | `/nix/store` | `/nix/store` |
   | `homebrew.toml` | `/opt/homebrew`, `/home/linuxbrew/.linuxbrew` | `/opt/homebrew` (or linuxbrew) |
   | `cargo.toml` | `$HOME/.cargo`, `$HOME/.rustup` | `$HOME/.cargo`, `$HOME/.rustup` |
   | `snap.toml` | `/snap` | `/snap` |
   | `flatpak.toml` | `/var/lib/flatpak`, `$HOME/.local/share/flatpak` | prefix paths |
   | `gnu-store.toml` | `/gnu/store` | `/gnu/store` |

3. **Explicit recipes** (`--recipe` / `-r` flags) add whatever
   `[filesystem].allow` paths they declare.

4. **Environment variable expansion** (`$HOME`, `$USER`, `${XDG_CONFIG_HOME}`)
   is performed during `into_sandbox_config()`, after merge but before the
   paths are used by the overlay module.

This design means adding support for a new package manager is "write a
`.toml` file" rather than "modify Rust code". The `detect_command_prefix()`
function was removed entirely.

**Security model:** Filesystem visibility does not equal execution permission.
Mounted paths are visible inside the sandbox, but `allow_execve` and the
USER_NOTIF supervisor's `execve()`/`execveat()` filtering control what can
actually be *executed*.

**Security property:** The process cannot see or access any host path that
was not explicitly included in the merged recipe chain. The host's current
working directory is always bind-mounted writable so the sandboxed process
can read/write files in its working directory. All other writes go to tmpfs
and are discarded when the process exits.

**AppArmor:** When AppArmor blocks mount operations (Ubuntu 24.04+),
filesystem isolation cannot be established and the sandbox aborts. Install
the AppArmor override profile to enable full isolation (see README).

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
parent, which still has host DNS access). These resolved IPs are passed to
the USER_NOTIF supervisor, which intercepts `connect()` syscalls and validates
the destination IP against the allowlist. A DNS proxy runs in the **parent
process** on an ephemeral port, filtering DNS queries to only resolve
whitelisted domains. The sandbox's `/etc/resolv.conf` is configured to use
slirp4netns's `--dns` forwarding (on `10.0.2.3:53`), which routes queries
to the parent's DNS proxy. This prevents DNS-based information exfiltration.

**Full mode:** No `CLONE_NEWNET`. The sandbox shares the host network.

**Security property:** In None mode, the process has zero network access.
In Filtered mode, connectivity is routed through slirp4netns, and the
USER_NOTIF supervisor enforces IP-level connect() filtering against the
allowed domain/IP whitelist. DNS queries are restricted to whitelisted
domains. In Full mode, there is no network isolation.

### 4. Seccomp BPF

**Syscall:** `prctl(PR_SET_NO_NEW_PRIVS)` + `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`

A classic BPF program is loaded right before `execve()`. The filter is
generated at runtime from the default baseline defined in
`recipes/default.toml` (~170 allowed, ~16 always-denied) plus any
`[syscalls]` overrides (`allow_extra` / `deny_extra`).

When the USER_NOTIF supervisor is enabled, two BPF filters are installed:

1. **Notifier filter** (installed first, via `seccomp()` with
   `SECCOMP_FILTER_FLAG_NEW_LISTENER`): Returns `SECCOMP_RET_USER_NOTIF` for
   six intercepted syscalls (`connect`, `clone`, `clone3`, `socket`, `execve`,
   `execveat`). All others return `SECCOMP_RET_ALLOW`.

2. **Main filter** (installed second, via `prctl(PR_SET_SECCOMP)`): The
   standard allow-list or deny-list filter described below.

The kernel evaluates filters in reverse install order, but
`SECCOMP_RET_USER_NOTIF` takes special precedence — when present, the kernel
always delivers the notification to the supervisor. See
[Seccomp USER_NOTIF Supervisor](#4b-seccomp-user_notif-supervisor) for details.

When the notifier is disabled (kernel < 5.9, monitor mode, or `notifier = false`),
only the main filter is installed.

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

### 4b. Seccomp USER_NOTIF Supervisor

**Syscall:** `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)`
**Module:** `notifier.rs`

The USER_NOTIF supervisor extends seccomp BPF with argument-level inspection.
Classic BPF can only check the syscall number and architecture — it cannot
dereference pointers or read memory. The supervisor intercepts specific
syscalls via `SECCOMP_RET_USER_NOTIF`, reads the actual argument data from
`/proc/<pid>/mem`, and makes a policy decision.

**Architecture:**

The supervisor runs as **PID 1** inside the sandbox's PID namespace. This is
necessary because:

1. After `unshare(CLONE_NEWPID)`, `clone(CLONE_THREAD)` fails with `EINVAL`,
   so a supervisor thread cannot be spawned.
2. The host's procfs denies `/proc/<pid>/mem` opens from a child user namespace.
   PID 1 mounts its own procfs (owned by the sandbox's user namespace).
3. As PID 1, the supervisor is an ancestor of all sandboxed processes, satisfying
   Yama `ptrace_scope=1` without `PR_SET_PTRACER`.

```
  PID 1 (supervisor)                     PID 2+ (worker / sandboxed)
  ──────────────────                     ──────────────────────────
  unshare(CLONE_NEWNS)                   Sandbox setup (overlay, pivot_root)
  mount /proc                            seccomp() → notifier fd
  recv_fd() via SCM_RIGHTS               send_fd() via SCM_RIGHTS
       │                                 install main BPF filter
       │    connect(AF_INET, ...)        execve()
       │ ──── SUSPENDED ────────────►         │
       │                               ┌──────┴──────────────┐
       │                               │  Supervisor (PID 1) │
       │                               │  1. NOTIF_RECV      │
       │                               │  2. open+read       │
       │                               │     /proc/<pid>/mem │
       │                               │  3. Check policy    │
       │                               │  4. NOTIF_ID_VALID  │
       │    ALLOW / ERRNO(EPERM)       │  5. NOTIF_SEND      │
       │ ◄──────────────────────────── └──────────────────────┘
       │
       ▼  (continues or gets EPERM)
```

The supervisor runs inline (single-threaded) using `poll()` with a 200ms timeout,
interleaved with non-blocking `waitpid` to detect when the worker exits. After the
worker exits, remaining in-flight notifications are drained before the supervisor
terminates.

**Filtered syscalls:**

| Syscall | What is inspected | Policy enforcement |
|---------|------------------|--------------------|
| `connect()` | `sockaddr` struct (IP + port) | Must match resolved `allow_domains` IPs, `allow_ips` CIDRs, or loopback |
| `clone()` | `flags` register | Namespace flags (`CLONE_NEWNS`, `CLONE_NEWUSER`, etc.) denied |
| `clone3()` | `clone_args.flags` in userspace memory | Same namespace flag check, struct read via `/proc/<pid>/mem` |
| `socket()` | `domain` + `type` registers | `AF_NETLINK` and `SOCK_RAW` denied |
| `execve()` | Pathname string in userspace memory | Must match `allow_execve` paths (empty = allow all) |
| `execveat()` | Pathname + dirfd | Same as `execve()`, with dirfd resolution |

**TOCTOU mitigation:** Between reading the worker's memory and sending the verdict,
a multi-threaded sandbox process could modify the inspected memory. The supervisor
calls `ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID)` after the policy check — if the
notification ID is no longer valid (thread exited or memory was remapped), the
verdict is skipped.

**Memory access:** The supervisor (PID 1) runs in the same user namespace and PID
namespace as all sandboxed processes. It mounts its own procfs (the user namespace
owns the PID namespace, so the mount succeeds). `notif.pid` in the seccomp
notification matches PIDs visible in this procfs. As PID 1, the supervisor is an
ancestor of all sandboxed processes, so Yama `ptrace_scope=1` is satisfied without
`PR_SET_PTRACER`. The supervisor does NOT have `PR_SET_NO_NEW_PRIVS` set, which
would otherwise block `/proc/<pid>/mem` access.

**Fd passing protocol:** Before `fork()`, the parent creates an anonymous
Unix socket pair (`socketpair(AF_UNIX, SOCK_STREAM)`). One end is inherited by
the worker (PID 2+), the other by the supervisor (PID 1). After the notifier
filter is installed, the worker sends the notifier fd to PID 1 as `SCM_RIGHTS`
ancillary data.

**Requirements:** Linux 5.9+ (auto-detected from `/proc/sys/kernel/osrelease`).
Disabled in monitor mode (incompatible with `SECCOMP_RET_LOG`). Configurable
via `[syscalls] notifier` in recipe config.

**Security property:** Even syscalls that pass the main BPF filter are
subject to argument-level inspection. A sandboxed process cannot connect to
unauthorized IPs, create new namespaces via clone flags, open raw/netlink
sockets, or exec binaries outside the `allow_execve` whitelist.

### 5. Process Control

**Modules:** `process.rs` (environment filtering, PID namespace, RLIMIT_NPROC,
allow_execve validation)

Process control enforces the `[process]` config section:

**PID Namespace** (`CLONE_NEWPID` + two forks):

The child calls `unshare(CLONE_NEWPID)` atomically with the other namespace
flags. Since `CLONE_NEWPID` affects children of the calling process (not the
caller itself), the child forks to enter the new PID namespace.

When the USER_NOTIF supervisor is enabled, a **second fork** inside the new
PID namespace creates the supervisor/worker split:

- **PID 1** (supervisor): Mounts its own `/proc` via `unshare(CLONE_NEWNS)`,
  receives the notifier fd from the worker via SCM_RIGHTS, and runs the
  supervisor loop inline (single-threaded poll + waitpid).
- **PID 2+** (worker): Performs sandbox setup (overlay, pivot_root, seccomp),
  installs the USER_NOTIF filter, sends the notifier fd to PID 1, then execs
  the target command.

When the notifier is disabled, there is only one fork. The child becomes
PID 1 and proceeds directly with sandbox setup and exec.

After the inner fork, `setsid()` is called to create a new session and
process group. This is necessary because PID 1 inherits an invisible
session/process-group from the parent namespace. Without `setsid()`,
bash's job control initialization fails because `getpgrp()` returns the
parent-namespace process group ID, which doesn't exist in the new PID
namespace — causing "initialize_job_control: getpgrp failed".

The intermediate parent (in the old PID namespace) waits and propagates the exit code.

```
  Outer child (after unshare)
       │
       ├── fork()  (enters new PID namespace)
       │     │
       │     ├── [notifier enabled] fork() again:
       │     │     │
       │     │     ├── PID 1: Supervisor
       │     │     │     ├── unshare(CLONE_NEWNS)
       │     │     │     ├── mount /proc
       │     │     │     ├── recv notifier fd
       │     │     │     └── poll/waitpid supervisor loop
       │     │     │
       │     │     └── PID 2: Worker
       │     │           ├── setsid()
       │     │           ├── setup overlay, network, seccomp
       │     │           ├── install notifier filter, send fd to PID 1
       │     │           └── execve()
       │     │
       │     ├── [notifier disabled] PID 1: direct setup + exec
       │     │     ├── setsid()
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

**Prefix rules:** Entries ending in `/*` match any binary under that
directory tree. For example, `/nix/store/*` allows any binary whose
resolved path starts with `/nix/store/`. The match requires a `/` boundary
to prevent false positives (e.g., `/nix/store-extra/foo` does NOT match
`/nix/store/*`). This is essential for content-addressed stores like Nix
where binary paths contain unpredictable hashes.

**Limitation:** `allow_execve` validates the *initial* command at the CLI
level. Ongoing enforcement of every `execve()` call inside the sandbox is
provided by the USER_NOTIF supervisor (see
[Seccomp USER_NOTIF Supervisor](#4b-seccomp-user_notif-supervisor)), which
intercepts `execve()` and `execveat()` syscalls and validates the pathname
against the `allow_execve` whitelist. When the notifier is disabled (kernel
< 5.9 or `notifier = false`), only the initial command is validated.

### 6. Cgroups v2

**Files:** `cgroups.rs`

Cgroups v2 enforces resource limits (memory and CPU) without requiring root.
It leverages systemd's per-user cgroup delegation, which is available on any
modern system running systemd (Ubuntu 22.04+, Fedora 36+, etc.).

Resource limits are **opt-in** — none of the shipped base recipes include
`[resources]`. Users add `memory_mb` and/or `cpu_percent` in their own
recipes when needed.

**Setup sequence** (happens before `pivot_root`, while `/sys/fs/cgroup` is
still accessible):

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

**Failure handling:** Cgroup setup failure aborts the sandbox. All setup
failures are fatal regardless of mode.

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
| USER_NOTIF supervisor | Active (intercepts syscalls) | Disabled (incompatible with `SECCOMP_RET_LOG`) |
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

3. **USER_NOTIF is disabled.** The notifier supervisor is incompatible with
   monitor mode because `SECCOMP_RET_USER_NOTIF` suspends the syscall (it
   does not log-and-allow like `SECCOMP_RET_LOG`). In monitor mode, all
   syscalls pass through to the kernel with logging only.

4. **Pre-run policy preview.** Before forking, the CLI prints a summary of
   the active policy so the user knows what enforcement points will be
   observed.

5. **Post-run summary.** After the sandboxed process exits, the CLI prints
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
enforcement, it tightens it. Both normal and strict mode treat all setup
failures as fatal. The key difference is the seccomp deny action.

**Changes in strict mode:**

| Enforcement point | Normal mode | Strict mode |
|-------------------|-------------|-------------|
| Filesystem isolation | **Aborts** on failure | **Aborts** on failure |
| Network setup | **Aborts** on failure | **Aborts** on failure |
| Loopback bring-up | **Aborts** on failure | **Aborts** on failure |
| Seccomp deny action | `SECCOMP_RET_ERRNO` (EPERM) | `SECCOMP_RET_KILL_PROCESS` |
| Cgroup setup | **Aborts** on failure | **Aborts** on failure |

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
  Child: install notifier filter, send fd to PID 1 supervisor (if enabled)
  Child: setup overlay, network, seccomp
  Child: execve()

  PID 1: receive notifier fd, run inline supervisor loop (if enabled)
```

This protocol is necessary because:

1. **UID/GID maps must be written from outside the namespace.** The kernel
   requires an external process to write `/proc/<pid>/uid_map`.

2. **slirp4netns needs the child's PID and network namespace.** It must be
   started after the child creates `CLONE_NEWNET` but before the child tries
   to use the network.

3. **Mount operations need mapped UIDs.** The child cannot mount anything
   until its UID is mapped (otherwise the kernel rejects it).

4. **The notifier fd must be passed from worker to supervisor.** The `seccomp()`
   syscall returns the notifier fd in the worker's process. The fd is sent to
   PID 1 (supervisor) via `SCM_RIGHTS` over an anonymous Unix socket pair
   created before the supervisor/worker fork.

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
| Mount namespace | Created but mounts fail → **aborts** | Works |
| Filesystem isolation | **Aborts** (cannot establish) | Full |
| Network namespace | Works | Works |
| Loopback bring-up | Fails → **aborts** | Works |
| slirp4netns | Works (runs in parent) | Works |
| Seccomp | Works | Works |
| USER_NOTIF supervisor | Works | Works |

**Detection:** `can check` reads
`/sys/kernel/security/apparmor/policy/unprivileged_userns` and
`/proc/sys/kernel/apparmor_restrict_unprivileged_userns` to detect the
restriction and report it clearly.

**Fix:** The `canister.apparmor` file provides a local override that grants
mount and umount permissions to processes in the `unprivileged_userns` profile.

---

## Known Limitations

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

- **USER_NOTIF TOCTOU window.** The `SECCOMP_IOCTL_NOTIF_ID_VALID` check
  mitigates but does not fully eliminate the time-of-check-time-of-use race
  in the USER_NOTIF supervisor. A highly concurrent, adversarial workload
  with precise timing could theoretically modify memory between the supervisor's
  read and verdict. This is an inherent limitation of the `seccomp_unotify`
  mechanism.
