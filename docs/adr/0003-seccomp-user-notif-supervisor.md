# ADR-0003: Seccomp USER_NOTIF Supervisor for Argument-Level Syscall Filtering

## Status
Accepted

## Date
2026-04-09

## Context

Canister's seccomp BPF filter (ADR-0001, Phase 2) restricts which syscalls the
sandboxed process can invoke. However, classic BPF (`SECCOMP_MODE_FILTER`) can
only inspect `seccomp_data.arch` and `seccomp_data.nr` — the CPU architecture
and syscall number. It **cannot**:

1. **Dereference pointers.** `connect()`'s `sockaddr` argument, `execve()`'s
   pathname, and `clone3()`'s `clone_args` struct are all passed as pointers.
   BPF sees the raw pointer value (a memory address), not the data behind it.

2. **Read userspace memory.** The BPF program runs in kernel context with no
   mechanism to follow pointers into the process's address space.

3. **Inspect register-based arguments with full context.** While BPF can read
   `seccomp_data.args[0..5]` (the raw register values), meaningful inspection
   requires understanding the argument's type and semantics — e.g., interpreting
   `clone()`'s flags bitmask requires knowing which bits are namespace flags.

This created three security gaps:

- **connect() filtering**: Allowed domains were pre-resolved to IPs at
  startup, but the resolved IPs were never used to filter actual `connect()`
  calls. The sandbox in filtered network mode could connect to any IP
  reachable via pasta.

- **Ongoing execve enforcement**: `allow_execve` validated the initial command
  before forking, but child processes inside the sandbox could exec arbitrary
  binaries visible in the mount namespace.

- **Namespace escape via clone flags**: A sandboxed process could call
  `clone(CLONE_NEWUSER | ...)` or `clone3()` with namespace flags to create
  new namespaces and potentially escape isolation layers.

## Options Considered

### Option 1: Classic BPF argument checks (register-value filtering)

**Description**: Use `BPF_LD | BPF_W | BPF_ABS` to load `seccomp_data.args[N]`
and compare register values directly in the BPF program.

**Pros**: No supervisor thread; no fd passing; lower latency; simpler
implementation.

**Cons**: Only works for non-pointer arguments where the raw register value
is meaningful (e.g., `socket()` domain, `clone()` flags). Cannot inspect
`connect()`'s `sockaddr` (pointer), `execve()`'s pathname (pointer), or
`clone3()`'s `clone_args` (pointer to struct). Covers maybe 30% of the
use cases.

**Estimated effort**: Low

### Option 2: SECCOMP_RET_USER_NOTIF supervisor thread (chosen)

**Description**: Install a second BPF filter that returns `SECCOMP_RET_USER_NOTIF`
for syscalls requiring argument inspection. The kernel suspends the calling
thread and delivers a notification to a supervisor thread in the parent process.
The supervisor reads `/proc/<pid>/mem` to inspect pointer-based arguments,
makes a policy decision, and sends an ALLOW or DENY verdict.

**Pros**: Can inspect any argument, including pointer-based data; can read
userspace memory safely; handles all six target syscalls; TOCTOU mitigation
via `SECCOMP_IOCTL_NOTIF_ID_VALID`; does not require root.

**Cons**: Adds complexity (supervisor thread, fd passing via SCM_RIGHTS, two
BPF filters); introduces latency for intercepted syscalls; requires Linux 5.9+;
inherent TOCTOU window that cannot be fully eliminated.

**Estimated effort**: High

### Option 3: eBPF-based filtering

**Description**: Use eBPF programs attached to seccomp hooks for richer
argument inspection with kernel-side execution.

**Pros**: In-kernel execution (no context switch to userspace); no TOCTOU
window; can use eBPF maps for dynamic policy updates.

**Cons**: Requires `CAP_BPF` or root (violates Canister's unprivileged design
principle); eBPF seccomp integration is experimental/unavailable on most
kernels; significantly more complex to implement and debug; no stable API.

**Estimated effort**: Very high

## Decision

**Option 2: SECCOMP_RET_USER_NOTIF with a supervisor thread.** This is the
only option that can inspect pointer-based arguments without requiring elevated
privileges. The added complexity is manageable and the latency impact is
acceptable for the six intercepted syscalls.

### Architecture

```
  Child (sandboxed)                      Parent (supervisor)
  ──────────────────                     ────────────────────
  1. seccomp(SET_MODE_FILTER,            4. recv_fd() via SCM_RIGHTS
     NEW_LISTENER, &notif_bpf)              → gets notifier fd
     → returns notifier fd
  2. send_fd(parent_sock, notif_fd)      5. spawn supervisor thread
     via SCM_RIGHTS
  3. prctl(PR_SET_SECCOMP,               6. Loop:
     SECCOMP_MODE_FILTER, &main_bpf)        ioctl(NOTIF_RECV) → notification
  ... execve() ...                           read /proc/<pid>/mem
                                             evaluate policy
                                             ioctl(NOTIF_ID_VALID) → TOCTOU check
                                             ioctl(NOTIF_SEND) → ALLOW or DENY
```

### Two-filter design

Two BPF filters are installed sequentially in the child:

1. **Notifier filter** — installed first via `seccomp()` with
   `SECCOMP_FILTER_FLAG_NEW_LISTENER`. Returns `SECCOMP_RET_USER_NOTIF` for
   the six intercepted syscalls; `SECCOMP_RET_ALLOW` for everything else.

2. **Main filter** — installed second via `prctl(PR_SET_SECCOMP)`. The
   existing allow-list/deny-list filter (unchanged from before this ADR).

The kernel evaluates filters in reverse install order. `SECCOMP_RET_USER_NOTIF`
has special precedence — when any filter returns it, the kernel always delivers
the notification, regardless of other filters' return values.

### Fd passing protocol

Before `fork()`, the parent creates a Unix socket pair via
`socketpair(AF_UNIX, SOCK_STREAM)`. The child installs the notifier filter
(which returns the notification fd), then sends it to the parent as
`SCM_RIGHTS` ancillary data on the pre-created socket. The parent receives
the fd and spawns a dedicated supervisor thread.

### Intercepted syscalls and evaluation logic

| Syscall | Argument source | Evaluation |
|---------|----------------|------------|
| `connect()` | `sockaddr` struct read from `/proc/<pid>/mem` | IP must be in resolved allowlist or loopback. `AF_UNIX` always allowed. |
| `clone()` | `flags` from `seccomp_data.args[0]` (register) | Deny if any namespace flag set (`CLONE_NEWNS`, `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWCGROUP`) |
| `clone3()` | `clone_args.flags` read from `/proc/<pid>/mem` | Same flag check as `clone()` |
| `socket()` | `domain` and `type` from `seccomp_data.args[0..1]` (registers) | Deny `AF_NETLINK` (16) and `SOCK_RAW` (3) |
| `execve()` | Pathname string read from `/proc/<pid>/mem` | Must match `allow_execve` paths (empty list = allow all) |
| `execveat()` | Pathname + `dirfd` from registers, string from `/proc/<pid>/mem` | Same as `execve()` |

### TOCTOU mitigation

After reading `/proc/<pid>/mem` and evaluating the policy, the supervisor
calls `ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID, &notification_id)`. If the kernel
returns `ENOENT`, the notification is stale (the thread exited or memory was
remapped) and the verdict is skipped. This is the standard mitigation from
`seccomp_unotify(2)`.

This does not fully eliminate the TOCTOU window — a sufficiently fast
multi-threaded attacker could modify memory between the validity check and
the verdict. This is an inherent limitation of the USER_NOTIF mechanism.

### Configuration and auto-detection

The `[syscalls] notifier` config field controls the supervisor:

| Value | Behavior |
|-------|----------|
| `true` | Force on (fail if kernel < 5.9) |
| `false` | Force off |
| omitted | Auto-detect: enabled if kernel >= 5.9 and not in monitor mode |

Auto-detection reads `/proc/sys/kernel/osrelease` to determine the kernel
version. In monitor mode, the notifier is always disabled because
`SECCOMP_RET_USER_NOTIF` is incompatible with `SECCOMP_RET_LOG` (the former
suspends the syscall, the latter allows it through).

## Consequences

### Positive
- `connect()` calls are now filtered against the resolved IP allowlist — the
  sandbox in filtered network mode can no longer reach arbitrary IPs
- Every `execve()` / `execveat()` inside the sandbox is validated against
  `allow_execve`, not just the initial command
- `clone()` / `clone3()` cannot create new namespaces (prevents namespace
  escape attacks)
- `socket()` cannot create `AF_NETLINK` or `SOCK_RAW` sockets (prevents
  netlink-based configuration manipulation and raw packet injection)
- DNS proxy integration ensures sandboxed processes can only resolve
  allowed domains

### Negative
- Adds a supervisor thread and fd passing protocol (increased complexity)
- Intercepted syscalls incur latency (context switch to supervisor and back)
- Requires Linux 5.9+ (older kernels fall back to BPF-only filtering)
- Inherent TOCTOU window that cannot be fully closed
- Notifier is incompatible with monitor mode

### Neutral
- The main BPF filter is unchanged — the notifier filter is additive
- Existing config files work without modification (auto-detection default)
- The `notifier` config field follows existing merge semantics (last-Some-wins)

## Follow-up Actions
- [x] Implement `notifier.rs` module (supervisor thread, BPF filter, evaluators)
- [x] Wire notifier into `namespace.rs` (fd channel, parent/child integration)
- [x] Implement clone/clone3 flag filtering
- [x] Implement socket domain filtering
- [x] Implement execve/execveat path filtering
- [x] Add `notifier` config field with merge support
- [x] Unit tests for all evaluators and BPF construction
- [x] Wire DNS proxy for domain-restricted resolution
- [x] Update documentation (SECCOMP.md, CONFIGURATION.md, ARCHITECTURE.md)
- [ ] End-to-end integration tests with actual seccomp notifications (requires Linux 5.9+ test environment)
- [ ] Performance benchmarking of intercepted syscall latency
