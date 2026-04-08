# Seccomp Profiles

Canister uses seccomp BPF to restrict which Linux syscalls the sandboxed
process can invoke. This document explains how profiles work, what each
built-in profile blocks, and how to choose the right one.

## Table of Contents

- [How Seccomp Works in Canister](#how-seccomp-works-in-canister)
- [Built-in Profiles](#built-in-profiles)
  - [generic](#generic)
  - [python](#python)
  - [node](#node)
  - [elixir](#elixir)
- [Always-Denied Syscalls](#always-denied-syscalls)
- [Choosing a Profile](#choosing-a-profile)
- [Deny Action: Errno vs Kill](#deny-action-errno-vs-kill)
- [Monitor Mode and SECCOMP_RET_LOG](#monitor-mode-and-seccomp_ret_log)
- [Architecture Validation](#architecture-validation)
- [Inspecting Profiles](#inspecting-profiles)

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
every syscall not explicitly listed in the profile is denied. This provides
a much smaller kernel attack surface. Each profile defines ~171-177 syscalls
that are permitted — everything else is blocked.

**Deny-list mode** is the permissive fallback: everything is allowed except
the ~16-22 syscalls explicitly blocked per profile. Use this when you need
maximum compatibility with unknown workloads, at the cost of a larger
attack surface.

Both modes share the same profile definitions — each profile specifies both
an allow list and a deny list. The `seccomp_mode` setting selects which one
is used at filter load time.

The filter cannot be removed or modified after loading. The `PR_SET_NO_NEW_PRIVS`
flag is set first, which is required for unprivileged seccomp and also prevents
the sandboxed process from gaining new privileges via `execve` of setuid
binaries.

---

## Built-in Profiles

### `generic`

**177 allowed syscalls / 16 denied syscalls.** The most permissive profile.
Suitable for arbitrary binaries where you don't know what syscalls they need.

Allows everything in the base set plus ptrace, personality, io_uring, and
seccomp (self-sandboxing). Only denies the always-dangerous set plus
namespace escape vectors (unshare/setns).

| Category | Blocked syscalls |
|----------|-----------------|
| System | `reboot`, `kexec_load`, `syslog`, `settimeofday`, `acct` |
| Kernel modules | `init_module`, `finit_module`, `delete_module` |
| Filesystem (privileged) | `mount`, `umount2`, `pivot_root`, `chroot`, `swapon`, `swapoff` |
| Namespace escape | `unshare`, `setns` |

Use `generic` when:
- Running compiled binaries you can't easily audit
- The workload type is unknown
- Maximum compatibility is needed

### `python`

**171 allowed syscalls / 22 denied syscalls.** Tighter than generic. Removes
ptrace, personality, io_uring, and seccomp from the allow list.

Everything in `generic`'s deny list, plus:

| Category | Blocked syscalls |
|----------|-----------------|
| Debugging | `ptrace`, `personality` |
| io_uring | `io_uring_setup`, `io_uring_enter`, `io_uring_register` |
| Seccomp | `seccomp` (prevents loading new filters from inside sandbox) |

Use `python` when:
- Running Python scripts or applications
- Running pip install operations
- The code doesn't need ptrace or io_uring (essentially all Python code)

**Why block io_uring?** io_uring is a powerful async I/O interface with a large
kernel attack surface. Python's standard library does not use it, and most
Python packages don't either. Blocking it reduces the kernel surface exposed
to the sandbox.

**Why block ptrace?** ptrace allows debugging other processes. A sandboxed
process should not be able to inspect or manipulate other processes.

### `node`

**171 allowed syscalls / 22 denied syscalls.** Same restrictions as `python`.
Preserves `clone` and `clone3` (allowed in all profiles) since Node.js uses
them for `worker_threads`.

Everything in `generic`'s deny list, plus:

| Category | Blocked syscalls |
|----------|-----------------|
| Debugging | `ptrace`, `personality` |
| io_uring | `io_uring_setup`, `io_uring_enter`, `io_uring_register` |
| Seccomp | `seccomp` |

Use `node` when:
- Running Node.js scripts or applications
- Running npm install/build operations
- The application uses worker threads (these work fine)

### `elixir`

**172 allowed syscalls / 21 denied syscalls.** Tailored for the BEAM virtual
machine (Erlang/OTP, Elixir). Allows one more syscall than python/node:
`ptrace`, which BEAM tooling (`:observer`, `:dbg`, `recon`) uses for
runtime introspection.

Everything in `generic`'s deny list, plus:

| Category | Blocked syscalls |
|----------|-----------------|
| Personality | `personality` |
| io_uring | `io_uring_setup`, `io_uring_enter`, `io_uring_register` |
| Seccomp | `seccomp` |

**Not blocked (unlike python/node):**

| Syscall | Why it's preserved |
|---------|-------------------|
| `ptrace` | Used by BEAM debugging tools (`:observer`, `:dbg`, `recon_trace`) |
| `clone`/`clone3` | BEAM spawns OS threads for schedulers, dirty schedulers, and async threads |
| `sendfile`/`splice` | Used by Cowboy/Bandit for efficient file serving |
| `epoll_*` | BEAM's I/O polling mechanism |
| `sched_getaffinity`/`sched_setaffinity` | BEAM scheduler CPU binding (`+sbt` flag) |
| `memfd_create` | BEAM JIT compiler (OTP 24+) |

Use `elixir` when:
- Running `mix` tasks (`mix test`, `mix compile`, `mix deps.get`)
- Running `iex` shells (`iex`, `iex -S mix`)
- Running Phoenix servers (`mix phx.server`, release binaries)
- Running any OTP application or Erlang code
- Running `rebar3` or `erlc` builds

**Why not just use `generic`?** The `generic` profile works for BEAM, but
the `elixir` profile additionally blocks `io_uring`, `personality`, and
`seccomp` which the BEAM never needs. This reduces the kernel attack
surface while remaining fully compatible with the BEAM ecosystem.

---

## Always-Denied Syscalls

All four profiles share a common base of 14 syscalls that are **always
denied**. These are dangerous kernel-level operations that a sandboxed
process should never need:

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

These are blocked even in `generic` because they represent operations that
only system administrators should perform, and a sandboxed process should
have no legitimate reason to invoke them.

---

## Choosing a Profile

```
Is the workload Elixir or Erlang?
  ├── Yes → use "elixir"
  └── No
      Is the workload Python?
        ├── Yes → use "python"
        └── No
            Is the workload Node.js?
              ├── Yes → use "node"
              └── No
                  Use "generic"
```

When in doubt, start with the most restrictive applicable profile. If the
sandboxed program fails with `EPERM` on a syscall it needs, switch to a
less restrictive profile.

You can identify which syscall was denied by running with verbose logging:

```bash
can -v run --profile python -- ./my_program
```

If the program exits with an error related to "Operation not permitted", a
seccomp denial is likely the cause.

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

## Inspecting Profiles

List all available profiles:

```
$ can profiles
Available seccomp profiles:

  generic      Generic profile for arbitrary binaries. (177 allowed, 16 denied)
  python       Profile for Python scripts. (171 allowed, 22 denied)
  node         Profile for Node.js scripts. (171 allowed, 22 denied)
  elixir       Profile for Elixir/Erlang (BEAM VM). (172 allowed, 21 denied)
```

To see exactly which syscalls a profile allows/blocks, check the source at
`crates/can-policy/src/profile.rs`. The `ALLOW_BASE` constant contains the
shared allow set (~171 syscalls), `DENY_ALWAYS` contains the shared deny
base (~14 syscalls), and each profile's constructor adds its specific
additions.
