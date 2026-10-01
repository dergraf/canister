# ADR-0019: Filesystem Access Events

## Status
Accepted (implemented 2026-10-01; the core change below was reviewed and approved)

## Date
2026-10-01

## Context

A consumer of the event stream (ADR-0010) wants to know when the sandboxed workload
reaches for files it was not given: `~/.ssh/id_ed25519`, `~/.aws/credentials`,
`~/.config/gcloud`, `/etc/shadow`, a path outside the project. That is the first thing a
compromised dependency does, and today the stream is silent about it. The egress side is
fully observed (`egress_request`, `dlp_block`, `canary_fire`); the filesystem side is
not observed at all.

Before choosing how to emit such an event, this ADR records precisely how filesystem
policy is enforced today, because the mechanism decides what can be observed.

### How filesystem policy is enforced today

There is no access check that says "no". The policy is enforced by **construction of the
mount namespace**, in `crates/can-sandbox/src/overlay.rs::setup_filesystem`:

1. A fresh tmpfs becomes the sandbox root (`mount_tmpfs`), with a skeleton of empty
   directories (`create_skeleton`, `SKELETON_DIRS`).
2. Every `filesystem.read` path is bind-mounted read-only at the same path
   (`bind_mount_allowed` → `bind_mount_ro`); every `filesystem.write` path read-write
   (`bind_mount_writable_paths` → `bind_mount_rw`); the host CWD read-write.
3. `filesystem.deny` is consulted only inside those two loops: an allowed path is skipped
   when it equals or lies under a deny entry (`source.starts_with(d)`). A denied path is
   therefore never mounted — it simply does not exist in the sandbox.
4. `filesystem.mask` binds `/dev/null` over files and an empty read-only tmpfs over
   directories (`mask_files`); `/proc` entries are masked the same way (`mount_proc`).
5. `pivot_root` and the old root is detached (`do_pivot_root`).

What the workload sees when it reaches for a forbidden file:

| Attempt | Result | Source of the result |
|---|---|---|
| Read a path that was never mounted (`~/.ssh/id_ed25519`, `/etc/shadow`, `/root/…`) | `ENOENT` | path lookup on the root tmpfs; no policy decision is taken |
| Create a file in an unmounted location (`~/.ssh/x`, `/etc/x`) | **succeeds**, on the ephemeral root tmpfs | tmpfs root is writable; discarded at exit |
| Write to a read-only bind (`/usr/bin/x`) | `EROFS` | VFS mount flag |
| Read a masked file (`canister.toml`) | empty read | `/dev/null` bind |
| Write to a masked directory | `EROFS` | read-only empty tmpfs |

Nothing else participates:

- **Landlock** is not used anywhere in the code base.
- **seccomp** allows the whole open/stat family unconditionally (`recipes/default.toml`:
  `open`, `openat`, `openat2`, `stat`, `newfstatat`, `statx`, `access`, `faccessat*`);
  the USER_NOTIF supervisor intercepts only `execve` and `execveat`
  (`crates/can-sandbox/src/notifier/filter.rs`, `NOTIFIED_SYSCALLS`).
- **AppArmor** confines the workload with `allow file rwlkm /{**,}`
  (`crates/can-sandbox/src/mac/apparmor.rs`, profile `canister_sandboxed`); it gates
  capabilities, mount and userns, not file paths. SELinux is analogous.

So **a "denied" filesystem access is, at the kernel level, an ordinary failed path
lookup**. No LSM hook rejects it, no audit record is produced, no seccomp filter sees
the path. Any mechanism that reports it has to observe lookups, or turn the absent path
into something that can be observed.

### How events are observed today

`process_exec` is emitted exactly once per run, by the CLI, for the entrypoint
(`crates/can-cli/src/commands.rs::run_sandbox`, `pid: None`). The supervisor installs a
`supervisor` event stream (`namespace.rs::install_event_stream`) but does not currently
emit anything; supervised `execve` decisions go to `tracing` only. Every other event is
emitted by the proxy process. There is no observation point inside the worker's mount
namespace outside the sandbox core.

### Kernel on the reference host

`uname -r` → `6.8.0`. Landlock audit records need 6.15.

## Options Considered

### Option 1: Landlock with audit logging
**Description**: Restrict the worker with a Landlock ruleset mirroring `read`/`write`,
and rely on Landlock's audit records (kernel ≥ 6.15) for denials.
**Pros**:
- Kernel-enforced, not bypassable from inside the sandbox.
- Carries pid, path and access right.
**Cons**:
- Does not see what we need: a never-mounted path fails lookup with `ENOENT` before
  Landlock is consulted. It would only report accesses to paths that are visible but
  outside the ruleset — which by construction do not exist.
- Audit records go to the kernel audit subsystem; reading them needs `CAP_AUDIT_READ` in
  the initial user namespace (root or journald). An unprivileged `can` cannot consume them.
- Kernel 6.15+; the reference host runs 6.8.
- `landlock_restrict_self` runs in the worker before `exec` — that is
  `namespace.rs`/`process.rs`, i.e. the core.
**Estimated effort**: Medium, and it would not deliver the event.

### Option 2: seccomp USER_NOTIF on the open/stat family (observe-only)
**Description**: Add the path-taking syscalls to `NOTIFIED_SYSCALLS`; the supervisor
reads the path, resolves it against the worker's cwd/dirfd, answers
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` unconditionally and emits an event when the path is
outside the policy.
**Pros**:
- Most complete: sees every attempt, including `ENOENT` probes and `stat`/`access`
  existence checks, with pid.
- Works on the kernels `can` already supports (5.9+).
**Cons**:
- Every `open`/`stat` in the workload becomes a round trip to the supervisor. BPF cannot
  filter on a string argument, so there is no cheap pre-filter. Builds, `npm install` and
  test suites perform millions of these; expect a large slowdown.
- ~20 syscalls to cover (`open`, `openat`, `openat2`, `creat`, `stat`, `lstat`,
  `newfstatat`, `statx`, `access`, `faccessat`, `faccessat2`, `readlink(at)`,
  `chdir`, `mkdir(at)`, `unlink(at)`, `rename*`, `link*`, `symlink*`, `truncate`,
  `utimensat`, `execve*`, …); missing one is a silent hole.
- The path read from `/proc/<pid>/mem` is raceable (the TOCTOU discussed in
  `notifier/eval_proc.rs`): the reported path can be made to differ from the one the
  kernel resolves. Acceptable for telemetry, not for evidence.
- Changes the filter and the supervisor loop — the most security-sensitive code in `can`.
**Estimated effort**: High

### Option 3: eBPF (LSM or tracepoint on `do_filp_open`/`path_lookupat`)
**Description**: Attach a BPF program that reports failed lookups by processes in the
sandbox's cgroup or pid namespace.
**Pros**: Complete, cheap per event, carries pid.
**Cons**: Needs `CAP_BPF` + `CAP_PERFMON` (and `CAP_MAC_ADMIN` for BPF-LSM) in the
initial user namespace. `can` is unprivileged by design and must stay so.
**Estimated effort**: High; not available to an unprivileged process.

### Option 4: `LD_PRELOAD` shim wrapping libc open/stat
**Description**: Inject a shared object that logs path calls before forwarding them.
**Pros**: No kernel requirements, no core change if injected through the environment.
**Cons**: Bypassed by static binaries (Go, musl builds), raw `syscall(2)`, `io_uring`,
and by any code that clears `LD_PRELOAD` — i.e. by exactly the hostile code this is for.
Telemetry the attacker controls is not evidence.
**Estimated effort**: Medium; rejected on bypassability.

### Option 5: fanotify on the sandbox mounts
**Description**: Watch the sandbox root and binds with fanotify.
**Pros**: Kernel-generated; mount/filesystem marks would see every open.
**Cons**: Unprivileged fanotify (5.13+) allows inode marks only, no permission events,
and reports `pid = 0` for other processes. Inode marks cannot be placed on paths that do
not exist, so failed lookups are invisible. With privileges it would need
`CAP_SYS_ADMIN` in the initial namespace.
**Estimated effort**: Medium; on its own it does not see the attempts we care about.

### Option 6: Decoy files watched with inotify (tripwires)
**Description**: Make chosen sensitive paths *exist* in the sandbox as decoys. The CLI
creates decoy files in a private host directory (`0700`, removed at exit), the sandbox
bind-mounts each one read-only at its sandbox path, and a thread in the CLI process
watches the host-side inodes with inotify. inotify is inode-based, so an open through the
bind mount in the sandbox's mount namespace fires the watch in the host namespace.
**Pros**:
- No privileges and no kernel requirement beyond what `can` already needs (inotify is
  2.6.13).
- Zero cost on the workload's hot path: no syscall is intercepted; events are delivered
  asynchronously to an observer outside the sandbox.
- Not bypassable for a listed path: the workload cannot remove or disable an inotify
  watch held by another process, and a read-only bind cannot be unlinked or replaced
  (`EBUSY`/`EROFS`). Reaching the decoy's contents generates the event.
- Composes with tagged canaries (ADR-0012): a decoy `~/.aws/credentials` can contain a
  canary key, so the read is reported here and any exfiltration as `canary_fire`.
- The observer and the event live outside the core (CLI + `can-events`).
**Cons**:
- Coverage is the decoy list, not "every forbidden path". A probe of an unlisted path
  stays an invisible `ENOENT`.
- inotify reports `open`/`read`/`write`/`close`, not `stat`/`access`: an existence check
  without an open is not seen.
- inotify carries no pid; the event cannot name the process.
- A careful attacker can recognise a decoy (empty or synthetic content, tmpfs device
  number). Recognising it costs them nothing, but also gains them nothing: the real file
  is still absent. The event then under-reports; it never over-reports.
- Requires one new mount step in `overlay.rs` — the core. See below.
**Estimated effort**: Medium

### Option 7: FUSE sentinel filesystem over sensitive prefixes
**Description**: Mount a FUSE filesystem (unprivileged in a user namespace since 4.18)
over `$HOME` and similar prefixes; the server sees every `LOOKUP`, including names that
do not exist, with the requesting pid.
**Pros**: Sees `ENOENT` probes and `stat`, carries pid, covers a whole prefix.
**Cons**:
- Needs `/dev/fuse` inside the sandbox's minimal `/dev`, a FUSE server process, and
  a mount step in `overlay.rs` — more core change than Option 6.
- Every nested bind under the prefix (CWD under `$HOME`, `~/.cargo`, …) must be
  synthesised by the server; a server bug or stall hangs the workload in `D` state.
- Adds a new protocol implementation (or a `fuser` dependency) to a security-critical
  binary.
**Estimated effort**: High

## Decision

**Proposed: Option 6 (decoy files watched with inotify), opt-in, flag-gated.**
It is the only option that is unprivileged, works on every supported kernel, costs the
workload nothing, cannot be switched off from inside the sandbox, and keeps both the
observer and the event outside the sandbox core. Its blind spot — unlisted paths and
pure `stat` probes — is acceptable for a tripwire whose job is to catch the well-known
first moves (SSH keys, cloud credentials, token stores). Option 2 is the right answer
only if complete coverage is later required and its cost is accepted; it is recorded
here so that the trade-off does not have to be rediscovered.

Every sound option, including the chosen one, needs a change to the sandbox's mount
setup: a denied path does not exist in the worker's mount namespace, and only
`overlay.rs` can make it exist. The change below was reviewed and accepted, and is
implemented as specified (`bind_mount_decoys`, `decoy_placement`).

`count` is a lower bound: inotify itself merges identical consecutive events that have
not been read yet, so a tight loop of opens may arrive as fewer events than it made.

### Minimal core change

One new, additive step in `crates/can-sandbox/src/overlay.rs`, active only when the
decoy list is non-empty (empty by default, so today's mount layout is unchanged):

- **New field** `FilesystemConfig::decoys: Vec<DecoyMount>` in
  `crates/can-policy/src/config/filesystem.rs`, where
  `DecoyMount { source: PathBuf /* host decoy file */, target: PathBuf /* sandbox path */ }`.
  `#[serde(skip)]`: it is populated by the CLI after it has materialised the decoys, never
  read from a recipe. (Not core.)
- **New function** `bind_mount_decoys(root: &Path, config: &FilesystemConfig,
  host_cwd: Option<&Path>) -> Result<(), OverlayError>`, called from
  `setup_filesystem` between step 5c (`mask_files`) and step 6 (`mount_proc`). For each
  decoy:
  1. Skip if `target` already exists under `root` — a real grant (`read`/`write`/CWD)
     always wins; a decoy never shadows a real file.
  2. Skip, with a warning, if `target` lies under any `config.write` path or under
     `host_cwd`. **This check is load-bearing**: `mkdir_p` under a writable bind would
     create directories on the host.
  3. Skip if `target` lies under any `config.read` path (the bind is read-only; `mkdir`
     would fail with `EROFS`).
  4. `mkdir_p(parent)`, `touch(target)` on the root tmpfs, then `bind_mount_ro(source,
     target)` — the existing helper, with `source ≠ target` for the first time.
  5. Failures are logged and skipped, never fatal (same posture as `mask_files`).
- Unit tests for the skip predicate (pure function over paths), including the CWD and
  writable-path cases.

Nothing in `namespace.rs`, the pipe protocol, seccomp or the supervisor changes. Risks:
the host-write leak in step 2 if the predicate is wrong; a decoy path that later becomes
a real grant is simply skipped. Ordering matters only in that decoys go after every real
bind so step 1 sees them.

### Outside the core (to implement once the above is accepted)

- **Recipe surface**: `[filesystem] decoy = ["$HOME/.ssh/id_ed25519", …]`
  (`deny_unknown_fields` + `merge` = union, `$HOME` expansion like `deny`), plus a shipped
  `recipes/system/tripwires.toml` with the usual credential locations. Opt-in by recipe;
  no recipe, no decoys.
- **CLI (`can-cli`, new `tripwire.rs`)**: create a `0700` temp dir, materialise each
  decoy (empty, or a canary payload when canaries are configured), fill
  `FilesystemConfig::decoys`, add one inotify watch per decoy
  (`IN_OPEN | IN_ACCESS | IN_MODIFY | IN_CLOSE_WRITE`), read events on a thread for the
  lifetime of `can_sandbox::run`, remove the directory afterwards. Emitted on the `cli`
  stream, between `run_start` and `run_end`.
- **Rate limiting per path**: the first event for a `(path, operation)` pair is emitted
  immediately with `count: 1`; further occurrences within a one-second window are
  coalesced and emitted once at the window's end with their `count`; pending counts are
  flushed before `run_end`. The number of distinct decoys is bounded by the recipe, so
  memory is bounded.

### Event shape (additive to schema v1)

```json
{"event":"fs_access","data":{
  "path":"/home/dev/.ssh/id_ed25519",
  "operation":"open",
  "mechanism":"decoy",
  "count":1
}}
```

| Field | Type | Meaning |
|---|---|---|
| `path` | string | Path as the workload sees it |
| `operation` | `open` \| `read` \| `write` \| `list` | What the workload did; `list` for an opened decoy directory |
| `mechanism` | `decoy` | How it was observed; reserved for future mechanisms (e.g. `syscall` for Option 2), which would also report `errno` |
| `count` | integer ≥ 1 | Occurrences coalesced into this event |
| `pid` | integer, optional | Absent for `decoy`; inotify does not report it |

This is a new variant, not a change to an existing payload, the same way
`exchange`, `canary_fire`, `policy_resolved`, `stats` and `stream_seal` joined v1
(ADR-0011, 0012, 0014–0016); the schema version does not change, and a consumer that
does not know `fs_access` skips it. A `stats` counter (`fs_access_by_operation`) can follow in the same way as
ADR-0015's counters.

## Consequences

### Positive
- The first move of a hostile dependency — reaching for SSH keys or cloud credentials —
  becomes a recorded event at zero hot-path cost and without privileges.
- With canary payloads, the stream can show both halves: the file was read, and its
  contents tried to leave.
- The mount layout change is a single additive step, inert when no decoy is configured.

### Negative
- Coverage is explicit: only listed paths are tripwires; arbitrary `ENOENT` probes and
  `stat` checks remain invisible. Documented as such so nobody reads silence as "nothing
  was attempted".
- No pid in the event.
- A decoy changes what the workload observes (`stat` now succeeds where it returned
  `ENOENT`). Code that branches on "credentials present" may behave differently with
  tripwires enabled — intentional, since that branch is what we want to observe, but it
  is why the feature is opt-in.

### Neutral
- `filesystem.deny` keeps its current meaning. Observed while writing this ADR and
  worth a separate fix: `deny` only removes an allowed path that equals or lies under a
  deny entry. A deny entry *below* an allowed path (`read = ["$HOME"]`,
  `deny = ["$HOME/.ssh"]`) is not enforced; the subtree stays visible, contrary to
  `docs/CONFIGURATION.md` ("Deny rules take precedence"). Fixing it is also an
  `overlay.rs` change (mask the denied subpath after the binds).

## Follow-up Actions
- [x] Review and accept the `bind_mount_decoys` core change above.
- [x] Implement the recipe field, `tripwires.toml`, the CLI watcher, the `fs_access`
      event (`schema.rs`, `docs/events-schema-v1.json`, golden file) and docs.
- [x] Integration test (`t_tripwires.sh`): opening a decoy yields an `fs_access` event
      before `run_end`; a burst of 500 opens yields a bounded number of events (their
      `count` is a lower bound, see above).
- [x] Separately: enforce `deny` entries that lie below an allowed path (branch
      `fix/deny-below-allowed-path`).
- [ ] Separately: emit `process_exec` from the supervisor for supervised `execve`, as the
      schema documentation already claims.
