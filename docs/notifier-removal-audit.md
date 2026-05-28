# Notifier removal — enforcement-mapping audit (Phase 1 GATE)

Status: **GATE — awaiting decision before any enforcement is mutated.**

This document maps every job the seccomp `SECCOMP_RET_USER_NOTIF` supervisor
does today onto a sound, race-free replacement, and surfaces the config modes
and syscalls where **no sound structural replacement exists yet**. It is the
deliverable of Phase 1 of the "eliminate the USER_NOTIF supervisor" task.

Everything below was verified against the code at the current `main`
(`2ef989d`), not the task brief. Where reality differed from the brief, the
discrepancy is called out.

---

## 0. Discrepancies vs. the task brief

The brief should not be trusted blindly; these are the points where it is wrong
about the current tree:

1. **There is no in-flight patch moving namespace-flag enforcement into the BPF
   prelude.** `filter.rs::NOTIFIED_SYSCALLS` still lists `clone` and `clone3`,
   and `eval_clone.rs` still decides them in the supervisor. The brief said this
   was "likely already done — reconcile." It is not done.

2. **`unshare` / `setns` are *not* routed through the supervisor at all.** They
   are in the **`deny` list** of `recipes/default.toml` (lines 265–268), i.e.
   denied by the *main* static BPF filter. So namespace creation via
   `unshare`/`setns` is already enforced soundly (static BPF, register-free —
   it's a flat syscall-number deny). Only `clone`/`clone3` namespace *flags* are
   supervisor-decided. The brief implied all four were handled together.

3. **The notifier prelude (`filter.rs`) is not the only static layer.** The main
   `seccomp.rs` allow/deny filter is the real baseline. `execveat` and
   `memfd_create` are in the baseline **deny** list; because `SECCOMP_RET_ERRNO`
   (0x00050000) outranks `SECCOMP_RET_USER_NOTIF` (0x7fc00000), the supervisor's
   `execveat` evaluator only ever runs when a recipe explicitly re-allows
   `execveat` via `allow_extra`.

4. **The proxy already has a sound domain/IP allow-list** (`can-proxy`
   `OutboundPolicy`, wired in `server/request.rs::gate_by_policy` and
   `server/util.rs`). The brief treats proxy domain filtering as "the sound way"
   — it exists and is enforced at L7 today; it is simply **not what forces the
   worker to use the proxy**.

5. **No firewall code exists.** `can-net/Cargo.toml` advertises "firewall rules"
   but there is no nftables/iptables/netfilter code anywhere in the tree. pasta's
   `-t`/`-u` only gate *inbound* port forwarding; outbound is unrestricted. This
   is the crux of the egress gap (§4).

---

## 1. Config-mode matrix (the crux of the audit)

`EgressMode` (recipe `[network] egress`, plus `[unsafe] unfiltered_egress` →
`Direct`) drives `NetworkMode::from_config`, which drives whether pasta and the
proxy even exist. The notifier policy is then built per-mode in
`policy_config.rs`.

| egress mode | extra config | `NetworkMode` | pasta? | proxy started? | netns | `restrict_outbound` | `enforce_proxy_egress` | **What restricts egress today** |
|---|---|---|---|---|---|---|---|---|
| `proxy` (default) | — | Filtered | yes | **yes** (proxy_ca set only for ProxyOnly) | shared netns w/ proxy | true | true | **supervisor only** (forces traffic to loopback:proxy_port) |
| `none` | — | None | no | no | empty netns, lo only | true | true (proxy_port=None ⇒ deny all) | **empty netns** (no uplink) — supervisor redundant |
| `direct` | no allowlist, no ports | Full | no | no | host netns (no CLONE_NEWNET) | false | false | nothing — intentional unfiltered |
| `direct` | ports only | Filtered | yes | no | shared netns | false | false | nothing — port-forward, outbound intentionally open |
| `direct` | `reachable_ips` / `[[host]]` | Filtered | yes | no | shared netns | **true** | false | **supervisor only** (IP/domain allow-list) |

Two rows enforce egress **only** via the supervisor and have **no structural
backstop**:

- **`proxy` (the default, most-used mode).** pasta gives the worker full
  outbound connectivity. The proxy is co-resident in the same netns. The only
  thing stopping the worker from ignoring `HTTP_PROXY` and dialing the internet
  directly is the supervisor's `connect/sendto/sendmsg` checks. **Remove the
  supervisor with nothing in its place and proxy-only egress, DLP, and the
  contract gate are all bypassable.**
- **`direct` + `reachable_ips`/`[[host]]`.** pasta is up, no proxy is started,
  and the IP/domain allow-list is enforced solely by the supervisor.

---

## 2. Per-syscall mapping

| syscall | decided on | sound today? | replacement | exists? | notes |
|---|---|---|---|---|---|
| `clone` | register `args[0]` (flags) | **sound** (regs captured atomically) but lives in supervisor | static BPF: `args[0] & NS_FLAGS_MASK != 0 → ERRNO`. All NS bits fit the low 32 bits (max bit 30), so one low-dword AND suffices. | must build (Phase 2) | behavior-preserving move |
| `clone3` | `args[0]` = **pointer** to `struct clone_args`; flags read from memory | **RACEABLE — this is issue #4** | **BPF cannot dereference the pointer.** Options: (a) return `ENOSYS` for `clone3` ⇒ glibc/musl fall back to `clone` (which is register-filtered); (b) hard-deny `clone3`. | must build (Phase 2) — **DECISION NEEDED**, see §4.2 |
| `socket` | registers `args[0..2]` (domain/type/proto) | **sound** but in supervisor | static BPF: deny `SOCK_RAW`; `AF_NETLINK` ⇒ only `NETLINK_ROUTE`; gate `AF_UNIX`/`AF_INET`/`AF_INET6` per policy. Policy bits compiled into the filter at build time. | must build (Phase 2) | `allow_af_unix`/`allow_af_inet` are hard-coded `true` today, so only SOCK_RAW + netlink restriction are actually live |
| `execve` | `args[0]` = pointer to pathname | **RACEABLE** | initial command: already validated host-side (`process.rs::validate_execve`, race-free). Child execs: rootfs composition / `noexec`. | partial — host check exists; rootfs enforcement must build (Phase 4) | |
| `execveat` | `args[1]` ptr (path) + `args[4]` reg (flags) | path: **RACEABLE**; `AT_EMPTY_PATH`: sound (register) | `AT_EMPTY_PATH` deny → static BPF (`args[4] & AT_EMPTY_PATH`). Path allow-list → rootfs/noexec. Note: `execveat` is baseline-denied unless re-allowed. | AT_EMPTY_PATH: build (Phase 2); path: build (Phase 4) | |
| `connect` | `args[1]` = pointer to sockaddr | **RACEABLE** | netns firewall (admit only proxy / allowed CIDRs) + proxy domain/IP gate | **must build (firewall) + proxy exists** (Phase 3) | see §4.1 |
| `sendto` | `args[4]` = pointer to dest sockaddr | **RACEABLE** | same as `connect` | same | UDP path; firewall must cover UDP too |
| `sendmsg` | `args[1]` = pointer to `msghdr` | **RACEABLE** | same as `connect`; the SCM_RIGHTS belt-and-suspenders is **redundant** (kernel already rejects SCM_RIGHTS on non-AF_UNIX) | drop-as-redundant + firewall | |

---

## 3. Per-`NotifierPolicy`-field mapping

| field | enforces today | sound? | replacement | exists? | config-mode gaps |
|---|---|---|---|---|---|
| `allowed_ips` | connect/sendto IP allow-list | raceable | netns firewall (allowed CIDRs) + proxy `allows_ip` | firewall must build; proxy exists | active in `proxy` and `direct+reachable_ips` — both need firewall |
| `allowed_cidrs` | CIDR allow-list | raceable | netns firewall CIDR rules | firewall must build | same |
| `restrict_outbound` | master on/off for IP filtering | raceable | implied by which firewall ruleset is installed | firewall must build | the `false` modes (Full / direct+ports) legitimately want no restriction — fine |
| `allowed_domains` | resolve-then-IP-match | raceable **and DNS-rebinding-prone** | proxy SNI/Host allow-list (`OutboundPolicy::allows_host`) — only sound if egress is *forced* through the proxy | proxy exists; forcing needs firewall | only `proxy` mode forces the proxy; `direct+[[host]]` does **not** start a proxy → gap |
| `dns_cache` / `dynamic_ips` | populate dynamic IP allow-list from DNS | raceable / rebinding | **dropped** — proxy filters by name, no IP pre-resolution needed | n/a (delete) | removing the resolve-then-match removes the rebinding bug too |
| `dns_server_addr` | recognise + allow DNS dst | raceable | firewall allows udp/tcp :53 to the namespace resolver; proxy resolves names itself | firewall must build | |
| `enforce_proxy_egress` | force traffic to loopback:proxy_port | raceable | **netns firewall: reject all egress except loopback:proxy_port and DNS** | **must build** | the central `proxy`-mode gap |
| `proxy_port` | the one allowed dst port | raceable | firewall rule target | must build | |
| `allow_af_unix` / `allow_af_inet` | socket() domain gate | sound (regs) | static BPF socket() gate (compiled from policy) | build (Phase 2) | currently always `true` |
| `allowed_exec_paths` / `allowed_exec_prefixes` | execve path allow-list | raceable | rootfs composition / `noexec` mounts | must build (Phase 4); host-side initial check exists | `exec=[paths]`; `entrypoint-only` is a **no-op today** (see §4.4) |

---

## 4. GATE — gaps with no sound structural replacement yet

Per the task's stop condition, these require a decision before any enforcement
is removed or weakened.

### 4.1 Egress has no structural backstop (the big one)

Forcing the worker through the proxy (`proxy` mode) and enforcing an IP
allow-list (`direct+reachable_ips`) are **supervisor-only** today. A sound
replacement is a **netns firewall**, which does not exist. Building it raises two
sub-problems:

- **External-runtime dependency.** A netns firewall means shelling out to `nft`
  or `iptables`, or talking netfilter over a netlink socket. This conflicts with
  the project's stated "no external runtime" property (CLAUDE.md / README). A
  raw-netlink nftables implementation avoids the binary dependency but is
  substantial new unsafe-adjacent code.
- **Proxy vs. worker share one netns.** The proxy joins the worker's netns
  (`setns(CLONE_NEWNET)`), so a firewall that "allows only the proxy out" cannot
  distinguish them by address alone. Sound options:
  - (a) run the proxy under a **second mapped UID** and match `meta skuid` in
    nft (worker can't impersonate it — `no_new_privs`, empty cap set);
  - (b) **re-architect** so the worker has *no* uplink: proxy lives in a
    separate netns with pasta, worker reaches it only via loopback or a unix
    socket. Bigger change, but removes the shared-netns problem and is the
    cleanest long-term design.

### 4.2 `clone3` cannot be filtered by BPF

Its flags are behind a pointer; BPF can't read them. **Decision needed:**
- (a) `clone3 → ENOSYS`: glibc ≥2.34 and musl fall back to `clone`, which we
  filter on registers. Maximally compatible; standard (systemd/Docker do this).
- (b) hard-deny `clone3` (`EPERM`): simplest, but breaks any caller that uses
  `clone3` without a fallback.

Either is strictly sounder than today's raceable supervisor check.

### 4.3 `direct` + allow-list is a structurally weak mode

`[unsafe] unfiltered_egress` combined with `reachable_ips`/`[[host]]` yields a
mode with an allow-list but **no proxy**. Decide whether this combination should
(a) be rejected at config-resolve time, (b) force a proxy, or (c) get firewall
CIDR rules. Until decided, its egress restriction cannot move off the supervisor.

### 4.4 Exec child-allow-list loses its only enforcement until Phase 4

- `exec=[paths]`: child execs are enforced solely by the (raceable) supervisor.
  Removing it before rootfs/`noexec` composition exists would regress to "any
  child exec allowed." Phase 4 must land first.
- `entrypoint-only`: **already a no-op for child execs** (`policy_config.rs`
  seeds no paths for `ExecPolicy::Mode`, so `evaluate_execve` returns `Allow`).
  Removing the supervisor loses nothing here, but the *intended* restriction is
  currently unmet and should be implemented (rootfs `noexec`, or drop `execve`
  from the allow-list after entrypoint) — or the README claim corrected.

### 4.5 Observability that genuinely degrades

Per-call `connect`/`sendto`/`execve` argument logging (destination IP/port, exec
path) goes away. Recoverable: HTTP-level egress (host, method, path, bytes) from
proxy logs/events; denied connects as firewall counters. **Not** recoverable
without a new mechanism: per-exec path audit for child processes (could be
provided by the MAC layer / auditd as a follow-up, noted as non-authoritative).

---

## 5. What is already sound and can move mechanically (no decision needed)

- `unshare`/`setns` namespace creation — already baseline-denied (static BPF).
- `socket()` SOCK_RAW / AF_NETLINK-non-ROUTE / AF gating — register-decidable,
  move to static BPF (Phase 2).
- `clone` namespace flags — register-decidable, move to static BPF (Phase 2).
- `execveat` `AT_EMPTY_PATH` — register flag, move to static BPF (Phase 2).
- Initial-command exec validation — already host-side and race-free.
- Domain/IP allow-listing *at L7* — already in the proxy; becomes authoritative
  once egress is forced through the proxy structurally (§4.1).

Precedence note for Phase 2: `SECCOMP_RET_ERRNO` (0x00050000) outranks both
`SECCOMP_RET_USER_NOTIF` and the baseline `SECCOMP_RET_ALLOW` (0x7fff0000), so a
prelude that returns `ERRNO`/`ENOSYS` for these register cases will correctly
override the baseline allow.

---

## 6. Baseline (pre-change) state

- `cargo build --workspace` — **pass**.
- `cargo test -p can-sandbox` — **pass** (153 tests).
- `./ci/verify.sh` — **pass** (fmt, clippy `-D warnings`, 5-crate test suite,
  ignored-test check, unwrap checks). Green before any change.
</content>
</invoke>
