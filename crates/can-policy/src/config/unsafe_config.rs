//! The `[unsafe]` block — the single home for every recipe setting that
//! *lowers* isolation below the baseline.
//!
//! Design principle: isolation is the floor. A recipe with no `[unsafe]`
//! block is provably unable to weaken the sandbox, and
//! `grep -rL '\[unsafe\]' recipes/` is the audited-safe set. Each of these
//! knobs used to live in an ordinary-looking section (`[network]`,
//! `[syscalls]`); pulling them here makes the security cost visible at
//! authoring time and at review. At resolve time
//! ([`super::recipe::RecipeFile::into_sandbox_config`]) these fold back
//! into the runtime `NetworkConfig` / `SyscallConfig`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::filesystem::PortMapping;
use super::merge::union_vecs;

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnsafeConfig {
    /// Bypass the L7 egress proxy: outbound is direct, so **DLP and
    /// per-host contract gates do not run**. Only the IP/policy layer
    /// applies. Was `[network] egress = "direct"`.
    #[serde(default)]
    pub unfiltered_egress: bool,

    /// IP addresses / CIDRs the sandbox may reach directly. IP-literal
    /// egress carries no service identity and bypasses the per-host
    /// contract and DLP gates. Was `[network] allow_ips`.
    #[serde(default)]
    pub reachable_ips: Vec<String>,

    /// Let the sandbox reach host loopback services via the
    /// `host.canister.local` alias — opens host-local daemons (DBs,
    /// sockets) to sandboxed code. Was `[network] allow_host_loopback`.
    #[serde(default)]
    pub host_loopback: bool,

    /// Forward host ports into the sandbox (inbound exposure).
    /// `[ip:]hostPort:containerPort[/protocol]`. Was `[network] ports`.
    #[serde(default)]
    pub expose_ports: Vec<PortMapping>,

    /// Flip seccomp to **default-allow** (deny-list): every syscall is
    /// permitted unless explicitly denied — the inverse of the secure
    /// default. Was `[syscalls] seccomp_mode = "deny-list"`.
    #[serde(default)]
    pub seccomp_default_allow: bool,

    /// High-risk syscalls to add to the allow list. These widen the
    /// kernel attack surface (e.g. `ptrace`, `bpf`, `mount`, `io_uring_*`)
    /// and are rejected from `[syscalls] allow_extra` — they must be
    /// declared here so the cost is explicit. See
    /// [`super::syscalls::DANGEROUS_SYSCALLS`].
    #[serde(default)]
    pub extra_syscalls: Vec<String>,
}

impl UnsafeConfig {
    /// `true` when this block weakens isolation in any way — used to
    /// gate the runtime warning and the (deferred) posture report.
    pub fn is_active(&self) -> bool {
        self.unfiltered_egress
            || self.host_loopback
            || self.seccomp_default_allow
            || !self.reachable_ips.is_empty()
            || !self.expose_ports.is_empty()
            || !self.extra_syscalls.is_empty()
    }

    /// Merge two `[unsafe]` blocks. Bools OR (a weakening in either layer
    /// stays on — matching every other security-monotonic field); vecs
    /// union.
    pub fn merge(self, overlay: Self) -> Self {
        Self {
            unfiltered_egress: self.unfiltered_egress || overlay.unfiltered_egress,
            reachable_ips: union_vecs(self.reachable_ips, overlay.reachable_ips),
            host_loopback: self.host_loopback || overlay.host_loopback,
            expose_ports: union_vecs(self.expose_ports, overlay.expose_ports),
            seccomp_default_allow: self.seccomp_default_allow || overlay.seccomp_default_allow,
            extra_syscalls: union_vecs(self.extra_syscalls, overlay.extra_syscalls),
        }
    }
}
