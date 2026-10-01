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
use super::network::EgressMode;
use super::sandbox::SandboxConfig;
use super::syscalls::{DANGEROUS_SYSCALLS, SeccompMode};

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

    /// The isolation-weakening settings in effect in a resolved policy.
    ///
    /// Read back from the runtime fields `[unsafe]` folds into, not from
    /// what any recipe authored, so it also covers weakenings that arrive
    /// another way (`--port` on the command line) and cannot disagree with
    /// what the sandbox enforces. `extra_syscalls` is the subset of
    /// `allow_extra` in [`DANGEROUS_SYSCALLS`], which `[syscalls]` rejects,
    /// so only `[unsafe]` can have put them there.
    pub fn in_effect(config: &SandboxConfig) -> Self {
        Self {
            unfiltered_egress: config.network.egress() == EgressMode::Direct,
            reachable_ips: config.network.allow_ips.clone(),
            host_loopback: config.network.allow_host_loopback,
            expose_ports: config.network.ports.clone(),
            seccomp_default_allow: config.syscalls.seccomp_mode() == SeccompMode::DenyList,
            extra_syscalls: config
                .syscalls
                .allow_extra
                .iter()
                .filter(|syscall| DANGEROUS_SYSCALLS.contains(&syscall.as_str()))
                .cloned()
                .collect(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(toml: &str) -> SandboxConfig {
        let recipe: super::super::recipe::RecipeFile = toml::from_str(toml).expect("parse recipe");
        recipe.into_sandbox_config().expect("resolve recipe")
    }

    #[test]
    fn a_policy_without_unsafe_has_nothing_in_effect() {
        let in_effect = UnsafeConfig::in_effect(&SandboxConfig::default_deny());

        assert!(!in_effect.is_active(), "{in_effect:?}");
    }

    #[test]
    fn every_authored_switch_is_read_back_from_the_resolved_policy() {
        let config = resolve(
            r#"
            [unsafe]
            reachable_ips = ["10.0.0.0/8"]
            host_loopback = true
            expose_ports = [{ host_port = 8080, container_port = 80 }]
            seccomp_default_allow = true
            extra_syscalls = ["ptrace"]
            "#,
        );

        let in_effect = UnsafeConfig::in_effect(&config);

        assert!(!in_effect.unfiltered_egress);
        assert_eq!(in_effect.reachable_ips, vec!["10.0.0.0/8".to_string()]);
        assert!(in_effect.host_loopback);
        assert_eq!(
            in_effect.expose_ports,
            vec![PortMapping::parse("8080:80").expect("port")]
        );
        assert!(in_effect.seccomp_default_allow);
        assert_eq!(in_effect.extra_syscalls, vec!["ptrace".to_string()]);
    }

    #[test]
    fn unfiltered_egress_is_read_back_from_the_egress_mode() {
        let config = resolve("[unsafe]\nunfiltered_egress = true\n");

        assert!(UnsafeConfig::in_effect(&config).unfiltered_egress);
    }

    #[test]
    fn ordinary_extra_syscalls_are_not_reported_as_unsafe() {
        let config = resolve(
            r#"
            [syscalls]
            allow_extra = ["sendmmsg"]

            [unsafe]
            extra_syscalls = ["bpf"]
            "#,
        );

        assert_eq!(
            UnsafeConfig::in_effect(&config).extra_syscalls,
            vec!["bpf".to_string()]
        );
    }

    #[test]
    fn a_port_added_after_resolution_is_in_effect() {
        let mut config = SandboxConfig::default_deny();
        config
            .network
            .ports
            .push(PortMapping::parse("127.0.0.1:9000:9000").expect("port"));

        let in_effect = UnsafeConfig::in_effect(&config);

        assert!(in_effect.is_active());
        assert_eq!(in_effect.expose_ports, config.network.ports);
    }
}
