// can-net: Network layer for the Canister sandbox.
//
// Phase 1: stub module. Implementation comes in Phase 3.

/// Placeholder for DNS proxy functionality.
pub mod dns {
    /// Start the DNS proxy inside the sandbox network namespace.
    ///
    /// Stub — implementation in Phase 3.
    pub fn start_dns_proxy() {
        tracing::debug!("DNS proxy not yet implemented (Phase 3)");
    }
}

/// Placeholder for veth pair setup.
pub mod veth {
    /// Create a veth pair linking sandbox namespace to host.
    ///
    /// Stub — implementation in Phase 3.
    pub fn setup_veth_pair() {
        tracing::debug!("veth setup not yet implemented (Phase 3)");
    }
}

/// Placeholder for firewall rules.
pub mod filter {
    /// Apply nftables rules for network isolation.
    ///
    /// Stub — implementation in Phase 3.
    pub fn apply_firewall_rules() {
        tracing::debug!("firewall rules not yet implemented (Phase 3)");
    }
}
