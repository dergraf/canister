//! The undeclared-host sink (ADR-0018).
//!
//! With `[network] undeclared_hosts = "sink"`, a request for a host no
//! `[[host]]` block declares is not refused at the connect gate. The
//! proxy terminates TLS with the sandbox CA as it does for a declared
//! host, runs the request through the same DLP and canary detectors, and
//! answers it itself with a fixed 403.
//!
//! The invariant a reviewer should check here: nothing in this module
//! resolves a name, opens a socket or calls into `upstream`. The only way
//! out of [`answer`] is [`ProxyError::sinked`].

use hyper::{Request, Response};

use super::capture::ExchangeRecorder;
use super::dlp_ctx::DlpCtx;
use super::entropy_account::EntropyAccount;
use super::limits::ProxyLimits;
use super::request::{
    BodyOutcome, buffer_and_scan_body, gate_by_dns_entropy, scan_headers_and_uri,
};
use super::responses::{ProxyBody, ProxyError};
use super::util::{host_allowed_by_outbound_policy, host_is_ip};
use crate::contracts::ContractTable;
use crate::policy::{HOST_LOOPBACK_ALIAS, OutboundPolicy};

/// Whether a request for `host` goes to the sink instead of being
/// refused or forwarded.
///
/// Only names are sunk: an IP literal carries no name to mint a
/// certificate for, and stays refused. A host is undeclared when the
/// connect gate would refuse it, or when the contract gate would refuse
/// it as unknown (no `[[host]]` blocks at all under `strict`).
pub(super) fn takes(host: &str, policy: &OutboundPolicy, contracts: &ContractTable) -> bool {
    if !policy.sinks_undeclared() || host.is_empty() || host_is_ip(host) {
        return false;
    }
    let is_loopback_alias =
        policy.host_loopback_target.is_some() && host.eq_ignore_ascii_case(HOST_LOOPBACK_ALIAS);
    if is_loopback_alias {
        return false;
    }
    !host_allowed_by_outbound_policy(host, policy) || contracts.refuses_as_unknown(host)
}

/// Scan a sunk request exactly as a declared host's request is scanned,
/// then answer it locally. Detector findings surface as their usual
/// `dlp_block` / `canary_fire` events; the answer itself never varies.
pub(super) async fn answer(
    req: Request<hyper::body::Incoming>,
    host: &str,
    limits: &ProxyLimits,
    dlp: &DlpCtx,
    recorder: Option<&mut ExchangeRecorder>,
) -> Response<ProxyBody> {
    // The stages mirror `run_request_stages` minus the contract gate
    // (an undeclared host has no contract), the secret swap and the
    // forward. Each stops at the first refusal, as it does there.
    if gate_by_dns_entropy(host, dlp).is_some() {
        return ProxyError::sinked(host).into_response();
    }

    let (parts, body) = req.into_parts();
    if scan_headers_and_uri(dlp, &parts, &parts.uri, host).is_some() {
        return ProxyError::sinked(host).into_response();
    }

    // An undeclared host has no `[[host]]` block, so no budget override.
    let entropy_account = EntropyAccount::for_request(&parts.uri, &parts.headers, None);
    let outcome = buffer_and_scan_body(
        parts.headers.clone(),
        body,
        Some(dlp),
        limits,
        host,
        &entropy_account,
        recorder.is_some(),
    )
    .await;
    if let (
        BodyOutcome::Ready {
            captured: Some(bytes),
            ..
        },
        Some(recorder),
    ) = (outcome, recorder)
    {
        recorder.record_request(
            parts.method.as_str(),
            &parts.uri.to_string(),
            &parts.headers,
            &bytes,
        );
    }

    ProxyError::sinked(host).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use can_policy::config::{ContractMode, HostBlock, NetworkConfig, UndeclaredHosts};

    fn hosts(domains: &[&str]) -> Vec<HostBlock> {
        domains
            .iter()
            .map(|d| HostBlock {
                domain: d.to_string(),
                ..Default::default()
            })
            .collect()
    }

    fn setup(
        mode: Option<UndeclaredHosts>,
        domains: &[&str],
        contract_mode: ContractMode,
    ) -> (OutboundPolicy, ContractTable) {
        let network = NetworkConfig {
            undeclared_hosts: mode,
            ..Default::default()
        };
        let blocks = hosts(domains);
        (
            OutboundPolicy::from_config(&network, &blocks),
            ContractTable::new(blocks, contract_mode),
        )
    }

    #[test]
    fn nothing_is_sunk_by_default() {
        let (policy, contracts) = setup(None, &["github.com"], ContractMode::Strict);
        assert!(!takes("evil.example", &policy, &contracts));

        let (policy, contracts) = setup(
            Some(UndeclaredHosts::Refuse),
            &["github.com"],
            ContractMode::Strict,
        );
        assert!(!takes("evil.example", &policy, &contracts));
    }

    #[test]
    fn sink_takes_hosts_the_connect_gate_refuses() {
        let (policy, contracts) = setup(
            Some(UndeclaredHosts::Sink),
            &["github.com"],
            ContractMode::Strict,
        );
        assert!(takes("evil.example", &policy, &contracts));
        assert!(takes("notgithub.com", &policy, &contracts));
    }

    #[test]
    fn sink_leaves_declared_hosts_alone() {
        let (policy, contracts) = setup(
            Some(UndeclaredHosts::Sink),
            &["github.com", "example.org"],
            ContractMode::Strict,
        );
        assert!(!takes("github.com", &policy, &contracts));
        assert!(!takes("api.github.com", &policy, &contracts));
        assert!(!takes("example.org", &policy, &contracts));
    }

    #[test]
    fn sink_takes_unknown_hosts_when_no_host_is_declared() {
        // No `[[host]]` at all: the connect gate lets every name through
        // and the strict contract gate refuses each as unknown.
        let (policy, contracts) = setup(Some(UndeclaredHosts::Sink), &[], ContractMode::Strict);
        assert!(takes("anything.example", &policy, &contracts));
    }

    #[test]
    fn sink_does_not_take_hosts_relaxed_mode_forwards() {
        let (policy, contracts) = setup(Some(UndeclaredHosts::Sink), &[], ContractMode::Relaxed);
        assert!(!takes("anything.example", &policy, &contracts));
    }

    #[test]
    fn ip_literals_and_empty_hosts_are_never_sunk() {
        let (policy, contracts) = setup(
            Some(UndeclaredHosts::Sink),
            &["github.com"],
            ContractMode::Strict,
        );
        assert!(!takes("203.0.113.7", &policy, &contracts));
        assert!(!takes("2001:db8::1", &policy, &contracts));
        assert!(!takes("", &policy, &contracts));
    }

    #[test]
    fn the_host_loopback_alias_is_never_sunk() {
        let (mut policy, contracts) = setup(Some(UndeclaredHosts::Sink), &[], ContractMode::Strict);
        policy.host_loopback_target = Some("169.254.1.2".parse().expect("ip"));
        assert!(!takes(HOST_LOOPBACK_ALIAS, &policy, &contracts));
    }

    #[test]
    fn the_sink_answer_is_a_fixed_403() {
        let resp = ProxyError::sinked("evil.example").into_response();
        assert_eq!(resp.status(), hyper::StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get("x-canister-error")
                .and_then(|v| v.to_str().ok()),
            Some("undeclared-host-sink")
        );
    }
}
