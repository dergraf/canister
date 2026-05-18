//! Pure helpers: host/port parsing, policy lookup, content-length update.

use hyper::header::{CONTENT_LENGTH, HOST, HeaderValue, TRANSFER_ENCODING};
use hyper::{HeaderMap, Request};

use crate::policy::OutboundPolicy;

/// Pull the destination host out of a `Request` — preferring the URI's
/// authority, falling back to the `Host` header.
pub(super) fn extract_host<B>(req: &Request<B>) -> String {
    if let Some(host) = req.uri().host() {
        return host.to_string();
    }
    req.headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(parse_host_from_authority)
        .unwrap_or_default()
}

/// Parse the host part out of an authority. Strips the optional `:port`
/// suffix and handles bracketed IPv6 literals.
pub(super) fn parse_host_from_authority(authority: &str) -> String {
    if let Some(stripped) = authority.strip_prefix('[') {
        if let Some(close) = stripped.find(']') {
            return stripped[..close].to_string();
        }
    }
    match authority.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() && !host.contains(':') => host.to_string(),
        _ => authority.to_string(),
    }
}

/// Split a CONNECT target into `(host, port)`. Handles bracketed IPv6.
pub(super) fn split_target_host_port(target: &str) -> Result<(String, u16), std::io::Error> {
    if let Some(stripped) = target.strip_prefix('[') {
        let close = stripped
            .find(']')
            .ok_or_else(|| std::io::Error::other("malformed IPv6 authority"))?;
        let host = &stripped[..close];
        let rest = &stripped[close + 1..];
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| std::io::Error::other("missing port after IPv6 authority"))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| std::io::Error::other("invalid port"))?;
        return Ok((host.to_string(), port));
    }

    let mut split = target.rsplitn(2, ':');
    let port_str = split
        .next()
        .ok_or_else(|| std::io::Error::other("missing port"))?;
    let host = split
        .next()
        .ok_or_else(|| std::io::Error::other("missing host"))?
        .to_string();
    let port = port_str
        .parse::<u16>()
        .map_err(|_| std::io::Error::other("invalid port"))?;
    Ok((host, port))
}

/// Check a caller-supplied host string against the outbound policy.
/// Required because callers have already extracted the host from a
/// CONNECT authority or `Host` header and don't know whether it's an IP
/// literal until we try to parse it.
pub(super) fn host_allowed_by_outbound_policy(host: &str, policy: &OutboundPolicy) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        policy.allows_ip_literal(ip)
    } else {
        policy.allows_host(host)
    }
}

/// Whether `host` is a literal IP address (vs. a DNS name). Used to
/// pick the right "policy refusal" body wording.
pub(super) fn host_is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Update `Content-Length` after rebuilding the body and drop any
/// `Transfer-Encoding` so we always re-emit a content-length-delimited
/// message.
pub(super) fn update_content_length(headers: &mut HeaderMap, len: usize) {
    if headers.contains_key(CONTENT_LENGTH) {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    }
    headers.remove(TRANSFER_ENCODING);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_from_authority_ipv6_bracketed() {
        assert_eq!(parse_host_from_authority("[::1]:8080"), "::1");
        assert_eq!(
            parse_host_from_authority("[2001:db8::1]:443"),
            "2001:db8::1"
        );
    }

    #[test]
    fn parse_host_from_authority_ipv4_with_port() {
        assert_eq!(parse_host_from_authority("127.0.0.1:8080"), "127.0.0.1");
    }

    #[test]
    fn parse_host_from_authority_host_only() {
        assert_eq!(parse_host_from_authority("example.com"), "example.com");
    }

    #[test]
    fn parse_host_from_authority_bare_ipv6_falls_back() {
        assert_eq!(parse_host_from_authority("::1"), "::1");
    }

    #[test]
    fn split_target_host_port_ipv6() {
        assert_eq!(
            split_target_host_port("[::1]:8080").unwrap(),
            ("::1".to_string(), 8080)
        );
        assert_eq!(
            split_target_host_port("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn split_target_host_port_ipv4() {
        assert_eq!(
            split_target_host_port("example.com:80").unwrap(),
            ("example.com".to_string(), 80)
        );
    }

    fn policy_with_domain(domain: &str) -> OutboundPolicy {
        let mut net = can_policy::config::NetworkConfig::default();
        net.allow_domains.push(domain.to_string());
        OutboundPolicy::from_config(&net)
    }

    fn policy_with_ip(ip: &str) -> OutboundPolicy {
        let mut net = can_policy::config::NetworkConfig::default();
        net.allow_ips.push(ip.to_string());
        OutboundPolicy::from_config(&net)
    }

    #[test]
    fn host_policy_allows_listed_domain_and_subdomains() {
        let p = policy_with_domain("example.com");
        assert!(host_allowed_by_outbound_policy("example.com", &p));
        assert!(host_allowed_by_outbound_policy("api.example.com", &p));
    }

    #[test]
    fn host_policy_rejects_unlisted_domain() {
        // Regression for F1: in proxy-only + DLP mode the proxy used to
        // forward to any host because `connect_upstream` skipped the
        // outbound policy. The integration test
        // `t_proxy_seccomp_parity.sh` exercises the full path; this unit
        // test pins the helper that all entry points now share.
        let p = policy_with_domain("example.com");
        assert!(!host_allowed_by_outbound_policy("cloudflare.com", &p));
    }

    #[test]
    fn host_policy_rejects_ip_literal_when_only_domains_listed() {
        let p = policy_with_domain("example.com");
        assert!(!host_allowed_by_outbound_policy("11.0.0.5", &p));
    }

    #[test]
    fn host_policy_allows_listed_ip_literal() {
        let p = policy_with_ip("192.0.2.1");
        assert!(host_allowed_by_outbound_policy("192.0.2.1", &p));
        assert!(!host_allowed_by_outbound_policy("198.51.100.1", &p));
    }
}
