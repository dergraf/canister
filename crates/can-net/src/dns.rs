//! Minimal DNS proxy with domain-based filtering.
//!
//! Runs in the parent process on the host, listening on an ephemeral port
//! on 127.0.0.1. pasta intercepts DNS queries from the sandbox and
//! forwards them to this proxy via `--dns-forward`. Queries for
//! whitelisted domains are forwarded to the upstream DNS server.
//! Queries for non-whitelisted domains get a REFUSED response.
//!
//! # DNS packet format (simplified)
//!
//! ```text
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      ID (16)                     |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |QR| Opcode |AA|TC|RD|RA| Z|AD|CD|   RCODE (4)    |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                    QDCOUNT (16)                   |
//! |                    ANCOUNT (16)                   |
//! |                    NSCOUNT (16)                   |
//! |                    ARCOUNT (16)                   |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use can_policy::config::NetworkConfig;

use crate::NetError;

/// Minimum valid DNS packet size (header only).
const DNS_HEADER_SIZE: usize = 12;

/// Maximum DNS UDP packet size.
const DNS_MAX_SIZE: usize = 512;

/// DNS RCODE: REFUSED (5).
const RCODE_REFUSED: u8 = 5;

/// Read the first `nameserver` entry from `/etc/resolv.conf`.
///
/// Returns `Some(addr:53)` on success, `None` if the file is missing,
/// unreadable, or contains no `nameserver` lines. Only plain IP
/// addresses are accepted (no scoped IPv6, no hostnames).
fn read_host_nameserver() -> Option<SocketAddr> {
    let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(addr_str) = parts.next() {
                if let Ok(ip) = addr_str.parse::<IpAddr>() {
                    return Some(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    None
}

/// Handle to control the DNS proxy from the parent.
pub struct DnsProxyHandle {
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    local_port: u16,
}

impl DnsProxyHandle {
    /// Signal the DNS proxy to shut down and wait for the thread.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }

    /// Get the port the DNS proxy is actually listening on.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }
}

/// Configuration for the DNS proxy.
pub struct DnsProxyConfig {
    /// Address to bind the proxy to (on the host's loopback).
    pub listen_addr: SocketAddr,

    /// Upstream DNS server to forward allowed queries to.
    /// In the parent process context, this is a real host DNS server
    /// (e.g., from /etc/resolv.conf or a well-known resolver).
    pub upstream_addr: SocketAddr,

    /// Network policy for filtering.
    pub policy: NetworkConfig,
}

impl DnsProxyConfig {
    /// Default config: listen on 127.0.0.1:0 (OS-assigned ephemeral port),
    /// upstream is the host's DNS resolver (from /etc/resolv.conf, or
    /// 8.8.8.8 as fallback).
    ///
    /// The DNS proxy runs in the parent process. pasta's `--dns-forward`
    /// option forwards sandbox DNS queries to this port on the host's
    /// loopback. Port 0 lets the OS pick an available port (port 53 is
    /// privileged and would require root).
    pub fn default_with_policy(policy: NetworkConfig) -> Self {
        let upstream = read_host_nameserver().unwrap_or_else(|| "8.8.8.8:53".parse().unwrap());
        Self {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            upstream_addr: upstream,
            policy,
        }
    }
}

/// Start the DNS proxy in a background thread.
///
/// Returns a handle that can be used to shut it down.
pub fn start_dns_proxy(config: DnsProxyConfig) -> Result<DnsProxyHandle, NetError> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    let socket = UdpSocket::bind(config.listen_addr).map_err(|e| {
        NetError::Dns(format!(
            "failed to bind DNS proxy on {}: {e}",
            config.listen_addr
        ))
    })?;

    let local_port = socket
        .local_addr()
        .map_err(|e| NetError::Dns(format!("failed to get local addr: {e}")))?
        .port();

    // Set a timeout so we can check the shutdown flag periodically.
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| NetError::Dns(format!("failed to set socket timeout: {e}")))?;

    tracing::info!(
        listen = %config.listen_addr,
        port = local_port,
        upstream = %config.upstream_addr,
        "DNS proxy starting"
    );

    let thread = thread::Builder::new()
        .name("can-dns-proxy".to_string())
        .spawn(move || {
            dns_proxy_loop(
                socket,
                config.upstream_addr,
                &config.policy,
                &shutdown_clone,
            );
        })
        .map_err(|e| NetError::Dns(format!("failed to spawn DNS proxy thread: {e}")))?;

    Ok(DnsProxyHandle {
        shutdown,
        thread: Some(thread),
        local_port,
    })
}

/// Start the DNS proxy, updating the config's listen_addr with the actual bound address.
///
/// This is useful when binding to port 0 (OS-assigned port). The config's
/// listen_addr will be updated after binding.
pub fn start_dns_proxy_with_addr(config: &mut DnsProxyConfig) -> Result<DnsProxyHandle, NetError> {
    let owned_config = DnsProxyConfig {
        listen_addr: config.listen_addr,
        upstream_addr: config.upstream_addr,
        policy: config.policy.clone(),
    };
    let handle = start_dns_proxy(owned_config)?;
    // Update the config with the actual port.
    config.listen_addr = SocketAddr::new(config.listen_addr.ip(), handle.local_port());
    Ok(handle)
}

/// Main loop for the DNS proxy.
fn dns_proxy_loop(
    socket: UdpSocket,
    upstream: SocketAddr,
    policy: &NetworkConfig,
    shutdown: &AtomicBool,
) {
    let mut buf = [0u8; DNS_MAX_SIZE];

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::debug!("DNS proxy shutting down");
            break;
        }

        let (len, client_addr) = match socket.recv_from(&mut buf) {
            Ok(result) => result,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => {
                tracing::error!(error = %e, "DNS proxy recv error");
                continue;
            }
        };

        if len < DNS_HEADER_SIZE {
            tracing::debug!(len, "DNS proxy: ignoring short packet");
            continue;
        }

        let packet = &buf[..len];

        match extract_query_name(packet) {
            Some(domain) => {
                if crate::is_domain_allowed(&domain, policy) {
                    tracing::debug!(domain, "DNS: allowed, forwarding");
                    match forward_query(packet, upstream) {
                        Ok(response) => {
                            let _ = socket.send_to(&response, client_addr);
                        }
                        Err(e) => {
                            tracing::warn!(domain, error = %e, "DNS: upstream forward failed");
                            let refused = build_refused_response(packet);
                            let _ = socket.send_to(&refused, client_addr);
                        }
                    }
                } else {
                    tracing::debug!(domain, "DNS: blocked by policy");
                    let refused = build_refused_response(packet);
                    let _ = socket.send_to(&refused, client_addr);
                }
            }
            None => {
                tracing::debug!("DNS: could not parse query name, refusing");
                let refused = build_refused_response(packet);
                let _ = socket.send_to(&refused, client_addr);
            }
        }
    }
}

/// Forward a DNS query to the upstream server and return the response.
fn forward_query(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, NetError> {
    let sock =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| NetError::Dns(format!("forward bind: {e}")))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| NetError::Dns(format!("forward timeout: {e}")))?;

    sock.send_to(query, upstream)
        .map_err(|e| NetError::Dns(format!("forward send: {e}")))?;

    let mut buf = [0u8; DNS_MAX_SIZE];
    let (len, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| NetError::Dns(format!("forward recv: {e}")))?;

    Ok(buf[..len].to_vec())
}

/// Extract the first query domain name from a DNS packet.
///
/// Returns the domain as a string (e.g., "example.com") or None if
/// the packet is malformed.
pub fn extract_query_name(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }

    // QDCOUNT is at bytes 4-5.
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    // Question section starts at byte 12.
    let mut pos = DNS_HEADER_SIZE;
    let mut labels = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }

        let label_len = packet[pos] as usize;
        pos += 1;

        if label_len == 0 {
            break; // Root label — end of name.
        }

        // Pointer compression — not expected in queries, but handle gracefully.
        if label_len >= 0xC0 {
            return None; // Don't follow pointers in query names.
        }

        if pos + label_len > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[pos..pos + label_len]).ok()?;
        labels.push(label.to_lowercase());
        pos += label_len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Build a REFUSED response for a DNS query.
///
/// Copies the query header, sets QR=1 (response) and RCODE=REFUSED,
/// keeps the question section.
pub fn build_refused_response(query: &[u8]) -> Vec<u8> {
    if query.len() < DNS_HEADER_SIZE {
        return vec![];
    }

    let mut response = query.to_vec();

    // Set QR=1 (response bit) — byte 2, bit 7.
    response[2] |= 0x80;

    // Set RCODE=REFUSED (5) in byte 3, low 4 bits.
    response[3] = (response[3] & 0xF0) | RCODE_REFUSED;

    // Zero out ANCOUNT, NSCOUNT, ARCOUNT — we have no answer.
    response[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);

    response
}

/// Build an NXDOMAIN response for a DNS query.
///
/// Like REFUSED but with RCODE=3 (NXDOMAIN) and AA=1.
pub fn build_nxdomain_response(query: &[u8]) -> Vec<u8> {
    if query.len() < DNS_HEADER_SIZE {
        return vec![];
    }

    let mut response = query.to_vec();

    // Set QR=1, AA=1 — byte 2.
    response[2] |= 0x84; // QR (0x80) + AA (0x04)

    // Set RCODE=NXDOMAIN (3) in byte 3.
    response[3] = (response[3] & 0xF0) | 3;

    // Zero out ANCOUNT, NSCOUNT, ARCOUNT.
    response[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for testing.
    fn build_test_query(domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // Header: ID=0x1234, QR=0, OPCODE=0, RD=1
        packet.extend_from_slice(&[
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ]);

        // Question: encode domain name as labels.
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label

        // QTYPE=A (1), QCLASS=IN (1)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        packet
    }

    #[test]
    fn extract_simple_domain() {
        let query = build_test_query("example.com");
        assert_eq!(extract_query_name(&query), Some("example.com".to_string()));
    }

    #[test]
    fn extract_subdomain() {
        let query = build_test_query("www.example.com");
        assert_eq!(
            extract_query_name(&query),
            Some("www.example.com".to_string())
        );
    }

    #[test]
    fn extract_single_label() {
        let query = build_test_query("localhost");
        assert_eq!(extract_query_name(&query), Some("localhost".to_string()));
    }

    #[test]
    fn extract_from_short_packet() {
        let packet = [0u8; 4];
        assert_eq!(extract_query_name(&packet), None);
    }

    #[test]
    fn extract_zero_qdcount() {
        let mut query = build_test_query("example.com");
        query[4] = 0;
        query[5] = 0; // QDCOUNT=0
        assert_eq!(extract_query_name(&query), None);
    }

    #[test]
    fn refused_response_has_correct_flags() {
        let query = build_test_query("evil.com");
        let response = build_refused_response(&query);

        // QR bit should be set.
        assert!(response[2] & 0x80 != 0, "QR bit not set");

        // RCODE should be 5 (REFUSED).
        assert_eq!(response[3] & 0x0F, 5, "RCODE not REFUSED");

        // ANCOUNT, NSCOUNT, ARCOUNT should be 0.
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);

        // ID should be preserved.
        assert_eq!(&response[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn nxdomain_response_has_correct_flags() {
        let query = build_test_query("evil.com");
        let response = build_nxdomain_response(&query);

        // QR and AA bits should be set.
        assert!(response[2] & 0x80 != 0, "QR bit not set");
        assert!(response[2] & 0x04 != 0, "AA bit not set");

        // RCODE should be 3 (NXDOMAIN).
        assert_eq!(response[3] & 0x0F, 3, "RCODE not NXDOMAIN");
    }

    #[test]
    fn case_insensitive_extraction() {
        let query = build_test_query("Example.COM");
        assert_eq!(extract_query_name(&query), Some("example.com".to_string()));
    }
}
