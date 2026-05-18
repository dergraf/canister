use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::merge::union_vecs;

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    /// Paths the sandboxed process is allowed to access (read-only).
    #[serde(default)]
    pub allow: Vec<PathBuf>,

    /// Paths bind-mounted writable into the sandbox.
    ///
    /// Use this for directories the sandboxed process must write to
    /// (e.g., database files, caches, state directories). These paths
    /// are mounted writable — changes persist on the host.
    #[serde(default)]
    pub allow_write: Vec<PathBuf>,

    /// Paths explicitly denied (checked before allow and allow_write).
    #[serde(default)]
    pub deny: Vec<PathBuf>,

    /// Paths to mask inside the sandbox (bind `/dev/null` over them).
    ///
    /// Used to hide files that would otherwise be visible through the
    /// CWD bind-mount. For example, `canister.toml` is auto-masked
    /// when running via `can up` to prevent the sandboxed process from
    /// reading the security policy.
    ///
    /// This field is set programmatically by the CLI layer and is not
    /// expected in recipe TOML files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mask: Vec<PathBuf>,
}

impl FilesystemConfig {
    pub fn merge(self, overlay: Self) -> Self {
        Self {
            allow: union_vecs(self.allow, overlay.allow),
            allow_write: union_vecs(self.allow_write, overlay.allow_write),
            deny: union_vecs(self.deny, overlay.deny),
            mask: union_vecs(self.mask, overlay.mask),
        }
    }
}

/// Protocol for port forwarding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    #[default]
    Tcp,
    Udp,
}

impl fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// A port forwarding rule mapping a host port to a container port.
///
/// Follows Docker/Podman syntax: `[ip:]hostPort:containerPort[/protocol]`
///
/// Examples:
/// - `8080:80` — TCP, host 8080 → container 80
/// - `8080:80/udp` — UDP, host 8080 → container 80
/// - `127.0.0.1:8080:80` — TCP, bind to 127.0.0.1, host 8080 → container 80
/// - `8080:8080` or just `8080` (shorthand) — TCP, same port both sides
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortMapping {
    /// Optional IP address to bind on the host side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<IpAddr>,

    /// Port on the host.
    pub host_port: u16,

    /// Port inside the container/sandbox.
    pub container_port: u16,

    /// Protocol (tcp or udp). Defaults to tcp.
    #[serde(default)]
    pub protocol: PortProtocol,
}

impl fmt::Display for PortMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip) = &self.host_ip {
            write!(f, "{ip}:")?;
        }
        write!(
            f,
            "{}:{}/{}",
            self.host_port, self.container_port, self.protocol
        )
    }
}

impl PortMapping {
    /// Parse a port mapping from Docker/Podman syntax.
    ///
    /// Supported formats:
    /// - `port` — shorthand for `port:port/tcp`
    /// - `hostPort:containerPort` — defaults to tcp
    /// - `hostPort:containerPort/protocol`
    /// - `ip:hostPort:containerPort`
    /// - `ip:hostPort:containerPort/protocol`
    pub fn parse(s: &str) -> Result<Self, String> {
        // Split off protocol suffix.
        let (addr_part, protocol) = if let Some((addr, proto)) = s.rsplit_once('/') {
            let protocol = match proto {
                "tcp" => PortProtocol::Tcp,
                "udp" => PortProtocol::Udp,
                other => return Err(format!("unknown protocol: {other}")),
            };
            (addr, protocol)
        } else {
            (s, PortProtocol::Tcp)
        };

        let parts: Vec<&str> = addr_part.split(':').collect();
        match parts.len() {
            1 => {
                // Single port: same on both sides.
                let port: u16 = parts[0]
                    .parse()
                    .map_err(|e| format!("invalid port '{}': {e}", parts[0]))?;
                Ok(PortMapping {
                    host_ip: None,
                    host_port: port,
                    container_port: port,
                    protocol,
                })
            }
            2 => {
                // hostPort:containerPort
                let host_port: u16 = parts[0]
                    .parse()
                    .map_err(|e| format!("invalid host port '{}': {e}", parts[0]))?;
                let container_port: u16 = parts[1]
                    .parse()
                    .map_err(|e| format!("invalid container port '{}': {e}", parts[1]))?;
                Ok(PortMapping {
                    host_ip: None,
                    host_port,
                    container_port,
                    protocol,
                })
            }
            3 => {
                // ip:hostPort:containerPort
                let host_ip: IpAddr = parts[0]
                    .parse()
                    .map_err(|e| format!("invalid IP '{}': {e}", parts[0]))?;
                let host_port: u16 = parts[1]
                    .parse()
                    .map_err(|e| format!("invalid host port '{}': {e}", parts[1]))?;
                let container_port: u16 = parts[2]
                    .parse()
                    .map_err(|e| format!("invalid container port '{}': {e}", parts[2]))?;
                Ok(PortMapping {
                    host_ip: Some(host_ip),
                    host_port,
                    container_port,
                    protocol,
                })
            }
            _ => Err(format!("invalid port mapping: {s}")),
        }
    }
}
