use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::merge::union_vecs;

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    /// Paths the sandboxed process may **read** (bind-mounted read-only).
    /// Read access still matters: a readable secret is exactly what the
    /// DLP layer exists to stop from leaving — name it honestly.
    #[serde(default)]
    pub read: Vec<PathBuf>,

    /// Paths bind-mounted **writable** into the sandbox.
    ///
    /// Use this for directories the sandboxed process must write to
    /// (e.g., database files, caches, state directories). These paths
    /// are mounted writable — **changes persist on the host**.
    #[serde(default)]
    pub write: Vec<PathBuf>,

    /// Whether the working directory is mounted writable (ADR-0024).
    /// `write` (default) lets the sandboxed process change project files;
    /// `read` mounts it read-only, so only `write` entries are writable,
    /// including ones inside the working directory.
    #[serde(default)]
    pub workdir: Option<WorkdirAccess>,

    /// Paths explicitly denied (checked before `read` and `write`).
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

    /// Tripwires: paths where an empty decoy file is placed, read-only,
    /// so that any access to it is reported as an `fs_access` event
    /// (ADR-0019). Meant for well-known credential locations
    /// (`$HOME/.ssh/id_ed25519`, `$HOME/.aws/credentials`). A real grant
    /// always wins: a decoy is never placed where a `read` or `write`
    /// path, or the working directory, already provides something.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decoy: Vec<PathBuf>,

    /// The decoys the CLI materialised on the host for this run, and
    /// where each appears in the sandbox. Set programmatically, never
    /// read from a recipe.
    #[serde(skip)]
    #[schemars(skip)]
    pub decoys: Vec<DecoyMount>,
}

/// How the working directory is mounted into the sandbox (ADR-0024).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WorkdirAccess {
    /// Writable: changes to project files persist on the host.
    #[default]
    Write,
    /// Read-only: only `write` entries are writable.
    Read,
    /// Only the `read` and `write` entries inside it are visible; the rest
    /// of the checkout is absent, and the directory itself is read-only
    /// (ADR-0032).
    Listed,
}

/// The narrower access in any layer wins (`listed`, then `read`), so a
/// layer that pins it cannot be widened by a later one.
fn merge_workdir(
    base: Option<WorkdirAccess>,
    overlay: Option<WorkdirAccess>,
) -> Option<WorkdirAccess> {
    match (base, overlay) {
        (Some(WorkdirAccess::Listed), _) | (_, Some(WorkdirAccess::Listed)) => {
            Some(WorkdirAccess::Listed)
        }
        (Some(WorkdirAccess::Read), _) | (_, Some(WorkdirAccess::Read)) => {
            Some(WorkdirAccess::Read)
        }
        (Some(WorkdirAccess::Write), _) | (_, Some(WorkdirAccess::Write)) => {
            Some(WorkdirAccess::Write)
        }
        (None, None) => None,
    }
}

/// A host decoy file and the sandbox path it is mounted at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyMount {
    pub source: PathBuf,
    pub target: PathBuf,
}

impl FilesystemConfig {
    /// Resolved working-directory access (writable if unset).
    pub fn workdir(&self) -> WorkdirAccess {
        self.workdir.unwrap_or_default()
    }

    pub fn merge(self, overlay: Self) -> Self {
        Self {
            read: union_vecs(self.read, overlay.read),
            write: union_vecs(self.write, overlay.write),
            workdir: merge_workdir(self.workdir, overlay.workdir),
            deny: union_vecs(self.deny, overlay.deny),
            mask: union_vecs(self.mask, overlay.mask),
            decoy: union_vecs(self.decoy, overlay.decoy),
            decoys: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn filesystem(toml_src: &str) -> FilesystemConfig {
        toml::from_str(toml_src).expect("filesystem config parses")
    }

    #[test]
    fn workdir_defaults_to_writable() {
        let config = filesystem("");
        assert_eq!(config.workdir, None);
        assert_eq!(config.workdir(), WorkdirAccess::Write);
    }

    #[test]
    fn workdir_parses_both_modes_and_nothing_else() {
        assert_eq!(
            filesystem("workdir = \"read\"").workdir(),
            WorkdirAccess::Read
        );
        assert_eq!(
            filesystem("workdir = \"write\"").workdir(),
            WorkdirAccess::Write
        );
        assert!(toml::from_str::<FilesystemConfig>("workdir = \"none\"").is_err());
        assert!(toml::from_str::<FilesystemConfig>("workdir = false").is_err());
    }

    #[test]
    fn workdir_listed_parses() {
        assert_eq!(
            filesystem("workdir = \"listed\"").workdir(),
            WorkdirAccess::Listed
        );
    }

    #[test]
    fn listed_wins_over_read_and_write_in_any_layer() {
        use WorkdirAccess::{Listed, Read, Write};
        let cases = [
            (Some(Listed), None, Some(Listed)),
            (None, Some(Listed), Some(Listed)),
            (Some(Listed), Some(Write), Some(Listed)),
            (Some(Write), Some(Listed), Some(Listed)),
            (Some(Listed), Some(Read), Some(Listed)),
            (Some(Read), Some(Listed), Some(Listed)),
        ];
        for (base, overlay, expected) in cases {
            let merged = FilesystemConfig {
                workdir: base,
                ..Default::default()
            }
            .merge(FilesystemConfig {
                workdir: overlay,
                ..Default::default()
            });
            assert_eq!(merged.workdir, expected, "{base:?} merged with {overlay:?}");
        }
    }

    #[test]
    fn workdir_merge_table() {
        use WorkdirAccess::{Read, Write};
        let cases = [
            (None, None, None),
            (None, Some(Write), Some(Write)),
            (Some(Write), None, Some(Write)),
            (None, Some(Read), Some(Read)),
            (Some(Read), None, Some(Read)),
            (Some(Read), Some(Write), Some(Read)),
            (Some(Write), Some(Read), Some(Read)),
        ];
        for (base, overlay, expected) in cases {
            let merged = FilesystemConfig {
                workdir: base,
                ..Default::default()
            }
            .merge(FilesystemConfig {
                workdir: overlay,
                ..Default::default()
            });
            assert_eq!(merged.workdir, expected, "{base:?} merged with {overlay:?}");
        }
    }
}
