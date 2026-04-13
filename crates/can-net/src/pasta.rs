//! pasta integration for providing user-mode networking to the sandbox.
//!
//! [pasta](https://passt.top/) provides a thin translation layer between
//! the host network and an unprivileged network namespace. It uses the kernel's
//! existing TCP/IP stack directly, achieving high throughput without a user-mode
//! TCP/IP stack.
//!
//! pasta is the default network backend for Podman (since 4.3.2) and
//! rootless Docker.
//!
//! ## Network layout
//!
//! pasta mirrors the host's real network configuration inside the namespace:
//! - Same IP address as the host's upstream interface
//! - Same default gateway as the host
//! - DNS configured via `--config-net` (copies host resolv.conf setup)
//!
//! DNS filtering is handled by the seccomp notifier in `can-sandbox`, which
//! intercepts `sendto`/`sendmsg` syscalls to port 53 and checks the queried
//! domain against the policy's allowed domains list. This avoids the need for
//! a separate DNS proxy process.
//!
//! ## Port forwarding
//!
//! pasta natively supports port forwarding via `-t` (TCP) and `-u` (UDP):
//! - `-t 8080` — forward host:8080 → namespace:8080
//! - `-t 8080:80` — forward host:8080 → namespace:80
//! - `-u 5000` — forward UDP host:5000 → namespace:5000
//!
//! By default, pasta auto-forwards all bound ports. We disable this
//! and only forward explicit ports configured via `-p`/`--port`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use can_policy::config::{PortMapping, PortProtocol};

use crate::NetError;

/// DNS address configured by pasta inside the namespace.
///
/// When pasta runs with `--config-net`, it writes a `resolv.conf` inside the
/// namespace pointing to this address. pasta then transparently forwards DNS
/// queries sent to this address to the host's upstream resolver.
///
/// The seccomp notifier allows `sendto`/`sendmsg` to this address on port 53
/// unconditionally (the domain-level check happens on the DNS query content,
/// not the destination IP). This constant is used by both the notifier policy
/// and the namespace setup to keep things consistent.
pub const PASTA_DNS_ADDR: &str = "169.254.0.1";

/// Check whether pasta is available on the system.
pub fn is_available() -> bool {
    which_pasta().is_some()
}

/// Find the pasta binary path.
fn which_pasta() -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join("pasta");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Detect the host's default gateway IPv4 address.
///
/// Reads `/proc/net/route` and finds the entry with destination `00000000`
/// (default route). Returns the gateway IP address.
pub fn detect_default_gateway() -> Option<std::net::Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        // Destination is field[1], Gateway is field[2] — hex-encoded, little-endian on x86.
        if fields[1] == "00000000" {
            let gw_hex = u32::from_str_radix(fields[2], 16).ok()?;
            // /proc/net/route stores IPs in host byte order (little-endian on x86).
            return Some(std::net::Ipv4Addr::from(gw_hex.to_be()));
        }
    }
    None
}

/// Check whether pasta supports a specific command-line option.
///
/// Runs `pasta --help` and searches for the option string.
fn pasta_supports_option(option: &str) -> bool {
    let Some(pasta_path) = which_pasta() else {
        return false;
    };
    let output = Command::new(pasta_path).arg("--help").output().ok();
    match output {
        Some(out) => {
            let help = String::from_utf8_lossy(&out.stdout);
            let help_stderr = String::from_utf8_lossy(&out.stderr);
            help.contains(option) || help_stderr.contains(option)
        }
        None => false,
    }
}

/// Options for starting pasta.
pub struct PastaConfig {
    /// Port forwarding rules (empty = no port forwarding).
    pub ports: Vec<PortMapping>,

    /// PID of the child process whose network namespace to join.
    ///
    /// pasta is invoked with:
    ///   `--userns /proc/<pid>/ns/user --netns /proc/<pid>/ns/net --runas <uid>`
    ///
    /// `setns(CLONE_NEWNET)` requires `CAP_SYS_ADMIN` in the user namespace
    /// that owns the target network namespace. Since the child created both
    /// namespaces via `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, the network
    /// namespace is owned by the child's user namespace — not the init user
    /// namespace. Pasta must therefore join the user namespace first
    /// (`setns(CLONE_NEWUSER)`) to acquire the necessary capability, then
    /// join the network namespace (`setns(CLONE_NEWNET)`).
    ///
    /// The child must call `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` before
    /// the parent starts pasta, so that pasta (a sibling process) can open
    /// `/proc/<pid>/ns/*` files despite Yama `ptrace_scope=1`.
    ///
    /// `--runas <uid>` prevents pasta from dropping to "nobody", which
    /// would fail the kernel's UID ownership check on namespace files.
    pub child_pid: Option<u32>,
}

/// Start pasta for a sandboxed process.
///
/// `config.child_pid` must be set to the PID of the child process that
/// has already called `unshare(CLONE_NEWUSER | CLONE_NEWNET)` and
/// `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`.
///
/// pasta is invoked as:
///   `pasta --userns /proc/<pid>/ns/user --netns /proc/<pid>/ns/net --runas <uid>`
///
/// - `--userns` + `--netns` — join the child's user namespace first (to
///   acquire `CAP_SYS_ADMIN` over the network namespace), then join the
///   network namespace. This two-step join is required because the kernel's
///   `setns(CLONE_NEWNET)` checks for `CAP_SYS_ADMIN` in the user namespace
///   that owns the target network namespace.
/// - `--runas <uid>` — stay as our uid instead of dropping to "nobody".
///
/// Returns the pasta child process handle.
pub fn start(config: &PastaConfig) -> Result<Child, NetError> {
    let pasta_path =
        which_pasta().ok_or_else(|| NetError::Pasta("pasta not found in PATH".to_string()))?;

    let child_pid = config
        .child_pid
        .ok_or_else(|| NetError::Pasta("child_pid must be set in PastaConfig".to_string()))?;

    tracing::info!(child_pid, ports = config.ports.len(), "starting pasta");

    let mut cmd = Command::new(pasta_path);

    // Run in foreground so we can manage the process lifecycle.
    cmd.arg("--foreground");

    // Keep running as the current user instead of dropping to "nobody".
    //
    // By default, pasta drops privileges to the "nobody" user. However,
    // when using --userns + --netns with /proc/<pid>/ns/* paths, the
    // "nobody" user cannot open these files because the kernel restricts
    // access to namespace files of processes owned by a different uid.
    // The child calls prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) to allow
    // pasta (a sibling process) to open /proc/<pid>/ns/* despite Yama
    // ptrace_scope=1, but this only works when pasta runs as the same uid.
    // Since pasta is already running unprivileged (no capabilities),
    // staying as the current user has no security implications.
    let uid = nix::unistd::getuid();
    cmd.arg("--runas").arg(uid.to_string());

    // Auto-configure addresses, routes, and bring up the tap device.
    cmd.arg("--config-net");

    // Set MTU for optimal performance.
    cmd.arg("--mtu").arg("65520");

    // Disable host loopback access for security:
    // prevents the sandbox from reaching host services via gateway→loopback mapping.
    // Newer pasta versions use `--map-host-loopback none`, older use `--no-map-gw`.
    if pasta_supports_option("--map-host-loopback") {
        cmd.arg("--map-host-loopback").arg("none");
    } else {
        cmd.arg("--no-map-gw");
    }

    // Port forwarding setup.
    //
    // By default, pasta auto-forwards all bound ports. We override this:
    // - If explicit port rules are provided, pass only those (no `-t none`
    //   prefix — older pasta versions reject mixing `none` with specific ports).
    // - If no explicit ports are provided, disable all auto-forwarding
    //   with `-t none -u none -T none -U none`.
    let tcp_spec = build_port_spec(&config.ports, PortProtocol::Tcp);
    let udp_spec = build_port_spec(&config.ports, PortProtocol::Udp);

    if let Some(spec) = tcp_spec {
        cmd.arg("-t").arg(spec);
    } else {
        cmd.arg("-t").arg("none");
    }

    if let Some(spec) = udp_spec {
        cmd.arg("-u").arg(spec);
    } else {
        cmd.arg("-u").arg("none");
    }

    // Disable reverse (namespace → host) auto-forwarding.
    cmd.arg("-T").arg("none");
    cmd.arg("-U").arg("none");

    // Target: the child's network namespace via /proc/<pid>/ns/* paths.
    //
    // setns(CLONE_NEWNET) requires CAP_SYS_ADMIN in the user namespace that
    // owns the target network namespace. Because the child created both
    // namespaces atomically with unshare(CLONE_NEWUSER | CLONE_NEWNET), the
    // network namespace is owned by the child's user namespace. Pasta must
    // therefore first join the user namespace (--userns) to acquire the
    // necessary capability, then join the network namespace (--netns).
    //
    // The child calls prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) before
    // signaling the parent, which allows pasta (a sibling process) to
    // open /proc/<child>/ns/* despite Yama ptrace_scope=1.
    let userns_path = format!("/proc/{child_pid}/ns/user");
    let netns_path = format!("/proc/{child_pid}/ns/net");
    cmd.arg("--userns").arg(&userns_path);
    cmd.arg("--netns").arg(&netns_path);

    // Log the full command for debugging.
    tracing::debug!(
        cmd = ?cmd,
        "pasta command"
    );

    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| NetError::Pasta(format!("failed to spawn pasta: {e}")))?;

    // Give pasta a moment to set up the interface.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Check if pasta exited immediately (indicates a configuration error).
    match child.try_wait() {
        Ok(Some(status)) => {
            let mut stderr_output = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut stderr, &mut stderr_output);
            }
            let msg = format!(
                "pasta exited immediately with {status}. stderr: {}",
                stderr_output.trim()
            );
            tracing::error!("{}", msg);
            return Err(NetError::Pasta(msg));
        }
        Ok(None) => {
            tracing::debug!("pasta started successfully (still running)");
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not check pasta status");
        }
    }

    Ok(child)
}

/// Build a pasta port spec string from a list of port mappings.
///
/// Groups ports of the given protocol into a comma-separated spec.
/// Returns `None` if no ports match.
fn build_port_spec(ports: &[PortMapping], protocol: PortProtocol) -> Option<String> {
    let specs: Vec<String> = ports
        .iter()
        .filter(|p| p.protocol == protocol)
        .map(|p| {
            let port_part = if p.host_port == p.container_port {
                p.host_port.to_string()
            } else {
                format!("{}:{}", p.host_port, p.container_port)
            };
            match &p.host_ip {
                Some(ip) => format!("{ip}/{port_part}"),
                None => port_part,
            }
        })
        .collect();

    if specs.is_empty() {
        None
    } else {
        Some(specs.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_gateway_parses_proc_net_route() {
        // Just verify it doesn't panic. The actual result depends on the host.
        let _ = detect_default_gateway();
    }

    #[test]
    fn build_port_spec_empty() {
        assert_eq!(build_port_spec(&[], PortProtocol::Tcp), None);
    }

    #[test]
    fn build_port_spec_single_same_port() {
        let ports = vec![PortMapping {
            host_ip: None,
            host_port: 8080,
            container_port: 8080,
            protocol: PortProtocol::Tcp,
        }];
        assert_eq!(
            build_port_spec(&ports, PortProtocol::Tcp),
            Some("8080".to_string())
        );
    }

    #[test]
    fn build_port_spec_different_ports() {
        let ports = vec![PortMapping {
            host_ip: None,
            host_port: 8080,
            container_port: 80,
            protocol: PortProtocol::Tcp,
        }];
        assert_eq!(
            build_port_spec(&ports, PortProtocol::Tcp),
            Some("8080:80".to_string())
        );
    }

    #[test]
    fn build_port_spec_with_ip() {
        let ports = vec![PortMapping {
            host_ip: Some("127.0.0.1".parse().unwrap()),
            host_port: 8080,
            container_port: 80,
            protocol: PortProtocol::Tcp,
        }];
        assert_eq!(
            build_port_spec(&ports, PortProtocol::Tcp),
            Some("127.0.0.1/8080:80".to_string())
        );
    }

    #[test]
    fn build_port_spec_filters_by_protocol() {
        let ports = vec![
            PortMapping {
                host_ip: None,
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::Tcp,
            },
            PortMapping {
                host_ip: None,
                host_port: 5000,
                container_port: 5000,
                protocol: PortProtocol::Udp,
            },
        ];
        assert_eq!(
            build_port_spec(&ports, PortProtocol::Tcp),
            Some("8080:80".to_string())
        );
        assert_eq!(
            build_port_spec(&ports, PortProtocol::Udp),
            Some("5000".to_string())
        );
    }

    #[test]
    fn build_port_spec_multiple() {
        let ports = vec![
            PortMapping {
                host_ip: None,
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::Tcp,
            },
            PortMapping {
                host_ip: None,
                host_port: 8443,
                container_port: 443,
                protocol: PortProtocol::Tcp,
            },
        ];
        assert_eq!(
            build_port_spec(&ports, PortProtocol::Tcp),
            Some("8080:80,8443:443".to_string())
        );
    }
}
