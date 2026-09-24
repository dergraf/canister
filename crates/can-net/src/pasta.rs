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

/// Detect whether IPv6 is disabled on the host.
///
/// Checks the kernel sysctl `net.ipv6.conf.all.disable_ipv6`.
/// Returns `true` if IPv6 is explicitly disabled (value = "1").
/// Returns `false` if IPv6 is enabled, the sysctl doesn't exist
/// (very old kernels), or the file can't be read.
pub fn is_ipv6_disabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
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

/// Detect the host's real upstream DNS server address.
///
/// On systems running `systemd-resolved`, `/etc/resolv.conf` typically
/// points to the stub resolver at `127.0.0.53`, which is unreachable
/// from inside a network namespace (there's no systemd-resolved listening
/// in the sandbox). pasta's auto-detection also fails for the same reason.
///
/// This function tries:
/// 1. `/run/systemd/resolve/resolv.conf` — systemd-resolved's upstream file
/// 2. `/etc/resolv.conf` — filtered to exclude loopback addresses
///
/// Returns the first non-loopback nameserver found, or `None`.
pub fn detect_upstream_dns() -> Option<String> {
    // Try systemd-resolved's upstream resolv.conf first.
    if let Some(dns) = parse_resolv_conf_for_nameserver("/run/systemd/resolve/resolv.conf") {
        tracing::debug!(dns, "detected upstream DNS from systemd-resolved");
        return Some(dns);
    }

    // Fall back to /etc/resolv.conf, filtering out loopback.
    if let Some(dns) = parse_resolv_conf_for_nameserver("/etc/resolv.conf") {
        tracing::debug!(dns, "detected upstream DNS from /etc/resolv.conf");
        return Some(dns);
    }

    tracing::warn!("could not detect upstream DNS server");
    None
}

/// Parse a resolv.conf file and return the first non-loopback nameserver.
fn parse_resolv_conf_for_nameserver(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if let Some(addr_str) = line.strip_prefix("nameserver") {
            let addr_str = addr_str.trim();
            // Skip loopback addresses (127.x.x.x, ::1).
            if addr_str.starts_with("127.") || addr_str == "::1" {
                continue;
            }
            // Validate it's a real IP address.
            if addr_str.parse::<std::net::IpAddr>().is_ok() {
                return Some(addr_str.to_string());
            }
        }
    }
    None
}

/// Options for starting pasta.
pub struct PastaConfig {
    /// Port forwarding rules (empty = no port forwarding).
    pub ports: Vec<PortMapping>,

    /// Allow the sandbox to reach the host's loopback through the
    /// namespace's default gateway.
    ///
    /// When `false` (default) pasta is invoked with `--no-map-gw` /
    /// `--map-host-loopback none` so the sandbox cannot reach host
    /// services via gateway → host:127.0.0.1 mapping. When `true`,
    /// those flags are omitted and pasta defaults to mapping host
    /// loopback to the gateway IP, which the proxy can use to forward
    /// requests for `host.canister.local`.
    pub allow_host_loopback: bool,

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
/// Returns the pasta child process handle and the DNS address configured
/// inside the namespace (needed by the seccomp notifier and supervisor
/// to recognize DNS traffic and resolve domains).
pub fn start(config: &PastaConfig) -> Result<(Child, String), NetError> {
    let pasta_path =
        which_pasta().ok_or_else(|| NetError::Pasta("pasta not found in PATH".to_string()))?;

    let child_pid = config
        .child_pid
        .ok_or_else(|| NetError::Pasta("child_pid must be set in PastaConfig".to_string()))?;

    tracing::info!(child_pid, ports = config.ports.len(), "starting pasta");

    let spawned_path = pasta_path.clone();
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
    //
    // Pass UID:GID explicitly. When only UID is given, pasta tries to
    // auto-resolve the GID which fails in enterprise environments where
    // UID != GID (e.g., Active Directory/SSSD domain users).
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();
    cmd.arg("--runas").arg(format!("{}:{}", uid, gid));

    // Auto-configure addresses, routes, and bring up the tap device.
    cmd.arg("--config-net");

    // If the host has IPv6 disabled, tell pasta to skip IPv6 configuration.
    // Without this, pasta may fail or emit errors when it tries to configure
    // IPv6 addresses/routes on a kernel with net.ipv6.conf.all.disable_ipv6=1.
    // Common on corporate RHEL/CentOS VMs with restrictive network policies.
    //
    // Guard behind pasta_supports_option() because older pasta versions
    // (e.g., those shipped with RHEL8) don't recognize --ipv4-only and
    // would exit immediately with an unknown-option error.
    if is_ipv6_disabled() {
        if pasta_supports_option("--ipv4-only") {
            tracing::info!("IPv6 disabled on host, passing --ipv4-only to pasta");
            cmd.arg("--ipv4-only");
        } else {
            tracing::warn!(
                "IPv6 disabled on host but pasta does not support --ipv4-only; \
                 pasta may fail to configure networking"
            );
        }
    }

    // Set MTU for optimal performance.
    cmd.arg("--mtu").arg("65520");

    for arg in host_loopback_args(
        config.allow_host_loopback,
        pasta_supports_option("--no-map-gw"),
        pasta_supports_option("--map-host-loopback"),
    ) {
        cmd.arg(arg);
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

    // DNS setup: configure the namespace to use a reachable DNS resolver.
    //
    // The host's /etc/resolv.conf may point to a stub resolver like
    // systemd-resolved on 127.0.0.53, which is unreachable from inside
    // the pasta network namespace. We detect the real upstream DNS servers
    // and configure pasta accordingly.
    //
    // `--dns ADDR` tells pasta what nameserver address to write in the
    // namespace's resolv.conf.
    // `--dns-forward ADDR` tells pasta to intercept DNS queries sent to
    // ADDR and forward them to the host's real upstream resolver.
    let dns_addr = if let Some(dns) = detect_upstream_dns() {
        tracing::info!(dns = %dns, "using detected upstream DNS for pasta");
        // Tell pasta to write this DNS address in the namespace resolv.conf.
        // The sandbox's resolv.conf will point to this real upstream DNS
        // server, which is routable inside the pasta network namespace.
        cmd.arg("--dns").arg(&dns);
        dns
    } else {
        // Fallback: use the well-known pasta DNS forwarder address.
        // Pasta will intercept queries sent to this address and forward
        // them to whatever upstream it can auto-detect.
        let fallback = PASTA_DNS_ADDR.to_string();
        cmd.arg("--dns").arg(PASTA_DNS_ADDR);
        cmd.arg("--dns-forward").arg(PASTA_DNS_ADDR);
        fallback
    };

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
            let mut msg = format!(
                "pasta exited immediately with {status}. stderr: {}",
                stderr_output.trim()
            );
            if let Some(hint) = userns_denied_hint(
                &stderr_output,
                &spawned_path,
                apparmor_restricts_unprivileged_userns(),
            ) {
                msg.push_str(&hint);
            }
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

    Ok((child, dns_addr))
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

/// The in-netns address that refers to the host's loopback when
/// `[unsafe] host_loopback` is on.
///
/// Deliberately *not* the default gateway. pasta's own default maps the
/// gateway address to host loopback, and on an ordinary machine that one
/// address is also the DNS server and the next hop for every outbound
/// packet — so taking it over silently costs the sandbox its name
/// resolution and its route to the internet. A link-local address of our
/// own choosing carries no such second job.
pub const HOST_LOOPBACK_ADDR: std::net::Ipv4Addr = std::net::Ipv4Addr::new(169, 254, 1, 1);

/// The pasta flags that decide whether — and how — the sandbox can reach
/// services on the host's loopback.
///
/// Three pasta variants are in the wild:
///   1. Old: only `--no-map-gw`.
///   2. Transitional (e.g. Fedora 42 default): both flags appear in
///      `--help` but `--map-host-loopback` rejects `none` as an address
///      ("Invalid address to remap to host: none").
///   3. New: `--map-host-loopback none` works.
///
/// Off (the default), the mapping is disabled outright. On, the host's
/// loopback is mapped to [`HOST_LOOPBACK_ADDR`] and the gateway is left
/// alone — pasta's built-in default would take the gateway instead, and
/// that address is usually also the resolver and the default route.
///
/// A pasta too old for `--map-host-loopback` cannot separate the two, so
/// the caller is told that enabling host loopback there costs external
/// egress rather than finding out through a timeout.
fn host_loopback_args(allow: bool, supports_no_map_gw: bool, supports_map: bool) -> Vec<String> {
    match (allow, supports_no_map_gw, supports_map) {
        (false, true, _) => vec!["--no-map-gw".to_string()],
        (false, false, true) => vec!["--map-host-loopback".to_string(), "none".to_string()],
        (false, false, false) => Vec::new(),

        (true, _, true) => vec![
            "--no-map-gw".to_string(),
            "--map-host-loopback".to_string(),
            HOST_LOOPBACK_ADDR.to_string(),
        ],

        (true, _, false) => {
            tracing::warn!(
                "[unsafe] host_loopback is on but this pasta has no --map-host-loopback, so the \
                 gateway must be remapped to reach the host — DNS and outbound egress through \
                 that address will not work. Upgrade pasta to keep both."
            );
            Vec::new()
        }
    }
}

/// Whether the kernel makes unprivileged user namespaces subject to
/// AppArmor (Ubuntu 24.04+ sets this to `1`).
fn apparmor_restricts_unprivileged_userns() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

/// Turn AppArmor's refusal into the command that fixes it.
///
/// `can setup` writes `allow ux` rules for the pasta it finds on PATH at
/// install time. A pasta somewhere else — Nix, Homebrew, a local build —
/// is then unconfined under `apparmor_restrict_unprivileged_userns=1`,
/// and every run dies with a denial that names neither AppArmor nor the
/// binary it objects to.
fn userns_denied_hint(stderr: &str, pasta_path: &Path, restricted: bool) -> Option<String> {
    if !restricted {
        return None;
    }
    if !(stderr.contains("user namespace") && stderr.contains("Permission denied")) {
        return None;
    }
    Some(format!(
        "\n\nThis is AppArmor: kernel.apparmor_restrict_unprivileged_userns is 1 and the \
         installed profile does not cover {}. Run:\n\n    sudo can setup --force --pasta-path {}",
        pasta_path.display(),
        pasta_path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this guards: pasta's default maps the *gateway* to host
    /// loopback, and on an ordinary machine that address is also the DNS
    /// server and the default route. Enabling host loopback then costs
    /// the sandbox its name resolution and its egress — with no error,
    /// just a timeout.
    #[test]
    fn enabling_host_loopback_does_not_surrender_the_gateway() {
        let args = host_loopback_args(true, true, true);

        assert!(
            args.contains(&"--no-map-gw".to_string()),
            "the gateway must stay the gateway: {args:?}"
        );
        assert_eq!(
            args,
            vec![
                "--no-map-gw".to_string(),
                "--map-host-loopback".to_string(),
                "169.254.1.1".to_string()
            ]
        );
    }

    #[test]
    fn host_loopback_off_disables_the_mapping_however_pasta_spells_it() {
        assert_eq!(host_loopback_args(false, true, true), vec!["--no-map-gw"]);
        assert_eq!(
            host_loopback_args(false, false, true),
            vec!["--map-host-loopback", "none"]
        );
        assert!(host_loopback_args(false, false, false).is_empty());
    }

    #[test]
    fn an_old_pasta_cannot_have_both_and_says_so() {
        // Nothing is passed, so pasta's default mapping applies and the
        // sandbox reaches the host — at the cost of egress. Warned, not
        // silently chosen.
        assert!(host_loopback_args(true, true, false).is_empty());
    }

    #[test]
    fn the_host_loopback_address_is_not_a_plausible_gateway() {
        assert!(
            HOST_LOOPBACK_ADDR.is_link_local(),
            "a routable address could collide with real infrastructure"
        );
    }

    #[test]
    fn userns_denial_names_the_pasta_apparmor_objects_to() {
        let hint = userns_denied_hint(
            "Couldn't open user namespace /proc/71086/ns/user: Permission denied",
            Path::new("/home/u/.nix-profile/bin/pasta"),
            true,
        )
        .expect("a denial under a restricting kernel must explain itself");

        assert!(hint.contains("/home/u/.nix-profile/bin/pasta"));
        assert!(hint.contains("sudo can setup --force --pasta-path"));
    }

    #[test]
    fn an_unrelated_pasta_failure_gets_no_apparmor_hint() {
        assert!(
            userns_denied_hint(
                "Couldn't bind to port 53: Address already in use",
                Path::new("/usr/bin/pasta"),
                true,
            )
            .is_none()
        );
    }

    #[test]
    fn a_kernel_that_does_not_restrict_userns_gets_no_hint() {
        assert!(
            userns_denied_hint(
                "Couldn't open user namespace /proc/1/ns/user: Permission denied",
                Path::new("/usr/bin/pasta"),
                false,
            )
            .is_none()
        );
    }

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

    #[test]
    fn is_ipv6_disabled_returns_bool() {
        // Smoke test: just verify it doesn't panic and returns a bool.
        // The actual value depends on the host's sysctl configuration.
        let _result: bool = is_ipv6_disabled();
    }
}
