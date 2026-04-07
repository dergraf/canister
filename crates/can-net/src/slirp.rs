//! slirp4netns integration for providing user-mode networking to the sandbox.
//!
//! [slirp4netns](https://github.com/rootless-containers/slirp4netns) provides
//! user-mode TCP/IP networking for unprivileged network namespaces. It creates
//! a TAP device inside the namespace and forwards traffic through the host's
//! network stack.
//!
//! Default slirp4netns network layout:
//! - Gateway/host: 10.0.2.2
//! - DNS: 10.0.2.3
//! - Sandbox IP: 10.0.2.100
//!
//! When the sandbox has whitelisted domains/IPs, we:
//! 1. Start slirp4netns to provide basic connectivity
//! 2. Override /etc/resolv.conf to point at our DNS proxy (127.0.0.1)
//! 3. Our DNS proxy filters queries and forwards allowed ones to 10.0.2.3

use std::path::Path;
use std::process::{Child, Command, Stdio};

use nix::unistd::Pid;

use crate::NetError;

/// Default slirp4netns DNS server address.
pub const SLIRP_DNS_ADDR: &str = "10.0.2.3";

/// Default slirp4netns gateway address.
pub const SLIRP_GATEWAY_ADDR: &str = "10.0.2.2";

/// Default IP assigned to the sandbox by slirp4netns.
pub const SLIRP_SANDBOX_ADDR: &str = "10.0.2.100";

/// Check whether slirp4netns is available on the system.
pub fn is_available() -> bool {
    which_slirp4netns().is_some()
}

/// Find the slirp4netns binary path.
fn which_slirp4netns() -> Option<std::path::PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join("slirp4netns");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Start slirp4netns for a sandboxed process.
///
/// `child_pid` is the PID of the process in the new network namespace.
/// slirp4netns will create a TAP device (`tap0`) inside that namespace.
///
/// Returns the slirp4netns child process handle.
pub fn start(child_pid: Pid) -> Result<Child, NetError> {
    start_inner(child_pid, None)
}

/// Start slirp4netns with DNS forwarded to a custom port on localhost.
///
/// DNS queries from the sandbox (to 10.0.2.3) will be forwarded to
/// `127.0.0.1:<dns_port>` on the host, where our filtering DNS proxy runs.
pub fn start_with_dns(child_pid: Pid, dns_port: u16) -> Result<Child, NetError> {
    start_inner(child_pid, Some(dns_port))
}

fn start_inner(child_pid: Pid, dns_port: Option<u16>) -> Result<Child, NetError> {
    let slirp_path = which_slirp4netns()
        .ok_or_else(|| NetError::Slirp("slirp4netns not found in PATH".to_string()))?;

    tracing::info!(
        pid = child_pid.as_raw(),
        dns_port = ?dns_port,
        "starting slirp4netns"
    );

    let mut cmd = Command::new(slirp_path);
    cmd.arg("--configure")
        .arg("--mtu=65520")
        .arg("--disable-host-loopback");

    // If we have a custom DNS port, tell slirp4netns to forward DNS there.
    if let Some(port) = dns_port {
        cmd.arg(format!("--dns=127.0.0.1:{port}"));
    }

    cmd.arg(child_pid.as_raw().to_string())
        .arg("tap0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let child = cmd
        .spawn()
        .map_err(|e| NetError::Slirp(format!("failed to spawn slirp4netns: {e}")))?;

    // Give slirp4netns a moment to set up the interface.
    std::thread::sleep(std::time::Duration::from_millis(200));

    tracing::debug!("slirp4netns started");
    Ok(child)
}
