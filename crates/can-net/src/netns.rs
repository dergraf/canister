//! Network namespace creation and loopback setup.
//!
//! When the sandbox needs network isolation, the child process calls
//! `unshare(CLONE_NEWNET)` to get an empty network namespace. We then
//! bring up the loopback interface so `127.0.0.1` works (needed for
//! the DNS proxy).
//!
//! Note: CLONE_NEWNET is handled separately from CLONE_NEWUSER+CLONE_NEWNS
//! because:
//! 1. It can be added to the same `unshare()` call safely
//! 2. It only takes effect if network isolation is requested by policy

use std::io::Write;

use nix::sched::CloneFlags;

use crate::NetError;

/// The clone flag for network namespace isolation.
pub const NET_NS_FLAG: CloneFlags = CloneFlags::CLONE_NEWNET;

/// Bring up the loopback interface inside the current (new) network namespace.
///
/// After `unshare(CLONE_NEWNET)`, the namespace has only a `lo` interface
/// that is DOWN. We need it UP for the DNS proxy to bind to 127.0.0.1.
///
/// We do this via the old-school `/sys/class/net/lo/flags` approach or
/// a netlink socket. The sysfs approach is simpler and works without
/// additional dependencies.
pub fn bring_up_loopback() -> Result<(), NetError> {
    // Method 1: Use ioctl SIOCSIFFLAGS via nix.
    // This is the most reliable approach in a user namespace.
    bring_up_loopback_ioctl()
}

/// Bring up loopback using ioctl.
fn bring_up_loopback_ioctl() -> Result<(), NetError> {
    // Create a raw socket — this works even when loopback is down
    // because it doesn't require binding to an address.
    // AF_INET + SOCK_DGRAM is sufficient for SIOCGIFFLAGS/SIOCSIFFLAGS.
    let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock_fd < 0 {
        return Err(NetError::Loopback(std::io::Error::last_os_error()));
    }

    // Ensure we close the socket on all exit paths.
    struct SockGuard(i32);
    impl Drop for SockGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let _guard = SockGuard(sock_fd);

    // Build the ifreq structure for "lo".
    // struct ifreq { char ifr_name[IFNAMSIZ]; short ifr_flags; ... }
    // IFNAMSIZ = 16, IFF_UP = 0x1, IFF_RUNNING = 0x40
    let mut ifr = [0u8; 40]; // ifreq is typically 40 bytes
    ifr[..2].copy_from_slice(b"lo");

    const IFF_UP: i16 = 0x1;
    const IFF_RUNNING: i16 = 0x40;

    // First get current flags with SIOCGIFFLAGS.
    // SIOCGIFFLAGS = 0x8913
    let ret = unsafe { libc::ioctl(sock_fd, libc::SIOCGIFFLAGS as _, ifr.as_mut_ptr()) };
    if ret < 0 {
        return Err(NetError::Loopback(std::io::Error::last_os_error()));
    }

    // Set IFF_UP | IFF_RUNNING in the flags field (offset 16, 2 bytes, little-endian on x86).
    let flags_offset = 16;
    let current_flags = i16::from_ne_bytes([ifr[flags_offset], ifr[flags_offset + 1]]);
    let new_flags = current_flags | IFF_UP | IFF_RUNNING;
    ifr[flags_offset..flags_offset + 2].copy_from_slice(&new_flags.to_ne_bytes());

    // SIOCSIFFLAGS = 0x8914
    let ret = unsafe { libc::ioctl(sock_fd, libc::SIOCSIFFLAGS as _, ifr.as_mut_ptr()) };
    if ret < 0 {
        return Err(NetError::Loopback(std::io::Error::last_os_error()));
    }

    tracing::debug!("loopback interface brought up");
    Ok(())
}

/// Write the sandbox's resolv.conf to point at our DNS server.
///
/// When using slirp4netns, the sandbox gets its own /etc/resolv.conf
/// pointing to the DNS proxy address (typically 10.0.2.3).
///
/// After pivot_root, /etc/resolv.conf is a read-only bind mount from
/// the host. We unmount it first (safe — we're in our own mount
/// namespace), then write a fresh file on the underlying tmpfs.
pub fn write_resolv_conf(dns_addr: &str) -> Result<(), NetError> {
    let path = "/etc/resolv.conf";

    // Remove the read-only bind mount from the host.
    // MNT_DETACH handles the case where the file is in use.
    // Ignore errors — the mount may not exist (e.g., minimal namespace setup).
    let _ = nix::mount::umount2(path, nix::mount::MntFlags::MNT_DETACH);

    let content = format!("nameserver {dns_addr}\n");
    let mut f = std::fs::File::create(path).map_err(NetError::Io)?;
    f.write_all(content.as_bytes()).map_err(NetError::Io)?;
    tracing::debug!(dns = dns_addr, "wrote sandbox resolv.conf");
    Ok(())
}
