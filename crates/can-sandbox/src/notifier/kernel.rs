//! Kernel-version detection for `SECCOMP_RET_USER_NOTIF` support.

/// Check whether the running kernel supports `SECCOMP_RET_USER_NOTIF`.
///
/// Requires Linux 5.0 for the basic notification mechanism and Linux 5.9
/// for `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (needed to allow syscalls).
pub fn is_notifier_supported() -> bool {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return false;
    }

    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
    let release_str = release.to_string_lossy();

    parse_kernel_version(&release_str)
        .map(|(major, minor)| (major, minor) >= (5, 9))
        .unwrap_or(false)
}

/// Parse "major.minor.patch-extra" into (major, minor).
pub(super) fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}
