//! Filesystem isolation for the sandbox.
//!
//! Creates an ephemeral root filesystem using tmpfs and bind mounts.
//! The sandboxed process gets a minimal filesystem with only whitelisted
//! paths visible. All writes go to tmpfs and are discarded on exit.
//!
//! # Approach
//!
//! Rather than using overlayfs directly (which has complex permission
//! requirements even in user namespaces), we use a simpler and more
//! reliable approach:
//!
//! 1. Mount a tmpfs as the new root
//! 2. Create a minimal directory skeleton (`/bin`, `/lib`, `/usr`, `/tmp`, etc.)
//! 3. Bind-mount whitelisted host paths read-only into the new root
//! 4. Mount a fresh `/proc` (for PID namespace)
//! 5. `pivot_root` to swap to the new root
//! 6. Unmount the old root
//!
//! This gives us:
//! - **Ephemeral writes**: anything written to tmpfs vanishes on exit
//! - **Minimal surface**: only whitelisted paths are visible
//! - **No root required**: works in unprivileged user namespaces

use std::path::{Path, PathBuf};

use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::pivot_root;

use can_policy::config::FilesystemConfig;

/// Errors from filesystem setup.
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    #[error("mount failed for {path}: {source}")]
    Mount { path: String, source: nix::Error },

    #[error("mkdir failed for {path}: {source}")]
    Mkdir {
        path: String,
        source: std::io::Error,
    },

    #[error("pivot_root failed: {0}")]
    PivotRoot(nix::Error),

    #[error("chdir failed: {0}")]
    Chdir(nix::Error),

    #[error("umount failed for {path}: {source}")]
    Umount { path: String, source: nix::Error },
}

/// Standard directories to create in the sandbox root.
/// These provide a minimal Linux filesystem skeleton.
const SKELETON_DIRS: &[&str] = &[
    "bin",
    "dev",
    "etc",
    "lib",
    "lib64",
    "proc",
    "run",
    "sbin",
    "sys",
    "tmp",
    "usr",
    "usr/bin",
    "usr/lib",
    "usr/lib64",
    "usr/sbin",
    "usr/share",
    "var",
    "var/tmp",
];

/// Attempt filesystem isolation, falling back gracefully if mounts are blocked.
///
/// All filesystem paths (essential OS mounts, auto-detected package manager
/// prefixes, and user-specified paths) are expected to be already merged
/// into `config.allow` via recipe composition.
///
/// Returns `true` if full isolation was applied, `false` if running in degraded mode.
pub fn try_setup_filesystem(config: &FilesystemConfig) -> Result<bool, OverlayError> {
    match setup_filesystem(config) {
        Ok(()) => Ok(true),
        Err(OverlayError::Mount { ref path, source }) if is_permission_error(source) => {
            tracing::error!(
                path,
                "mount operation blocked by AppArmor. \
                 Filesystem isolation is DISABLED — the sandboxed process has full host filesystem access. \
                 Run `sudo can setup` to install the AppArmor profile and enable isolation."
            );
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Check if a nix error is a permission error (EACCES or EPERM).
fn is_permission_error(err: nix::Error) -> bool {
    matches!(err, nix::Error::EACCES | nix::Error::EPERM)
}

/// Set up the sandbox filesystem with full isolation.
///
/// This must be called from within the child process, after namespaces
/// have been created and UID/GID maps written.
///
/// Creates a tmpfs root, bind-mounts whitelisted paths (which now include
/// essential OS paths from base.toml), mounts /proc, and does pivot_root.
///
/// Returns `Err` if mount operations are blocked (e.g., by AppArmor).
pub fn setup_filesystem(config: &FilesystemConfig) -> Result<(), OverlayError> {
    let sandbox_root = PathBuf::from("/tmp/canister-root");

    // 0. Break mount propagation. First make slave (allowed from shared),
    //    then make private. This prevents mounts from propagating back to
    //    the host and is required for mount operations in a user namespace.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_SLAVE,
        None::<&str>,
    )
    .map_err(|source| OverlayError::Mount {
        path: "/ (make slave)".to_string(),
        source,
    })?;

    // 1. Create the sandbox root directory.
    mkdir_p(&sandbox_root)?;

    // 2. Mount a tmpfs as the sandbox root.
    mount_tmpfs(&sandbox_root)?;

    // 3. Create the directory skeleton.
    create_skeleton(&sandbox_root)?;

    // 4. Bind-mount all whitelisted paths (read-only).
    //    This includes essential OS paths (from base.toml), auto-detected
    //    package manager paths, and user-specified paths — all merged into
    //    config.allow via recipe composition.
    bind_mount_whitelist(&sandbox_root, config)?;

    // 5. Create a writable /tmp inside the sandbox.
    let sandbox_tmp = sandbox_root.join("tmp");
    mount_tmpfs(&sandbox_tmp)?;

    // 6. Mount a fresh /proc for PID namespace.
    mount_proc(&sandbox_root)?;

    // 7. Create minimal /dev entries.
    setup_minimal_dev(&sandbox_root)?;

    // 8. Pivot root: make sandbox_root the new /.
    do_pivot_root(&sandbox_root)?;

    tracing::debug!("filesystem isolation complete");
    Ok(())
}

/// Mount a tmpfs at the given path.
fn mount_tmpfs(target: &Path) -> Result<(), OverlayError> {
    tracing::debug!(target = %target.display(), "mounting tmpfs");
    mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=256m,mode=0755"),
    )
    .map_err(|source| OverlayError::Mount {
        path: target.display().to_string(),
        source,
    })
}

/// Create the minimal directory skeleton in the sandbox root.
fn create_skeleton(root: &Path) -> Result<(), OverlayError> {
    for dir in SKELETON_DIRS {
        mkdir_p(&root.join(dir))?;
    }
    Ok(())
}

/// Bind-mount whitelisted paths into the sandbox.
///
/// This handles all paths in `config.allow`, which includes:
/// - Essential OS paths (from base.toml)
/// - Auto-detected package manager paths (from matched recipes)
/// - User-specified paths (from explicit recipe arguments)
///
/// All are merged into a single list via recipe composition.
fn bind_mount_whitelist(root: &Path, config: &FilesystemConfig) -> Result<(), OverlayError> {
    for source in &config.allow {
        if !source.exists() {
            tracing::warn!(path = %source.display(), "whitelist path not found, skipping");
            continue;
        }

        // Check if this path is denied.
        let denied = config.deny.iter().any(|d| source.starts_with(d));
        if denied {
            tracing::warn!(path = %source.display(), "whitelist path is also in deny list, skipping");
            continue;
        }

        let rel = source.strip_prefix("/").unwrap_or(source);
        let target = root.join(rel);

        if let Some(parent) = target.parent() {
            mkdir_p(parent)?;
        }

        if source.is_dir() {
            mkdir_p(&target)?;
        } else {
            touch(&target)?;
        }

        bind_mount_ro(source, &target)?;
        tracing::debug!(source = %source.display(), target = %target.display(), "whitelisted path mounted");
    }
    Ok(())
}

/// Mount /proc inside the sandbox for the new PID namespace.
///
/// After mounting, masks sensitive /proc paths following the Docker
/// approach to prevent information leaks:
/// - Bind-mount /dev/null over files like /proc/kcore, /proc/keys
/// - Mount tmpfs over directories like /proc/acpi, /proc/scsi
/// - Remount /proc/sys read-only
fn mount_proc(root: &Path) -> Result<(), OverlayError> {
    let proc_path = root.join("proc");
    mkdir_p(&proc_path)?;

    tracing::debug!("mounting /proc in sandbox");
    mount(
        Some("proc"),
        &proc_path,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|source| OverlayError::Mount {
        path: proc_path.display().to_string(),
        source,
    })?;

    // Mask sensitive /proc files by bind-mounting /dev/null over them.
    // These paths can leak host kernel state even from inside a PID namespace.
    let masked_files = &[
        "kcore",         // physical memory — trivially exploitable
        "keys",          // kernel keyring (encryption keys)
        "sysrq-trigger", // can force kernel crash, reboot, etc.
        "timer_list",    // high-res timer info, side-channel risk
        "latency_stats", // scheduler internals
    ];
    let dev_null = root.join("dev/null");
    for entry in masked_files {
        let target = proc_path.join(entry);
        if target.exists() {
            match mount(
                Some(&dev_null),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            ) {
                Ok(()) => tracing::debug!(path = %target.display(), "masked /proc entry"),
                Err(e) => {
                    tracing::debug!(path = %target.display(), error = %e, "could not mask /proc entry (non-fatal)");
                }
            }
        }
    }

    // Mask sensitive /proc directories by mounting empty tmpfs over them.
    let masked_dirs = &[
        "acpi", // ACPI tables — host hardware info
        "scsi", // SCSI device info — host hardware
    ];
    for entry in masked_dirs {
        let target = proc_path.join(entry);
        if target.is_dir() {
            match mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
                Some("size=0"),
            ) {
                Ok(()) => tracing::debug!(path = %target.display(), "masked /proc directory"),
                Err(e) => {
                    tracing::debug!(path = %target.display(), error = %e, "could not mask /proc dir (non-fatal)");
                }
            }
        }
    }

    // Remount /proc/sys as read-only to prevent sysctl writes.
    let proc_sys = proc_path.join("sys");
    if proc_sys.is_dir() {
        // First bind-mount onto itself, then remount read-only.
        let _ = mount(
            Some(&proc_sys),
            &proc_sys,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        );
        let _ = mount(
            None::<&str>,
            &proc_sys,
            None::<&str>,
            MsFlags::MS_BIND
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_RDONLY
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV
                | MsFlags::MS_NOEXEC,
            None::<&str>,
        );
        tracing::debug!("/proc/sys remounted read-only");
    }

    Ok(())
}

/// Create minimal /dev with null, zero, urandom, etc.
///
/// In a user namespace, we can't mknod, so we bind-mount from the host.
fn setup_minimal_dev(root: &Path) -> Result<(), OverlayError> {
    let dev_dir = root.join("dev");
    mkdir_p(&dev_dir)?;

    // Mount a tmpfs for /dev.
    mount(
        Some("tmpfs"),
        &dev_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("size=1m,mode=0755"),
    )
    .map_err(|source| OverlayError::Mount {
        path: dev_dir.display().to_string(),
        source,
    })?;

    // Bind-mount essential device nodes from host.
    let devices = &["null", "zero", "urandom", "random", "tty"];
    for dev in devices {
        let host_dev = Path::new("/dev").join(dev);
        let sandbox_dev = dev_dir.join(dev);

        if host_dev.exists() {
            touch(&sandbox_dev)?;
            bind_mount_ro(&host_dev, &sandbox_dev)?;
        }
    }

    // Create /dev/stdin, /dev/stdout, /dev/stderr as symlinks.
    let _ = std::os::unix::fs::symlink("/proc/self/fd/0", dev_dir.join("stdin"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/1", dev_dir.join("stdout"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/2", dev_dir.join("stderr"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd", dev_dir.join("fd"));

    // Create /dev/shm.
    let shm_dir = dev_dir.join("shm");
    mkdir_p(&shm_dir)?;
    mount(
        Some("tmpfs"),
        &shm_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=64m"),
    )
    .map_err(|source| OverlayError::Mount {
        path: shm_dir.display().to_string(),
        source,
    })?;

    Ok(())
}

/// Pivot the root filesystem to the sandbox root.
///
/// After this, the old root is no longer accessible.
fn do_pivot_root(new_root: &Path) -> Result<(), OverlayError> {
    // Create a directory for the old root inside new_root.
    let old_root_dir = new_root.join("oldroot");
    mkdir_p(&old_root_dir)?;

    tracing::debug!(
        new_root = %new_root.display(),
        "pivoting root"
    );

    // pivot_root requires that new_root is a mount point.
    // Our tmpfs mount satisfies this.
    pivot_root(new_root, &old_root_dir).map_err(OverlayError::PivotRoot)?;

    // Change directory to the new root.
    nix::unistd::chdir("/").map_err(OverlayError::Chdir)?;

    // Unmount the old root (lazily, in case something still references it).
    umount2("/oldroot", MntFlags::MNT_DETACH).map_err(|source| OverlayError::Umount {
        path: "/oldroot".to_string(),
        source,
    })?;

    // Remove the old root mount point.
    let _ = std::fs::remove_dir("/oldroot");

    Ok(())
}

/// Create a read-only bind mount.
///
/// In user namespaces, remounting a bind mount as read-only requires
/// preserving all existing restrictive flags from the source mount.
/// The kernel rejects remounts that would drop flags set on the source.
/// We read the source mount flags via /proc/self/mountinfo and include
/// them in the remount call.
fn bind_mount_ro(source: &Path, target: &Path) -> Result<(), OverlayError> {
    // First bind mount (needs MS_BIND).
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|source_err| OverlayError::Mount {
        path: format!("{} -> {}", source.display(), target.display()),
        source: source_err,
    })?;

    // Read the mount flags from the now-mounted target and preserve them
    // when remounting as read-only.
    let source_flags = read_mount_flags(target);

    mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | source_flags,
        None::<&str>,
    )
    .map_err(|source_err| OverlayError::Mount {
        path: format!("{} (remount ro)", target.display()),
        source: source_err,
    })?;

    Ok(())
}

/// Read mount flags for a given path from /proc/self/mountinfo.
///
/// Returns the restrictive flags (nosuid, nodev, noexec, relatime, etc.)
/// that must be preserved when remounting in a user namespace.
fn read_mount_flags(path: &Path) -> MsFlags {
    // Default flags to include if we can't read mountinfo.
    let default_flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME;

    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return default_flags;
    };

    // Canonicalize the target path for matching.
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let target_str = canonical.to_string_lossy();

    // Find the mount entry for this path (best = longest matching mount point).
    let mut best_flags = default_flags;
    let mut best_len = 0;

    for line in mountinfo.lines() {
        // mountinfo format:
        // id parent_id major:minor root mount_point options ... - fstype source super_options
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let mount_point = fields[4];
        let options = fields[5];

        // Check if this mount point is a prefix of our target.
        if target_str.starts_with(mount_point) && mount_point.len() > best_len {
            best_len = mount_point.len();
            best_flags = parse_mount_options(options);
        }
    }

    best_flags
}

/// Parse mount options string into MsFlags.
fn parse_mount_options(options: &str) -> MsFlags {
    let mut flags = MsFlags::empty();
    for opt in options.split(',') {
        match opt {
            "nosuid" => flags |= MsFlags::MS_NOSUID,
            "nodev" => flags |= MsFlags::MS_NODEV,
            "noexec" => flags |= MsFlags::MS_NOEXEC,
            "relatime" => flags |= MsFlags::MS_RELATIME,
            "noatime" => flags |= MsFlags::MS_NOATIME,
            "nodiratime" => flags |= MsFlags::MS_NODIRATIME,
            "ro" => flags |= MsFlags::MS_RDONLY,
            _ => {} // ignore other options
        }
    }
    flags
}

/// Create directory and all parents (like `mkdir -p`).
fn mkdir_p(path: &Path) -> Result<(), OverlayError> {
    std::fs::create_dir_all(path).map_err(|source| OverlayError::Mkdir {
        path: path.display().to_string(),
        source,
    })
}

/// Create an empty file (touch).
fn touch(path: &Path) -> Result<(), OverlayError> {
    if let Some(parent) = path.parent() {
        mkdir_p(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|source| OverlayError::Mkdir {
            path: path.display().to_string(),
            source,
        })?;
    Ok(())
}
