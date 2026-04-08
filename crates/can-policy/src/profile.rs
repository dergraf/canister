use serde::Deserialize;

/// A seccomp profile defines which syscalls are allowed or denied for a given
/// workload type.
///
/// Supports two enforcement modes:
/// - **Allow-list** (default deny): only syscalls in `allow_syscalls` are
///   permitted. Everything else is blocked. This is the recommended mode
///   for production and CI.
/// - **Deny-list** (default allow): only syscalls in `deny_syscalls` are
///   blocked. Everything else is permitted. More permissive, useful for
///   compatibility when the workload's syscall set is unknown.
///
/// The mode is selected via `[profile] seccomp_mode` in the config.
#[derive(Debug, Clone, Deserialize)]
pub struct SeccompProfile {
    /// Human-readable name.
    pub name: String,

    /// Description of what this profile is designed for.
    pub description: String,

    /// Syscalls explicitly allowed (used in allow-list mode).
    #[serde(default)]
    pub allow_syscalls: Vec<String>,

    /// Syscalls explicitly blocked (used in deny-list mode).
    #[serde(default)]
    pub deny_syscalls: Vec<String>,
}

/// Syscalls that are dangerous in any context — kernel-level operations
/// that a sandboxed process should never need. These are always denied
/// regardless of mode and never appear in any allow list.
const DENY_ALWAYS: &[&str] = &[
    "reboot",
    "kexec_load",
    "init_module",
    "finit_module",
    "delete_module",
    "swapon",
    "swapoff",
    "acct",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "syslog",
    "settimeofday",
];

// ---------------------------------------------------------------------------
// Allow-list base sets
//
// These are the syscalls needed by virtually every userspace workload.
// Profile-specific syscalls are added on top of this base.
// ---------------------------------------------------------------------------

/// Syscalls needed by virtually any Linux process — libc init, memory
/// allocation, signal handling, file I/O, and thread primitives.
const ALLOW_BASE: &[&str] = &[
    // Process lifecycle
    "fork",
    "vfork",
    "clone",
    "clone3",
    "execve",
    "execveat",
    "kill",
    "tkill",
    "tgkill",
    "exit",
    "exit_group",
    "wait4",
    "waitid",
    // Process control (prctl only — ptrace, personality, seccomp per-profile)
    "prctl",
    // File I/O
    "open",
    "openat",
    "openat2",
    "creat",
    "close",
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "lseek",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    // File metadata
    "stat",
    "fstat",
    "lstat",
    "newfstatat",
    "access",
    "faccessat",
    "faccessat2",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    // Directory operations
    "mkdir",
    "mkdirat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "unlink",
    "unlinkat",
    "symlink",
    "symlinkat",
    "readlink",
    "readlinkat",
    "getdents",
    "getdents64",
    // Memory
    "mmap",
    "mprotect",
    "munmap",
    "mremap",
    "madvise",
    "brk",
    "mlock",
    "mlock2",
    "munlock",
    "mlockall",
    "munlockall",
    // Network
    "socket",
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "getsockopt",
    "setsockopt",
    "getsockname",
    "getpeername",
    "socketpair",
    // Signals
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    // Time
    "nanosleep",
    "clock_nanosleep",
    "clock_gettime",
    "clock_getres",
    "gettimeofday",
    // Polling / async I/O
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "eventfd",
    "eventfd2",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    // IPC
    "pipe",
    "pipe2",
    "shmget",
    "shmat",
    "shmctl",
    "shmdt",
    "semget",
    "semop",
    "semctl",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    // Process info
    "getpid",
    "getppid",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "gettid",
    "getpgid",
    "setpgid",
    "setsid",
    "getgroups",
    "setgroups",
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    // I/O control + legacy AIO
    "ioctl",
    "io_setup",
    "io_submit",
    "io_getevents",
    "io_destroy",
    // Misc / threading
    "futex",
    "set_tid_address",
    "set_robust_list",
    "get_robust_list",
    "sched_yield",
    "sched_getaffinity",
    "sched_setaffinity",
    "getcwd",
    "chdir",
    "fchdir",
    "umask",
    "uname",
    "sysinfo",
    "getrandom",
    "memfd_create",
    "copy_file_range",
    "sendfile",
    "splice",
    "tee",
    // Arch-specific
    "arch_prctl",
];

impl SeccompProfile {
    /// Load a built-in profile by name.
    ///
    /// Returns `None` if the profile name is unknown.
    pub fn builtin(name: &str) -> Option<Self> {
        match name {
            "generic" => Some(Self::generic()),
            "python" => Some(Self::python()),
            "node" => Some(Self::node()),
            "elixir" => Some(Self::elixir()),
            _ => None,
        }
    }

    /// List all built-in profile names.
    pub fn builtin_names() -> &'static [&'static str] {
        &["generic", "python", "node", "elixir"]
    }

    /// Generic profile — broadest built-in profile.
    ///
    /// Suitable for arbitrary compiled binaries (C, Rust, Go) where the
    /// syscall set is unknown. Allows ptrace (debuggers), personality
    /// (multilib), io_uring (modern async I/O), and seccomp (self-sandboxing).
    /// Only denies DENY_ALWAYS + namespace escapes (unshare/setns).
    fn generic() -> Self {
        let mut allow = allow_base();
        // Generic additionally allows these (other profiles restrict them).
        allow.extend_from_slice(&[
            "ptrace".to_string(),
            "personality".to_string(),
            "seccomp".to_string(),
            "io_uring_setup".to_string(),
            "io_uring_enter".to_string(),
            "io_uring_register".to_string(),
        ]);

        let mut deny = deny_always();
        deny.extend_from_slice(&["unshare".to_string(), "setns".to_string()]);

        Self {
            name: "generic".to_string(),
            description: "Generic profile for arbitrary binaries. Blocks dangerous kernel \
                          operations and namespace escapes. Allows ptrace, io_uring, \
                          personality, and self-sandboxing."
                .to_string(),
            allow_syscalls: allow,
            deny_syscalls: deny,
        }
    }

    /// Python profile — tighter than generic.
    ///
    /// Python scripts don't need ptrace, personality changes, io_uring, or
    /// self-sandboxing via seccomp. multiprocessing (clone/clone3) and
    /// subprocess (execve) are allowed via ALLOW_BASE.
    fn python() -> Self {
        let allow = allow_base();

        let mut deny = deny_always();
        deny.extend_from_slice(&[
            "unshare".to_string(),
            "setns".to_string(),
            "ptrace".to_string(),
            "personality".to_string(),
            "io_uring_setup".to_string(),
            "io_uring_enter".to_string(),
            "io_uring_register".to_string(),
            "seccomp".to_string(),
        ]);

        Self {
            name: "python".to_string(),
            description: "Profile for Python scripts. Blocks kernel ops, ptrace, io_uring, \
                          and namespace manipulation."
                .to_string(),
            allow_syscalls: allow,
            deny_syscalls: deny,
        }
    }

    /// Node.js profile — similar restrictions to Python.
    ///
    /// Node uses worker_threads (clone/clone3) and libuv's epoll-based
    /// event loop. Does not need ptrace, io_uring, personality, or seccomp.
    fn node() -> Self {
        let allow = allow_base();

        let mut deny = deny_always();
        deny.extend_from_slice(&[
            "unshare".to_string(),
            "setns".to_string(),
            "ptrace".to_string(),
            "personality".to_string(),
            "io_uring_setup".to_string(),
            "io_uring_enter".to_string(),
            "io_uring_register".to_string(),
            "seccomp".to_string(),
        ]);

        Self {
            name: "node".to_string(),
            description: "Profile for Node.js. Blocks kernel ops, ptrace, io_uring, \
                          and namespace manipulation. Preserves clone for worker threads."
                .to_string(),
            allow_syscalls: allow,
            deny_syscalls: deny,
        }
    }

    /// Elixir/Erlang profile — tailored for the BEAM VM.
    ///
    /// The BEAM runtime requires ptrace for `:observer`, `:dbg`, and
    /// `erlang:trace/3`. This profile allows ptrace but blocks personality,
    /// io_uring (BEAM uses epoll), and seccomp self-modification.
    ///
    /// Suitable for: `mix` tasks, `iex`, Phoenix applications, OTP releases.
    fn elixir() -> Self {
        let mut allow = allow_base();
        // BEAM needs ptrace for tracing/debugging tools.
        allow.push("ptrace".to_string());

        let mut deny = deny_always();
        deny.extend_from_slice(&[
            "unshare".to_string(),
            "setns".to_string(),
            "personality".to_string(),
            "io_uring_setup".to_string(),
            "io_uring_enter".to_string(),
            "io_uring_register".to_string(),
            "seccomp".to_string(),
        ]);

        Self {
            name: "elixir".to_string(),
            description: "Profile for Elixir/Erlang (BEAM VM). Blocks kernel ops, io_uring, \
                          and namespace manipulation. Preserves clone, ptrace, and epoll for \
                          BEAM schedulers and OTP tooling."
                .to_string(),
            allow_syscalls: allow,
            deny_syscalls: deny,
        }
    }
}

/// Build the base deny list from the always-denied set.
fn deny_always() -> Vec<String> {
    DENY_ALWAYS.iter().map(|s| (*s).to_string()).collect()
}

/// Build the base allow list shared by all profiles.
fn allow_base() -> Vec<String> {
    ALLOW_BASE.iter().map(|s| (*s).to_string()).collect()
}
