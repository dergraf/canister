use serde::Deserialize;

/// A seccomp profile defines which syscalls are blocked for a given workload type.
///
/// Uses a deny-list model: everything is allowed except explicitly denied
/// syscalls. This keeps profiles simple and avoids breaking workloads that
/// depend on obscure syscalls.
#[derive(Debug, Clone, Deserialize)]
pub struct SeccompProfile {
    /// Human-readable name.
    pub name: String,

    /// Description of what this profile is designed for.
    pub description: String,

    /// Syscalls explicitly allowed (reserved for future allow-list mode).
    #[serde(default)]
    pub allow_syscalls: Vec<String>,

    /// Syscalls explicitly blocked.
    #[serde(default)]
    pub deny_syscalls: Vec<String>,
}

/// Syscalls that are dangerous in any context — kernel-level operations
/// that a sandboxed process should never need.
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

    /// Generic profile — blocks dangerous kernel-level operations.
    ///
    /// Permissive by design: suitable for arbitrary binaries where you
    /// don't know what syscalls they need. Blocks things that no
    /// sandboxed process should ever do.
    fn generic() -> Self {
        let mut deny = deny_always();

        // Also block namespace/container escape vectors.
        deny.extend_from_slice(&["unshare".to_string(), "setns".to_string()]);

        Self {
            name: "generic".to_string(),
            description: "Generic profile for arbitrary binaries. Blocks dangerous kernel \
                          operations and namespace escapes."
                .to_string(),
            allow_syscalls: Vec::new(),
            deny_syscalls: deny,
        }
    }

    /// Python profile — tighter than generic.
    ///
    /// Python scripts typically don't need ptrace, personality changes,
    /// or raw io_uring. This blocks those in addition to the generic set.
    fn python() -> Self {
        let mut deny = deny_always();
        deny.extend_from_slice(&[
            // Namespace escape
            "unshare".to_string(),
            "setns".to_string(),
            // Debugging / introspection
            "ptrace".to_string(),
            "personality".to_string(),
            // io_uring (complex attack surface, Python doesn't use it)
            "io_uring_setup".to_string(),
            "io_uring_enter".to_string(),
            "io_uring_register".to_string(),
            // Kernel crypto / keyring (not needed)
            "seccomp".to_string(),
        ]);

        Self {
            name: "python".to_string(),
            description: "Profile for Python scripts. Blocks kernel ops, ptrace, io_uring, \
                          and namespace manipulation."
                .to_string(),
            allow_syscalls: Vec::new(),
            deny_syscalls: deny,
        }
    }

    /// Node.js profile — similar to Python but preserves clone for workers.
    ///
    /// Node.js uses worker_threads which need clone/clone3. This profile
    /// blocks the same set as Python.
    fn node() -> Self {
        let mut deny = deny_always();
        deny.extend_from_slice(&[
            // Namespace escape
            "unshare".to_string(),
            "setns".to_string(),
            // Debugging
            "ptrace".to_string(),
            "personality".to_string(),
            // io_uring
            "io_uring_setup".to_string(),
            "io_uring_enter".to_string(),
            "io_uring_register".to_string(),
            // Prevent loading new seccomp filters from inside sandbox
            "seccomp".to_string(),
        ]);

        Self {
            name: "node".to_string(),
            description: "Profile for Node.js scripts. Blocks kernel ops, ptrace, io_uring, \
                          and namespace manipulation. Preserves clone for worker threads."
                .to_string(),
            allow_syscalls: Vec::new(),
            deny_syscalls: deny,
        }
    }

    /// Elixir/Erlang profile — tailored for the BEAM VM.
    ///
    /// The BEAM runtime requires:
    /// - `clone`/`clone3` for scheduler threads, dirty schedulers, and async threads
    /// - `epoll_*`, `eventfd2`, `timerfd_*` for I/O polling (all allowed by default)
    /// - `sched_getaffinity`/`sched_setaffinity` for scheduler CPU binding
    /// - `sendfile`/`splice` for Cowboy/Bandit file serving
    /// - `memfd_create` for JIT code loading (OTP 24+)
    /// - `pipe2` for port drivers (e.g., os:cmd/1, System.cmd/3)
    /// - `mmap`/`mprotect` for the JIT compiler
    ///
    /// This profile blocks the same dangerous set as python/node. It does NOT
    /// block ptrace because BEAM uses it internally for some debugging/tracing
    /// features (`:observer`, `:dbg`), but it does block `personality` and
    /// `io_uring` which the BEAM does not use.
    ///
    /// Suitable for: `mix` tasks, `iex` shells, Phoenix applications,
    /// `mix phx.server`, releases, and OTP applications in general.
    fn elixir() -> Self {
        let mut deny = deny_always();
        deny.extend_from_slice(&[
            // Namespace escape
            "unshare".to_string(),
            "setns".to_string(),
            // Personality changes (BEAM doesn't need this)
            "personality".to_string(),
            // io_uring (BEAM uses epoll, not io_uring)
            "io_uring_setup".to_string(),
            "io_uring_enter".to_string(),
            "io_uring_register".to_string(),
            // Prevent loading new seccomp filters from inside sandbox
            "seccomp".to_string(),
        ]);

        Self {
            name: "elixir".to_string(),
            description: "Profile for Elixir/Erlang (BEAM VM). Blocks kernel ops, io_uring, \
                          and namespace manipulation. Preserves clone, ptrace, and epoll for \
                          BEAM schedulers and OTP tooling."
                .to_string(),
            allow_syscalls: Vec::new(),
            deny_syscalls: deny,
        }
    }
}

/// Build the base deny list from the always-denied set.
fn deny_always() -> Vec<String> {
    DENY_ALWAYS.iter().map(|s| (*s).to_string()).collect()
}
