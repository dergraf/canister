use std::io::IsTerminal;

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the logging subsystem.
///
/// Detects whether stdout is a TTY:
/// - TTY: human-readable, colored output
/// - Pipe: JSON lines
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let is_tty = std::io::stdout().is_terminal();

    if is_tty {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(false).with_level(true))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_target(true))
            .init();
    }
}

/// Initialize logging in verbose mode (debug level).
pub fn init_verbose() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    let is_tty = std::io::stdout().is_terminal();

    if is_tty {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true).with_level(true))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_target(true))
            .init();
    }
}

/// Initialize logging for monitor mode.
///
/// Forces at least `debug` level so all monitor observations are visible.
/// Monitor-mode log lines use `MONITOR:` prefix in their messages for
/// easy filtering.
pub fn init_monitor() {
    // Allow RUST_LOG override, but default to debug for full visibility.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    let is_tty = std::io::stdout().is_terminal();

    if is_tty {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_level(true)
                    .with_thread_ids(false),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_target(true))
            .init();
    }
}

/// A record of a policy enforcement point that was relaxed in monitor mode.
///
/// Collected during sandbox setup and printed as a summary after the
/// sandboxed process exits, along with a suggested policy.
#[derive(Debug, Clone)]
pub struct MonitorEvent {
    /// Which enforcement category this belongs to.
    pub category: MonitorCategory,
    /// Human-readable description of what would have happened.
    pub description: String,
    /// The value that was observed (e.g., the env var name, syscall name).
    pub observed_value: Option<String>,
}

/// Categories of policy enforcement observed in monitor mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorCategory {
    /// Command blocked by `allow_execve`.
    ExecBlocked,
    /// Environment variable that would be stripped.
    EnvStripped,
    /// `RLIMIT_NPROC` that would be enforced.
    MaxPids,
    /// Seccomp syscall that would be denied.
    SeccompDenied,
}

impl std::fmt::Display for MonitorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitorCategory::ExecBlocked => write!(f, "allow_execve"),
            MonitorCategory::EnvStripped => write!(f, "env_passthrough"),
            MonitorCategory::MaxPids => write!(f, "max_pids"),
            MonitorCategory::SeccompDenied => write!(f, "seccomp"),
        }
    }
}

/// Print a monitor mode summary to stderr.
///
/// Shows what policy enforcement actions would have been taken and
/// suggests a TOML policy config based on observations.
pub fn print_monitor_summary(events: &[MonitorEvent]) {
    if events.is_empty() {
        eprintln!("\n--- Monitor Summary ---");
        eprintln!(
            "No policy violations detected. The current config allows everything this process did."
        );
        eprintln!("--- End Monitor Summary ---");
        return;
    }

    eprintln!("\n--- Monitor Summary ---");
    eprintln!(
        "Detected {} policy enforcement points that would affect this process:\n",
        events.len()
    );

    for event in events {
        let value = event.observed_value.as_deref().unwrap_or("");
        if value.is_empty() {
            eprintln!(
                "  [{category}] {desc}",
                category = event.category,
                desc = event.description
            );
        } else {
            eprintln!(
                "  [{category}] {desc}: {value}",
                category = event.category,
                desc = event.description,
            );
        }
    }

    // Suggest env_passthrough additions.
    let env_vars: Vec<&str> = events
        .iter()
        .filter(|e| e.category == MonitorCategory::EnvStripped)
        .filter_map(|e| e.observed_value.as_deref())
        .collect();

    if !env_vars.is_empty() {
        eprintln!("\nSuggested env_passthrough additions:");
        eprintln!("  [process]");
        eprintln!("  env_passthrough = {:?}", env_vars);
    }

    eprintln!("--- End Monitor Summary ---");
}
