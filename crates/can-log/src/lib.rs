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
