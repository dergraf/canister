use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(
    name = "can",
    about = "Canister: a lightweight sandbox for running untrusted code safely",
    version,
    propagate_version = true,
)]
struct Cli {
    /// Enable verbose (debug) logging.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command inside the sandbox.
    Run {
        /// Path to TOML config file.
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Seccomp profile name (overrides config).
        #[arg(short, long)]
        profile: Option<String>,

        /// Run in monitor mode: log access attempts without enforcing.
        #[arg(short, long)]
        monitor: bool,

        /// The command to execute.
        #[arg(required = true)]
        command: Vec<String>,
    },

    /// Check available kernel capabilities for sandboxing.
    Check,

    /// List available seccomp profiles.
    Profiles,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize logging.
    if cli.verbose {
        can_log::init_verbose();
    } else {
        can_log::init();
    }

    let result = match cli.command {
        Commands::Run {
            config,
            profile,
            monitor,
            command,
        } => commands::run(config, profile, monitor, command),
        Commands::Check => commands::check(),
        Commands::Profiles => commands::profiles(),
    };

    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
