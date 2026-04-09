use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod commands;
mod recipes;
mod registry;

#[derive(Parser)]
#[command(
    name = "can",
    about = "Canister: a lightweight sandbox for running untrusted code safely",
    version,
    propagate_version = true
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
        /// Recipe name or path. Can be repeated for composition.
        ///
        /// If the argument contains `/` or ends with `.toml`, it is treated
        /// as a file path. Otherwise it is looked up by name across the
        /// recipe search path (e.g., `-r nix` resolves to `nix.toml`).
        ///
        /// Multiple recipes are merged left-to-right.
        #[arg(short, long)]
        recipe: Vec<String>,

        /// Run in monitor mode: log access attempts without enforcing.
        #[arg(short, long)]
        monitor: bool,

        /// Strict mode: fail hard instead of degrading gracefully.
        /// Seccomp uses KILL_PROCESS, filesystem isolation failures are fatal.
        /// Intended for CI / production use.
        #[arg(short, long)]
        strict: bool,

        /// Allow degraded mode: permit sandbox to continue when isolation
        /// features are unavailable.
        ///
        /// By default, canister fails hard when isolation cannot be
        /// established (e.g., AppArmor blocks mount operations). This flag
        /// opts into reduced isolation instead of aborting.
        #[arg(long)]
        allow_degraded: bool,

        /// The command to execute.
        #[arg(required = true)]
        command: Vec<String>,
    },

    /// Check available kernel capabilities for sandboxing.
    Check,

    /// Install or manage the AppArmor profile for filesystem isolation.
    Setup {
        /// Remove the AppArmor profile instead of installing it.
        #[arg(long)]
        remove: bool,
    },

    /// List available recipes and the default baseline syscall counts.
    Recipes,

    /// Download community recipes to the local config directory.
    ///
    /// Clones the canister GitHub repository (shallow) and copies recipe
    /// .toml files into $XDG_CONFIG_HOME/canister/recipes/.
    /// Requires git. Prints manual instructions if git is unavailable.
    Init {
        /// GitHub repository (owner/repo) to fetch from.
        #[arg(long, default_value = None)]
        repo: Option<String>,

        /// Branch to fetch.
        #[arg(long, default_value = None)]
        branch: Option<String>,

        /// Skip SHA-256 checksum verification of recipe files.
        /// Required when using custom/forked repositories.
        #[arg(long)]
        no_verify: bool,
    },

    /// Update community recipes from the remote repository.
    ///
    /// Re-downloads and overwrites all recipes. Equivalent to `can init`.
    Update {
        /// GitHub repository (owner/repo) to fetch from.
        #[arg(long, default_value = None)]
        repo: Option<String>,

        /// Branch to fetch.
        #[arg(long, default_value = None)]
        branch: Option<String>,

        /// Skip SHA-256 checksum verification of recipe files.
        /// Required when using custom/forked repositories.
        #[arg(long)]
        no_verify: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize logging.
    // In monitor mode, use debug level for full visibility.
    let is_monitor = matches!(&cli.command, Commands::Run { monitor: true, .. });
    if is_monitor {
        can_log::init_monitor();
    } else if cli.verbose {
        can_log::init_verbose();
    } else {
        can_log::init();
    }

    let result = match cli.command {
        Commands::Run {
            recipe,
            monitor,
            strict,
            allow_degraded,
            command,
        } => commands::run(&recipe, monitor, strict, allow_degraded, command),
        Commands::Check => commands::check(),
        Commands::Setup { remove } => commands::setup(remove),
        Commands::Recipes => recipes::list(),
        Commands::Init {
            repo,
            branch,
            no_verify,
        } => registry::init(repo.as_deref(), branch.as_deref(), no_verify),
        Commands::Update {
            repo,
            branch,
            no_verify,
        } => registry::update(repo.as_deref(), branch.as_deref(), no_verify),
    };

    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
