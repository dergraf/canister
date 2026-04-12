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

        /// Strict mode: fail hard on all setup failures.
        /// Seccomp uses KILL_PROCESS, filesystem isolation failures are fatal.
        /// Intended for CI / production use.
        #[arg(short, long)]
        strict: bool,

        /// Publish a container port to the host.
        ///
        /// Syntax: [ip:]hostPort:containerPort[/protocol]
        /// Examples: -p 8080:80, -p 127.0.0.1:8443:443/tcp, -p 5000:5000/udp
        /// Can be repeated. Implies filtered network mode.
        #[arg(short = 'p', long = "port")]
        ports: Vec<String>,

        /// The command to execute.
        #[arg(required = true)]
        command: Vec<String>,
    },

    /// Check available kernel capabilities for sandboxing.
    Check,

    /// Install or manage the security policy (AppArmor/SELinux) for filesystem isolation.
    Setup {
        /// Remove the security policy instead of installing it.
        #[arg(long)]
        remove: bool,

        /// Force reinstall even if the policy is already installed.
        /// Useful after upgrading canister to pick up policy changes.
        #[arg(long, short)]
        force: bool,
    },

    /// Manage and inspect recipes.
    Recipe {
        #[command(subcommand)]
        action: RecipeAction,
    },

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

#[derive(Subcommand)]
enum RecipeAction {
    /// List available recipes and the default baseline syscall counts.
    List,

    /// Show the fully resolved recipe as TOML.
    ///
    /// Merges base.toml, auto-detected recipes, and explicit --recipe
    /// arguments, expands environment variables, then prints the final
    /// effective policy. The output is valid TOML that can be saved as a
    /// standalone recipe file.
    Show {
        /// Recipe name or path. Can be repeated for composition.
        #[arg(short, long)]
        recipe: Vec<String>,

        /// Optional command to resolve (enables auto-detection of recipes).
        ///
        /// The command is NOT executed — it is only used to determine which
        /// recipes would be auto-detected based on `match_prefix`.
        command: Vec<String>,
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
            ports,
            command,
        } => commands::run(&recipe, monitor, strict, &ports, command),
        Commands::Check => commands::check(),
        Commands::Setup { remove, force } => commands::setup(remove, force),
        Commands::Recipe { action } => match action {
            RecipeAction::List => recipes::list(),
            RecipeAction::Show { recipe, command } => commands::show(&recipe, command),
        },
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
