use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod canaries;
mod commands;
mod events;
mod keys;
mod policy_event;
mod recipes;
mod registry;
mod tripwire;

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
    /// Run a named sandbox from canister.toml.
    ///
    /// Discovers canister.toml by walking up from the current directory,
    /// resolves the named sandbox (or the first-defined one), composes
    /// its recipes, and runs the command.
    Up {
        /// Sandbox name to run (defaults to the first defined in canister.toml).
        name: Option<String>,

        /// Extra recipe to merge on top of the sandbox definition.
        ///
        /// Repeatable, merged after the manifest so it wins. For policy a
        /// caller generates per run — routing a declared host to a local
        /// mock, say. Like any recipe that is not pinned by checksum, it
        /// cannot grant credential scope; that belongs in canister.toml.
        #[arg(long = "recipe", value_name = "PATH")]
        recipes: Vec<String>,

        /// Preview the resolved policy without running the sandbox.
        #[arg(long)]
        dry_run: bool,

        /// Run in monitor mode: log access attempts without enforcing.
        #[arg(short, long)]
        monitor: bool,

        /// Override strict mode from the CLI.
        #[arg(short, long)]
        strict: bool,

        /// Publish a container port to the host.
        ///
        /// Syntax: [ip:]hostPort:containerPort[/protocol]
        /// Can be repeated. Implies filtered network mode.
        #[arg(short = 'p', long = "port")]
        ports: Vec<String>,

        /// JSON file of externally supplied, tagged canaries to watch for
        /// on egress (ADR-0012). Same shape as
        /// `[[network.dlp.external_canaries]]`.
        #[arg(long, value_name = "PATH")]
        canaries_file: Option<std::path::PathBuf>,

        #[command(flatten)]
        events: events::EventFlags,
    },

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

        /// JSON file of externally supplied, tagged canaries to watch for
        /// on egress (ADR-0012). Same shape as
        /// `[[network.dlp.external_canaries]]`.
        #[arg(long, value_name = "PATH")]
        canaries_file: Option<std::path::PathBuf>,

        #[command(flatten)]
        events: events::EventFlags,

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

        /// Explicit path to the pasta binary for non-standard installations.
        ///
        /// When pasta is installed via Nix, Homebrew, or custom builds, sudo
        /// may not find it in PATH. Use this to generate correct AppArmor rules:
        ///   sudo can setup --pasta-path $(which pasta)
        #[arg(long)]
        pasta_path: Option<String>,
    },

    /// Generate an Ed25519 key for --events-sign-key (ADR-0021).
    ///
    /// Writes a fresh 32-byte seed to PATH as 64 hex characters, with
    /// mode 0600, and prints its public key — the value a consumer adds
    /// to its trusted keys. The seed is never printed: stdout ends up in
    /// terminal scrollback and CI logs, the places a key must not reach.
    Keygen {
        /// File to write the seed to.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,

        /// Replace an existing file. Seals signed with the old key will
        /// no longer match the new public key.
        #[arg(long)]
        force: bool,
    },

    /// Print the public key of an --events-sign-key seed file.
    ///
    /// Prints 64 lowercase hex characters, exactly as a `stream_seal`
    /// event carries it in `public_key`. Accepts the same files as
    /// --events-sign-key: 32 raw bytes or 64 hex characters.
    Pubkey {
        /// Seed file (from `can keygen` or `openssl rand -hex 32`).
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,
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

    /// Explain what a recipe does in human-readable form.
    ///
    /// Shows the recipe's declared paths (read-only, writable, denied),
    /// which paths actually exist on the host, allowed domains, and
    /// environment variables. Useful for debugging "why can't my tool
    /// find its config?".
    Explain {
        /// Recipe name or path. Can be repeated.
        #[arg(short, long, required = true)]
        recipe: Vec<String>,
    },

    /// Suggest recipes for a command.
    ///
    /// Resolves the command binary and recommends recipes based on
    /// binary name matching and `match_prefix` patterns. Output is a
    /// ready-to-paste `recipes = [...]` line.
    Suggest {
        /// The command to look up (not executed).
        #[arg(required = true)]
        command: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize logging.
    // In monitor mode, use debug level for full visibility.
    let is_monitor = matches!(
        &cli.command,
        Commands::Run { monitor: true, .. } | Commands::Up { monitor: true, .. }
    );
    if is_monitor {
        can_log::init_monitor();
    } else if cli.verbose {
        can_log::init_verbose();
    } else {
        can_log::init();
    }

    let result = match cli.command {
        Commands::Up {
            name,
            recipes,
            dry_run,
            monitor,
            strict,
            ports,
            canaries_file,
            events,
        } => commands::up(commands::UpArgs {
            name: name.as_deref(),
            dry_run,
            monitor,
            strict,
            ports: &ports,
            canaries_file: canaries_file.as_deref(),
            recipes: &recipes,
            events: &events,
        }),
        Commands::Run {
            recipe,
            monitor,
            strict,
            ports,
            canaries_file,
            events,
            command,
        } => commands::run(
            &recipe,
            monitor,
            strict,
            &ports,
            canaries_file.as_deref(),
            &events,
            command,
        ),
        Commands::Check => commands::check(),
        Commands::Setup {
            remove,
            force,
            pasta_path,
        } => commands::setup(remove, force, pasta_path.as_deref()),
        Commands::Keygen { path, force } => keys::keygen(&path, force),
        Commands::Pubkey { path } => keys::pubkey(&path),
        Commands::Recipe { action } => match action {
            RecipeAction::List => recipes::list(),
            RecipeAction::Show { recipe, command } => commands::show(&recipe, command),
            RecipeAction::Explain { recipe } => recipes::explain(&recipe),
            RecipeAction::Suggest { command } => recipes::suggest(&command),
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
