use std::path::PathBuf;

use anyhow::{Context, Result};

use can_policy::{SandboxConfig, SeccompProfile};
use can_sandbox::SandboxOpts;
use can_sandbox::capabilities::KernelCapabilities;

/// Execute the `can run` command.
pub fn run(
    config_path: Option<PathBuf>,
    profile: Option<String>,
    monitor: bool,
    command: Vec<String>,
) -> Result<i32> {
    let config = match config_path {
        Some(ref path) => SandboxConfig::from_file(path)
            .with_context(|| format!("loading config: {}", path.display()))?,
        None => {
            tracing::info!("no config file specified, using default deny-all policy");
            SandboxConfig::default_deny()
        }
    };

    // Override profile if specified on command line.
    let _profile_name = profile.unwrap_or_else(|| config.profile.name.clone());

    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no command specified"))?;

    let opts = SandboxOpts {
        command: cmd.clone(),
        args: args.to_vec(),
        config,
        monitor,
    };

    let exit_code = can_sandbox::run(&opts)?;
    Ok(exit_code)
}

/// Execute the `can check` command.
pub fn check() -> Result<i32> {
    let caps = KernelCapabilities::detect();
    println!("{}", caps.summary());

    if caps.meets_minimum() {
        println!("\nCanister can run on this system.");
        Ok(0)
    } else {
        println!("\nWARNING: This system does not meet minimum requirements.");
        println!("Canister requires at least user namespaces and PID namespaces.");
        Ok(1)
    }
}

/// Execute the `can profiles` command.
pub fn profiles() -> Result<i32> {
    println!("Available seccomp profiles:\n");
    for name in SeccompProfile::builtin_names() {
        let profile = SeccompProfile::builtin(name).unwrap();
        println!("  {:<12} {}", profile.name, profile.description);
    }
    Ok(0)
}
