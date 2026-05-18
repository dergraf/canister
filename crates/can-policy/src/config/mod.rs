//! Recipe / sandbox configuration.
//!
//! Per-section structs live in dedicated submodules; this file is a
//! thin facade that re-exports the public surface so existing call sites
//! continue to use `can_policy::config::Foo` unchanged.
//!
//! Adding a new field to a config section: edit only the relevant
//! submodule. Its `Foo::merge` and the section-local tests stay
//! co-located with the struct definition.

mod dlp;
mod env;
mod error;
mod filesystem;
mod merge;
mod network;
mod process;
mod proxy;
mod recipe;
mod recipe_merge;
mod resources;
mod sandbox;
mod syscalls;
mod trust;

pub use dlp::DlpConfig;
pub use env::expand_env_vars;
pub use error::ConfigError;
pub use filesystem::{FilesystemConfig, PortMapping, PortProtocol};
pub use network::{EgressMode, NetworkConfig};
pub use process::ProcessConfig;
pub use proxy::ProxyConfig;
pub use recipe::{RecipeFile, RecipeMeta};
pub use resources::ResourceConfig;
pub use sandbox::SandboxConfig;
pub use syscalls::{SeccompMode, SyscallConfig};

#[cfg(test)]
mod tests;
