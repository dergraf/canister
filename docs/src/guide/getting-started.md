# Getting Started

## Installation

Download the latest binary from [GitHub Releases](https://github.com/dergraf/canister/releases):

```bash
# Install to ~/.local/bin so no sudo is needed for the binary itself.
# Make sure ~/.local/bin is on your PATH (most distros add it automatically).
mkdir -p ~/.local/bin
curl -fsSL https://github.com/dergraf/canister/releases/download/latest/canister-x86_64-linux.tar.gz \
  | tar xz -C ~/.local/bin

# Verify
can --version
```

Or build from source:

```bash
git clone https://github.com/dergraf/canister.git
cd canister
cargo build --release
cp target/release/can ~/.local/bin/
```

## Runtime requirements

- **Filtered network mode** uses `pasta` from the `passt` package — install it on the host (`sudo apt install passt` on Debian/Ubuntu, `sudo dnf install passt` on Fedora). Canister itself ships no daemon; pasta runs only for the lifetime of a sandbox that opts into filtered networking.
- **Hardened distros** (Ubuntu 24.04+, Fedora 41+, RHEL 10+) restrict unprivileged user-namespace creation. Run `sudo can setup` once to install the AppArmor or SELinux policy that grants the `can` binary that capability. After that, day-to-day `can run` / `can up` invocations stay unprivileged.

## First-time Setup

Run the setup command to configure your system for unprivileged user namespaces:

```bash
can setup
```

## Quick Start

Run a command inside a sandbox:

```bash
can run -- ls /
```

This runs `ls /` inside an isolated environment with the default recipe applied. The sandbox restricts filesystem access, blocks network traffic, and filters syscalls.

## Using Recipes

Recipes are TOML files that define sandbox policies. Use built-in recipes or write your own:

```bash
# List available built-in recipes
can recipe list

# Run with a specific recipe
can run --recipe python -- python3 script.py

# Auto-detect recipe from command
can run -- python3 script.py
```

See [Configuration](configuration.md) for the full configuration guide and [Built-in Recipes](../generated/recipes.md) for all available recipes.

## Project Manifests

For projects that need reproducible sandbox configurations, create a `canister.toml` manifest:

```toml
[sandbox.dev]
recipes = ["python", "network-curl"]

[sandbox.dev.config.network]
[[host]]
domain = "pypi.org"

[[host]]
domain = "files.pythonhosted.org"
```

Then use `can up` to launch the sandbox:

```bash
can up dev
```

See the [Manifest Reference](../generated/manifest.md) for full schema documentation.
