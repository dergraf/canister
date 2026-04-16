# Getting Started

## Installation

Download the latest binary from [GitHub Releases](https://github.com/dergraf/canister/releases):

```bash
# Download and extract
curl -fsSL https://github.com/dergraf/canister/releases/latest/download/canister-x86_64-linux.tar.gz \
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
allow_domains = ["pypi.org", "files.pythonhosted.org"]
```

Then use `can up` to launch the sandbox:

```bash
can up dev
```

See the [Manifest Reference](../generated/manifest.md) for full schema documentation.
