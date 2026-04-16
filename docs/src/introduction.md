# Canister

**A lightweight sandbox for running untrusted code safely on Linux.**

Canister (`can`) runs any command inside an isolated sandbox with restricted filesystem, network, and syscall access. No root required. Single binary, zero runtime dependencies.

```
$ can run --recipe recipes/example.toml -- python3 untrusted_script.py
```

The script sees an empty filesystem (except explicitly allowed paths), can only reach allowed domains, and is blocked from dangerous syscalls.

## Key Features

- **Namespace isolation** — mount, PID, network, user, and UTS namespaces
- **Filesystem control** — read-only bind mounts with explicit write paths
- **Network filtering** — DNS-level domain filtering + IP/CIDR rules
- **Seccomp BPF** — syscall allow/deny lists with optional `SECCOMP_RET_USER_NOTIF` supervisor
- **Recipe composition** — layered TOML configs that merge predictably
- **Zero dependencies** — static Rust binary, no daemon, no root

## Documentation Structure

This documentation is organized into three sections:

- **User Guide** — conceptual explanations, getting started, configuration patterns
- **Reference** — auto-generated from source code: CLI flags, config schema, recipes, merge semantics
- **Architecture** — system design overview and Architecture Decision Records (ADRs)
