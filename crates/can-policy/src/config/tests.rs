use std::path::PathBuf;

use super::*;

#[test]
fn parse_minimal_config() {
    let toml = r#"
[filesystem]
allow = ["/usr/lib", "/tmp/workspace"]

[network]
allow_domains = ["pypi.org"]
"#;
    let recipe: RecipeFile = toml::from_str(toml).unwrap();
    let config = recipe.into_sandbox_config().unwrap();
    assert_eq!(config.filesystem.allow.len(), 2);
    assert_eq!(config.network.allow_domains, vec!["pypi.org"]);
    assert_eq!(config.network.egress(), EgressMode::ProxyOnly); // default
    assert!(config.syscalls.allow_extra.is_empty());
}

#[test]
fn parse_full_config() {
    let toml = r#"
[filesystem]
allow = ["/usr/lib"]
allow_write = ["/var/data"]
deny = ["/etc/shadow"]

[network]
allow_domains = ["pypi.org", "registry.npmjs.org"]
allow_ips = ["10.0.0.0/8"]
egress = "proxy-only"

[process]
max_pids = 64
allow_execve = ["/usr/bin/python3"]
env_passthrough = ["PATH", "HOME", "LANG"]

[resources]
memory_mb = 512
cpu_percent = 50

[syscalls]
seccomp_mode = "allow-list"
allow_extra = ["ptrace"]
"#;
    let recipe: RecipeFile = toml::from_str(toml).unwrap();
    let config = recipe.into_sandbox_config().unwrap();
    assert_eq!(config.resources.memory_mb, Some(512));
    assert_eq!(config.process.max_pids, Some(64));
    assert_eq!(config.syscalls.allow_extra, vec!["ptrace"]);
    assert_eq!(config.syscalls.seccomp_mode(), SeccompMode::AllowList);
    assert_eq!(
        config.filesystem.allow_write,
        vec![PathBuf::from("/var/data")]
    );
}

#[test]
fn default_deny_config() {
    let config = SandboxConfig::default_deny();
    assert_eq!(config.network.egress(), EgressMode::ProxyOnly);
    assert!(config.filesystem.allow.is_empty());
    assert!(config.network.allow_domains.is_empty());
    assert!(config.syscalls.allow_extra.is_empty());
    assert!(config.syscalls.deny_extra.is_empty());
}

#[test]
fn egress_default_is_proxy_only() {
    let network = NetworkConfig::default();
    assert_eq!(network.egress(), EgressMode::ProxyOnly);
}

#[test]
fn reject_unknown_fields() {
    let toml = r#"
[filesystem]
allow = ["/tmp"]
bogus_field = true
"#;
    let result: Result<RecipeFile, _> = toml::from_str(toml);
    assert!(result.is_err());
}

// ---- Recipe tests ----

#[test]
fn parse_recipe_with_metadata() {
    let toml = r#"
[recipe]
name = "python-pip"
description = "Install Python packages with pip"
version = "1"

[filesystem]
allow = ["/usr/lib", "/tmp"]

[network]
allow_domains = ["pypi.org", "files.pythonhosted.org"]
egress = "proxy-only"

[process]
env_passthrough = ["PATH", "HOME"]
"#;
    let recipe: RecipeFile = toml::from_str(toml).unwrap();
    assert_eq!(recipe.display_name("fallback"), "python-pip");
    assert_eq!(recipe.description(), "Install Python packages with pip");

    let config = recipe.into_sandbox_config().unwrap();
    assert_eq!(config.filesystem.allow.len(), 2);
}

#[test]
fn parse_recipe_without_metadata() {
    let toml = r#"
[filesystem]
allow = ["/usr/lib"]

[syscalls]
allow_extra = ["ptrace"]
"#;
    let recipe: RecipeFile = toml::from_str(toml).unwrap();
    assert!(recipe.recipe.is_none());
    assert_eq!(recipe.display_name("fallback"), "fallback");

    let config = recipe.into_sandbox_config().unwrap();
    assert_eq!(config.syscalls.allow_extra, vec!["ptrace"]);
}

#[test]
fn parse_recipe_with_syscall_overrides() {
    let toml = r#"
[recipe]
name = "elixir-dev"

[syscalls]
allow_extra = ["ptrace"]
deny_extra = ["personality", "seccomp"]
"#;
    let recipe: RecipeFile = toml::from_str(toml).unwrap();
    let config = recipe.into_sandbox_config().unwrap();
    assert_eq!(config.syscalls.allow_extra, vec!["ptrace"]);
    assert_eq!(config.syscalls.deny_extra, vec!["personality", "seccomp"]);
}

#[test]
fn recipe_defaults_to_empty_overrides() {
    let toml = "";
    let recipe: RecipeFile = toml::from_str(toml).unwrap();
    let config = recipe.into_sandbox_config().unwrap();
    assert!(config.syscalls.allow_extra.is_empty());
    assert!(config.syscalls.deny_extra.is_empty());
    assert_eq!(config.syscalls.seccomp_mode(), SeccompMode::AllowList);
}

#[test]
fn reject_unknown_baseline_field() {
    let toml = r#"
[recipe]
name = "test"
baseline = "python"
"#;
    let result: Result<RecipeFile, _> = toml::from_str(toml);
    assert!(result.is_err(), "baseline field should be rejected");
}

#[test]
fn reject_profile_section() {
    let toml = r#"
[profile]
name = "python"
"#;
    let result: Result<RecipeFile, _> = toml::from_str(toml);
    assert!(result.is_err(), "[profile] section should be rejected");
}

// ---- Baseline (allow/deny) tests ----

#[test]
fn parse_baseline_with_absolute_lists() {
    let toml = r#"
[recipe]
name = "default"

[syscalls]
allow = ["read", "write", "exit_group"]
deny = ["reboot", "mount"]
"#;
    let recipe = RecipeFile::parse(toml).unwrap();
    let config = recipe.into_sandbox_config().unwrap();
    assert_eq!(config.syscalls.allow, vec!["read", "write", "exit_group"]);
    assert_eq!(config.syscalls.deny, vec!["reboot", "mount"]);
    assert!(config.syscalls.allow_extra.is_empty());
    assert!(config.syscalls.deny_extra.is_empty());
    assert!(config.syscalls.is_baseline());
    assert!(!config.syscalls.is_override());
}

#[test]
fn reject_mixed_absolute_and_relative() {
    let toml = r#"
[syscalls]
allow = ["read", "write"]
allow_extra = ["ptrace"]
"#;
    let result = RecipeFile::parse(toml);
    assert!(result.is_err(), "mixing allow and allow_extra should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("cannot mix"),
        "error should mention mutual exclusion: {err}"
    );
}

#[test]
fn reject_mixed_deny_and_deny_extra() {
    let toml = r#"
[syscalls]
deny = ["reboot"]
deny_extra = ["ptrace"]
"#;
    let result = RecipeFile::parse(toml);
    assert!(result.is_err(), "mixing deny and deny_extra should fail");
}

#[test]
fn reject_mixed_allow_and_deny_extra() {
    let toml = r#"
[syscalls]
allow = ["read", "write"]
deny_extra = ["ptrace"]
"#;
    let result = RecipeFile::parse(toml);
    assert!(result.is_err(), "mixing allow and deny_extra should fail");
}

#[test]
fn empty_syscalls_is_neither_baseline_nor_override() {
    let config = SyscallConfig::default();
    assert!(!config.is_baseline());
    assert!(!config.is_override());
    assert!(config.validate().is_ok());
}

#[test]
fn parse_default_toml_as_baseline() {
    let content = include_str!("../../../../recipes/default.toml");
    let recipe = RecipeFile::parse(content).unwrap();
    assert_eq!(recipe.display_name("fallback"), "default");
    let config = recipe.into_sandbox_config().unwrap();
    assert!(config.syscalls.is_baseline());
    assert!(!config.syscalls.is_override());
    assert!(
        config.syscalls.allow.len() > 100,
        "default baseline should have >100 allowed syscalls, got {}",
        config.syscalls.allow.len()
    );
    assert!(
        config.syscalls.deny.len() >= 16,
        "default baseline should have >=16 denied syscalls, got {}",
        config.syscalls.deny.len()
    );
}

// ---- Merge tests ----

fn parse_recipe(toml: &str) -> RecipeFile {
    RecipeFile::parse(toml).unwrap()
}

#[test]
fn merge_filesystem_union() {
    let base = parse_recipe(
        r#"
[filesystem]
allow = ["/usr/lib", "/usr/bin"]
allow_write = ["/tmp/state"]
deny = ["/etc/shadow"]
"#,
    );
    let overlay = parse_recipe(
        r#"
[filesystem]
allow = ["/usr/bin", "/tmp/workspace"]
allow_write = ["/tmp/state", "/var/cache/app"]
deny = ["/root"]
"#,
    );
    let merged = base.merge(overlay);
    assert_eq!(
        merged.filesystem.allow,
        vec![
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/tmp/workspace"),
        ]
    );
    assert_eq!(
        merged.filesystem.allow_write,
        vec![PathBuf::from("/tmp/state"), PathBuf::from("/var/cache/app"),]
    );
    assert_eq!(
        merged.filesystem.deny,
        vec![PathBuf::from("/etc/shadow"), PathBuf::from("/root")]
    );
}

#[test]
fn merge_strict_or_semantics() {
    let a = parse_recipe("");
    let b = parse_recipe("");
    assert_eq!(a.merge(b).strict, None);

    let a = parse_recipe("");
    let b = parse_recipe("strict = false");
    assert_eq!(a.merge(b).strict, Some(false));

    let a = parse_recipe("strict = false");
    let b = parse_recipe("strict = true");
    assert_eq!(a.merge(b).strict, Some(true));

    let a = parse_recipe("strict = true");
    let b = parse_recipe("strict = false");
    assert_eq!(a.merge(b).strict, Some(true));

    let a = parse_recipe("strict = true");
    let b = parse_recipe("");
    assert_eq!(a.merge(b).strict, Some(true));
}

#[test]
fn merge_egress_last_wins() {
    let a = parse_recipe("");
    let b = parse_recipe("");
    assert_eq!(a.merge(b).network.egress, None);

    let a = parse_recipe("");
    let b = parse_recipe("[network]\negress = \"direct\"");
    assert_eq!(a.merge(b).network.egress, Some(EgressMode::Direct));

    let a = parse_recipe("[network]\negress = \"proxy-only\"");
    let b = parse_recipe("[network]\negress = \"direct\"");
    assert_eq!(a.merge(b).network.egress, Some(EgressMode::Direct));

    let a = parse_recipe("[network]\negress = \"direct\"");
    let b = parse_recipe("");
    assert_eq!(a.merge(b).network.egress, Some(EgressMode::Direct));
}

#[test]
fn merge_network_domains_union() {
    let a = parse_recipe(
        r#"
[network]
allow_domains = ["pypi.org", "github.com"]
"#,
    );
    let b = parse_recipe(
        r#"
[network]
allow_domains = ["github.com", "hex.pm"]
"#,
    );
    let merged = a.merge(b);
    assert_eq!(
        merged.network.allow_domains,
        vec!["pypi.org", "github.com", "hex.pm"]
    );
}

#[test]
fn merge_seccomp_mode_last_wins() {
    let a = parse_recipe(
        r#"
[syscalls]
seccomp_mode = "allow-list"
"#,
    );
    let b = parse_recipe(
        r#"
[syscalls]
seccomp_mode = "deny-list"
"#,
    );
    assert_eq!(
        a.merge(b).syscalls.seccomp_mode,
        Some(SeccompMode::DenyList)
    );

    let a = parse_recipe(
        r#"
[syscalls]
seccomp_mode = "deny-list"
"#,
    );
    let b = parse_recipe("");
    assert_eq!(
        a.merge(b).syscalls.seccomp_mode,
        Some(SeccompMode::DenyList)
    );
}

#[test]
fn merge_syscall_extras_union() {
    let a = parse_recipe(
        r#"
[syscalls]
allow_extra = ["ptrace", "personality"]
deny_extra = ["reboot"]
"#,
    );
    let b = parse_recipe(
        r#"
[syscalls]
allow_extra = ["personality", "seccomp"]
deny_extra = ["mount"]
"#,
    );
    let merged = a.merge(b);
    assert_eq!(
        merged.syscalls.allow_extra,
        vec!["ptrace", "personality", "seccomp"]
    );
    assert_eq!(merged.syscalls.deny_extra, vec!["reboot", "mount"]);
}

#[test]
fn merge_resources_last_wins() {
    let a = parse_recipe(
        r#"
[resources]
memory_mb = 512
cpu_percent = 50
"#,
    );
    let b = parse_recipe(
        r#"
[resources]
memory_mb = 1024
"#,
    );
    let merged = a.merge(b);
    assert_eq!(merged.resources.memory_mb, Some(1024));
    assert_eq!(merged.resources.cpu_percent, Some(50));
}

#[test]
fn merge_process_union_and_last_wins() {
    let a = parse_recipe(
        r#"
[process]
max_pids = 64
allow_execve = ["/usr/bin/python3"]
env_passthrough = ["PATH", "HOME"]
"#,
    );
    let b = parse_recipe(
        r#"
[process]
max_pids = 256
env_passthrough = ["HOME", "LANG"]
"#,
    );
    let merged = a.merge(b);
    assert_eq!(merged.process.max_pids, Some(256));
    assert_eq!(merged.process.env_passthrough, vec!["PATH", "HOME", "LANG"]);
    assert_eq!(
        merged.process.allow_execve,
        vec![PathBuf::from("/usr/bin/python3")]
    );
}

#[test]
fn merge_recipe_meta_overlay_wins() {
    let a = parse_recipe(
        r#"
[recipe]
name = "base"
description = "base recipe"
"#,
    );
    let b = parse_recipe(
        r#"
[recipe]
name = "overlay"
description = "overlay recipe"
"#,
    );
    let merged = a.merge(b);
    assert_eq!(merged.display_name("fallback"), "overlay");
    assert_eq!(merged.description(), "overlay recipe");
}

#[test]
fn merge_three_recipes() {
    let a = parse_recipe(
        r#"
[filesystem]
allow = ["/usr/lib"]
"#,
    );
    let b = parse_recipe(
        r#"
[filesystem]
allow = ["/usr/bin"]

[syscalls]
allow_extra = ["ptrace"]
"#,
    );
    let c = parse_recipe(
        r#"
strict = true

[filesystem]
allow = ["/tmp"]
deny = ["/root"]
"#,
    );
    let merged = a.merge(b).merge(c);
    assert_eq!(
        merged.filesystem.allow,
        vec![
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/tmp"),
        ]
    );
    assert_eq!(merged.filesystem.deny, vec![PathBuf::from("/root")]);
    assert_eq!(merged.syscalls.allow_extra, vec!["ptrace"]);
    assert_eq!(merged.strict, Some(true));
}

#[test]
fn merge_three_recipes_any_strict_true_wins() {
    let strict_first = parse_recipe("strict = true")
        .merge(parse_recipe(""))
        .merge(parse_recipe("strict = false"));
    assert_eq!(strict_first.strict, Some(true), "strict=true in slot 0");

    let strict_middle = parse_recipe("")
        .merge(parse_recipe("strict = true"))
        .merge(parse_recipe("strict = false"));
    assert_eq!(strict_middle.strict, Some(true), "strict=true in slot 1");

    let strict_last = parse_recipe("strict = false")
        .merge(parse_recipe(""))
        .merge(parse_recipe("strict = true"));
    assert_eq!(strict_last.strict, Some(true), "strict=true in slot 2");
}

#[test]
fn merge_three_recipes_egress_chain_last_wins() {
    let merged = parse_recipe("")
        .merge(parse_recipe(
            r#"
[network]
egress = "direct"
"#,
        ))
        .merge(parse_recipe(
            r#"
[network]
egress = "proxy-only"
"#,
        ));
    assert_eq!(merged.network.egress, Some(EgressMode::ProxyOnly));

    let merged = parse_recipe(
        r#"
[network]
egress = "proxy-only"
"#,
    )
    .merge(parse_recipe(""))
    .merge(parse_recipe(
        r#"
[network]
egress = "direct"
"#,
    ));
    assert_eq!(merged.network.egress, Some(EgressMode::Direct));
}

#[test]
fn merge_three_recipes_allow_extra_union_dedupes() {
    let merged = parse_recipe(
        r#"
[syscalls]
allow_extra = ["ptrace"]
"#,
    )
    .merge(parse_recipe(
        r#"
[syscalls]
allow_extra = ["ptrace", "io_uring_setup"]
"#,
    ))
    .merge(parse_recipe(
        r#"
[syscalls]
allow_extra = ["io_uring_setup", "io_uring_enter"]
"#,
    ));
    assert_eq!(merged.syscalls.allow_extra.len(), 3);
    for s in ["ptrace", "io_uring_setup", "io_uring_enter"] {
        assert!(
            merged.syscalls.allow_extra.contains(&s.to_string()),
            "{s} missing from merged allow_extra",
        );
    }
}

#[test]
fn merge_recipe_with_allow_and_deny_extra_keeps_both() {
    let merged = parse_recipe(
        r#"
[syscalls]
allow_extra = ["ptrace"]
deny_extra = ["ptrace"]
"#,
    );
    assert!(merged.syscalls.allow_extra.contains(&"ptrace".to_string()));
    assert!(merged.syscalls.deny_extra.contains(&"ptrace".to_string()));
}

#[test]
fn merge_three_recipes_strict_invariant_with_egress_change() {
    let strict_base = parse_recipe(
        r#"
strict = true

[network]
egress = "proxy-only"
"#,
    );
    let auto_detected = parse_recipe(
        r#"
[network]
allow_domains = ["github.com"]
"#,
    );
    let cli_override = parse_recipe(
        r#"
[network]
allow_domains = ["registry.npmjs.org"]
"#,
    );
    let merged = strict_base.merge(auto_detected).merge(cli_override);
    assert_eq!(merged.strict, Some(true));
    assert_eq!(merged.network.egress, Some(EgressMode::ProxyOnly));
    assert!(
        merged
            .network
            .allow_domains
            .iter()
            .any(|d| d == "github.com")
    );
    assert!(
        merged
            .network
            .allow_domains
            .iter()
            .any(|d| d == "registry.npmjs.org")
    );
}

#[test]
fn merge_proxy_limit_options_last_some_wins() {
    let base = parse_recipe(
        r#"
[proxy]
max_buffered_body_bytes = 1024
"#,
    );
    let merged_empty_overlay = base.clone().merge(parse_recipe(""));
    assert_eq!(
        merged_empty_overlay.proxy.max_buffered_body_bytes,
        Some(1024)
    );

    let merged_override = base.merge(parse_recipe(
        r#"
[proxy]
max_buffered_body_bytes = 8192
upstream_request_timeout_ms = 5000
"#,
    ));
    assert_eq!(merged_override.proxy.max_buffered_body_bytes, Some(8192));
    assert_eq!(
        merged_override.proxy.upstream_request_timeout_ms,
        Some(5000)
    );
}

#[test]
fn merge_case_different_domains_preserved_then_normalized_at_policy() {
    let a = parse_recipe(
        r#"
[network]
allow_domains = ["Example.com"]
"#,
    );
    let b = parse_recipe(
        r#"
[network]
allow_domains = ["example.com"]
"#,
    );
    let merged = a.merge(b);
    assert!(
        merged
            .network
            .allow_domains
            .iter()
            .any(|d| d == "Example.com"),
        "merged should still contain Example.com",
    );
    assert!(
        merged
            .network
            .allow_domains
            .iter()
            .any(|d| d == "example.com"),
        "merged should still contain example.com",
    );
}

#[test]
fn merge_match_prefix_preserved() {
    let a = parse_recipe(
        r#"
[recipe]
name = "nix"
match_prefix = ["/nix/store"]
"#,
    );
    let b = parse_recipe(
        r#"
[recipe]
name = "elixir"
"#,
    );
    let merged = a.merge(b);
    assert_eq!(merged.display_name("fallback"), "elixir");
    assert!(merged.match_prefixes().is_empty());
}

// ---------------------------------------------------------------
// Environment variable expansion tests
//
// SAFETY: Tests use unique variable names prefixed with _CANISTER_TEST_
// and are not safety-critical. The unsafe blocks are needed because
// Rust 2024 marks set_var/remove_var as unsafe (not thread-safe).
// ---------------------------------------------------------------

#[test]
fn expand_env_vars_no_vars() {
    assert_eq!(expand_env_vars("/usr/lib"), "/usr/lib");
}

#[test]
fn expand_env_vars_home() {
    unsafe { std::env::set_var("_CANISTER_TEST_HOME", "/home/testuser") };
    assert_eq!(
        expand_env_vars("$_CANISTER_TEST_HOME/.cargo/bin"),
        "/home/testuser/.cargo/bin"
    );
    unsafe { std::env::remove_var("_CANISTER_TEST_HOME") };
}

#[test]
fn expand_env_vars_braced() {
    unsafe { std::env::set_var("_CANISTER_TEST_USER", "alice") };
    assert_eq!(
        expand_env_vars("/home/${_CANISTER_TEST_USER}/.local"),
        "/home/alice/.local"
    );
    unsafe { std::env::remove_var("_CANISTER_TEST_USER") };
}

#[test]
fn expand_env_vars_multiple() {
    unsafe { std::env::set_var("_CT_A", "aaa") };
    unsafe { std::env::set_var("_CT_B", "bbb") };
    assert_eq!(expand_env_vars("$_CT_A/$_CT_B"), "aaa/bbb");
    unsafe { std::env::remove_var("_CT_A") };
    unsafe { std::env::remove_var("_CT_B") };
}

#[test]
fn expand_env_vars_unset_becomes_empty() {
    unsafe { std::env::remove_var("_CANISTER_SURELY_UNSET") };
    assert_eq!(
        expand_env_vars("/prefix/$_CANISTER_SURELY_UNSET/suffix"),
        "/prefix//suffix"
    );
}

#[test]
fn expand_env_vars_double_dollar_escapes() {
    assert_eq!(expand_env_vars("cost: $$100"), "cost: $100");
}

#[test]
fn expand_env_vars_lone_dollar_preserved() {
    assert_eq!(expand_env_vars("a $ b"), "a $ b");
}

#[test]
fn expand_env_vars_in_sandbox_config() {
    unsafe { std::env::set_var("_CANISTER_TEST_HOME2", "/home/bob") };
    let recipe = parse_recipe(
        r#"
[filesystem]
allow = ["$_CANISTER_TEST_HOME2/.cargo"]
allow_write = ["$_CANISTER_TEST_HOME2/.local/share/app"]
deny = ["$_CANISTER_TEST_HOME2/.ssh"]

[process]
allow_execve = ["$_CANISTER_TEST_HOME2/.cargo/bin/rustc"]
"#,
    );
    let config = recipe.into_sandbox_config().unwrap();
    assert_eq!(
        config.filesystem.allow,
        vec![PathBuf::from("/home/bob/.cargo")]
    );
    assert_eq!(
        config.filesystem.allow_write,
        vec![PathBuf::from("/home/bob/.local/share/app")]
    );
    assert_eq!(
        config.filesystem.deny,
        vec![PathBuf::from("/home/bob/.ssh")]
    );
    assert_eq!(
        config.process.allow_execve,
        vec![PathBuf::from("/home/bob/.cargo/bin/rustc")]
    );
    unsafe { std::env::remove_var("_CANISTER_TEST_HOME2") };
}

#[test]
fn expand_env_vars_match_prefixes_expanded() {
    unsafe { std::env::set_var("_CANISTER_TEST_HOME3", "/home/carol") };
    let recipe = parse_recipe(
        r#"
[recipe]
name = "cargo"
match_prefix = ["$_CANISTER_TEST_HOME3/.cargo"]
"#,
    );
    assert_eq!(recipe.match_prefixes(), &["$_CANISTER_TEST_HOME3/.cargo"]);
    assert_eq!(
        recipe.match_prefixes_expanded(),
        vec!["/home/carol/.cargo".to_string()]
    );
    unsafe { std::env::remove_var("_CANISTER_TEST_HOME3") };
}

#[test]
fn r16_untrusted_recipe_scopes_dropped() {
    let content = r#"
[recipe]
name = "evil"

[network]
egress = "proxy-only"
allow_domains = ["api.example.com"]

[network.dlp]
enabled = true

[network.dlp.scopes]
github_pat = ["attacker.example.com"]
bearer_token = ["attacker.example.com"]
"#;
    let dir = std::env::temp_dir().join("can-r16-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fake-evil-recipe.toml");
    std::fs::write(&path, content).unwrap();

    let recipe = RecipeFile::from_file(&path).unwrap();
    let dlp = recipe
        .network
        .dlp
        .as_ref()
        .expect("dlp section should still be present");
    assert!(
        dlp.scopes.is_empty(),
        "untrusted recipe's scopes should be cleared, got: {:?}",
        dlp.scopes
    );
    assert_eq!(dlp.enabled, Some(true));
    assert_eq!(recipe.network.allow_domains, vec!["api.example.com"]);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn r16_parse_path_skipped_for_string_parse() {
    let content = r#"
[network]
egress = "proxy-only"

[network.dlp]
enabled = true

[network.dlp.scopes]
github_pat = ["github.corp.example.com"]
"#;
    let recipe = RecipeFile::parse(content).unwrap();
    let dlp = recipe.network.dlp.as_ref().unwrap();
    assert!(
        !dlp.scopes.is_empty(),
        "RecipeFile::parse should not trigger trust filtering"
    );
}
