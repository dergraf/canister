use super::*;

#[test]
fn parse_minimal_manifest() {
    let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"
"#;
    let manifest = Manifest::parse(toml).unwrap();
    assert_eq!(manifest.sandbox.len(), 1);
    let dev = manifest.get("dev").unwrap();
    assert_eq!(dev.recipes, vec!["elixir"]);
    assert_eq!(dev.command, "iex");
    assert!(dev.description.is_none());
    assert!(dev.strict.is_none());
}

#[test]
fn parse_full_manifest() {
    let toml = r#"
[sandbox.dev]
description = "Neovim + Elixir development"
recipes = ["neovim", "elixir", "nix"]
command = "nvim"

[sandbox.dev.filesystem]
allow_write = ["$HOME/.local/share/nvim"]

[sandbox.dev.network]
allow_domains = ["api.myproject.dev"]

[sandbox.test]
description = "Mix test runner"
recipes = ["elixir", "nix"]
command = "mix test"

[sandbox.test.network]
egress = "proxy-only"

[sandbox.ci]
description = "CI — strict, no network"
recipes = ["elixir", "nix", "generic-strict"]
command = "mix test --cover"
strict = true

[sandbox.ci.resources]
memory_mb = 2048
cpu_percent = 100
"#;
    let manifest = Manifest::parse(toml).unwrap();
    assert_eq!(manifest.sandbox.len(), 3);

    let dev = manifest.get("dev").unwrap();
    assert_eq!(
        dev.description.as_deref(),
        Some("Neovim + Elixir development")
    );
    assert_eq!(dev.recipes, vec!["neovim", "elixir", "nix"]);
    assert_eq!(dev.command, "nvim");
    assert_eq!(dev.filesystem.allow_write.len(), 1);
    assert_eq!(dev.network.allow_domains, vec!["api.myproject.dev"]);

    let test = manifest.get("test").unwrap();
    assert_eq!(test.recipes, vec!["elixir", "nix"]);
    assert_eq!(test.command, "mix test");
    assert_eq!(test.network.egress(), crate::config::EgressMode::ProxyOnly);

    let ci = manifest.get("ci").unwrap();
    assert_eq!(ci.recipes, vec!["elixir", "nix", "generic-strict"]);
    assert_eq!(ci.command, "mix test --cover");
    assert_eq!(ci.strict, Some(true));
    assert_eq!(ci.resources.memory_mb, Some(2048));
    assert_eq!(ci.resources.cpu_percent, Some(100));
}

#[test]
fn parse_manifest_with_syscall_overrides() {
    let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"

[sandbox.dev.syscalls]
allow_extra = ["ptrace"]
deny_extra = ["personality"]
"#;
    let manifest = Manifest::parse(toml).unwrap();
    let dev = manifest.get("dev").unwrap();
    assert_eq!(dev.syscalls.allow_extra, vec!["ptrace"]);
    assert_eq!(dev.syscalls.deny_extra, vec!["personality"]);
}

#[test]
fn reject_empty_manifest() {
    let toml = "";
    let result = Manifest::parse(toml);
    assert!(result.is_err());
}

#[test]
fn reject_empty_sandbox_section() {
    let toml = "[sandbox]\n";
    let result = Manifest::parse(toml);
    assert!(result.is_err(), "empty [sandbox] should be rejected");
}

#[test]
fn reject_sandbox_without_recipes_or_tools() {
    // A sandbox with no recipes AND no tools has nothing to compose
    // beyond the embedded base/default baseline — and the existing
    // validation says that is not enough policy to be worth running.
    let toml = r#"
[sandbox.dev]
command = "nvim"
"#;
    let result = Manifest::parse(toml);
    assert!(
        result.is_err(),
        "sandbox without recipes or tools should be rejected"
    );
}

#[test]
fn reject_sandbox_with_empty_recipes_and_no_tools() {
    let toml = r#"
[sandbox.dev]
recipes = []
command = "nvim"
"#;
    let result = Manifest::parse(toml);
    assert!(
        result.is_err(),
        "sandbox with empty recipes and no tools should be rejected"
    );
}

#[test]
fn accept_sandbox_with_only_tools() {
    let toml = r#"
[sandbox.dev]
tools = ["npm"]
command = "npm test"
"#;
    let manifest = Manifest::parse(toml).expect("manifest with only tools should parse");
    let dev = manifest.get("dev").unwrap();
    assert_eq!(dev.tools, vec!["npm"]);
    assert!(dev.recipes.is_empty());
}

#[test]
fn accept_sandbox_with_recipes_and_tools() {
    let toml = r#"
[sandbox.dev]
recipes = ["nodejs"]
tools = ["npm", "gh"]
command = "npm test"
"#;
    let manifest = Manifest::parse(toml).expect("both fields together must parse");
    let dev = manifest.get("dev").unwrap();
    assert_eq!(dev.recipes, vec!["nodejs"]);
    assert_eq!(dev.tools, vec!["npm", "gh"]);
}

#[test]
fn reject_sandbox_with_empty_recipes_and_empty_tools() {
    let toml = r#"
[sandbox.dev]
recipes = []
tools = []
command = "nvim"
"#;
    let result = Manifest::parse(toml);
    assert!(
        result.is_err(),
        "sandbox with both fields empty should be rejected"
    );
}

#[test]
fn reject_sandbox_without_command() {
    let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
"#;
    let result = Manifest::parse(toml);
    assert!(
        result.is_err(),
        "sandbox without command should be rejected"
    );
}

#[test]
fn reject_sandbox_with_empty_command() {
    let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = ""
"#;
    let result = Manifest::parse(toml);
    assert!(
        result.is_err(),
        "sandbox with empty command should be rejected"
    );
}

#[test]
fn reject_unknown_fields() {
    let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"
bogus = "nope"
"#;
    let result = Manifest::parse(toml);
    assert!(result.is_err(), "unknown fields should be rejected");
}

#[test]
fn reject_unknown_top_level_fields() {
    let toml = r#"
extra_stuff = true

[sandbox.dev]
recipes = ["elixir"]
command = "iex"
"#;
    let result = Manifest::parse(toml);
    assert!(
        result.is_err(),
        "unknown top-level fields should be rejected"
    );
}

#[test]
fn sandbox_names_sorted() {
    let toml = r#"
[sandbox.zebra]
recipes = ["elixir"]
command = "z"

[sandbox.alpha]
recipes = ["elixir"]
command = "a"

[sandbox.middle]
recipes = ["elixir"]
command = "m"
"#;
    let manifest = Manifest::parse(toml).unwrap();
    assert_eq!(manifest.sandbox_names(), vec!["alpha", "middle", "zebra"]);
}

#[test]
fn command_parts_splits_whitespace() {
    let toml = r#"
[sandbox.test]
recipes = ["elixir"]
command = "mix test --cover --force"
"#;
    let manifest = Manifest::parse(toml).unwrap();
    let test = manifest.get("test").unwrap();
    assert_eq!(
        test.command_parts(),
        vec!["mix", "test", "--cover", "--force"]
    );
}

#[test]
fn sandbox_def_converts_to_recipe_via_from() {
    let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"
strict = true

[sandbox.dev.filesystem]
allow_write = ["/tmp/state"]

[sandbox.dev.network]
allow_domains = ["hex.pm"]

[sandbox.dev.syscalls]
allow_extra = ["ptrace"]
"#;
    let manifest = Manifest::parse(toml).unwrap();
    let dev = manifest.get("dev").unwrap();
    let recipe: RecipeFile = dev.into();

    assert_eq!(recipe.strict, Some(true));
    assert_eq!(recipe.filesystem.allow_write.len(), 1);
    assert_eq!(recipe.network.allow_domains, vec!["hex.pm"]);
    assert_eq!(recipe.syscalls.allow_extra, vec!["ptrace"]);
}

#[test]
fn discover_manifest_finds_in_current_dir() {
    let tmp = std::env::temp_dir().join("canister-test-discover");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let manifest_path = tmp.join("canister.toml");
    std::fs::write(
        &manifest_path,
        "[sandbox.dev]\nrecipes = [\"base\"]\ncommand = \"sh\"\n",
    )
    .unwrap();

    let result = discover_manifest(&tmp);
    assert_eq!(result, Some(manifest_path));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn discover_manifest_walks_up() {
    let tmp = std::env::temp_dir().join("canister-test-discover-walk");
    let child = tmp.join("subdir").join("deep");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&child).unwrap();

    let manifest_path = tmp.join("canister.toml");
    std::fs::write(
        &manifest_path,
        "[sandbox.dev]\nrecipes = [\"base\"]\ncommand = \"sh\"\n",
    )
    .unwrap();

    let result = discover_manifest(&child);
    assert_eq!(result, Some(manifest_path));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn discover_manifest_returns_none_when_not_found() {
    let tmp = std::env::temp_dir().join("canister-test-discover-none");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let result = discover_manifest(&tmp);
    assert!(result.is_none());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn reject_mixed_syscall_modes_in_sandbox() {
    let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"

[sandbox.dev.syscalls]
allow = ["read", "write"]
allow_extra = ["ptrace"]
"#;
    let result = Manifest::parse(toml);
    assert!(result.is_err(), "mixing allow and allow_extra should fail");
}
