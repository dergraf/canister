//! Trust signal for credential-scope entries. A recipe whose SHA-256
//! doesn't match the embedded canonical-recipes snapshot is "untrusted";
//! every `[[host]] allow_credentials` list it declares is dropped at
//! load time so a malicious or stale third-party recipe can't silently
//! widen credential trust.

use std::collections::HashMap;

use serde::Deserialize;

/// Embedded snapshot of the canonical recipes' SHA-256 checksums.
///
/// Same file `can-cli` uses for `can pull` verification. We include it
/// here because trust evaluation happens at recipe-load time inside the
/// policy crate, not in the CLI.
const EMBEDDED_RECIPE_CHECKSUMS: &str = include_str!("../../../../recipes/checksums.toml");

pub fn recipe_checksum_matches(filename: &str, content: &str) -> bool {
    let checksums = match parse_embedded_checksums() {
        Some(c) => c,
        None => return false,
    };
    use sha2::{Digest, Sha256};
    let actual = Sha256::digest(content.as_bytes());
    let actual_hex: String = actual.iter().map(|b| format!("{b:02x}")).collect();

    // Fast path: exact filename → hash match. Top-level recipes
    // (`base.toml`, `default.toml`) reach us keyed by their bare filename,
    // which is also their key in `checksums.toml`.
    if let Some(expected) = checksums.get(filename) {
        if actual_hex.eq_ignore_ascii_case(expected) {
            return true;
        }
    }

    // Nested recipes (`services/github.toml`) reach the trust gate with only
    // their bare filename — `RecipeFile::from_file` uses `path.file_name()`,
    // which never matches the relative-path keys in `checksums.toml`. Fall
    // back to content-hash membership: trust is a property of the recipe
    // *content* being one of the official pinned recipes, independent of
    // where the file lives. This is the same content that `can pull`
    // verifies by relative path (`registry.rs`); here we only need to know
    // "is this official?", so a path-independent check is both correct and
    // robust to a pinned recipe being installed under a different name.
    checksums
        .values()
        .any(|expected| actual_hex.eq_ignore_ascii_case(expected))
}

fn parse_embedded_checksums() -> Option<HashMap<String, String>> {
    #[derive(Deserialize)]
    struct File {
        checksums: HashMap<String, String>,
    }
    toml::from_str::<File>(EMBEDDED_RECIPE_CHECKSUMS)
        .ok()
        .map(|f| f.checksums)
}
