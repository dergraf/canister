//! R16: trust signal for `[dlp.scopes]`. A recipe whose SHA-256 doesn't
//! match the embedded canonical-recipes snapshot is "untrusted"; its
//! `[dlp.scopes]` entries are dropped at load time so a malicious or
//! stale third-party recipe can't silently widen credential trust.

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
    match checksums.get(filename) {
        Some(expected) => {
            use sha2::{Digest, Sha256};
            let actual = Sha256::digest(content.as_bytes());
            let actual_hex: String = actual.iter().map(|b| format!("{b:02x}")).collect();
            actual_hex.eq_ignore_ascii_case(expected)
        }
        None => false,
    }
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
