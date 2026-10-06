//! The sandbox CA in the trust bundles a client reads without being told
//! (ADR-0028).
//!
//! `SSL_CERT_FILE` reaches only a client that keeps its environment and
//! reads the variable. Every other one falls back to a bundle at a fixed
//! place: OpenSSL's compiled-in default, or `certifi`'s copy inside a
//! Python environment. With `[network] overlay_ca_bundles`, each such
//! bundle present in the sandbox is overlaid with a copy that also holds
//! the sandbox CA.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::overlay::{OverlayError, bind_mount_ro};

/// A place clients read trust anchors from, and who reads it.
struct BundleLocation {
    /// Absolute path; may start with `$CWD` or `$HOME`, and `*` matches
    /// within one path segment.
    pattern: &'static str,
    read_by: &'static str,
}

const BUNDLE_LOCATIONS: &[BundleLocation] = &[
    BundleLocation {
        pattern: "/etc/ssl/certs/ca-certificates.crt",
        read_by: "OpenSSL, Go, curl on Debian, Ubuntu, Alpine, Arch",
    },
    BundleLocation {
        pattern: "/etc/pki/tls/certs/ca-bundle.crt",
        read_by: "OpenSSL, Go, curl on Fedora, RHEL",
    },
    BundleLocation {
        pattern: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        read_by: "OpenSSL, Go, curl on Fedora, RHEL",
    },
    BundleLocation {
        pattern: "/etc/ssl/cert.pem",
        read_by: "OpenSSL, LibreSSL on Alpine, Arch",
    },
    BundleLocation {
        pattern: "/etc/ssl/ca-bundle.pem",
        read_by: "OpenSSL on openSUSE",
    },
    BundleLocation {
        pattern: "/usr/lib/python3*/site-packages/certifi/cacert.pem",
        read_by: "httpx, requests: the system Python",
    },
    BundleLocation {
        pattern: "/usr/local/lib/python3*/*-packages/certifi/cacert.pem",
        read_by: "httpx, requests: pip installs outside a virtualenv",
    },
    BundleLocation {
        pattern: "$HOME/.local/lib/python3*/site-packages/certifi/cacert.pem",
        read_by: "httpx, requests: pip install --user",
    },
    BundleLocation {
        pattern: "$HOME/.cache/uv/archive-v0/*/lib/python3*/site-packages/certifi/cacert.pem",
        read_by: "httpx, requests: tools run with uvx",
    },
    BundleLocation {
        pattern: "$CWD/.venv/lib/python3*/site-packages/certifi/cacert.pem",
        read_by: "httpx, requests: the project's virtualenv",
    },
    BundleLocation {
        pattern: "$CWD/venv/lib/python3*/site-packages/certifi/cacert.pem",
        read_by: "httpx, requests: the project's virtualenv",
    },
];

/// Where the combined copies live inside the sandbox.
const COPIES_DIR: &str = "/tmp/.canister-trust";

/// Overlay every known bundle present in the sandbox with a copy that
/// also holds `ca_pem`. Must run after `pivot_root`, while the worker can
/// still mount. A bundle that cannot be overlaid is logged and skipped:
/// its clients then reject the CA, which the proxy records.
pub fn overlay_bundles(ca_pem: &str, cwd: Option<&Path>, home: Option<&Path>) -> Vec<PathBuf> {
    let mut overlaid = Vec::new();

    for (index, (bundle, read_by)) in present_bundles(cwd, home).into_iter().enumerate() {
        match overlay_one(&bundle, ca_pem, index) {
            Ok(()) => {
                tracing::debug!(bundle = %bundle.display(), read_by, "CA bundle overlaid");
                overlaid.push(bundle);
            }
            Err(e) => {
                tracing::warn!(bundle = %bundle.display(), error = %e, "CA bundle not overlaid")
            }
        }
    }

    tracing::info!(bundles = ?overlaid, "sandbox CA added to trust bundles");
    overlaid
}

/// The known bundles that exist, each resolved to the file it names and
/// listed once, with who reads it.
fn present_bundles(cwd: Option<&Path>, home: Option<&Path>) -> BTreeMap<PathBuf, &'static str> {
    let mut present = BTreeMap::new();
    for location in BUNDLE_LOCATIONS {
        let Some(pattern) = substitute(location.pattern, cwd, home) else {
            continue;
        };
        for path in expand(&pattern) {
            if let Some(file) = std::fs::canonicalize(path)
                .ok()
                .filter(|file| file.is_file())
            {
                present.entry(file).or_insert(location.read_by);
            }
        }
    }
    present
}

/// Replace a leading `$CWD` or `$HOME`; `None` if that directory is unknown.
fn substitute(pattern: &str, cwd: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    for (variable, value) in [("$CWD", cwd), ("$HOME", home)] {
        if let Some(rest) = pattern.strip_prefix(variable) {
            return value.map(|dir| dir.join(rest.trim_start_matches('/')));
        }
    }
    Some(PathBuf::from(pattern))
}

/// The paths a pattern names that exist, `*` matching within one segment.
fn expand(pattern: &Path) -> Vec<PathBuf> {
    let mut matches = vec![PathBuf::from("/")];

    for segment in pattern.iter().skip(1) {
        let segment = segment.to_string_lossy();
        matches = if segment.contains('*') {
            matches
                .iter()
                .filter_map(|dir| std::fs::read_dir(dir).ok())
                .flatten()
                .filter_map(Result::ok)
                .filter(|entry| wildcard_match(&segment, &entry.file_name().to_string_lossy()))
                .map(|entry| entry.path())
                .collect()
        } else {
            matches
                .into_iter()
                .map(|dir| dir.join(segment.as_ref()))
                .filter(|path| path.exists())
                .collect()
        };
    }

    matches.sort();
    matches
}

/// `*` matches any run of characters, everything else itself.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((prefix, rest)) => {
            name.starts_with(prefix)
                && (prefix.len()..=name.len())
                    .any(|i| name.is_char_boundary(i) && wildcard_match(rest, &name[i..]))
        }
    }
}

/// The bundle's own anchors, then the sandbox CA.
fn combined(original: &str, ca_pem: &str) -> String {
    let separator = if original.is_empty() || original.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    format!("{original}{separator}{ca_pem}")
}

fn overlay_one(bundle: &Path, ca_pem: &str, index: usize) -> Result<(), OverlayError> {
    let io_error = |source| OverlayError::File {
        path: bundle.display().to_string(),
        source,
    };
    let original = std::fs::read_to_string(bundle).map_err(io_error)?;
    let copy = Path::new(COPIES_DIR).join(format!("{index}.pem"));

    std::fs::create_dir_all(COPIES_DIR).map_err(io_error)?;
    std::fs::write(&copy, combined(&original, ca_pem)).map_err(io_error)?;
    bind_mount_ro(&copy, bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_star_matches_within_a_segment() {
        assert!(wildcard_match("python3*", "python3.12"));
        assert!(wildcard_match("python3*", "python3"));
        assert!(wildcard_match("*-packages", "dist-packages"));
        assert!(wildcard_match("*", "anything"));
        assert!(!wildcard_match("python3*", "python2.7"));
        assert!(!wildcard_match("*-packages", "packages"));
        assert!(wildcard_match("exact", "exact"));
        assert!(!wildcard_match("exact", "exactly"));
    }

    #[test]
    fn cwd_and_home_are_substituted_and_an_unknown_one_skips_the_location() {
        let cwd = Path::new("/work");
        let home = Path::new("/home/u");

        assert_eq!(
            substitute("$CWD/.venv/x", Some(cwd), Some(home)),
            Some(PathBuf::from("/work/.venv/x"))
        );
        assert_eq!(
            substitute("$HOME/.local/x", Some(cwd), Some(home)),
            Some(PathBuf::from("/home/u/.local/x"))
        );
        assert_eq!(substitute("$HOME/.local/x", Some(cwd), None), None);
        assert_eq!(
            substitute("/etc/ssl/cert.pem", None, None),
            Some(PathBuf::from("/etc/ssl/cert.pem"))
        );
    }

    #[test]
    fn expansion_finds_every_matching_environment_and_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        for python in ["python3.11", "python3.12", "python2.7"] {
            let certifi = root.join(format!(".venv/lib/{python}/site-packages/certifi"));
            std::fs::create_dir_all(&certifi).expect("mkdir");
            std::fs::write(certifi.join("cacert.pem"), "anchors").expect("write");
        }
        std::fs::create_dir_all(root.join(".venv/lib/python3.13/site-packages")).expect("mkdir");

        let pattern = substitute(
            "$CWD/.venv/lib/python3*/site-packages/certifi/cacert.pem",
            Some(root),
            None,
        )
        .expect("substituted");
        let found = expand(&pattern);

        assert_eq!(
            found,
            vec![
                root.join(".venv/lib/python3.11/site-packages/certifi/cacert.pem"),
                root.join(".venv/lib/python3.12/site-packages/certifi/cacert.pem"),
            ]
        );
    }

    #[test]
    fn a_bundle_named_twice_through_a_symlink_is_overlaid_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let certifi = dir
            .path()
            .join(".venv/lib/python3.12/site-packages/certifi");
        std::fs::create_dir_all(&certifi).expect("mkdir");
        std::fs::write(certifi.join("cacert.pem"), "anchors").expect("write");
        std::os::unix::fs::symlink(dir.path().join(".venv"), dir.path().join("venv"))
            .expect("symlink");

        let project: Vec<PathBuf> = present_bundles(Some(dir.path()), None)
            .into_keys()
            .filter(|path| path.starts_with(dir.path().canonicalize().expect("canonical")))
            .collect();

        assert_eq!(project.len(), 1, "{project:?}");
    }

    #[test]
    fn the_copy_keeps_the_original_anchors_and_adds_the_ca() {
        let ca = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";

        assert_eq!(combined("A\n", ca), format!("A\n{ca}"));
        assert_eq!(combined("A", ca), format!("A\n{ca}"));
        assert_eq!(combined("", ca), ca);
    }

    #[test]
    fn every_location_is_absolute_once_substituted() {
        for location in BUNDLE_LOCATIONS {
            let path = substitute(
                location.pattern,
                Some(Path::new("/w")),
                Some(Path::new("/h")),
            )
            .expect("substituted");
            assert!(path.is_absolute(), "{}", location.pattern);
            assert!(!location.read_by.is_empty());
        }
    }
}
