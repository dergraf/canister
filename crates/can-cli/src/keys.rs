//! `can keygen` and `can pubkey`: the signing key behind
//! `--events-sign-key` (ADR-0016, ADR-0021).
//!
//! A key file holds the 32-byte Ed25519 seed as 64 lowercase hex
//! characters and a newline — the same thing `openssl rand -hex 32`
//! writes, and one of the two forms `SealKey::from_file` reads. The
//! public key is printed exactly as a `stream_seal` event carries it in
//! `public_key`, so a verifier's trust list can hold the line verbatim.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use can_events::SealKey;

/// Owner read/write only: the seed is the one secret a seal rests on.
const KEY_FILE_MODE: u32 = 0o600;

/// Generate a new key into `path` and print its public key.
pub fn keygen(path: &Path, force: bool) -> Result<i32> {
    let public_key = write_new_key(path, force)?;

    println!("{public_key}");
    Ok(0)
}

/// Print the public key of the seed in `path`.
pub fn pubkey(path: &Path) -> Result<i32> {
    println!("{}", public_key_of(path)?);
    Ok(0)
}

fn public_key_of(path: &Path) -> Result<String> {
    let key = SealKey::from_file(path).context("loading the signing key")?;

    Ok(key.public_key_hex())
}

/// Write a fresh seed to `path` with mode 0600 and return its public key.
///
/// An existing file is refused unless `force` is set: overwriting a key
/// silently orphans every seal it signed. With `force` the old file is
/// removed rather than truncated, so the new key never inherits the old
/// file's permissions.
fn write_new_key(path: &Path, force: bool) -> Result<String> {
    let seed = random_seed()?;

    if force {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| format!("removing {}", path.display()));
            }
        }
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(KEY_FILE_MODE)
        .open(path)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow::anyhow!(
                    "{} already exists; pass --force to replace it (seals signed with the old key will no longer match it)",
                    path.display()
                )
            } else {
                anyhow::Error::new(err).context(format!("creating {}", path.display()))
            }
        })?;

    file.write_all(format!("{}\n", hex(&seed)).as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", path.display()))?;

    Ok(SealKey::from_bytes(seed).public_key_hex())
}

fn random_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];

    std::fs::File::open("/dev/urandom")
        .and_then(|mut urandom| urandom.read_exact(&mut seed))
        .context("reading /dev/urandom")?;

    Ok(seed)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn a_generated_key_signs_seals_that_verify_against_its_public_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("seal.key");

        let printed = write_new_key(&path, false).expect("keygen");
        let key = SealKey::from_file(&path).expect("the written key must load");
        let head = [0x42u8; 32];
        let signature = key.sign("r-keygen", "cli", 3, &head);

        assert_eq!(printed, public_key_of(&path).expect("pubkey"));
        can_events::seal::verify(
            can_events::seal::SEAL_ALGORITHM,
            &printed,
            &signature,
            "r-keygen",
            "cli",
            3,
            &hex(&head),
        )
        .expect("a seal signed with the seed must verify against the printed public key");
    }

    #[test]
    fn the_key_file_is_64_hex_characters_and_a_newline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("seal.key");
        write_new_key(&path, false).expect("keygen");

        let contents = std::fs::read_to_string(&path).expect("read");
        let seed = contents.strip_suffix('\n').expect("trailing newline");

        assert_eq!(seed.len(), 64);
        assert!(
            seed.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn the_public_key_is_printed_as_a_seal_carries_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("openssl.key");
        std::fs::write(&path, format!("{}\n", hex(&[7u8; 32]))).expect("write");

        let printed = public_key_of(&path).expect("pubkey");

        assert_eq!(printed, SealKey::from_bytes([7u8; 32]).public_key_hex());
        assert_eq!(printed.len(), 64);
        assert_eq!(printed, printed.to_lowercase());
    }

    #[test]
    fn two_generated_keys_differ() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = write_new_key(&dir.path().join("a.key"), false).expect("a");
        let second = write_new_key(&dir.path().join("b.key"), false).expect("b");

        assert_ne!(first, second);
    }

    #[test]
    fn the_key_file_is_readable_by_its_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("seal.key");
        write_new_key(&path, false).expect("keygen");

        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn an_existing_key_is_not_overwritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("seal.key");
        let original = write_new_key(&path, false).expect("keygen");

        let err = write_new_key(&path, false).expect_err("must refuse");

        assert!(err.to_string().contains("--force"), "{err}");
        assert_eq!(public_key_of(&path).expect("pubkey"), original);
    }

    #[test]
    fn force_replaces_the_key_and_resets_a_lax_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("seal.key");
        let original = write_new_key(&path, false).expect("keygen");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let replaced = write_new_key(&path, true).expect("forced keygen");

        assert_ne!(replaced, original);
        assert_eq!(public_key_of(&path).expect("pubkey"), replaced);
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn force_writes_a_key_where_none_existed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("seal.key");

        write_new_key(&path, true).expect("forced keygen on a fresh path");

        assert!(SealKey::from_file(&path).is_ok());
    }

    #[test]
    fn pubkey_of_a_malformed_file_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.key");
        std::fs::write(&path, "not a key\n").expect("write");

        assert!(public_key_of(&path).is_err());
        assert!(public_key_of(&dir.path().join("missing.key")).is_err());
    }
}
