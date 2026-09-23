//! Signing and verifying a stream's closing seal (ADR-0016).
//!
//! The hash chain makes a stream internally consistent: no line can be
//! changed, dropped or reordered without breaking it. It does not say
//! *who* wrote the stream, and whoever can rewrite a line can recompute
//! the chain over their rewrite. Everything downstream of `can` — the
//! runner, the CI job, an artifact store, a vendor — sits in that gap.
//!
//! A seal closes it. The emitting process signs its final chain head
//! with an Ed25519 key the sandboxed workload never has access to, and a
//! consumer that knows the public key can tell "these are the bytes
//! `can` wrote" from "these are bytes someone produced afterwards".
//!
//! The signed message is deliberately dull and reproducible without a
//! JSON parser:
//!
//! ```text
//! canister-event-stream-v1\n<run_id>\n<stream>\n<events>\n<chain_head>
//! ```
//!
//! What a seal does **not** claim: that the machine was trustworthy, or
//! that the key was not stolen. It narrows "trust the whole pipeline" to
//! "trust the key", which is the smallest thing a deployment can defend.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Domain separator. A signature over one kind of message must never be
/// replayable as a signature over another.
pub const SEAL_CONTEXT: &str = "canister-event-stream-v1";

/// Algorithm name written into the seal.
pub const SEAL_ALGORITHM: &str = "ed25519";

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("failed to read signing key {path}: {source}")]
    ReadKey {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("signing key {path} must be 32 raw bytes or 64 hex characters, found {found} byte(s)")]
    KeyLength {
        path: std::path::PathBuf,
        found: usize,
    },
    #[error("unsupported seal algorithm {0:?}, expected {SEAL_ALGORITHM}")]
    Algorithm(String),
    #[error("malformed {field} in seal: {detail}")]
    Malformed { field: &'static str, detail: String },
    #[error("seal signature does not verify")]
    BadSignature,
}

/// The key a process signs its stream with.
#[derive(Clone)]
pub struct SealKey {
    signing: SigningKey,
}

impl std::fmt::Debug for SealKey {
    // Never print key material, not even truncated: a debug line in a CI
    // log is exactly how a signing key escapes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealKey")
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

impl SealKey {
    /// Load a key from a file holding either 32 raw bytes or 64 hex
    /// characters. Both exist in the wild and telling them apart is
    /// unambiguous, so accepting both costs nothing and saves an
    /// operator one failed run.
    pub fn from_file(path: &Path) -> Result<Self, SealError> {
        let contents = std::fs::read(path).map_err(|source| SealError::ReadKey {
            path: path.to_path_buf(),
            source,
        })?;

        let bytes = match decode_key(&contents) {
            Some(bytes) => bytes,
            None => {
                return Err(SealError::KeyLength {
                    path: path.to_path_buf(),
                    found: contents.len(),
                });
            }
        };

        Ok(Self {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    /// Build from raw key bytes. Tests and callers that hold the key in
    /// memory use this.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn public_key_hex(&self) -> String {
        hex(self.signing.verifying_key().as_bytes())
    }

    /// Sign one stream's closing state.
    pub fn sign(&self, run_id: &str, stream: &str, events: u64, chain_head: &[u8; 32]) -> String {
        let message = seal_message(run_id, stream, events, &hex(chain_head));

        hex(&self.signing.sign(message.as_bytes()).to_bytes())
    }
}

/// The exact bytes a seal signs.
pub fn seal_message(run_id: &str, stream: &str, events: u64, chain_head_hex: &str) -> String {
    format!("{SEAL_CONTEXT}\n{run_id}\n{stream}\n{events}\n{chain_head_hex}")
}

/// Check a seal against the stream it claims to close.
///
/// The caller supplies what it observed — the run id, the stream name,
/// how many events it saw and their final chain hash — so a seal that is
/// valid for a *different* stream cannot be pasted onto this one.
pub fn verify(
    algorithm: &str,
    public_key_hex: &str,
    signature_hex: &str,
    run_id: &str,
    stream: &str,
    events: u64,
    chain_head_hex: &str,
) -> Result<(), SealError> {
    if algorithm != SEAL_ALGORITHM {
        return Err(SealError::Algorithm(algorithm.to_string()));
    }

    let key_bytes: [u8; 32] = unhex(public_key_hex, "public_key")?
        .try_into()
        .map_err(|_| SealError::Malformed {
            field: "public_key",
            detail: "expected 32 bytes".to_string(),
        })?;

    let signature_bytes: [u8; 64] =
        unhex(signature_hex, "signature")?
            .try_into()
            .map_err(|_| SealError::Malformed {
                field: "signature",
                detail: "expected 64 bytes".to_string(),
            })?;

    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|err| SealError::Malformed {
        field: "public_key",
        detail: err.to_string(),
    })?;

    let message = seal_message(run_id, stream, events, chain_head_hex);

    key.verify(message.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .map_err(|_| SealError::BadSignature)
}

fn decode_key(contents: &[u8]) -> Option<[u8; 32]> {
    if let Ok(bytes) = <[u8; 32]>::try_from(contents) {
        return Some(bytes);
    }

    let text = std::str::from_utf8(contents).ok()?.trim();
    let decoded = unhex(text, "key").ok()?;

    <[u8; 32]>::try_from(decoded.as_slice()).ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str, field: &'static str) -> Result<Vec<u8>, SealError> {
    if text.len() % 2 != 0 {
        return Err(SealError::Malformed {
            field,
            detail: "odd number of hex characters".to_string(),
        });
    }

    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| SealError::Malformed {
                field,
                detail: "not hexadecimal".to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
