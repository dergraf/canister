//! Structured event stream emitted by `can` (schema v1, ADR-0010).
//!
//! `can` is multi-process: the CLI forks a proxy process and, with
//! argument-level filtering, a supervisor process. Each emitting process
//! opens its **own** connection and owns an independent `(stream, seq)`
//! space and hash chain, so no two processes ever interleave writes into
//! one line. A consumer merges streams by `ts_ms` and verifies each
//! stream's chain separately.
//!
//! Line format (one compact JSON object per line, `chain_hash` last):
//!
//! ```text
//! {"schema":1,"run_id":"r-1","stream":"proxy","seq":0,"ts_ms":1760000000000,
//!  "prev_hash":"00…0","event":"run_start","data":{…},"chain_hash":"9f…"}
//! ```
//!
//! `chain_hash` is `sha256(body)` where `body` is the line with the
//! trailing `,"chain_hash":"<64 hex>"` removed. `prev_hash` is inside the
//! body, so every event commits to its predecessor; the first event of a
//! stream uses 64 zeros. Verification needs no re-serialization.
//!
//! Emission is best-effort: a write failure is logged once and the stream
//! goes dead. Losing the observer must never change what the sandbox
//! enforces.

pub mod schema;
pub mod seal;

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

pub use schema::{Event, SCHEMA_VERSION};
pub use seal::{SealError, SealKey};

/// Genesis value for a stream's `prev_hash`.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// How long a write to the event consumer may block before the stream is
/// given up for dead.
///
/// A consumer that exits is harmless: the socket closes and the next
/// write fails. A consumer that stops *reading* without closing is not —
/// the socket buffer fills, `write_all` blocks, and because emission
/// happens on the proxy's request path that blocks enforcement behind
/// observation. Losing the observer must never do that, so a write that
/// cannot make progress in this long kills the stream instead.
///
/// Generous enough that a busy consumer is not dropped for being slow,
/// short enough that a run cannot wedge on one.
pub const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("failed to connect to event socket {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open event file {path}: {source}")]
    OpenFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Where a process writes its events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventTarget {
    /// Connect to an existing `SOCK_STREAM` Unix socket. `can` is the
    /// client; the consumer listens.
    Socket(PathBuf),
    /// Append JSONL to a file.
    File(PathBuf),
}

/// What the proxy should record into `exchange` events (ADR-0011).
///
/// Travels with [`EventConfig`] because it follows the same path from the
/// CLI into the forked proxy process, and because capture is meaningless
/// without a stream to emit into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Emit one `exchange` event per HTTP exchange through the proxy.
    pub exchanges: bool,
    /// Per-body cap; larger bodies are truncated and flagged.
    pub max_bytes: usize,
}

impl CaptureConfig {
    pub const DEFAULT_MAX_BYTES: usize = 1024 * 1024;
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            exchanges: false,
            max_bytes: Self::DEFAULT_MAX_BYTES,
        }
    }
}

/// Event emission settings, threaded from the CLI into the sandbox and
/// proxy processes.
#[derive(Debug, Clone)]
pub struct EventConfig {
    pub target: EventTarget,
    pub run_id: String,
    pub capture: CaptureConfig,
    /// How often the proxy emits a cumulative `stats` event (ADR-0015).
    /// `None` disables periodic stats; a final snapshot is still emitted
    /// when the proxy shuts down.
    pub stats_interval_ms: Option<u64>,
    /// Key each emitting process signs its closing seal with (ADR-0016).
    /// `None` leaves streams unsigned, exactly as before.
    pub seal_key: Option<SealKey>,
}

/// Which process a stream belongs to. Each gets its own connection,
/// sequence space and hash chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamId {
    /// The `can` CLI process: run lifecycle and the entrypoint exec.
    Cli,
    /// The forked proxy process: egress, contracts, DLP, exchanges, stats.
    Proxy,
    /// The USER_NOTIF supervisor: argument-level syscall decisions.
    Supervisor,
}

impl StreamId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Proxy => "proxy",
            Self::Supervisor => "supervisor",
        }
    }
}

/// One process's connection to the event consumer.
pub struct EventStream {
    run_id: String,
    stream: StreamId,
    seal_key: Option<SealKey>,
    inner: Mutex<Inner>,
}

struct Inner {
    /// `None` once a write has failed — the stream is dead and further
    /// events are dropped rather than retried per event.
    writer: Option<Box<dyn Write + Send>>,
    seq: u64,
    prev_hash: [u8; 32],
}

impl EventStream {
    /// Open the configured target. Call this **before** joining any
    /// namespace, and once per emitting process.
    pub fn open(config: &EventConfig, stream: StreamId) -> Result<Self, EventError> {
        let writer: Box<dyn Write + Send> = match &config.target {
            EventTarget::Socket(path) => {
                // Rust sets SOCK_CLOEXEC, so the fd is gone after the
                // worker's execve — the sandboxed workload cannot forge
                // events.
                let sock = connect_socket(path).map_err(|source| EventError::Connect {
                    path: path.clone(),
                    source,
                })?;
                Box::new(sock)
            }
            EventTarget::File(path) => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|source| EventError::OpenFile {
                        path: path.clone(),
                        source,
                    })?;
                Box::new(file)
            }
        };

        Ok(
            Self::with_writer(&config.run_id, stream, writer)
                .with_seal_key(config.seal_key.clone()),
        )
    }

    /// Build a stream over an arbitrary writer. Used by tests and by
    /// callers that already own a file descriptor.
    pub fn with_writer(run_id: &str, stream: StreamId, writer: Box<dyn Write + Send>) -> Self {
        Self {
            run_id: run_id.to_string(),
            stream,
            seal_key: None,
            inner: Mutex::new(Inner {
                writer: Some(writer),
                seq: 0,
                prev_hash: GENESIS_HASH,
            }),
        }
    }

    /// Sign this stream's seal with `key` when it closes.
    pub fn with_seal_key(mut self, key: Option<SealKey>) -> Self {
        self.seal_key = key;
        self
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream
    }

    /// Serialize and write one event. Never panics, never fails a run.
    pub fn emit(&self, event: &Event) {
        // SAFETY-UNWRAP: the only code under this lock is serialization
        // and a write; a poisoned lock would mean a panic there, and
        // recovering the guard keeps event emission best-effort rather
        // than turning observability into a crash.
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if inner.writer.is_none() {
            return;
        }

        let line = match render_line(
            &self.run_id,
            self.stream,
            inner.seq,
            unix_ms(),
            &inner.prev_hash,
            event,
        ) {
            Ok(rendered) => rendered,
            Err(err) => {
                tracing::warn!(
                    event = event.name(),
                    error = %err,
                    "event stream: failed to serialize event, dropping it"
                );
                return;
            }
        };

        let write_result = inner
            .writer
            .as_mut()
            .map(|w| w.write_all(line.text.as_bytes()).and_then(|()| w.flush()));

        match write_result {
            Some(Ok(())) => {
                inner.seq += 1;
                inner.prev_hash = line.chain_hash;
            }
            Some(Err(err)) => {
                tracing::warn!(
                    stream = self.stream.as_str(),
                    error = %err,
                    "event stream: write failed, no further events will be emitted from this process"
                );
                inner.writer = None;
            }
            None => {}
        }
    }

    /// Close the stream with a signed seal over everything it emitted
    /// (ADR-0016), then stop emitting.
    ///
    /// Without a key this only closes the stream: an unsigned seal would
    /// look like evidence of authenticity while proving nothing. Safe to
    /// call twice — the second call finds a closed stream and does
    /// nothing, because shutdown paths are rarely as linear as they look.
    pub fn seal(&self) {
        let Some(key) = self.seal_key.as_ref() else {
            self.close();
            return;
        };

        let (events, chain_head) = {
            let inner = match self.inner.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };

            if inner.writer.is_none() {
                return;
            }

            (inner.seq, inner.prev_hash)
        };

        let seal = Event::StreamSeal(schema::StreamSeal {
            algorithm: seal::SEAL_ALGORITHM.to_string(),
            public_key: key.public_key_hex(),
            signature: key.sign(&self.run_id, self.stream.as_str(), events, &chain_head),
            events,
            chain_head: hex32(&chain_head),
        });

        self.emit(&seal);
        self.close();
    }

    fn close(&self) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        inner.writer = None;
    }

    /// Whether this stream is still writing. A stream goes dead on the
    /// first write it cannot complete, and stays dead.
    pub fn alive(&self) -> bool {
        match self.inner.lock() {
            Ok(guard) => guard.writer.is_some(),
            Err(poisoned) => poisoned.into_inner().writer.is_some(),
        }
    }

    /// Number of events written so far. Tests and the run summary use it.
    pub fn emitted(&self) -> u64 {
        match self.inner.lock() {
            Ok(guard) => guard.seq,
            Err(poisoned) => poisoned.into_inner().seq,
        }
    }
}

struct RenderedLine {
    text: String,
    chain_hash: [u8; 32],
}

/// The body of an envelope: every field except `chain_hash`, in a fixed
/// order. `chain_hash` is appended afterwards so it is always last and
/// the chain input is a plain prefix of the line.
#[derive(Serialize)]
struct Body<'a> {
    schema: u32,
    run_id: &'a str,
    stream: &'a str,
    seq: u64,
    ts_ms: u64,
    prev_hash: String,
    #[serde(flatten)]
    event: &'a Event,
}

/// Render one envelope line, including the trailing newline.
///
/// Public so consumers and golden tests can reproduce the exact bytes
/// `can` writes for a given event without running a sandbox.
pub fn render_envelope(
    run_id: &str,
    stream: StreamId,
    seq: u64,
    ts_ms: u64,
    prev_hash: &[u8; 32],
    event: &Event,
) -> Result<String, serde_json::Error> {
    render_line(run_id, stream, seq, ts_ms, prev_hash, event).map(|line| line.text)
}

fn render_line(
    run_id: &str,
    stream: StreamId,
    seq: u64,
    ts_ms: u64,
    prev_hash: &[u8; 32],
    event: &Event,
) -> Result<RenderedLine, serde_json::Error> {
    let body = serde_json::to_string(&Body {
        schema: SCHEMA_VERSION,
        run_id,
        stream: stream.as_str(),
        seq,
        ts_ms,
        prev_hash: hex32(prev_hash),
        event,
    })?;

    let chain_hash = chain_hash(body.as_bytes());

    // `body` ends with '}'; replace it with the chain_hash field so the
    // hashed prefix is exactly `body`.
    let mut text = String::with_capacity(body.len() + 80);
    text.push_str(&body[..body.len() - 1]);
    text.push_str(",\"chain_hash\":\"");
    text.push_str(&hex32(&chain_hash));
    text.push_str("\"}\n");

    Ok(RenderedLine { text, chain_hash })
}

/// `sha256` over the envelope body — the line minus its `chain_hash`
/// field. Consumers reproduce this by stripping the suffix.
pub fn chain_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Connect to the consumer and bound how long a write may block.
pub(crate) fn connect_socket(
    path: &std::path::Path,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    // Rust sets SOCK_CLOEXEC, so the fd is gone after the worker's
    // execve — the sandboxed workload cannot forge events.
    let sock = std::os::unix::net::UnixStream::connect(path)?;
    sock.set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok(sock)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Process-global stream
//
// Every emitting process installs exactly one stream. Forked children
// inherit the parent's installed stream; they must call `install` with
// their own connection (which drops the inherited one) before emitting.
// ---------------------------------------------------------------------------

static GLOBAL: Mutex<Option<Arc<EventStream>>> = Mutex::new(None);

/// Install this process's stream, replacing (and closing) any stream
/// inherited across `fork`.
pub fn install(stream: EventStream) {
    let mut guard = lock_global();
    *guard = Some(Arc::new(stream));
}

/// Remove the installed stream. Used by tests and by children that must
/// not emit at all.
pub fn uninstall() {
    let mut guard = lock_global();
    *guard = None;
}

/// Close this process's stream with a signed seal (ADR-0016).
///
/// Called once, where the process knows it has nothing left to say. A
/// process that exits without sealing leaves an unsealed stream, which a
/// consumer reports as unsealed rather than as tampered with: crashing
/// is not forgery.
pub fn seal() {
    if let Some(stream) = lock_global().as_ref() {
        stream.seal();
    }
}

/// Whether this process has an installed stream.
pub fn enabled() -> bool {
    lock_global().is_some()
}

/// Emit through the installed stream. A no-op when none is installed, so
/// call sites need no `if` around them.
pub fn emit(event: Event) {
    let stream = {
        let guard = lock_global();
        guard.as_ref().map(Arc::clone)
    };
    if let Some(stream) = stream {
        stream.emit(&event);
    }
}

fn lock_global() -> std::sync::MutexGuard<'static, Option<Arc<EventStream>>> {
    match GLOBAL.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests;
