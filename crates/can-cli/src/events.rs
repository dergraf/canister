//! CLI wiring for the structured event stream (ADR-0010).
//!
//! The flags live here rather than in `main.rs` so `can run` and `can up`
//! share one definition. `EventFlags::init` opens this process's stream and
//! returns the config that the sandbox hands to the proxy process, which
//! opens a connection of its own.

use std::path::PathBuf;

use anyhow::{Context, Result};
use can_events::{CaptureConfig, EventConfig, EventStream, EventTarget, SealKey, StreamId};
use clap::Args;

#[derive(Args, Debug, Clone)]
pub struct EventFlags {
    /// Stream structured run events to a Unix socket (SOCK_STREAM).
    ///
    /// `can` connects as a client; the consumer listens. One connection per
    /// emitting process. Schema: docs/events-schema-v1.json.
    #[arg(long, value_name = "PATH")]
    pub events_socket: Option<PathBuf>,

    /// Append structured run events to a file as JSON lines.
    #[arg(long, value_name = "PATH", conflicts_with = "events_socket")]
    pub events_file: Option<PathBuf>,

    /// Run identifier stamped on every event. Defaults to a generated id.
    #[arg(long, value_name = "ID")]
    pub run_id: Option<String>,

    /// Emit an `exchange` event per HTTP exchange through the proxy:
    /// request and response headers, bodies and timings (ADR-0011).
    ///
    /// Credential headers and configured secrets are always redacted.
    #[arg(long)]
    pub capture_exchanges: bool,

    /// Per-body capture cap in bytes. Larger bodies are truncated and
    /// flagged with `truncated: true`.
    #[arg(long, value_name = "BYTES", default_value_t = CaptureConfig::DEFAULT_MAX_BYTES)]
    pub capture_max_bytes: usize,

    /// How often the proxy emits a cumulative `stats` event, in
    /// milliseconds (ADR-0015). `0` disables periodic stats; a final
    /// snapshot is still emitted when the run ends.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_STATS_INTERVAL_MS)]
    pub stats_interval_ms: u64,

    /// Sign each stream's closing seal with this Ed25519 key, so a
    /// consumer can tell the bytes `can` wrote from bytes produced
    /// afterwards (ADR-0016).
    ///
    /// The file holds 32 raw bytes or 64 hex characters. The sandboxed
    /// workload never sees it: it is read before the namespace is
    /// entered and never enters the child's environment.
    #[arg(long, value_name = "PATH")]
    pub events_sign_key: Option<PathBuf>,
}

/// Frequent enough to show a run progressing, rare enough to stay out of
/// the way of the events that carry evidence.
pub const DEFAULT_STATS_INTERVAL_MS: u64 = 5_000;

/// Hand-written so `EventFlags::default()` matches what clap produces for
/// a command line with no event flags.
impl Default for EventFlags {
    fn default() -> Self {
        Self {
            events_socket: None,
            events_file: None,
            run_id: None,
            capture_exchanges: false,
            capture_max_bytes: CaptureConfig::DEFAULT_MAX_BYTES,
            stats_interval_ms: DEFAULT_STATS_INTERVAL_MS,
            events_sign_key: None,
        }
    }
}

impl EventFlags {
    fn target(&self) -> Option<EventTarget> {
        if let Some(path) = &self.events_socket {
            Some(EventTarget::Socket(path.clone()))
        } else {
            self.events_file.clone().map(EventTarget::File)
        }
    }

    /// Open and install this process's event stream.
    ///
    /// Returns the config to pass to the sandbox (`None` when no event flag
    /// was given, in which case `can` behaves exactly as before).
    pub fn init(&self) -> Result<Option<EventConfig>> {
        let Some(target) = self.target() else {
            if self.run_id.is_some() {
                anyhow::bail!("--run-id requires --events-socket or --events-file");
            }
            if self.capture_exchanges {
                anyhow::bail!("--capture-exchanges requires --events-socket or --events-file");
            }
            if self.events_sign_key.is_some() {
                anyhow::bail!("--events-sign-key requires --events-socket or --events-file");
            }
            return Ok(None);
        };

        if self.capture_max_bytes == 0 {
            anyhow::bail!("--capture-max-bytes must be greater than zero");
        }

        let config = EventConfig {
            target,
            run_id: self.run_id.clone().unwrap_or_else(generate_run_id),
            capture: CaptureConfig {
                exchanges: self.capture_exchanges,
                max_bytes: self.capture_max_bytes,
            },
            stats_interval_ms: Some(self.stats_interval_ms).filter(|ms| *ms > 0),
            seal_key: self
                .events_sign_key
                .as_deref()
                .map(SealKey::from_file)
                .transpose()
                .context("loading the event signing key")?,
        };

        let stream = EventStream::open(&config, StreamId::Cli)
            .context("opening the event stream for the can process")?;
        can_events::install(stream);

        Ok(Some(config))
    }
}

/// Generate a run id when the caller did not supply one. Unique enough to
/// tell two runs apart on one machine; orchestrators pass their own.
fn generate_run_id() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("can-{ms:x}-{:x}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flags_means_no_event_stream() {
        let flags = EventFlags::default();
        assert!(flags.init().expect("init").is_none());
    }

    #[test]
    fn run_id_without_a_target_is_an_error() {
        let flags = EventFlags {
            run_id: Some("r-1".to_string()),
            ..EventFlags::default()
        };
        let err = flags.init().expect_err("must be rejected");
        assert!(err.to_string().contains("--run-id requires"));
    }

    #[test]
    fn capture_without_a_target_is_an_error() {
        let flags = EventFlags {
            capture_exchanges: true,
            ..EventFlags::default()
        };
        let err = flags.init().expect_err("must be rejected");
        assert!(err.to_string().contains("--capture-exchanges requires"));
    }

    #[test]
    fn defaults_match_the_clap_defaults() {
        use clap::Parser;

        #[derive(Parser)]
        struct Harness {
            #[command(flatten)]
            events: EventFlags,
        }

        let parsed = Harness::parse_from(["can"]);
        assert_eq!(
            parsed.events.capture_max_bytes,
            EventFlags::default().capture_max_bytes
        );
        assert!(!parsed.events.capture_exchanges);
    }

    #[test]
    fn a_zero_capture_cap_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let flags = EventFlags {
            events_file: Some(dir.path().join("events.jsonl")),
            capture_exchanges: true,
            capture_max_bytes: 0,
            ..EventFlags::default()
        };
        let err = flags.init().expect_err("must be rejected");
        assert!(err.to_string().contains("--capture-max-bytes"));
    }

    #[test]
    fn a_zero_stats_interval_disables_periodic_stats() {
        let dir = tempfile::tempdir().expect("tempdir");
        let flags = EventFlags {
            events_file: Some(dir.path().join("events.jsonl")),
            stats_interval_ms: 0,
            ..EventFlags::default()
        };

        let config = flags.init().expect("init").expect("config");
        can_events::uninstall();

        assert_eq!(config.stats_interval_ms, None);
    }

    #[test]
    fn capture_settings_reach_the_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let flags = EventFlags {
            events_file: Some(dir.path().join("events.jsonl")),
            run_id: Some("r-capture".to_string()),
            capture_exchanges: true,
            capture_max_bytes: 4096,
            ..EventFlags::default()
        };

        let config = flags.init().expect("init").expect("config");
        can_events::uninstall();

        assert!(config.capture.exchanges);
        assert_eq!(config.capture.max_bytes, 4096);
        assert_eq!(config.stats_interval_ms, Some(DEFAULT_STATS_INTERVAL_MS));
    }

    #[test]
    fn file_target_is_opened_and_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("events.jsonl");
        let flags = EventFlags {
            events_file: Some(path.clone()),
            run_id: Some("r-file".to_string()),
            ..EventFlags::default()
        };

        let config = flags.init().expect("init").expect("config");
        assert!(!config.capture.exchanges, "capture is off unless asked for");
        assert_eq!(config.run_id, "r-file");
        assert_eq!(config.target, EventTarget::File(path.clone()));

        can_events::emit(can_events::Event::RunEnd(can_events::schema::RunEnd {
            exit_code: Some(0),
            error: None,
            duration_ms: 1,
        }));
        can_events::uninstall();

        let contents = std::fs::read_to_string(&path).expect("read events");
        assert!(contents.contains(r#""run_id":"r-file""#));
        assert!(contents.contains(r#""event":"run_end""#));
    }

    #[test]
    fn generated_run_ids_are_distinct_per_call() {
        assert_ne!(generate_run_id(), {
            std::thread::sleep(std::time::Duration::from_millis(2));
            generate_run_id()
        });
    }
}
