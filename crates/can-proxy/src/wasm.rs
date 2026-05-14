use extism::{CancelHandle, Manifest, Plugin, Wasm};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("Failed to load plugin: {0}")]
    Load(String),
    #[error("Failed to execute plugin: {0}")]
    Execute(String),
    #[error("Wasm hook {function} for {domain} exceeded {timeout_ms} ms")]
    Timeout {
        domain: String,
        function: String,
        timeout_ms: u64,
    },
}

struct PluginEntry {
    plugin: parking_lot::Mutex<Plugin>,
    cancel: CancelHandle,
}

pub struct WasmEngine {
    plugins: HashMap<String, Arc<PluginEntry>>,
}

impl WasmEngine {
    pub fn new(interceptors: &HashMap<String, PathBuf>) -> Result<Self, WasmError> {
        let mut plugins = HashMap::new();

        for (domain, path) in interceptors {
            let wasm = Wasm::file(path);
            let manifest = Manifest::new([wasm]);
            match Plugin::new(&manifest, [], true) {
                Ok(plugin) => {
                    debug!(
                        "Loaded Wasm plugin for domain {} from {}",
                        domain,
                        path.display()
                    );
                    let cancel = plugin.cancel_handle();
                    plugins.insert(
                        domain.clone(),
                        Arc::new(PluginEntry {
                            plugin: parking_lot::Mutex::new(plugin),
                            cancel,
                        }),
                    );
                }
                Err(e) => {
                    return Err(WasmError::Load(format!(
                        "Failed to load plugin for {}: {}",
                        domain, e
                    )));
                }
            }
        }

        Ok(Self { plugins })
    }

    pub fn has_plugin(&self, domain: &str) -> bool {
        self.plugins.contains_key(domain)
    }

    /// Execute a Wasm hook with a deadline. If the plugin call exceeds
    /// `timeout`, the running call is cancelled via Extism's
    /// `CancelHandle` and `WasmError::Timeout` is returned.
    ///
    /// `parking_lot::Mutex` is used (not `std::sync::Mutex`) to avoid the
    /// poisoning failure mode where one cancelled call would render the
    /// plugin permanently unusable.
    pub fn execute(
        &self,
        domain: &str,
        function: &str,
        input: impl AsRef<[u8]>,
        timeout: Duration,
    ) -> Result<Vec<u8>, WasmError> {
        let entry = self
            .plugins
            .get(domain)
            .ok_or_else(|| WasmError::Execute(format!("No plugin for domain {}", domain)))?;

        // Arm a watchdog thread before locking. When `tx` is dropped (either
        // by an explicit send below, or by the function returning early), the
        // watchdog wakes via Disconnected and exits without cancelling. If the
        // deadline fires first, it triggers `cancel()` AND sets `cancelled`,
        // which is the authoritative signal that any subsequent plugin error
        // came from our timeout (not from a plugin-returned Err).
        let (tx, rx) = sync_channel::<()>(1);
        let cancel = entry.cancel.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_watchdog = cancelled.clone();
        let function_owned = function.to_string();
        let domain_owned = domain.to_string();
        let timeout_for_log = timeout;
        let watchdog = std::thread::spawn(move || match rx.recv_timeout(timeout_for_log) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
            Err(RecvTimeoutError::Timeout) => {
                cancelled_watchdog.store(true, Ordering::SeqCst);
                if let Err(e) = cancel.cancel() {
                    warn!(
                        "wasm watchdog: cancel() for {} {} failed: {}",
                        domain_owned, function_owned, e
                    );
                }
            }
        });

        let result = {
            let mut plugin = entry.plugin.lock();
            plugin
                .call::<_, &[u8]>(function, input.as_ref())
                .map(|o| o.to_vec())
        };

        // Tell the watchdog we're done — drop tx so the channel disconnects.
        drop(tx);
        let _ = watchdog.join();

        match result {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                if cancelled.load(Ordering::SeqCst) {
                    Err(WasmError::Timeout {
                        domain: domain.to_string(),
                        function: function.to_string(),
                        timeout_ms: timeout.as_millis() as u64,
                    })
                } else {
                    Err(WasmError::Execute(e.to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_engine_execute() {
        let mut interceptors = HashMap::new();
        let wasm_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm",
        );

        // If the wasm hasn't been built during `cargo test`, we skip the test instead of failing
        if !wasm_path.exists() {
            println!("Skipping WasmEngine test because test_plugin.wasm is not built.");
            return;
        }

        interceptors.insert("example.com".to_string(), wasm_path);

        let engine = WasmEngine::new(&interceptors).expect("Failed to initialize WasmEngine");

        assert!(engine.has_plugin("example.com"));
        assert!(!engine.has_plugin("other.com"));

        let input = serde_json::json!({
            "method": "GET",
            "uri": "https://example.com/test",
            "headers": {}
        });

        let result = engine
            .execute(
                "example.com",
                "on_request_headers",
                serde_json::to_vec(&input).unwrap(),
                Duration::from_secs(5),
            )
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(resp["action"], "Continue");
    }
}
