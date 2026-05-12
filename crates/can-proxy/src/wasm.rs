use extism::{Manifest, Plugin, Wasm};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::debug;

#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("Failed to load plugin: {0}")]
    Load(String),
    #[error("Failed to execute plugin: {0}")]
    Execute(String),
}

pub struct WasmEngine {
    plugins: HashMap<String, Arc<std::sync::Mutex<Plugin>>>,
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
                    plugins.insert(domain.clone(), Arc::new(std::sync::Mutex::new(plugin)));
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

    pub fn execute(
        &self,
        domain: &str,
        function: &str,
        input: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, WasmError> {
        if let Some(plugin) = self.plugins.get(domain) {
            let mut plugin = plugin.lock().unwrap();
            let input_ref = input.as_ref();
            match plugin.call::<_, &[u8]>(function, input_ref) {
                Ok(output) => Ok(output.to_vec()),
                Err(e) => Err(WasmError::Execute(e.to_string())),
            }
        } else {
            Err(WasmError::Execute(format!(
                "No plugin for domain {}",
                domain
            )))
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
            "headers": {},
            "body": ""
        });

        let result = engine
            .execute(
                "example.com",
                "handle_request",
                serde_json::to_vec(&input).unwrap(),
            )
            .unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(resp["status"], 200);
        assert_eq!(resp["body"], "eyJtZXNzYWdlIjogImhlbGxvIGZyb20gd2FzbSJ9");
    }
}
