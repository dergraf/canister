//! `--canaries-file`: external, tagged canaries supplied per run (ADR-0012).
//!
//! An orchestrator that generates synthetic data for the workload knows
//! which values it planted and where each may legitimately go. Writing
//! that into `canister.toml` per run would be awkward, so the same shape
//! is accepted as a JSON file:
//!
//! ```json
//! [{"value":"CNRY-7Q2X-AHV","data_class":"ahv",
//!   "allowed_hosts":["claims.mock.internal","api.anthropic.com"]}]
//! ```

use std::path::Path;

use anyhow::{Context, Result};
use can_policy::SandboxConfig;
use can_policy::config::{DlpConfig, ExternalCanary};

/// Parse a canaries file and merge it into the resolved policy.
///
/// Entries merge exactly like `[[network.dlp.external_canaries]]` in a
/// recipe: a value declared in both places takes the file's class and
/// destinations.
pub fn apply_canaries_file(config: &mut SandboxConfig, path: &Path) -> Result<()> {
    let canaries = load(path)?;
    let count = canaries.len();

    let dlp = config.network.dlp.get_or_insert_with(DlpConfig::default);
    for canary in canaries {
        match dlp
            .external_canaries
            .iter_mut()
            .find(|existing| existing.value == canary.value)
        {
            Some(existing) => *existing = canary,
            None => dlp.external_canaries.push(canary),
        }
    }

    if !dlp.is_enabled() && config.network.egress() != can_policy::config::EgressMode::ProxyOnly {
        tracing::warn!(
            "external canaries were supplied but DLP is off; they will not be watched for. \
             Set `egress = \"proxy-only\"` or `[network.dlp] enabled = true`."
        );
    }

    tracing::info!(count, path = %path.display(), "loaded external canaries");
    Ok(())
}

fn load(path: &Path) -> Result<Vec<ExternalCanary>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading canaries file {}", path.display()))?;
    let canaries: Vec<ExternalCanary> = serde_json::from_str(&text)
        .with_context(|| format!("parsing canaries file {}", path.display()))?;

    for canary in &canaries {
        if canary.value.trim().is_empty() {
            anyhow::bail!("{}: a canary value must not be empty", path.display());
        }
        if canary.data_class.trim().is_empty() {
            anyhow::bail!(
                "{}: canary '{}' has no data_class",
                path.display(),
                canary.value
            );
        }
    }

    Ok(canaries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("canaries.json");
        std::fs::write(&path, body).expect("write canaries");
        path
    }

    fn proxy_only_config() -> SandboxConfig {
        let mut config = SandboxConfig::default_deny();
        config.network.egress = Some(can_policy::config::EgressMode::ProxyOnly);
        config
    }

    #[test]
    fn canaries_are_added_to_the_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            &dir,
            r#"[{"value":"CNRY-1","data_class":"ahv","allowed_hosts":["claims.example"]}]"#,
        );
        let mut config = proxy_only_config();

        apply_canaries_file(&mut config, &path).expect("apply");

        let dlp = config.network.dlp.expect("dlp section created");
        assert_eq!(dlp.external_canaries.len(), 1);
        assert_eq!(dlp.external_canaries[0].data_class, "ahv");
        assert_eq!(dlp.external_canaries[0].allowed_hosts, ["claims.example"]);
    }

    #[test]
    fn allowed_hosts_may_be_omitted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(&dir, r#"[{"value":"CNRY-1","data_class":"secret"}]"#);
        let mut config = proxy_only_config();

        apply_canaries_file(&mut config, &path).expect("apply");

        let dlp = config.network.dlp.expect("dlp section");
        assert!(dlp.external_canaries[0].allowed_hosts.is_empty());
    }

    #[test]
    fn a_file_entry_replaces_a_recipe_entry_for_the_same_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            &dir,
            r#"[{"value":"CNRY-1","data_class":"iban_ch","allowed_hosts":["bank.example"]}]"#,
        );
        let mut config = proxy_only_config();
        config.network.dlp = Some(DlpConfig {
            external_canaries: vec![ExternalCanary {
                value: "CNRY-1".to_string(),
                data_class: "ahv".to_string(),
                allowed_hosts: vec!["claims.example".to_string()],
            }],
            ..DlpConfig::default()
        });

        apply_canaries_file(&mut config, &path).expect("apply");

        let dlp = config.network.dlp.expect("dlp section");
        assert_eq!(dlp.external_canaries.len(), 1, "no duplicate value");
        assert_eq!(dlp.external_canaries[0].data_class, "iban_ch");
    }

    #[test]
    fn an_empty_file_is_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(&dir, "[]");
        let mut config = proxy_only_config();

        apply_canaries_file(&mut config, &path).expect("apply");

        assert!(
            config
                .network
                .dlp
                .expect("dlp section")
                .external_canaries
                .is_empty()
        );
    }

    #[test]
    fn a_canary_without_a_data_class_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(&dir, r#"[{"value":"CNRY-1","data_class":"  "}]"#);
        let mut config = proxy_only_config();

        let err = apply_canaries_file(&mut config, &path).expect_err("must be rejected");
        assert!(err.to_string().contains("data_class"));
    }

    #[test]
    fn malformed_json_reports_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(&dir, "{not json}");
        let mut config = proxy_only_config();

        let err = apply_canaries_file(&mut config, &path).expect_err("must be rejected");
        assert!(format!("{err:#}").contains("canaries.json"));
    }

    #[test]
    fn a_missing_file_reports_the_path() {
        let mut config = proxy_only_config();

        let err = apply_canaries_file(&mut config, Path::new("/nonexistent/canaries.json"))
            .expect_err("must be rejected");
        assert!(format!("{err:#}").contains("/nonexistent/canaries.json"));
    }
}
