use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::merge::merge_or_bool;

/// Data Loss Prevention configuration for the egress proxy.
///
/// When enabled, the proxy scans outbound requests for credential patterns
/// (GitHub PATs, npm tokens, AWS keys, etc.) and enforces per-detector
/// domain scoping: each token type can only flow to its home service.
#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DlpConfig {
    /// Enable DLP scanning. Implicitly enabled in `--strict` mode when
    /// `egress = "proxy-only"`.
    #[serde(default)]
    pub enabled: Option<bool>,

    /// Inject canary tokens (fake credentials) into the sandbox environment
    /// to detect exfiltration attempts. Default: true when DLP is enabled.
    #[serde(default)]
    pub canary_tokens: Option<bool>,

    /// Maximum encoding chain recursion depth (base64, hex, percent-encoding).
    /// Default: 32.
    #[serde(default)]
    pub max_decode_depth: Option<usize>,

    /// Decompress request bodies (gzip/deflate/brotli) before scanning.
    /// Default: true.
    #[serde(default)]
    pub decompress: Option<bool>,

    /// Normalised per-label entropy ratio for DNS exfiltration detection.
    /// A label's Shannon entropy is divided by `log2(len)` to get a value in
    /// `[0.0, 1.0]`; the FQDN trips when two or more labels exceed this
    /// ratio. Default: 0.92. (Pre-2026-05 configs used absolute bits — those
    /// values are now clamped to 1.0 and effectively disable the check.)
    #[serde(default)]
    pub dns_entropy_threshold: Option<f64>,

    /// Cumulative high-entropy bytes allowed per sandbox session before
    /// requests are blocked. Default: 8192.
    #[serde(default)]
    pub session_entropy_budget: Option<u64>,

    /// Env-var secrets the sandbox should never see in cleartext. For
    /// each entry the sandbox is given a *fake* value (matching the
    /// named credential's format); the proxy swaps it for the real host
    /// value only on egress to a host authorized for that credential
    /// (`[[host]] allow_credentials` / the detector's home domains). A
    /// secret the sandbox encrypts and exfiltrates therefore only ever
    /// leaks the useless fake. See `docs/refusals.md`.
    #[serde(default)]
    pub fake_secrets: Vec<FakeSecret>,
}

/// One env-var secret to fake-and-swap. `env` is the variable name the
/// real secret normally arrives in (e.g. `GITHUB_TOKEN`); `credential`
/// is the DLP detector id (e.g. `github_pat`) that classifies it. The
/// detector governs both fake generation (the fake matches its pattern)
/// and swap authorization (the fake is swapped wherever that detector is
/// in scope).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FakeSecret {
    pub env: String,
    pub credential: String,
}

impl DlpConfig {
    pub const DEFAULT_MAX_DECODE_DEPTH: usize = 32;
    pub const DEFAULT_DNS_ENTROPY_THRESHOLD: f64 = 0.92;
    pub const DEFAULT_SESSION_ENTROPY_BUDGET: u64 = 8192;

    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    pub fn canary_tokens(&self) -> bool {
        self.canary_tokens.unwrap_or(true)
    }

    pub fn max_decode_depth(&self) -> usize {
        self.max_decode_depth
            .unwrap_or(Self::DEFAULT_MAX_DECODE_DEPTH)
    }

    pub fn decompress(&self) -> bool {
        self.decompress.unwrap_or(true)
    }

    pub fn dns_entropy_threshold(&self) -> f64 {
        self.dns_entropy_threshold
            .unwrap_or(Self::DEFAULT_DNS_ENTROPY_THRESHOLD)
    }

    pub fn session_entropy_budget(&self) -> u64 {
        self.session_entropy_budget
            .unwrap_or(Self::DEFAULT_SESSION_ENTROPY_BUDGET)
    }

    /// Merge two `DlpConfig` values.
    ///
    /// - `enabled`, `canary_tokens`: OR semantics (a security escalation
    ///   in either layer wins).
    /// - Numeric / `Option<T>` fields: last-Some-wins.
    fn merge_inner(self, overlay: Self) -> Self {
        Self {
            enabled: merge_or_bool(self.enabled, overlay.enabled),
            canary_tokens: merge_or_bool(self.canary_tokens, overlay.canary_tokens),
            max_decode_depth: overlay.max_decode_depth.or(self.max_decode_depth),
            decompress: overlay.decompress.or(self.decompress),
            dns_entropy_threshold: overlay.dns_entropy_threshold.or(self.dns_entropy_threshold),
            session_entropy_budget: overlay
                .session_entropy_budget
                .or(self.session_entropy_budget),
            fake_secrets: merge_fake_secrets(self.fake_secrets, overlay.fake_secrets),
        }
    }
}

/// Union two `fake_secrets` lists keyed by `env`: base order is
/// preserved, and an overlay entry for an already-declared `env`
/// overrides its `credential` (last-Some-wins, matching the rest of the
/// DLP merge) rather than producing two conflicting fakes for one var.
fn merge_fake_secrets(base: Vec<FakeSecret>, overlay: Vec<FakeSecret>) -> Vec<FakeSecret> {
    let mut out = base;
    for o in overlay {
        match out.iter_mut().find(|e| e.env == o.env) {
            Some(existing) => existing.credential = o.credential,
            None => out.push(o),
        }
    }
    out
}

/// Lift `DlpConfig::merge_inner` over `Option<DlpConfig>`. The DLP
/// section is optional, so the wrapper handles the four base/overlay
/// presence combinations.
pub fn merge_dlp(base: Option<DlpConfig>, overlay: Option<DlpConfig>) -> Option<DlpConfig> {
    match (base, overlay) {
        (None, None) => None,
        (Some(b), None) => Some(b),
        (None, Some(o)) => Some(o),
        (Some(b), Some(o)) => Some(b.merge_inner(o)),
    }
}
