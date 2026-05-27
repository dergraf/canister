use rand::Rng;

use crate::registry::{Charset, REGISTRY, lookup};

/// One generated canary: which detector it belongs to, where it lives
/// in the worker's env, and its random value.
#[derive(Debug, Clone)]
pub struct CanaryValue {
    pub detector_id: &'static str,
    pub env_var: &'static str,
    pub value: String,
}

/// A session-scoped set of canary tokens, one per detector that has a
/// `CanarySpec` in the registry. The sandbox injects each as an env
/// var; the proxy scans for the values in outbound bodies/headers and
/// in inbound responses.
///
/// Adding a new canary is **one registry edit** (`canary: Some(...)`).
/// This struct and its methods don't change.
pub struct CanarySet {
    values: Vec<CanaryValue>,
}

impl CanarySet {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut values = Vec::new();
        for def in REGISTRY {
            let Some(spec) = def.canary else { continue };
            let random = match spec.charset {
                Charset::Alnum => random_alnum(&mut rng, spec.random_len),
                Charset::UpperAlnum => random_upper_alnum(&mut rng, spec.random_len),
            };
            values.push(CanaryValue {
                detector_id: def.id,
                env_var: spec.env_var,
                value: format!("{}{}", spec.prefix, random),
            });
        }
        Self { values }
    }

    /// All canary token values (without metadata). Used to seed the
    /// regex set's substring matcher and the proxy's response scanner.
    pub fn values(&self) -> Vec<String> {
        self.values.iter().map(|c| c.value.clone()).collect()
    }

    /// `(env_var, value)` pairs to inject into the worker's
    /// environment. The sandbox's namespace setup iterates this list.
    pub fn env_vars(&self) -> Vec<(&'static str, &str)> {
        self.values
            .iter()
            .map(|c| (c.env_var, c.value.as_str()))
            .collect()
    }

    /// Iterate over the (detector_id, env_var, value) triples. Used by
    /// tests and the response scanner that wants to attribute a canary
    /// fire to its origin detector.
    pub fn entries(&self) -> impl Iterator<Item = &CanaryValue> {
        self.values.iter()
    }
}

/// Generate a *fake* credential value matching `detector_id`'s pattern,
/// for the env-var fake-secret swap (`[network.dlp] fake_secrets`). The
/// value is shaped by the detector's [`crate::registry::CanarySpec`] so
/// it fires that detector's regex — exactly the property that lets the
/// scanner block it when it flows to an unauthorized host.
///
/// Returns `None` when the detector is unknown or has no generation spec.
/// Callers fail safe by leaving the variable unset (never injecting the
/// real secret) rather than substituting an unrecognizable fake.
///
/// Distinct from [`CanarySet`]: a faked secret is injected under the
/// *real* env-var name and is swappable at authorized hosts, whereas a
/// canary is a pure honeypot injected under `CANISTER_CANARY_*` and never
/// swapped.
pub fn generate_fake(detector_id: &str) -> Option<String> {
    let spec = lookup(detector_id)?.canary?;
    let mut rng = rand::thread_rng();
    let random = match spec.charset {
        Charset::Alnum => random_alnum(&mut rng, spec.random_len),
        Charset::UpperAlnum => random_upper_alnum(&mut rng, spec.random_len),
    };
    Some(format!("{}{}", spec.prefix, random))
}

fn random_alnum(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_upper_alnum(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::PatternSet;

    #[test]
    fn every_registered_canary_appears_in_set() {
        // Walking the registry to enumerate expectations means adding a
        // new canary is a single registry edit; this test grows
        // automatically.
        let canaries = CanarySet::generate();
        for def in REGISTRY {
            let Some(spec) = def.canary else { continue };
            let found = canaries
                .entries()
                .find(|c| c.detector_id == def.id)
                .unwrap_or_else(|| panic!("no canary generated for {}", def.id));
            assert_eq!(
                found.env_var, spec.env_var,
                "[{}] env_var mismatch with registry",
                def.id
            );
            assert!(
                found.value.starts_with(spec.prefix),
                "[{}] canary {:?} doesn't start with prefix {:?}",
                def.id,
                found.value,
                spec.prefix,
            );
            assert_eq!(
                found.value.len(),
                spec.prefix.len() + spec.random_len,
                "[{}] canary length mismatch",
                def.id
            );
        }
    }

    #[test]
    fn canary_values_match_their_detectors() {
        // The registry-side test `canary_prefix_matches_detector_regex`
        // verifies a synthesised sample matches; this verifies the
        // *runtime-generated* canary also fires the right detector.
        let canaries = CanarySet::generate();
        let ps = PatternSet::new().unwrap();
        for c in canaries.entries() {
            let findings = ps.scan(&c.value);
            assert!(
                findings
                    .iter()
                    .any(|f| f.detector.as_str() == c.detector_id),
                "canary for {} (value={:?}) did not fire its own detector; findings={:?}",
                c.detector_id,
                c.value,
                findings
                    .iter()
                    .map(|f| f.detector.as_str())
                    .collect::<Vec<_>>(),
            );
        }
    }

    #[test]
    fn canary_tokens_are_unique() {
        // Different sessions get different values. Don't pin a specific
        // detector; any canary detector in the registry counts.
        let a = CanarySet::generate();
        let b = CanarySet::generate();
        assert_eq!(a.values().len(), b.values().len());
        for (av, bv) in a.entries().zip(b.entries()) {
            assert_eq!(av.detector_id, bv.detector_id);
            assert_ne!(
                av.value, bv.value,
                "canary for {} was not random across sessions",
                av.detector_id
            );
        }
    }

    #[test]
    fn generate_fake_fires_its_detector() {
        // A faked secret must match its credential detector's regex so the
        // scanner can block it when it flows to an unauthorized host.
        let ps = PatternSet::new().unwrap();
        for def in REGISTRY {
            if def.canary.is_none() {
                continue;
            }
            let fake = generate_fake(def.id)
                .unwrap_or_else(|| panic!("generate_fake returned None for {}", def.id));
            let findings = ps.scan(&fake);
            assert!(
                findings.iter().any(|f| f.detector.as_str() == def.id),
                "fake for {} (value={fake:?}) did not fire its own detector",
                def.id
            );
        }
    }

    #[test]
    fn generate_fake_unknown_detector_is_none() {
        assert!(generate_fake("no_such_detector").is_none());
        // `bearer_token` is a real detector but has no canary/generation spec.
        assert!(generate_fake("bearer_token").is_none());
    }

    #[test]
    fn env_vars_export_every_canary() {
        // The sandbox iterates env_vars() to inject canaries into the
        // worker. Lengths must match.
        let canaries = CanarySet::generate();
        assert_eq!(canaries.env_vars().len(), canaries.values().len());
        for (var, val) in canaries.env_vars() {
            assert!(var.starts_with("CANISTER_CANARY_"));
            assert!(!val.is_empty());
        }
    }
}
