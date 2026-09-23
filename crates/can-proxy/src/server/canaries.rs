//! Externally supplied, tagged canaries (ADR-0012).
//!
//! A generated canary token is a pure tripwire: it exists nowhere
//! legitimately, so any appearance on egress is an exfiltration attempt.
//! An *external* canary is different — an orchestrator plants it inside
//! synthetic data that the workload is supposed to use, so the same value
//! legitimately reaches some destinations and not others. The table below
//! answers that question for a fired canary: which data class was it, and
//! was this destination allowed to see it?

use can_policy::config::ExternalCanary;

/// Resolved external canaries for a proxy session. Small (one entry per
/// planted value) and read on every canary hit.
#[derive(Debug, Default)]
pub(super) struct ExternalCanaryTable {
    entries: Vec<ExternalCanary>,
}

/// What the enforcement layer needs to know about a fired canary.
pub(super) struct CanaryVerdict {
    pub(super) data_class: Option<String>,
    /// `true` when this destination is allowed to see this data class, so
    /// the fire is observational and the request proceeds.
    pub(super) allowed: bool,
}

impl ExternalCanaryTable {
    pub(super) fn new(entries: Vec<ExternalCanary>) -> Self {
        Self { entries }
    }

    pub(super) fn values(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.value.clone()).collect()
    }

    /// Classify a canary hit.
    ///
    /// `matched_text` is what the detector matched, which may be a
    /// decoded or normalized form, so an entry matches when either value
    /// contains the other. A hit that belongs to no external canary is a
    /// generated tripwire: no data class, never allowed.
    pub(super) fn classify(&self, matched_text: &str, host: &str) -> CanaryVerdict {
        let Some(entry) = self.lookup(matched_text) else {
            return CanaryVerdict {
                data_class: None,
                allowed: false,
            };
        };

        CanaryVerdict {
            data_class: Some(entry.data_class.clone()),
            allowed: entry.allows_host(host),
        }
    }

    fn lookup(&self, matched_text: &str) -> Option<&ExternalCanary> {
        self.entries
            .iter()
            .find(|entry| matched_text.contains(&entry.value) || entry.value.contains(matched_text))
    }
}

#[cfg(test)]
mod tests;
