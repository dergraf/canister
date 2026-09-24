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
    /// contains the other — see [`Self::lookup`] for why the direction
    /// matters. A hit that belongs to no external canary is a generated
    /// tripwire: no data class, never allowed.
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

    /// The entry a match belongs to.
    ///
    /// Two kinds of match, and the order between them is what keeps a
    /// value from borrowing another entry's permissions:
    ///
    /// 1. **The entry's value is in the traffic** — the value really did
    ///    leave. The longest such entry wins, so a short prefix entry
    ///    cannot shadow the specific one it is a prefix of.
    /// 2. **The traffic is part of an entry's value** — a detector
    ///    reported a decoded or normalized form. Only considered when
    ///    nothing matched the first way: otherwise a narrow value with
    ///    no allowed destinations would resolve to a wider entry that
    ///    has one, and a leak would be recorded as an expected flow.
    fn lookup(&self, matched_text: &str) -> Option<&ExternalCanary> {
        let longest = |left: &&ExternalCanary, right: &&ExternalCanary| {
            left.value.len().cmp(&right.value.len())
        };

        self.entries
            .iter()
            .filter(|entry| matched_text.contains(&entry.value))
            .max_by(longest)
            .or_else(|| {
                self.entries
                    .iter()
                    .filter(|entry| entry.value.contains(matched_text))
                    .max_by(longest)
            })
    }
}

#[cfg(test)]
mod tests;
