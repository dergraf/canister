//! Unit tests for the external canary table.

use super::*;

fn canary(value: &str, data_class: &str, allowed_hosts: &[&str]) -> ExternalCanary {
    ExternalCanary {
        value: value.to_string(),
        data_class: data_class.to_string(),
        allowed_hosts: allowed_hosts.iter().map(|h| h.to_string()).collect(),
    }
}

fn table() -> ExternalCanaryTable {
    ExternalCanaryTable::new(vec![
        canary(
            "CNRY-7Q2X-AHV",
            "ahv",
            &["claims.mock.internal", "api.anthropic.com"],
        ),
        canary("CNRY-5H1M-DIAG", "diagnosis", &["medcodes.mock.internal"]),
        canary("CNRY-NOEXIT", "secret", &[]),
    ])
}

#[test]
fn an_allowed_destination_is_observed_not_blocked() {
    let verdict = table().classify("CNRY-7Q2X-AHV", "claims.mock.internal");

    assert_eq!(verdict.data_class.as_deref(), Some("ahv"));
    assert!(verdict.allowed);
}

#[test]
fn a_subdomain_of_an_allowed_destination_is_allowed() {
    let verdict = table().classify("CNRY-7Q2X-AHV", "eu.api.anthropic.com");

    assert!(verdict.allowed);
}

#[test]
fn a_different_destination_is_a_leak() {
    let verdict = table().classify("CNRY-7Q2X-AHV", "medcodes.mock.internal");

    assert_eq!(verdict.data_class.as_deref(), Some("ahv"));
    assert!(!verdict.allowed);
}

#[test]
fn an_empty_allow_list_means_the_value_may_not_leave_at_all() {
    let verdict = table().classify("CNRY-NOEXIT", "claims.mock.internal");

    assert_eq!(verdict.data_class.as_deref(), Some("secret"));
    assert!(!verdict.allowed);
}

#[test]
fn a_value_embedded_in_a_larger_match_is_still_classified() {
    let verdict = table().classify("prefix CNRY-5H1M-DIAG suffix", "medcodes.mock.internal");

    assert_eq!(verdict.data_class.as_deref(), Some("diagnosis"));
    assert!(verdict.allowed);
}

#[test]
fn a_generated_tripwire_has_no_class_and_is_never_allowed() {
    let verdict = table().classify("ghp_generated_canary", "claims.mock.internal");

    assert_eq!(verdict.data_class, None);
    assert!(!verdict.allowed);
}

#[test]
fn a_host_that_merely_ends_with_the_allowed_name_is_not_a_subdomain() {
    let verdict = table().classify("CNRY-7Q2X-AHV", "evil-claims.mock.internal.attacker.test");

    assert!(!verdict.allowed);
}

#[test]
fn an_empty_table_classifies_nothing() {
    let empty = ExternalCanaryTable::default();

    assert!(empty.values().is_empty());
    assert_eq!(empty.classify("anything", "host.example").data_class, None);
}

#[test]
fn values_feed_the_detector_set() {
    assert_eq!(
        table().values(),
        vec!["CNRY-7Q2X-AHV", "CNRY-5H1M-DIAG", "CNRY-NOEXIT"]
    );
}

/// A value must not inherit another entry's permissions by being a
/// prefix of it.
///
/// Structured identifiers overlap by construction: an AHV number and the
/// same number with its check digits, an IBAN and its account part. If a
/// shorter match can resolve to a longer entry, the *narrower* value
/// silently acquires the *wider* value's allowed destinations, and a
/// leak is recorded as an expected flow.
#[test]
fn a_shorter_value_does_not_inherit_a_longer_entrys_permissions() {
    let table = ExternalCanaryTable::new(vec![
        ExternalCanary {
            value: "756.1234.5678.9712".to_string(),
            data_class: "ahv".to_string(),
            allowed_hosts: vec!["analytics.vendor.example".to_string()],
        },
        ExternalCanary {
            value: "756.1234.5678.97".to_string(),
            data_class: "ahv".to_string(),
            allowed_hosts: vec![],
        },
    ]);

    let verdict = table.classify("756.1234.5678.97", "analytics.vendor.example");

    assert!(
        !verdict.allowed,
        "the entry that may not leave at all must not borrow the other's allow-list"
    );
}

/// The longest entry that matches wins, whatever order they are listed
/// in: a prefix entry must not shadow a more specific one.
#[test]
fn the_most_specific_match_wins() {
    let table = ExternalCanaryTable::new(vec![
        ExternalCanary {
            value: "756.1234".to_string(),
            data_class: "partial".to_string(),
            allowed_hosts: vec![],
        },
        ExternalCanary {
            value: "756.1234.5678.9712".to_string(),
            data_class: "ahv".to_string(),
            allowed_hosts: vec!["analytics.vendor.example".to_string()],
        },
    ]);

    let verdict = table.classify("756.1234.5678.9712", "analytics.vendor.example");

    assert_eq!(verdict.data_class.as_deref(), Some("ahv"));
    assert!(verdict.allowed);
}
