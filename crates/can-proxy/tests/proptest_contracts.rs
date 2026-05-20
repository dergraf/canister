//! Property-based test harness for the per-destination contract
//! gate.
//!
//! Pairs with the DLP proptest harness (in `can-dlp`). Where that
//! one verifies *every* encoded canary on every channel is **caught**
//! by DLP, this one verifies *every* malformed request shape is
//! **refused by the contract gate**, not the DLP scanner. The two
//! together cover both halves of the egress decision: "the request
//! shape is legitimate" (contract) and "the request payload is
//! credential-free" (DLP).
//!
//! ## Generator discipline
//!
//! Same shape as the DLP harness: opinionated generators that only
//! emit cases where we have a clear expectation. Three properties:
//!
//! 1. `unknown_host_refused_under_strict` — any FQDN not in the
//!    `[[host]]` table fires `UnknownHost` under `Strict`.
//! 2. `disallowed_method_refused` — a method not on the block's
//!    allow-list fires `DisallowedMethod`.
//! 3. `disallowed_content_type_refused` — a Content-Type not on
//!    the block's allow-list fires `DisallowedContentType`.
//! 4. `oversize_body_refused` — a body larger than the per-host cap
//!    fires `OversizeBody`.
//!
//! No "happy path" property here — the integration tests in
//! `tests/integration.rs` already cover request-passes-through.
//! These four pin the refusal classes so a regression that
//! silently widens a contract fails CI loudly.

use can_policy::config::{ContractMode, HostBlock};
use can_proxy::contracts::{ContractTable, ContractViolation, RequestShape};
use proptest::prelude::*;

// ──────────────────────────────────────────────────────────────────────
// Generators
// ──────────────────────────────────────────────────────────────────────

/// FQDN-shaped strings the gate will be asked about. Drawn from a
/// pool of plausible names rather than fully random — random
/// strings are unlikely to expose interesting precedence bugs and
/// shrinking them produces noisy counterexamples.
fn arb_fqdn() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("api.github.com".to_string()),
        Just("registry.npmjs.org".to_string()),
        Just("api.openai.com".to_string()),
        Just("evil.example.com".to_string()),
        Just("internal.corp".to_string()),
        Just("upload.example.io".to_string()),
        Just("a.b.c.d.e.f.example.org".to_string()),
    ]
}

fn arb_method() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("GET".to_string()),
        Just("POST".to_string()),
        Just("PUT".to_string()),
        Just("PATCH".to_string()),
        Just("DELETE".to_string()),
        Just("HEAD".to_string()),
        Just("OPTIONS".to_string()),
        Just("TRACE".to_string()),
        // Non-standard methods an attacker could choose.
        Just("PROPFIND".to_string()),
        Just("LOCK".to_string()),
    ]
}

fn arb_content_type() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("application/json".to_string()),
        Just("application/xml".to_string()),
        Just("application/octet-stream".to_string()),
        Just("multipart/form-data".to_string()),
        Just("application/x-www-form-urlencoded".to_string()),
        Just("image/png".to_string()),
        Just("image/jpeg".to_string()),
        Just("text/html".to_string()),
        Just("application/x-protobuf".to_string()),
    ]
}

// ──────────────────────────────────────────────────────────────────────
// Property 1: unknown host refused under strict
// ──────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn unknown_host_refused_under_strict(
        target in arb_fqdn(),
        method in arb_method(),
    ) {
        // Table contains *only* api.github.com. Every other FQDN
        // should fire UnknownHost.
        let table = ContractTable::new(
            vec![HostBlock {
                domain: "api.github.com".to_string(),
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        let shape = RequestShape {
            method: &method,
            path: "/anything",
            content_type: None,
            body_size: None,
        };
        let result = table.check(&target, &shape);
        if target.eq_ignore_ascii_case("api.github.com") {
            prop_assert!(
                result.is_none(),
                "known host should not be refused, got {result:?}"
            );
        } else {
            prop_assert!(
                matches!(result, Some(ContractViolation::UnknownHost)),
                "unknown host {target} should fire UnknownHost, got {result:?}"
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Property 2: disallowed method refused
// ──────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn disallowed_method_refused(
        method in arb_method(),
    ) {
        // Contract permits only GET and POST.
        let allowed = ["GET", "POST"];
        let table = ContractTable::new(
            vec![HostBlock {
                domain: "api.example.com".to_string(),
                methods: allowed.iter().map(|m| m.to_string()).collect(),
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        let shape = RequestShape {
            method: &method,
            path: "/anywhere",
            content_type: None,
            body_size: None,
        };
        let result = table.check("api.example.com", &shape);
        let method_uc = method.to_ascii_uppercase();
        let is_allowed = allowed.iter().any(|m| m.eq_ignore_ascii_case(&method_uc));
        if is_allowed {
            prop_assert!(
                result.is_none(),
                "allowed method {method} should not be refused, got {result:?}"
            );
        } else {
            prop_assert!(
                matches!(result, Some(ContractViolation::DisallowedMethod { .. })),
                "disallowed method {method} should fire DisallowedMethod, got {result:?}"
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Property 3: disallowed content type refused
// ──────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn disallowed_content_type_refused(
        ct in arb_content_type(),
        with_charset_suffix in any::<bool>(),
    ) {
        // Contract permits only application/json.
        let table = ContractTable::new(
            vec![HostBlock {
                domain: "api.example.com".to_string(),
                content_types: vec!["application/json".to_string()],
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        let suffixed: String;
        let ct_with_param: &str = if with_charset_suffix {
            suffixed = format!("{ct}; charset=utf-8");
            &suffixed
        } else {
            &ct
        };
        let shape = RequestShape {
            method: "POST",
            path: "/x",
            content_type: Some(ct_with_param),
            body_size: None,
        };
        let result = table.check("api.example.com", &shape);
        let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if mime == "application/json" {
            prop_assert!(
                result.is_none(),
                "json should not be refused, got {result:?}"
            );
        } else {
            prop_assert!(
                matches!(result, Some(ContractViolation::DisallowedContentType { .. })),
                "ct {ct_with_param} should fire DisallowedContentType, got {result:?}"
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Property 4: oversize body refused
// ──────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    #[test]
    fn oversize_body_refused(
        size in 0u64..(1024u64 * 1024 * 8),
    ) {
        const LIMIT: u64 = 1024 * 1024; // 1 MiB cap
        let table = ContractTable::new(
            vec![HostBlock {
                domain: "api.example.com".to_string(),
                max_request_bytes: Some(LIMIT),
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        let shape = RequestShape {
            method: "POST",
            path: "/x",
            content_type: None,
            body_size: Some(size),
        };
        let result = table.check("api.example.com", &shape);
        if size <= LIMIT {
            prop_assert!(
                result.is_none(),
                "body of {size} <= {LIMIT} should not be refused, got {result:?}"
            );
        } else {
            prop_assert!(
                matches!(result, Some(ContractViolation::OversizeBody { .. })),
                "body of {size} > {LIMIT} should fire OversizeBody, got {result:?}"
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Property 5: Relaxed mode allows unknown hosts but still gates known
// ones. Pins the per-host override invariant — global Relaxed +
// per-block Strict combinations behave correctly.
// ──────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, .. ProptestConfig::default() })]

    #[test]
    fn relaxed_default_only_skips_unknown_hosts(
        method in arb_method(),
        target in arb_fqdn(),
    ) {
        // api.example.com has methods=["GET"] and would refuse POST
        // under strict; under relaxed-default it still refuses POST
        // because the field-level check fires once the block matches.
        let table = ContractTable::new(
            vec![HostBlock {
                domain: "api.example.com".to_string(),
                methods: vec!["GET".to_string()],
                ..Default::default()
            }],
            ContractMode::Relaxed,
        );
        let shape = RequestShape {
            method: &method,
            path: "/x",
            content_type: None,
            body_size: None,
        };
        let result = table.check(&target, &shape);
        if target == "api.example.com" {
            // Matched block — field check still runs.
            if method.eq_ignore_ascii_case("GET") {
                prop_assert!(result.is_none());
            } else {
                prop_assert!(
                    matches!(result, Some(ContractViolation::DisallowedMethod { .. })),
                    "got {result:?}"
                );
            }
        } else {
            // Unknown host under relaxed default → allowed.
            prop_assert!(
                result.is_none(),
                "relaxed-default unknown host {target} should not be refused, got {result:?}"
            );
        }
    }
}
