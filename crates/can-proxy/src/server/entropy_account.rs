//! Which session entropy budget a request body is charged to, and under
//! which scope its high-entropy bytes count as already delivered
//! (ADR-0020).

use hyper::HeaderMap;
use hyper::Uri;

/// Headers that say on whose behalf a request is made. Bytes delivered
/// under one credential do not count as delivered under another, so a
/// second account on a shared host is charged afresh.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
];

/// The budget a request body is charged to, beyond its host.
pub(super) struct EntropyAccount {
    /// Request target plus credential headers; see [`dedupe_scope`].
    pub(super) scope: String,
    /// The `[[host]]` override of the session budget, if any.
    pub(super) budget_override: Option<u64>,
}

impl EntropyAccount {
    pub(super) fn for_request(
        uri: &Uri,
        headers: &HeaderMap,
        budget_override: Option<u64>,
    ) -> Self {
        Self {
            scope: dedupe_scope(uri, headers),
            budget_override,
        }
    }

    pub(super) fn destination<'a>(&'a self, host: &'a str) -> can_dlp::EntropyDestination<'a> {
        can_dlp::EntropyDestination {
            host,
            scope: &self.scope,
            budget_override: self.budget_override,
        }
    }
}

/// The request target and credential header values, as one string. Any
/// difference between two requests — another endpoint, another account,
/// a rotated token — gives another scope, so deduplication only applies
/// where the same recipient demonstrably already holds the bytes.
fn dedupe_scope(uri: &Uri, headers: &HeaderMap) -> String {
    let mut scope = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    for name in CREDENTIAL_HEADERS {
        for value in headers.get_all(*name) {
            scope.push('\n');
            scope.push_str(name);
            scope.push('=');
            scope.push_str(&String::from_utf8_lossy(value.as_bytes()));
        }
    }
    scope
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, value.parse().unwrap());
        }
        map
    }

    fn scope(uri: &str, pairs: &[(&'static str, &'static str)]) -> String {
        dedupe_scope(&uri.parse().unwrap(), &headers(pairs))
    }

    #[test]
    fn the_same_endpoint_and_credential_share_a_scope() {
        let a = scope(
            "/v1/messages?beta=true",
            &[("x-api-key", "sk-1"), ("accept", "a")],
        );
        let b = scope(
            "/v1/messages?beta=true",
            &[("x-api-key", "sk-1"), ("accept", "b")],
        );
        assert_eq!(a, b);
    }

    #[test]
    fn another_credential_is_another_scope() {
        for header in CREDENTIAL_HEADERS {
            let a = scope("/gists", &[(*header, "victim")]);
            let b = scope("/gists", &[(*header, "attacker")]);
            assert_ne!(a, b, "{header} does not separate scopes");
        }
    }

    #[test]
    fn a_missing_credential_is_another_scope() {
        assert_ne!(
            scope("/gists", &[("authorization", "token victim")]),
            scope("/gists", &[])
        );
    }

    #[test]
    fn another_path_or_query_is_another_scope() {
        let base = scope("/repos/me/private", &[]);
        assert_ne!(base, scope("/repos/attacker/public", &[]));
        assert_ne!(base, scope("/repos/me/private?x=1", &[]));
    }

    #[test]
    fn an_absolute_form_uri_scopes_by_its_path() {
        assert_eq!(
            scope("http://api.example.com/v1/x?q=1", &[]),
            scope("/v1/x?q=1", &[])
        );
    }

    #[test]
    fn the_destination_carries_host_scope_and_override() {
        let account = EntropyAccount::for_request(
            &"/v1/messages".parse().unwrap(),
            &headers(&[("x-api-key", "sk-1")]),
            Some(4096),
        );
        let dest = account.destination("api.example.com");
        assert_eq!(dest.host, "api.example.com");
        assert_eq!(dest.scope, "/v1/messages\nx-api-key=sk-1");
        assert_eq!(dest.budget_override, Some(4096));
    }
}
