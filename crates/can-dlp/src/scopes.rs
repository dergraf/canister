use std::collections::HashMap;

use crate::detectors::DetectorId;

pub fn domain_matches(host: &str, pattern: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if host == pattern {
        return true;
    }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        return host.ends_with(suffix);
    }
    host.ends_with(&format!(".{pattern}"))
}

fn builtin_home_domains(detector: DetectorId) -> &'static [&'static str] {
    match detector {
        DetectorId::GithubPat => &["github.com", "*.github.com"],
        DetectorId::NpmToken => &["registry.npmjs.org"],
        DetectorId::AwsAccessKey => &["*.amazonaws.com"],
        DetectorId::SlackToken => &["*.slack.com"],
        DetectorId::SshPrivateKey | DetectorId::CanaryToken => &[],
        DetectorId::BearerToken | DetectorId::GenericHighEntropy => &[],
    }
}

pub struct DlpScopes {
    scopes: HashMap<DetectorId, Vec<String>>,
}

impl DlpScopes {
    pub fn new(extra_scopes: &HashMap<String, Vec<String>>) -> Self {
        let mut scopes = HashMap::new();

        for &detector in DetectorId::all() {
            let mut domains: Vec<String> = builtin_home_domains(detector)
                .iter()
                .map(|s| s.to_string())
                .collect();

            if let Some(extras) = extra_scopes.get(detector.as_str()) {
                for extra in extras {
                    if !domains.contains(extra) {
                        domains.push(extra.clone());
                    }
                }
            }
            scopes.insert(detector, domains);
        }

        Self { scopes }
    }

    pub fn is_allowed(
        &self,
        detector: DetectorId,
        destination_host: &str,
        allowed_domains: &[String],
    ) -> bool {
        match detector {
            DetectorId::SshPrivateKey | DetectorId::CanaryToken => false,

            DetectorId::BearerToken | DetectorId::GenericHighEntropy => allowed_domains
                .iter()
                .any(|d| domain_matches(destination_host, d)),

            _ => {
                let home = self
                    .scopes
                    .get(&detector)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                home.iter().any(|d| domain_matches(destination_host, d))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn scopes() -> DlpScopes {
        DlpScopes::new(&HashMap::new())
    }

    #[test]
    fn github_pat_allowed_to_github() {
        let s = scopes();
        assert!(s.is_allowed(DetectorId::GithubPat, "github.com", &[]));
        assert!(s.is_allowed(DetectorId::GithubPat, "api.github.com", &[]));
    }

    #[test]
    fn github_pat_blocked_to_npm() {
        let s = scopes();
        assert!(!s.is_allowed(DetectorId::GithubPat, "registry.npmjs.org", &[]));
    }

    #[test]
    fn npm_token_allowed_to_npmjs() {
        let s = scopes();
        assert!(s.is_allowed(DetectorId::NpmToken, "registry.npmjs.org", &[]));
    }

    #[test]
    fn npm_token_blocked_to_github() {
        let s = scopes();
        assert!(!s.is_allowed(DetectorId::NpmToken, "github.com", &[]));
    }

    #[test]
    fn aws_key_allowed_to_amazonaws() {
        let s = scopes();
        assert!(s.is_allowed(DetectorId::AwsAccessKey, "s3.amazonaws.com", &[]));
        assert!(s.is_allowed(DetectorId::AwsAccessKey, "sts.us-east-1.amazonaws.com", &[]));
    }

    #[test]
    fn aws_key_blocked_to_attacker() {
        let s = scopes();
        assert!(!s.is_allowed(DetectorId::AwsAccessKey, "evil.com", &[]));
    }

    #[test]
    fn slack_token_allowed_to_slack() {
        let s = scopes();
        assert!(s.is_allowed(DetectorId::SlackToken, "hooks.slack.com", &[]));
    }

    #[test]
    fn ssh_key_always_blocked() {
        let s = scopes();
        assert!(!s.is_allowed(DetectorId::SshPrivateKey, "github.com", &[]));
        assert!(!s.is_allowed(DetectorId::SshPrivateKey, "any.host", &[]));
    }

    #[test]
    fn canary_always_blocked() {
        let s = scopes();
        assert!(!s.is_allowed(DetectorId::CanaryToken, "github.com", &[]));
    }

    #[test]
    fn bearer_token_allowed_to_allow_domains() {
        let s = scopes();
        let allowed = vec!["api.example.com".to_string()];
        assert!(s.is_allowed(DetectorId::BearerToken, "api.example.com", &allowed));
        assert!(!s.is_allowed(DetectorId::BearerToken, "evil.com", &allowed));
    }

    #[test]
    fn extra_scopes_extend_builtin() {
        let mut extras = HashMap::new();
        extras.insert(
            "github_pat".to_string(),
            vec!["github.corp.example.com".to_string()],
        );
        let s = DlpScopes::new(&extras);
        assert!(s.is_allowed(DetectorId::GithubPat, "github.com", &[]));
        assert!(s.is_allowed(DetectorId::GithubPat, "github.corp.example.com", &[]));
        assert!(!s.is_allowed(DetectorId::GithubPat, "evil.com", &[]));
    }

    #[test]
    fn domain_matches_exact() {
        assert!(domain_matches("github.com", "github.com"));
        assert!(!domain_matches("evil.com", "github.com"));
    }

    #[test]
    fn domain_matches_subdomain() {
        assert!(domain_matches("api.github.com", "github.com"));
        assert!(!domain_matches("notgithub.com", "github.com"));
    }

    #[test]
    fn domain_matches_wildcard() {
        assert!(domain_matches("hooks.slack.com", "*.slack.com"));
        assert!(domain_matches("api.slack.com", "*.slack.com"));
        assert!(!domain_matches("slack.com", "*.slack.com"));
    }

    #[test]
    fn domain_matches_case_insensitive() {
        assert!(domain_matches("GitHub.COM", "github.com"));
        assert!(domain_matches("API.GitHub.Com", "*.github.com"));
    }
}
