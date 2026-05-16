use std::fmt;

use regex::RegexSet;

use crate::error::DlpError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectorId {
    GithubPat,
    NpmToken,
    AwsAccessKey,
    BearerToken,
    SshPrivateKey,
    SlackToken,
    GenericHighEntropy,
    CanaryToken,
}

impl fmt::Display for DetectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DetectorId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GithubPat => "github_pat",
            Self::NpmToken => "npm_token",
            Self::AwsAccessKey => "aws_access_key",
            Self::BearerToken => "bearer_token",
            Self::SshPrivateKey => "ssh_private_key",
            Self::SlackToken => "slack_token",
            Self::GenericHighEntropy => "generic_high_entropy",
            Self::CanaryToken => "canary_token",
        }
    }

    pub fn default_action(&self) -> DetectorAction {
        match self {
            Self::GenericHighEntropy => DetectorAction::Warn,
            _ => DetectorAction::Block,
        }
    }

    pub fn all() -> &'static [DetectorId] {
        &[
            Self::GithubPat,
            Self::NpmToken,
            Self::AwsAccessKey,
            Self::BearerToken,
            Self::SshPrivateKey,
            Self::SlackToken,
            Self::GenericHighEntropy,
            Self::CanaryToken,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorAction {
    Block,
    Warn,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub detector: DetectorId,
    pub matched_text: String,
}

const PATTERNS: &[&str] = &[
    // 0: GithubPat — fine-grained PAT
    r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
    // 1: GithubPat — classic token prefixes (ghp_, gho_, ghu_, ghs_, ghr_)
    r"gh[pousr]_[A-Za-z0-9]{36}",
    // 2: NpmToken
    r"npm_[A-Za-z0-9]{36}",
    // 3: AwsAccessKey
    r"AKIA[A-Z0-9]{16}",
    // 4: BearerToken (in header context — Authorization: Bearer ...)
    r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*",
    // 5: SshPrivateKey
    r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    // 6: SlackToken
    r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
];

fn pattern_to_detector(index: usize) -> DetectorId {
    match index {
        0 | 1 => DetectorId::GithubPat,
        2 => DetectorId::NpmToken,
        3 => DetectorId::AwsAccessKey,
        4 => DetectorId::BearerToken,
        5 => DetectorId::SshPrivateKey,
        6 => DetectorId::SlackToken,
        _ => unreachable!("pattern index out of range"),
    }
}

pub struct PatternSet {
    regex_set: RegexSet,
    canary_values: Vec<String>,
}

impl PatternSet {
    pub fn new() -> Result<Self, DlpError> {
        let regex_set = RegexSet::new(PATTERNS)?;
        Ok(Self {
            regex_set,
            canary_values: Vec::new(),
        })
    }

    pub fn with_canaries(canaries: Vec<String>) -> Result<Self, DlpError> {
        let regex_set = RegexSet::new(PATTERNS)?;
        Ok(Self {
            regex_set,
            canary_values: canaries,
        })
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for canary in &self.canary_values {
            if text.contains(canary.as_str()) {
                findings.push(Finding {
                    detector: DetectorId::CanaryToken,
                    matched_text: canary.clone(),
                });
            }
        }

        for index in self.regex_set.matches(text) {
            let detector = pattern_to_detector(index);
            findings.push(Finding {
                detector,
                matched_text: extract_match(text, PATTERNS[index]),
            });
        }

        findings
    }
}

fn extract_match(text: &str, pattern: &str) -> String {
    regex::Regex::new(pattern)
        .ok()
        .and_then(|re| re.find(text).map(|m| m.as_str().to_string()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ps() -> PatternSet {
        PatternSet::new().unwrap()
    }

    #[test]
    fn detects_github_pat_classic() {
        let token = format!("ghp_{}", "A".repeat(36));
        let findings = ps().scan(&token);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::GithubPat);
    }

    #[test]
    fn detects_github_pat_fine_grained() {
        let part1 = "A".repeat(22);
        let part2 = "B".repeat(59);
        let token = format!("github_pat_{part1}_{part2}");
        assert_eq!(token.len(), 11 + 22 + 1 + 59);
        let findings = ps().scan(&token);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::GithubPat);
    }

    #[test]
    fn detects_all_github_prefixes() {
        for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
            let token = format!("{prefix}{}", "X".repeat(36));
            let findings = ps().scan(&token);
            assert!(
                findings.iter().any(|f| f.detector == DetectorId::GithubPat),
                "missed prefix {prefix}"
            );
        }
    }

    #[test]
    fn detects_npm_token() {
        let token = format!("npm_{}", "A".repeat(36));
        let findings = ps().scan(&token);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::NpmToken);
    }

    #[test]
    fn detects_aws_access_key() {
        let token = format!("AKIA{}", "A".repeat(16));
        let findings = ps().scan(&token);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::AwsAccessKey);
    }

    #[test]
    fn detects_bearer_token() {
        let token = format!("Bearer {}", "A".repeat(40));
        let findings = ps().scan(&token);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::BearerToken);
    }

    #[test]
    fn detects_ssh_private_key() {
        let findings = ps().scan("-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::SshPrivateKey);
    }

    #[test]
    fn detects_openssh_private_key() {
        let findings = ps().scan("-----BEGIN OPENSSH PRIVATE KEY-----");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::SshPrivateKey);
    }

    #[test]
    fn detects_slack_token() {
        let token = format!(
            "xoxb-{}-{}-{}",
            "1".repeat(12),
            "2".repeat(12),
            "A".repeat(24)
        );
        let findings = ps().scan(&token);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::SlackToken);
    }

    #[test]
    fn detects_canary_token() {
        let canary = format!("ghp_{}", "C".repeat(36));
        let ps = PatternSet::with_canaries(vec![canary.clone()]).unwrap();
        let findings = ps.scan(&canary);
        assert!(
            findings
                .iter()
                .any(|f| f.detector == DetectorId::CanaryToken)
        );
    }

    #[test]
    fn no_false_positive_on_normal_text() {
        let findings = ps().scan("Hello, this is a normal HTTP request body with some data.");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_token_embedded_in_json() {
        let token = format!("ghp_{}", "A".repeat(36));
        let json = format!(r#"{{"auth": "{token}"}}"#);
        let findings = ps().scan(&json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::GithubPat);
    }

    #[test]
    fn detects_token_in_query_string() {
        let token = format!("npm_{}", "X".repeat(36));
        let url = format!("https://example.com/api?token={token}&foo=bar");
        let findings = ps().scan(&url);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, DetectorId::NpmToken);
    }

    #[test]
    fn bearer_too_short_not_detected() {
        let findings = ps().scan("Bearer short");
        assert!(findings.is_empty());
    }

    #[test]
    fn aws_key_wrong_prefix_not_detected() {
        let findings = ps().scan(&format!("AKIB{}", "A".repeat(16)));
        assert!(findings.is_empty());
    }

    #[test]
    fn display_detector_id() {
        assert_eq!(DetectorId::GithubPat.to_string(), "github_pat");
        assert_eq!(DetectorId::CanaryToken.to_string(), "canary_token");
    }
}
