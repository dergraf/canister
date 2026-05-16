use rand::Rng;

pub struct CanarySet {
    pub github_pat: String,
    pub npm_token: String,
    pub aws_access_key: String,
}

impl CanarySet {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            github_pat: format!("ghp_{}", random_alnum(&mut rng, 36)),
            npm_token: format!("npm_{}", random_alnum(&mut rng, 36)),
            aws_access_key: format!("AKIA{}", random_upper_alnum(&mut rng, 16)),
        }
    }

    pub fn values(&self) -> Vec<String> {
        vec![
            self.github_pat.clone(),
            self.npm_token.clone(),
            self.aws_access_key.clone(),
        ]
    }

    pub fn env_vars(&self) -> Vec<(&'static str, &str)> {
        vec![
            ("CANISTER_CANARY_GITHUB_PAT", &self.github_pat),
            ("CANISTER_CANARY_NPM_TOKEN", &self.npm_token),
            ("CANISTER_CANARY_AWS_ACCESS_KEY", &self.aws_access_key),
        ]
    }
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
    fn canary_tokens_match_detector_patterns() {
        let canaries = CanarySet::generate();
        let ps = PatternSet::new().unwrap();

        let gh_findings = ps.scan(&canaries.github_pat);
        assert!(
            gh_findings
                .iter()
                .any(|f| f.detector == crate::detectors::DetectorId::GithubPat),
            "canary github_pat should match GithubPat detector"
        );

        let npm_findings = ps.scan(&canaries.npm_token);
        assert!(
            npm_findings
                .iter()
                .any(|f| f.detector == crate::detectors::DetectorId::NpmToken),
            "canary npm_token should match NpmToken detector"
        );

        let aws_findings = ps.scan(&canaries.aws_access_key);
        assert!(
            aws_findings
                .iter()
                .any(|f| f.detector == crate::detectors::DetectorId::AwsAccessKey),
            "canary aws_access_key should match AwsAccessKey detector"
        );
    }

    #[test]
    fn canary_tokens_are_unique() {
        let a = CanarySet::generate();
        let b = CanarySet::generate();
        assert_ne!(a.github_pat, b.github_pat);
        assert_ne!(a.npm_token, b.npm_token);
        assert_ne!(a.aws_access_key, b.aws_access_key);
    }

    #[test]
    fn canary_env_vars_have_correct_names() {
        let canaries = CanarySet::generate();
        let vars = canaries.env_vars();
        assert_eq!(vars[0].0, "CANISTER_CANARY_GITHUB_PAT");
        assert_eq!(vars[1].0, "CANISTER_CANARY_NPM_TOKEN");
        assert_eq!(vars[2].0, "CANISTER_CANARY_AWS_ACCESS_KEY");
    }

    #[test]
    fn canary_values_length() {
        let canaries = CanarySet::generate();
        assert_eq!(canaries.github_pat.len(), 4 + 36); // "ghp_" + 36
        assert_eq!(canaries.npm_token.len(), 4 + 36); // "npm_" + 36
        assert_eq!(canaries.aws_access_key.len(), 4 + 16); // "AKIA" + 16
    }
}
