#[derive(Debug, thiserror::Error)]
pub enum DlpError {
    #[error("DLP blocked: detector={detector}, host={host}")]
    Blocked { detector: String, host: String },

    #[error("DLP regex compilation failed: {0}")]
    RegexCompilation(#[from] regex::Error),

    #[error("DLP entropy budget exceeded: {used}/{budget} high-entropy bytes")]
    EntropyBudgetExceeded { used: u64, budget: u64 },
}
