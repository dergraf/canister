use std::sync::atomic::{AtomicU64, Ordering};

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn high_entropy_byte_count(data: &[u8], window: usize, threshold: f64) -> u64 {
    if data.len() < window {
        let e = shannon_entropy(data);
        return if e > threshold { data.len() as u64 } else { 0 };
    }

    let mut count = 0u64;
    let mut i = 0;
    while i + window <= data.len() {
        let e = shannon_entropy(&data[i..i + window]);
        if e > threshold {
            count += window as u64;
            i += window;
        } else {
            i += 1;
        }
    }
    count
}

pub fn dns_label_entropy(hostname: &str, threshold: f64) -> bool {
    for label in hostname.split('.') {
        if label.len() >= 8 && shannon_entropy(label.as_bytes()) > threshold {
            return true;
        }
    }
    false
}

pub struct SessionEntropyBudget {
    budget_bytes: u64,
    used: AtomicU64,
}

impl SessionEntropyBudget {
    pub fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            used: AtomicU64::new(0),
        }
    }

    pub fn record(&self, high_entropy_bytes: u64) -> bool {
        let prev = self.used.fetch_add(high_entropy_bytes, Ordering::Relaxed);
        prev + high_entropy_bytes <= self.budget_bytes
    }

    pub fn exceeded(&self) -> bool {
        self.used.load(Ordering::Relaxed) > self.budget_bytes
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn budget(&self) -> u64 {
        self.budget_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros() {
        let data = vec![0u8; 100];
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn entropy_of_random_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(
            e > 7.9,
            "uniform distribution should have ~8.0 bits, got {e}"
        );
    }

    #[test]
    fn entropy_of_repeated_char() {
        let data = b"aaaaaaaaaaaaaaaaaaa";
        assert!(shannon_entropy(data) < 0.01);
    }

    #[test]
    fn entropy_of_hex_string() {
        let hex = "4a6f686e446f654031323334353637383930";
        let e = shannon_entropy(hex.as_bytes());
        assert!(e > 3.0, "hex strings have moderate entropy, got {e}");
    }

    #[test]
    fn entropy_empty_input() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn dns_label_high_entropy() {
        // 20 unique chars → Shannon entropy ~4.32 bits
        assert!(dns_label_entropy("a3f8b2c1e9d4z7x5y6w0.attacker.com", 4.0));
    }

    #[test]
    fn dns_label_normal() {
        assert!(!dns_label_entropy("www.google.com", 4.0));
        assert!(!dns_label_entropy("api.github.com", 4.0));
    }

    #[test]
    fn dns_label_short_labels_skipped() {
        assert!(!dns_label_entropy("ab.cd.ef", 4.0));
    }

    #[test]
    fn session_budget_basic() {
        let budget = SessionEntropyBudget::new(100);
        assert!(budget.record(50));
        assert!(!budget.exceeded());
        assert!(budget.record(50));
        assert!(!budget.exceeded());
        budget.record(1);
        assert!(budget.exceeded());
    }

    #[test]
    fn session_budget_single_overflow() {
        let budget = SessionEntropyBudget::new(100);
        assert!(!budget.record(200));
        assert!(budget.exceeded());
    }

    #[test]
    fn high_entropy_byte_count_low_entropy() {
        let data = vec![b'a'; 200];
        assert_eq!(high_entropy_byte_count(&data, 32, 4.0), 0);
    }

    #[test]
    fn high_entropy_byte_count_high_entropy() {
        let data: Vec<u8> = (0..=255).cycle().take(256).collect();
        let count = high_entropy_byte_count(&data, 32, 4.0);
        assert!(count > 0, "random-ish data should have high entropy bytes");
    }
}
