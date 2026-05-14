use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};

/// Default cap on the number of domains held in the cache. The cache is
/// supervisor-side state and serves a single sandboxed process, so this is
/// generous; the goal is to bound worst-case memory if a workload churns
/// through many distinct hostnames.
pub const DEFAULT_MAX_ENTRIES: usize = 1024;

#[derive(Debug, Clone)]
pub struct DnsCache {
    inner: Arc<RwLock<DnsCacheInner>>,
    min_ttl: Duration,
    max_entries: usize,
}

#[derive(Debug, Clone)]
struct DnsCacheInner {
    entries: HashMap<String, DnsEntry>,
}

#[derive(Debug, Clone)]
struct DnsEntry {
    ips: HashSet<IpAddr>,
    expires_at: Instant,
    /// Last-access timestamp used for LRU eviction when the cache hits
    /// `max_entries`. Updated on every cache hit and on insert.
    last_used: Instant,
}

impl DnsCache {
    pub fn new(min_ttl: Duration) -> Self {
        Self::with_capacity(min_ttl, DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(min_ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DnsCacheInner {
                entries: HashMap::new(),
            })),
            min_ttl,
            max_entries: max_entries.max(1),
        }
    }

    pub fn get_fresh(&self, domain: &str) -> Option<HashSet<IpAddr>> {
        let now = Instant::now();
        // Need a write lock to update last_used on hit, so the LRU stays
        // accurate. Cache reads are not a hot path (one per supervised
        // syscall at most), so the contention cost is acceptable.
        let mut guard = self.inner.write().ok()?;
        let entry = guard.entries.get_mut(domain)?;
        if entry.expires_at > now {
            entry.last_used = now;
            Some(entry.ips.clone())
        } else {
            None
        }
    }

    pub fn resolve_and_store(&self, domain: &str) -> Option<HashSet<IpAddr>> {
        let nameserver: IpAddr = can_crate_upstream_dns()?;
        let group = NameServerConfigGroup::from_ips_clear(&[nameserver], 53, true);
        let config = ResolverConfig::from_parts(None, Vec::new(), group);
        let resolver = Resolver::new(config, ResolverOpts::default()).ok()?;

        // CDNs (Cloudflare, Fastly, …) typically return one A record per
        // query and rotate edges across requests. A single lookup catches
        // only the supervisor's slice of edges; the sandboxed worker's
        // separate query may land on a different one. Issue a small burst
        // of queries and union the results to widen coverage. `min_ttl`
        // (and the per-domain `valid_until`) still bound how often the
        // burst re-runs.
        let mut ips: HashSet<IpAddr> = HashSet::new();
        let mut min_valid_until = None;
        for _ in 0..3 {
            let Ok(lookup) = resolver.lookup_ip(domain) else {
                break;
            };
            ips.extend(lookup.iter());
            min_valid_until = match min_valid_until {
                None => Some(lookup.valid_until()),
                Some(prev) => Some(prev.min(lookup.valid_until())),
            };
        }
        if ips.is_empty() {
            return None;
        }

        let now = Instant::now();
        let ttl_from_resolver = min_valid_until
            .map(|t| t.saturating_duration_since(now))
            .unwrap_or(Duration::ZERO);
        let ttl = std::cmp::max(self.min_ttl, ttl_from_resolver);

        let mut guard = self.inner.write().ok()?;
        // Evict before inserting so the cap is the post-insert size. Both
        // expired entries and (if still over capacity) the least-recently-
        // used entry are removed.
        evict_to_capacity(&mut guard.entries, self.max_entries, now);
        guard.entries.insert(
            domain.to_string(),
            DnsEntry {
                ips: ips.clone(),
                expires_at: now + ttl,
                last_used: now,
            },
        );

        Some(ips)
    }

    pub fn resolve_cached_or_lookup(&self, domain: &str) -> Option<HashSet<IpAddr>> {
        self.get_fresh(domain)
            .or_else(|| self.resolve_and_store(domain))
    }

    pub fn all_current_ips(&self) -> HashSet<IpAddr> {
        let now = Instant::now();
        let mut out = HashSet::new();
        if let Ok(guard) = self.inner.read() {
            for entry in guard.entries.values() {
                if entry.expires_at > now {
                    out.extend(entry.ips.iter().copied());
                }
            }
        }
        out
    }
}

fn can_crate_upstream_dns() -> Option<IpAddr> {
    let detected = crate::pasta::detect_upstream_dns()?;
    detected.parse().ok()
}

/// Reduce `entries` until its size is below `max_entries`. First drops
/// expired entries (free real estate); if that's not enough, evicts the
/// entry with the oldest `last_used` until we're under the cap.
fn evict_to_capacity(entries: &mut HashMap<String, DnsEntry>, max_entries: usize, now: Instant) {
    if entries.len() < max_entries {
        return;
    }

    // Pass 1: drop expired entries.
    entries.retain(|_, entry| entry.expires_at > now);

    // Pass 2: while still at/over capacity, evict the LRU entry. We need
    // post-insert size < max_entries, so loop until len() < max_entries.
    while entries.len() >= max_entries {
        let oldest_key = entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| k.clone());
        match oldest_key {
            Some(k) => {
                entries.remove(&k);
            }
            None => break, // map is empty
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn entry(ip: IpAddr, expires: Instant, last_used: Instant) -> DnsEntry {
        let mut ips = HashSet::new();
        ips.insert(ip);
        DnsEntry {
            ips,
            expires_at: expires,
            last_used,
        }
    }

    #[test]
    fn evict_to_capacity_no_op_when_under_cap() {
        let mut entries = HashMap::new();
        let now = Instant::now();
        entries.insert(
            "a.example".into(),
            entry(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                now + Duration::from_secs(60),
                now,
            ),
        );
        evict_to_capacity(&mut entries, 4, now);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn evict_to_capacity_drops_expired_first() {
        let mut entries = HashMap::new();
        let now = Instant::now();
        // Two expired, one fresh.
        entries.insert(
            "old1".into(),
            entry(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                now - Duration::from_secs(1),
                now - Duration::from_secs(100),
            ),
        );
        entries.insert(
            "old2".into(),
            entry(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
                now - Duration::from_secs(1),
                now - Duration::from_secs(50),
            ),
        );
        entries.insert(
            "fresh".into(),
            entry(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3)),
                now + Duration::from_secs(60),
                now,
            ),
        );

        evict_to_capacity(&mut entries, 3, now);
        // After expiry pass, only "fresh" remains.
        assert_eq!(entries.len(), 1);
        assert!(entries.contains_key("fresh"));
    }

    #[test]
    fn evict_to_capacity_evicts_lru_when_all_fresh() {
        let mut entries = HashMap::new();
        let now = Instant::now();
        // Three fresh; LRU is "oldest_use".
        entries.insert(
            "newest_use".into(),
            entry(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                now + Duration::from_secs(60),
                now,
            ),
        );
        entries.insert(
            "medium_use".into(),
            entry(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
                now + Duration::from_secs(60),
                now - Duration::from_secs(10),
            ),
        );
        entries.insert(
            "oldest_use".into(),
            entry(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3)),
                now + Duration::from_secs(60),
                now - Duration::from_secs(60),
            ),
        );

        evict_to_capacity(&mut entries, 3, now);
        // Need to be < 3 after eviction (so post-insert it's exactly 3).
        assert_eq!(entries.len(), 2);
        assert!(!entries.contains_key("oldest_use"));
    }
}
