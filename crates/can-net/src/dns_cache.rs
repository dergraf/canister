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

    /// Insert a synthetic entry into the cache without performing a DNS
    /// lookup. Intended for tests that exercise downstream code paths
    /// (notifier dynamic-allowlist refresh, supervisor policy checks)
    /// without requiring network access.
    ///
    /// Production code MUST NOT call this — go through
    /// `resolve_cached_or_lookup` instead so TTL semantics stay honest.
    #[doc(hidden)]
    pub fn insert_for_testing(&self, domain: &str, ips: HashSet<IpAddr>, ttl: Duration) {
        let now = Instant::now();
        let entry = DnsEntry {
            ips,
            expires_at: now + ttl,
            last_used: now,
        };
        if let Ok(mut guard) = self.inner.write() {
            guard.entries.insert(domain.to_string(), entry);
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

        // CDNs (Cloudflare, Fastly, …) typically return one A record per
        // query and rotate edges across requests. A single lookup catches
        // only the supervisor's slice of edges; the sandboxed worker's
        // separate query may land on a different one. Issue a small burst
        // of queries through fresh resolvers (no internal hickory cache)
        // and union the results to widen coverage. `min_ttl` (and the
        // per-domain `valid_until`) still bound how often the burst
        // re-runs.
        let mut opts = ResolverOpts::default();
        opts.cache_size = 0;
        let mut ips: HashSet<IpAddr> = HashSet::new();
        let mut min_valid_until = None;
        for _ in 0..5 {
            let Ok(resolver) = Resolver::new(config.clone(), opts.clone()) else {
                break;
            };
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

    // ========================================================================
    // Concurrency
    // ========================================================================
    //
    // The cache is shared between the notifier supervisor (read-heavy on
    // every supervised syscall) and the proxy/DNS path (write-heavy on a
    // first-touch lookup). These tests validate that the Arc<RwLock>
    // wrapping keeps the invariants the supervisor depends on:
    //
    //   * concurrent inserts of distinct domains never lose data,
    //   * concurrent inserts of the same domain leave the cache in a
    //     valid (last-writer-wins) state without panicking,
    //   * `get_fresh` (which takes a write lock to update last_used)
    //     does not deadlock against itself or insert_for_testing,
    //   * clones of `DnsCache` share storage (the supervisor and proxy
    //     hold separate `DnsCache` clones), and
    //   * a poisoned RwLock degrades gracefully — get_fresh returns
    //     None instead of panicking, which is the contract the notifier
    //     relies on to fail-closed under partial state corruption.

    use std::thread;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ipset(ips: &[IpAddr]) -> HashSet<IpAddr> {
        ips.iter().copied().collect()
    }

    #[test]
    fn concurrent_inserts_distinct_domains_all_visible() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let n_threads = 16;
        let per_thread = 32;

        thread::scope(|s| {
            for t in 0..n_threads {
                let cache = cache.clone();
                s.spawn(move || {
                    for i in 0..per_thread {
                        let domain = format!("t{t}-d{i}.example");
                        let ip = ip(10, t as u8, (i >> 8) as u8, (i & 0xff) as u8);
                        cache.insert_for_testing(&domain, ipset(&[ip]), Duration::from_secs(60));
                    }
                });
            }
        });

        // Every (t, i) must be present and resolve to its assigned IP.
        for t in 0..n_threads {
            for i in 0..per_thread {
                let domain = format!("t{t}-d{i}.example");
                let got = cache
                    .get_fresh(&domain)
                    .unwrap_or_else(|| panic!("missing {domain}"));
                let expected = ip(10, t as u8, (i >> 8) as u8, (i & 0xff) as u8);
                assert_eq!(got, ipset(&[expected]), "wrong ip set for {domain}");
            }
        }
    }

    #[test]
    fn concurrent_inserts_same_domain_end_with_some_writer_winning() {
        // Hammer the same key. Last-writer-wins is acceptable; the
        // critical invariants are (a) no panic / deadlock, (b) the
        // final entry is one of the values some writer actually
        // inserted (not a corrupted mix), and (c) `all_current_ips`
        // returns *exactly one* IP set member.
        let cache = DnsCache::new(Duration::from_secs(60));
        let n_threads = 32;

        thread::scope(|s| {
            for t in 0..n_threads {
                let cache = cache.clone();
                s.spawn(move || {
                    for _ in 0..64 {
                        let candidate = ip(192, 168, 0, t as u8);
                        cache.insert_for_testing(
                            "race.example",
                            ipset(&[candidate]),
                            Duration::from_secs(60),
                        );
                    }
                });
            }
        });

        let got = cache.get_fresh("race.example").expect("entry present");
        assert_eq!(got.len(), 1, "exactly one IP must survive");
        let only = got.into_iter().next().unwrap();
        match only {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                assert_eq!(octets[0], 192);
                assert_eq!(octets[1], 168);
                assert_eq!(octets[2], 0);
                assert!(
                    (octets[3] as usize) < n_threads,
                    "winner must be a value some thread inserted, got {v4}"
                );
            }
            _ => panic!("expected v4"),
        }
    }

    #[test]
    fn concurrent_get_fresh_and_insert_do_not_deadlock() {
        // Mix readers (get_fresh, which takes a write lock to update
        // last_used) with writers (insert_for_testing) across many
        // threads. The test passes if every thread joins within the
        // soft timeout; a deadlock would hang scope() forever.
        let cache = DnsCache::new(Duration::from_secs(60));

        // Seed a few keys so get_fresh has work to do.
        for i in 0..8 {
            cache.insert_for_testing(
                &format!("seed{i}.example"),
                ipset(&[ip(10, 0, 0, i)]),
                Duration::from_secs(60),
            );
        }

        let start = Instant::now();
        thread::scope(|s| {
            // 8 readers.
            for _ in 0..8 {
                let cache = cache.clone();
                s.spawn(move || {
                    for _ in 0..2_000 {
                        for i in 0..8 {
                            let _ = cache.get_fresh(&format!("seed{i}.example"));
                        }
                    }
                });
            }
            // 4 writers (distinct keys, doesn't churn the seeds).
            for w in 0..4 {
                let cache = cache.clone();
                s.spawn(move || {
                    for i in 0..1_000 {
                        cache.insert_for_testing(
                            &format!("write{w}-{i}.example"),
                            ipset(&[ip(172, 16, w as u8, (i & 0xff) as u8)]),
                            Duration::from_secs(60),
                        );
                    }
                });
            }
            // 2 snapshot readers (read lock path).
            for _ in 0..2 {
                let cache = cache.clone();
                s.spawn(move || {
                    for _ in 0..500 {
                        let _ = cache.all_current_ips();
                    }
                });
            }
        });
        // 5 seconds is generous; on dev hardware this completes in
        // well under a second. A failure here is almost certainly a
        // deadlock, not a timing fluke.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "mixed reader/writer load took {:?} — possible deadlock",
            start.elapsed()
        );

        // Sanity-check: original seeds still present.
        for i in 0..8 {
            assert!(
                cache.get_fresh(&format!("seed{i}.example")).is_some(),
                "seed{i} disappeared under concurrent load"
            );
        }
    }

    #[test]
    fn clone_shares_storage_with_original() {
        // Two clones of the same DnsCache must observe each other's
        // writes — the proxy and notifier both hold clones and rely on
        // this.
        let a = DnsCache::new(Duration::from_secs(60));
        let b = a.clone();

        a.insert_for_testing(
            "shared.example",
            ipset(&[ip(8, 8, 8, 8)]),
            Duration::from_secs(60),
        );
        assert_eq!(
            b.get_fresh("shared.example"),
            Some(ipset(&[ip(8, 8, 8, 8)]))
        );

        // And the other direction.
        b.insert_for_testing(
            "shared2.example",
            ipset(&[ip(1, 1, 1, 1)]),
            Duration::from_secs(60),
        );
        assert_eq!(
            a.get_fresh("shared2.example"),
            Some(ipset(&[ip(1, 1, 1, 1)]))
        );
    }

    #[test]
    fn expired_entry_returns_none_under_concurrent_lookup() {
        // TTL of 1ms; after sleeping past it, many concurrent
        // get_fresh callers must all observe `None` — i.e., the
        // expiry check is not raced by last_used updates.
        let cache = DnsCache::new(Duration::from_secs(60));
        cache.insert_for_testing(
            "ephemeral.example",
            ipset(&[ip(127, 0, 0, 1)]),
            Duration::from_millis(1),
        );
        std::thread::sleep(Duration::from_millis(20));

        thread::scope(|s| {
            for _ in 0..16 {
                let cache = cache.clone();
                s.spawn(move || {
                    for _ in 0..100 {
                        assert!(
                            cache.get_fresh("ephemeral.example").is_none(),
                            "expired entry was returned by get_fresh"
                        );
                    }
                });
            }
        });
    }

    #[test]
    fn all_current_ips_returns_consistent_snapshot_under_writes() {
        // While writers churn, the read-locked snapshot must contain
        // only entries that were really inserted (no half-inserted
        // garbage) and only IPs that are still in some live entry.
        let cache = DnsCache::new(Duration::from_secs(60));
        for i in 0..32 {
            cache.insert_for_testing(
                &format!("d{i}.example"),
                ipset(&[ip(10, 0, 0, i as u8)]),
                Duration::from_secs(60),
            );
        }

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        thread::scope(|s| {
            let stop_writer = stop.clone();
            let writer_cache = cache.clone();
            s.spawn(move || {
                let mut i = 0u32;
                while !stop_writer.load(std::sync::atomic::Ordering::Relaxed) {
                    writer_cache.insert_for_testing(
                        &format!("churn{i}.example"),
                        ipset(&[ip(10, 1, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8)]),
                        Duration::from_secs(60),
                    );
                    i = i.wrapping_add(1);
                }
            });

            // Each snapshot must contain the original 32 seeds (they
            // are never removed). Any unexpected count means we read a
            // mid-write state.
            for _ in 0..200 {
                let snap = cache.all_current_ips();
                for i in 0..32u8 {
                    assert!(
                        snap.contains(&ip(10, 0, 0, i)),
                        "seed {i} missing from snapshot of size {}",
                        snap.len()
                    );
                }
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    }

    #[test]
    fn poisoned_lock_returns_none_instead_of_panicking() {
        // The notifier's contract is to fail-closed if the cache is
        // unhealthy. Simulate a poisoned RwLock by panicking inside a
        // write guard; the next caller of get_fresh must observe None
        // (not panic), and all_current_ips must observe an empty set.
        let cache = DnsCache::new(Duration::from_secs(60));
        cache.insert_for_testing(
            "victim.example",
            ipset(&[ip(127, 0, 0, 1)]),
            Duration::from_secs(60),
        );

        let cache_for_panicker = cache.clone();
        let handle = std::thread::spawn(move || {
            let _guard = cache_for_panicker.inner.write().unwrap();
            panic!("intentional panic to poison the lock");
        });
        let _ = handle.join(); // join the panicked thread, ignore.

        // The lock is now poisoned. get_fresh uses `.ok()?` so it
        // must return None rather than propagate the poison.
        assert!(cache.get_fresh("victim.example").is_none());
        // all_current_ips swallows the poison and yields empty.
        assert!(cache.all_current_ips().is_empty());
    }
}
