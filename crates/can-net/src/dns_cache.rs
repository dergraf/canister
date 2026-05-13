use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};

#[derive(Debug, Clone)]
pub struct DnsCache {
    inner: Arc<RwLock<DnsCacheInner>>,
    min_ttl: Duration,
}

#[derive(Debug, Clone)]
struct DnsCacheInner {
    entries: HashMap<String, DnsEntry>,
}

#[derive(Debug, Clone)]
struct DnsEntry {
    ips: HashSet<IpAddr>,
    expires_at: Instant,
}

impl DnsCache {
    pub fn new(min_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DnsCacheInner {
                entries: HashMap::new(),
            })),
            min_ttl,
        }
    }

    pub fn get_fresh(&self, domain: &str) -> Option<HashSet<IpAddr>> {
        let now = Instant::now();
        let guard = self.inner.read().ok()?;
        let entry = guard.entries.get(domain)?;
        if entry.expires_at > now {
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
        let lookup = resolver.lookup_ip(domain).ok()?;
        let ips: HashSet<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return None;
        }

        let now = Instant::now();
        let ttl_from_resolver = lookup.valid_until().saturating_duration_since(now);
        let ttl = std::cmp::max(self.min_ttl, ttl_from_resolver);

        let mut guard = self.inner.write().ok()?;
        guard.entries.insert(
            domain.to_string(),
            DnsEntry {
                ips: ips.clone(),
                expires_at: now + ttl,
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
