use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use http::uri::Authority;

use crate::config::{parse_endpoint, BalanceStrategy, UpstreamConfig};

#[derive(Debug)]
pub struct Endpoint {
    pub authority: Authority,
    in_flight: AtomicUsize,
    healthy: AtomicBool,
    consecutive_ok: AtomicU32,
    consecutive_fail: AtomicU32,
}

impl Endpoint {
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            in_flight: AtomicUsize::new(0),
            healthy: AtomicBool::new(true),
            consecutive_ok: AtomicU32::new(0),
            consecutive_fail: AtomicU32::new(0),
        }
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Records a health probe result; returns the new health state when it flips.
    pub fn observe_probe(
        &self,
        ok: bool,
        healthy_after: u32,
        unhealthy_after: u32,
    ) -> Option<bool> {
        if ok {
            self.consecutive_fail.store(0, Ordering::Relaxed);
            let n = self.consecutive_ok.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= healthy_after && !self.healthy.swap(true, Ordering::Relaxed) {
                return Some(true);
            }
        } else {
            self.consecutive_ok.store(0, Ordering::Relaxed);
            let n = self.consecutive_fail.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= unhealthy_after && self.healthy.swap(false, Ordering::Relaxed) {
                return Some(false);
            }
        }
        None
    }

    pub fn begin(self: &Arc<Self>) -> InflightGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InflightGuard(self.clone())
    }
}

/// Decrements the endpoint's in-flight count when dropped.
#[derive(Debug)]
pub struct InflightGuard(Arc<Endpoint>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct Pool {
    pub name: String,
    pub endpoints: Vec<Arc<Endpoint>>,
    strategy: BalanceStrategy,
    cursor: AtomicUsize,
}

impl Pool {
    pub fn from_config(cfg: &UpstreamConfig) -> Result<Self, String> {
        let endpoints = cfg
            .endpoints
            .iter()
            .map(|e| parse_endpoint(e).map(|a| Arc::new(Endpoint::new(a))))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(&cfg.name, endpoints, cfg.balance))
    }

    pub fn new(name: &str, endpoints: Vec<Arc<Endpoint>>, strategy: BalanceStrategy) -> Self {
        Self {
            name: name.to_string(),
            endpoints,
            strategy,
            cursor: AtomicUsize::new(0),
        }
    }

    /// Picks a healthy endpoint, or `None` when every endpoint is down.
    pub fn select(&self) -> Option<Arc<Endpoint>> {
        let n = self.endpoints.len();
        if n == 0 {
            return None;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        let mut candidates = (0..n)
            .map(|i| &self.endpoints[(start + i) % n])
            .filter(|e| e.is_healthy());
        match self.strategy {
            BalanceStrategy::RoundRobin => candidates.next().cloned(),
            // Rotating the scan start breaks ties fairly between idle endpoints.
            BalanceStrategy::LeastConnections => candidates.min_by_key(|e| e.in_flight()).cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn pool(n: usize, strategy: BalanceStrategy) -> Pool {
        let eps = (0..n)
            .map(|i| Arc::new(Endpoint::new(format!("10.0.0.{i}:80").parse().unwrap())))
            .collect();
        Pool::new("p", eps, strategy)
    }

    #[test]
    fn round_robin_cycles_evenly() {
        let p = pool(3, BalanceStrategy::RoundRobin);
        let mut counts = HashMap::new();
        for _ in 0..300 {
            *counts
                .entry(p.select().unwrap().authority.to_string())
                .or_insert(0) += 1;
        }
        assert!(counts.values().all(|&c| c == 100), "{counts:?}");
    }

    #[test]
    fn round_robin_skips_unhealthy() {
        let p = pool(3, BalanceStrategy::RoundRobin);
        p.endpoints[1].observe_probe(false, 1, 1);
        for _ in 0..30 {
            assert_ne!(p.select().unwrap().authority.as_str(), "10.0.0.1:80");
        }
        p.endpoints[0].observe_probe(false, 1, 1);
        p.endpoints[2].observe_probe(false, 1, 1);
        assert!(p.select().is_none());
    }

    #[test]
    fn least_connections_prefers_idle() {
        let p = pool(3, BalanceStrategy::LeastConnections);
        let _busy0 = p.endpoints[0].begin();
        let _busy0b = p.endpoints[0].begin();
        let _busy2 = p.endpoints[2].begin();
        for _ in 0..10 {
            assert_eq!(p.select().unwrap().authority.as_str(), "10.0.0.1:80");
        }
        drop((_busy0, _busy0b));
        assert_eq!(p.endpoints[0].in_flight(), 0);
    }

    #[test]
    fn health_thresholds() {
        let ep = Endpoint::new("a:1".parse().unwrap());
        assert_eq!(ep.observe_probe(false, 2, 3), None);
        assert_eq!(ep.observe_probe(false, 2, 3), None);
        assert_eq!(ep.observe_probe(false, 2, 3), Some(false));
        assert_eq!(ep.observe_probe(true, 2, 3), None);
        assert_eq!(ep.observe_probe(true, 2, 3), Some(true));
        assert_eq!(ep.observe_probe(true, 2, 3), None);
    }
}
