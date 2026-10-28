//! Token-bucket rate limiting keyed by an arbitrary string (client IP, subject,
//! header value, ...), exposed as a tower layer.

use std::collections::HashMap;
use std::future::Future;
use std::hash::{BuildHasher, RandomState};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::{Extensions, HeaderMap, Request};
use tower::{Layer, Service};

use crate::error::GatewayError;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BucketParams {
    /// Tokens added per second.
    pub rate: f64,
    /// Maximum tokens held, i.e. the allowed burst.
    pub capacity: f64,
}

impl BucketParams {
    pub fn new(rate: f64, burst: u32) -> Self {
        Self {
            rate,
            capacity: f64::from(burst.max(1)),
        }
    }

    /// Time for an empty bucket to refill completely. A bucket idle for this
    /// long is indistinguishable from a fresh one and can be evicted.
    fn fill_time(&self) -> Duration {
        Duration::from_secs_f64(self.capacity / self.rate)
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn full(params: &BucketParams, now: Instant) -> Self {
        Self {
            tokens: params.capacity,
            last: now,
        }
    }

    /// Takes one token, or returns how long until one becomes available.
    pub fn try_take(&mut self, params: &BucketParams, now: Instant) -> Result<(), Duration> {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * params.rate).min(params.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - self.tokens) / params.rate))
        }
    }
}

const SHARDS: usize = 16;

/// A set of token buckets, one per key, sharded to keep lock contention low.
#[derive(Debug)]
pub struct KeyedLimiter {
    params: BucketParams,
    shards: Box<[Mutex<HashMap<String, TokenBucket>>]>,
    hasher: RandomState,
    max_keys_per_shard: usize,
}

impl KeyedLimiter {
    pub fn new(params: BucketParams) -> Self {
        Self::with_capacity(params, 100_000)
    }

    pub fn with_capacity(params: BucketParams, max_keys: usize) -> Self {
        Self {
            params,
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            hasher: RandomState::new(),
            max_keys_per_shard: (max_keys / SHARDS).max(1),
        }
    }

    pub fn check(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let shard = &self.shards[self.hasher.hash_one(key) as usize % SHARDS];
        let mut map = shard.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(bucket) = map.get_mut(key) {
            return bucket.try_take(&self.params, now);
        }
        if map.len() >= self.max_keys_per_shard {
            let ttl = self.params.fill_time();
            map.retain(|_, b| now.saturating_duration_since(b.last) < ttl);
        }
        let mut bucket = TokenBucket::full(&self.params, now);
        let res = bucket.try_take(&self.params, now);
        map.insert(key.to_owned(), bucket);
        res
    }

    pub fn tracked_keys(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|p| p.into_inner()).len())
            .sum()
    }
}

pub type KeyFn = Arc<dyn Fn(&HeaderMap, &Extensions) -> String + Send + Sync>;

#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<KeyedLimiter>,
    key_fn: KeyFn,
}

impl RateLimitLayer {
    pub fn new(limiter: Arc<KeyedLimiter>, key_fn: KeyFn) -> Self {
        Self { limiter, key_fn }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimit {
            inner,
            limiter: self.limiter.clone(),
            key_fn: self.key_fn.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimit<S> {
    inner: S,
    limiter: Arc<KeyedLimiter>,
    key_fn: KeyFn,
}

impl<S, B> Service<Request<B>> for RateLimit<S>
where
    S: Service<Request<B>, Error = GatewayError> + Clone + Send + 'static,
    S::Response: Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = GatewayError;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, GatewayError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let key = (self.key_fn)(req.headers(), req.extensions());
        if let Err(retry_after) = self.limiter.check(&key, Instant::now()) {
            return Box::pin(std::future::ready(Err(GatewayError::RateLimited {
                retry_after,
            })));
        }
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        Box::pin(async move { inner.call(req).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let p = BucketParams::new(2.0, 3);
        let t0 = Instant::now();
        let mut b = TokenBucket::full(&p, t0);
        for _ in 0..3 {
            assert!(b.try_take(&p, t0).is_ok());
        }
        let wait = b.try_take(&p, t0).unwrap_err();
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-9, "wait was {wait:?}");
        assert!(b.try_take(&p, t0 + Duration::from_millis(499)).is_err());
        assert!(b.try_take(&p, t0 + Duration::from_millis(1000)).is_ok());
        // Long idle never exceeds capacity.
        let later = t0 + Duration::from_secs(60);
        for _ in 0..3 {
            assert!(b.try_take(&p, later).is_ok());
        }
        assert!(b.try_take(&p, later).is_err());
    }

    #[test]
    fn keys_are_isolated() {
        let lim = KeyedLimiter::new(BucketParams::new(1.0, 1));
        let now = Instant::now();
        assert!(lim.check("a", now).is_ok());
        assert!(lim.check("a", now).is_err());
        assert!(lim.check("b", now).is_ok());
    }

    #[test]
    fn evicts_only_idle_full_buckets() {
        let lim = KeyedLimiter::with_capacity(BucketParams::new(10.0, 1), SHARDS);
        let t0 = Instant::now();
        for i in 0..200 {
            let _ = lim.check(&format!("k{i}"), t0);
        }
        assert!(lim.tracked_keys() <= 200);
        // After the fill time every bucket is reclaimable.
        let later = t0 + Duration::from_secs(1);
        for i in 0..SHARDS * 4 {
            let _ = lim.check(&format!("n{i}"), later);
        }
        assert!(lim.tracked_keys() < 200);
    }

    #[tokio::test]
    async fn layer_rejects_with_retry_after() {
        let limiter = Arc::new(KeyedLimiter::new(BucketParams::new(1.0, 2)));
        let key_fn: KeyFn = Arc::new(|h: &HeaderMap, _: &Extensions| {
            h.get("x-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("anon")
                .to_string()
        });
        let svc = RateLimitLayer::new(limiter, key_fn).layer(tower::service_fn(
            |_req: Request<()>| async { Ok::<_, GatewayError>(http::StatusCode::OK) },
        ));
        let req = || Request::builder().header("x-key", "k1").body(()).unwrap();
        assert!(svc.clone().oneshot(req()).await.is_ok());
        assert!(svc.clone().oneshot(req()).await.is_ok());
        match svc.clone().oneshot(req()).await {
            Err(GatewayError::RateLimited { retry_after }) => {
                assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_secs(1))
            }
            other => panic!("expected rate limit, got {other:?}"),
        }
        let other = Request::builder().header("x-key", "k2").body(()).unwrap();
        assert!(svc.oneshot(other).await.is_ok());
    }
}
