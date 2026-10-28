//! Consecutive-failure circuit breaker with closed, open and half-open states,
//! exposed as a tower layer. Outcomes are tagged with the state generation they
//! were admitted under so late results cannot corrupt a newer state.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::{Request, Response};
use tower::{Layer, Service};

use crate::config::CircuitBreakerConfig;
use crate::error::GatewayError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    /// Numeric encoding exported as a gauge.
    pub fn as_gauge(self) -> i64 {
        match self {
            Self::Closed => 0,
            Self::HalfOpen => 1,
            Self::Open => 2,
        }
    }
}

impl fmt::Display for BreakerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        })
    }
}

#[derive(Debug)]
enum Inner {
    Closed { failures: u32 },
    Open { until: Instant },
    HalfOpen { in_flight: u32, successes: u32 },
}

#[derive(Debug)]
struct Guarded {
    inner: Inner,
    generation: u64,
}

pub type TransitionHook = Box<dyn Fn(BreakerState) + Send + Sync>;

pub struct CircuitBreaker {
    failure_threshold: u32,
    open_duration: Duration,
    half_open_max: u32,
    state: Mutex<Guarded>,
    on_transition: Option<TransitionHook>,
}

impl fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitBreaker")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

/// Admission ticket. Report the outcome with `success` or `failure`; dropping it
/// unreported (e.g. on cancellation) releases a half-open probe slot.
pub struct Permit {
    breaker: Arc<CircuitBreaker>,
    generation: u64,
    probe: bool,
    reported: bool,
}

impl Permit {
    pub fn success(mut self, now: Instant) {
        self.reported = true;
        self.breaker.record(self.generation, true, now);
    }

    pub fn failure(mut self, now: Instant) {
        self.reported = true;
        self.breaker.record(self.generation, false, now);
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if !self.reported && self.probe {
            self.breaker.release_probe(self.generation);
        }
    }
}

impl CircuitBreaker {
    pub fn new(cfg: &CircuitBreakerConfig) -> Self {
        Self {
            failure_threshold: cfg.failure_threshold.max(1),
            open_duration: cfg.open_duration,
            half_open_max: cfg.half_open_max_requests.max(1),
            state: Mutex::new(Guarded {
                inner: Inner::Closed { failures: 0 },
                generation: 0,
            }),
            on_transition: None,
        }
    }

    pub fn with_hook(mut self, hook: TransitionHook) -> Self {
        self.on_transition = Some(hook);
        self
    }

    pub fn state(&self) -> BreakerState {
        match self.lock().inner {
            Inner::Closed { .. } => BreakerState::Closed,
            Inner::Open { .. } => BreakerState::Open,
            Inner::HalfOpen { .. } => BreakerState::HalfOpen,
        }
    }

    pub fn try_acquire(self: &Arc<Self>, now: Instant) -> Option<Permit> {
        let mut g = self.lock();
        if let Inner::Open { until } = g.inner {
            if now < until {
                return None;
            }
            self.transition(
                &mut g,
                Inner::HalfOpen {
                    in_flight: 0,
                    successes: 0,
                },
            );
        }
        let generation = g.generation;
        let probe = match &mut g.inner {
            Inner::Closed { .. } => false,
            Inner::HalfOpen {
                in_flight,
                successes,
            } => {
                if *in_flight + *successes >= self.half_open_max {
                    return None;
                }
                *in_flight += 1;
                true
            }
            Inner::Open { .. } => unreachable!("handled above"),
        };
        Some(Permit {
            breaker: self.clone(),
            generation,
            probe,
            reported: false,
        })
    }

    fn record(&self, generation: u64, ok: bool, now: Instant) {
        let mut g = self.lock();
        if g.generation != generation {
            return;
        }
        let next = match &mut g.inner {
            Inner::Closed { failures } => {
                if ok {
                    *failures = 0;
                    None
                } else {
                    *failures += 1;
                    (*failures >= self.failure_threshold).then_some(Inner::Open {
                        until: now + self.open_duration,
                    })
                }
            }
            Inner::HalfOpen {
                in_flight,
                successes,
            } => {
                *in_flight = in_flight.saturating_sub(1);
                if ok {
                    *successes += 1;
                    (*successes >= self.half_open_max).then_some(Inner::Closed { failures: 0 })
                } else {
                    Some(Inner::Open {
                        until: now + self.open_duration,
                    })
                }
            }
            Inner::Open { .. } => None,
        };
        if let Some(next) = next {
            self.transition(&mut g, next);
        }
    }

    fn release_probe(&self, generation: u64) {
        let mut g = self.lock();
        if g.generation != generation {
            return;
        }
        if let Inner::HalfOpen { in_flight, .. } = &mut g.inner {
            *in_flight = in_flight.saturating_sub(1);
        }
    }

    fn transition(&self, g: &mut Guarded, next: Inner) {
        g.inner = next;
        g.generation += 1;
        if let Some(hook) = &self.on_transition {
            hook(match g.inner {
                Inner::Closed { .. } => BreakerState::Closed,
                Inner::Open { .. } => BreakerState::Open,
                Inner::HalfOpen { .. } => BreakerState::HalfOpen,
            });
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Guarded> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[derive(Clone)]
pub struct CircuitBreakerLayer {
    breaker: Arc<CircuitBreaker>,
    upstream: Arc<str>,
}

impl CircuitBreakerLayer {
    pub fn new(breaker: Arc<CircuitBreaker>, upstream: &str) -> Self {
        Self {
            breaker,
            upstream: upstream.into(),
        }
    }
}

impl<S> Layer<S> for CircuitBreakerLayer {
    type Service = CircuitBreakerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CircuitBreakerService {
            inner,
            breaker: self.breaker.clone(),
            upstream: self.upstream.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CircuitBreakerService<S> {
    inner: S,
    breaker: Arc<CircuitBreaker>,
    upstream: Arc<str>,
}

impl<S, B, RB> Service<Request<B>> for CircuitBreakerService<S>
where
    S: Service<Request<B>, Response = Response<RB>, Error = GatewayError> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
    RB: Send + 'static,
{
    type Response = Response<RB>;
    type Error = GatewayError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<RB>, GatewayError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let Some(permit) = self.breaker.try_acquire(Instant::now()) else {
            let upstream = self.upstream.to_string();
            return Box::pin(std::future::ready(Err(GatewayError::CircuitOpen {
                upstream,
            })));
        };
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        Box::pin(async move {
            let res = inner.call(req).await;
            let now = Instant::now();
            match &res {
                Ok(resp) if resp.status().is_server_error() => permit.failure(now),
                Ok(_) => permit.success(now),
                Err(e) if e.is_retryable() => permit.failure(now),
                Err(_) => drop(permit),
            }
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};
    use tower::ServiceExt;

    fn breaker(threshold: u32, half_open: u32) -> Arc<CircuitBreaker> {
        Arc::new(CircuitBreaker::new(&CircuitBreakerConfig {
            failure_threshold: threshold,
            open_duration: Duration::from_secs(10),
            half_open_max_requests: half_open,
        }))
    }

    #[test]
    fn opens_after_consecutive_failures() {
        let b = breaker(3, 1);
        let t = Instant::now();
        b.try_acquire(t).unwrap().failure(t);
        b.try_acquire(t).unwrap().failure(t);
        b.try_acquire(t).unwrap().success(t); // resets the streak
        for _ in 0..3 {
            b.try_acquire(t).unwrap().failure(t);
        }
        assert_eq!(b.state(), BreakerState::Open);
        assert!(b.try_acquire(t + Duration::from_secs(9)).is_none());
    }

    #[test]
    fn half_open_limits_probes_and_closes_on_success() {
        let b = breaker(1, 2);
        let t = Instant::now();
        b.try_acquire(t).unwrap().failure(t);
        let later = t + Duration::from_secs(10);
        let p1 = b.try_acquire(later).expect("first probe");
        assert_eq!(b.state(), BreakerState::HalfOpen);
        let p2 = b.try_acquire(later).expect("second probe");
        assert!(b.try_acquire(later).is_none(), "probe budget exhausted");
        p1.success(later);
        assert_eq!(b.state(), BreakerState::HalfOpen);
        p2.success(later);
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn half_open_failure_reopens() {
        let b = breaker(1, 1);
        let t = Instant::now();
        b.try_acquire(t).unwrap().failure(t);
        let later = t + Duration::from_secs(10);
        b.try_acquire(later).unwrap().failure(later);
        assert_eq!(b.state(), BreakerState::Open);
        assert!(b.try_acquire(later + Duration::from_secs(5)).is_none());
    }

    #[test]
    fn stale_outcomes_and_cancelled_probes_are_ignored() {
        let b = breaker(1, 1);
        let t = Instant::now();
        let slow = b.try_acquire(t).unwrap();
        b.try_acquire(t).unwrap().failure(t);
        assert_eq!(b.state(), BreakerState::Open);
        let later = t + Duration::from_secs(10);
        let probe = b.try_acquire(later).unwrap();
        // A request admitted while closed must not close the half-open breaker.
        slow.success(later);
        assert_eq!(b.state(), BreakerState::HalfOpen);
        drop(probe);
        assert!(
            b.try_acquire(later).is_some(),
            "dropped probe released its slot"
        );
    }

    #[test]
    fn hook_sees_every_transition() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let b = Arc::new(
            CircuitBreaker::new(&CircuitBreakerConfig {
                failure_threshold: 1,
                open_duration: Duration::from_secs(1),
                half_open_max_requests: 1,
            })
            .with_hook(Box::new(move |s| sink.lock().unwrap().push(s))),
        );
        let t = Instant::now();
        b.try_acquire(t).unwrap().failure(t);
        let later = t + Duration::from_secs(1);
        b.try_acquire(later).unwrap().success(later);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                BreakerState::Open,
                BreakerState::HalfOpen,
                BreakerState::Closed
            ]
        );
    }

    #[tokio::test]
    async fn layer_short_circuits_when_open() {
        let status = Arc::new(AtomicU16::new(503));
        let calls = Arc::new(AtomicU16::new(0));
        let (s, c) = (status.clone(), calls.clone());
        let inner = tower::service_fn(move |_req: Request<()>| {
            c.fetch_add(1, Ordering::SeqCst);
            let code = s.load(Ordering::SeqCst);
            async move {
                let mut r = Response::new(());
                *r.status_mut() = http::StatusCode::from_u16(code).unwrap();
                Ok::<_, GatewayError>(r)
            }
        });
        let svc = CircuitBreakerLayer::new(breaker(2, 1), "users").layer(inner);
        for _ in 0..2 {
            let r = svc.clone().oneshot(Request::new(())).await.unwrap();
            assert_eq!(r.status(), 503);
        }
        match svc.clone().oneshot(Request::new(())).await {
            Err(GatewayError::CircuitOpen { upstream }) => assert_eq!(upstream, "users"),
            other => panic!("expected open circuit, got {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
