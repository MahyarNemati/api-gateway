//! Prometheus instrumentation. Each `Metrics` owns its registry so multiple
//! gateways (e.g. in tests) never collide.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

pub struct Metrics {
    registry: Registry,
    pub requests: IntCounterVec,
    pub request_duration: HistogramVec,
    pub errors: IntCounterVec,
    pub in_flight: IntGauge,
    pub upstream_requests: IntCounterVec,
    pub upstream_duration: HistogramVec,
    pub retries: IntCounterVec,
    pub breaker_state: IntGaugeVec,
    pub endpoint_healthy: IntGaugeVec,
    pub config_reloads: IntCounterVec,
    pub jwks_refreshes: IntCounterVec,
}

const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

impl Metrics {
    pub fn new() -> prometheus::Result<Self> {
        let registry = Registry::new_custom(Some("gateway".into()), None)?;
        let counter =
            |name: &str, help: &str, labels: &[&str]| -> prometheus::Result<IntCounterVec> {
                let c = IntCounterVec::new(Opts::new(name, help), labels)?;
                registry.register(Box::new(c.clone()))?;
                Ok(c)
            };
        let histogram =
            |name: &str, help: &str, labels: &[&str]| -> prometheus::Result<HistogramVec> {
                let h = HistogramVec::new(
                    HistogramOpts::new(name, help).buckets(LATENCY_BUCKETS.to_vec()),
                    labels,
                )?;
                registry.register(Box::new(h.clone()))?;
                Ok(h)
            };
        let gauge = |name: &str, help: &str, labels: &[&str]| -> prometheus::Result<IntGaugeVec> {
            let g = IntGaugeVec::new(Opts::new(name, help), labels)?;
            registry.register(Box::new(g.clone()))?;
            Ok(g)
        };

        let in_flight = IntGauge::new("requests_in_flight", "Requests currently being processed")?;
        registry.register(Box::new(in_flight.clone()))?;

        Ok(Self {
            requests: counter(
                "requests_total",
                "Requests handled",
                &["route", "method", "status"],
            )?,
            request_duration: histogram(
                "request_duration_seconds",
                "End-to-end request latency",
                &["route"],
            )?,
            errors: counter(
                "errors_total",
                "Requests rejected or failed by the gateway",
                &["route", "kind"],
            )?,
            in_flight,
            upstream_requests: counter(
                "upstream_requests_total",
                "Attempts sent to upstream endpoints",
                &["upstream", "outcome"],
            )?,
            upstream_duration: histogram(
                "upstream_duration_seconds",
                "Time to upstream response headers",
                &["upstream"],
            )?,
            retries: counter("retries_total", "Upstream attempts retried", &["route"])?,
            breaker_state: gauge(
                "circuit_breaker_state",
                "0 = closed, 1 = half-open, 2 = open",
                &["upstream"],
            )?,
            endpoint_healthy: gauge(
                "upstream_endpoint_healthy",
                "1 when the endpoint passes active health checks",
                &["upstream", "endpoint"],
            )?,
            config_reloads: counter(
                "config_reloads_total",
                "Configuration reload attempts",
                &["result"],
            )?,
            jwks_refreshes: counter(
                "jwks_refreshes_total",
                "JWKS fetches",
                &["provider", "result"],
            )?,
            registry,
        })
    }

    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        if let Err(e) = TextEncoder::new().encode(&self.registry.gather(), &mut buf) {
            tracing::error!(error = %e, "encoding metrics");
        }
        String::from_utf8(buf).unwrap_or_default()
    }
}
