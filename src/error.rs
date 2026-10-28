//! Gateway error taxonomy and its mapping onto HTTP responses.

use std::time::Duration;

use http::{header, HeaderValue, Response, StatusCode};

use crate::body::{full, ProxyBody};

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("no route matches the request")]
    NoRoute,
    #[error("request body exceeds {limit} bytes")]
    PayloadTooLarge { limit: usize },
    #[error("failed to read request body: {0}")]
    BadRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("rate limit exceeded")]
    RateLimited { retry_after: Duration },
    #[error("circuit open for upstream {upstream}")]
    CircuitOpen { upstream: String },
    #[error("no healthy endpoint in upstream {upstream}")]
    NoHealthyEndpoint { upstream: String },
    #[error("upstream {upstream} timed out")]
    UpstreamTimeout { upstream: String },
    #[error("upstream {upstream} request failed: {reason}")]
    UpstreamConnect { upstream: String, reason: String },
    #[error("route deadline exceeded")]
    RouteTimeout,
    #[error("authentication backend unavailable: {0}")]
    AuthUnavailable(String),
}

impl GatewayError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NoRoute => StatusCode::NOT_FOUND,
            Self::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::CircuitOpen { .. } | Self::NoHealthyEndpoint { .. } => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::UpstreamTimeout { .. } | Self::RouteTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UpstreamConnect { .. } => StatusCode::BAD_GATEWAY,
            Self::AuthUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Transport-level failures that are safe to retry for idempotent requests.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::UpstreamConnect { .. }
                | Self::UpstreamTimeout { .. }
                | Self::NoHealthyEndpoint { .. }
        )
    }

    /// Short machine-readable label used in metrics and logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoRoute => "no_route",
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::RateLimited { .. } => "rate_limited",
            Self::CircuitOpen { .. } => "circuit_open",
            Self::NoHealthyEndpoint { .. } => "no_healthy_endpoint",
            Self::UpstreamTimeout { .. } => "upstream_timeout",
            Self::UpstreamConnect { .. } => "upstream_error",
            Self::RouteTimeout => "route_timeout",
            Self::AuthUnavailable(_) => "auth_unavailable",
        }
    }

    pub fn into_response(self, request_id: &str) -> Response<ProxyBody> {
        let status = self.status();
        // Upstream details stay in the logs; clients get a stable message.
        let message = match &self {
            Self::UpstreamConnect { .. } => "upstream request failed".to_string(),
            Self::AuthUnavailable(_) => "authentication backend unavailable".to_string(),
            other => other.to_string(),
        };
        let body = serde_json::json!({
            "error": self.kind(),
            "message": message,
            "request_id": request_id,
        });
        let mut resp = Response::new(full(body.to_string()));
        *resp.status_mut() = status;
        let headers = resp.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        match self {
            Self::RateLimited { retry_after } => {
                let secs = retry_after.as_secs_f64().ceil().max(1.0) as u64;
                headers.insert(header::RETRY_AFTER, HeaderValue::from(secs));
            }
            Self::Unauthorized(_) => {
                headers.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_token\""),
                );
            }
            _ => {}
        }
        resp
    }
}
