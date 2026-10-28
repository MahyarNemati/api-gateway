//! Request entry point: route lookup, body buffering, header hygiene,
//! deadline enforcement, metrics and access logging.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, Uri};
use http_body_util::{BodyExt, Limited};
use hyper::body::Body;
use tower::ServiceExt;
use tracing::Instrument;

use crate::body::{BoxError, ProxyBody};
use crate::context::{ClientIp, RequestId};
use crate::error::GatewayError;
use crate::gateway::{Gateway, Snapshot};
use crate::router::strip_route_prefix;

pub const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

const HOP_BY_HOP: [HeaderName; 8] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
];

struct InFlight(prometheus::IntGauge);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// Handles one downstream request end to end. Never fails: gateway errors are
/// rendered as JSON responses carrying the request id.
pub async fn handle<B>(
    gateway: Arc<Gateway>,
    req: Request<B>,
    peer: SocketAddr,
) -> Response<ProxyBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let started = Instant::now();
    let metrics = gateway.metrics().clone();
    metrics.in_flight.inc();
    let _in_flight = InFlight(metrics.in_flight.clone());

    let request_id = request_id(req.headers());
    let method = req.method().clone();
    let span = tracing::info_span!(
        "request",
        id = %request_id,
        method = %method,
        path = %req.uri().path(),
    );

    async move {
        let snapshot = gateway.snapshot();
        let host = request_host(&req).map(str::to_owned);
        let route_idx = snapshot
            .router
            .find(host.as_deref(), req.uri().path(), &method);
        let route_name = route_idx.map_or("none", |i| snapshot.route(i).config.name.as_str());

        let result = match route_idx {
            Some(idx) => forward(&snapshot, idx, req, peer, host, &request_id).await,
            None => Err(GatewayError::NoRoute),
        };

        let mut resp = match result {
            Ok(resp) => resp,
            Err(err) => {
                metrics
                    .errors
                    .with_label_values(&[route_name, err.kind()])
                    .inc();
                if err.status().is_server_error() {
                    tracing::warn!(route = route_name, error = %err, "request failed");
                } else {
                    tracing::debug!(route = route_name, error = %err, "request rejected");
                }
                err.into_response(&request_id)
            }
        };
        strip_hop_by_hop(resp.headers_mut());
        if let Ok(v) = HeaderValue::from_str(&request_id) {
            resp.headers_mut().insert(REQUEST_ID, v);
        }

        let elapsed = started.elapsed();
        let status = resp.status();
        metrics
            .requests
            .with_label_values(&[route_name, method_label(&method), status.as_str()])
            .inc();
        metrics
            .request_duration
            .with_label_values(&[route_name])
            .observe(elapsed.as_secs_f64());
        tracing::info!(
            route = route_name,
            status = status.as_u16(),
            latency_ms = elapsed.as_secs_f64() * 1000.0,
            "request completed"
        );
        resp
    }
    .instrument(span)
    .await
}

async fn forward<B>(
    snapshot: &Snapshot,
    idx: usize,
    req: Request<B>,
    peer: SocketAddr,
    host: Option<String>,
    request_id: &str,
) -> Result<Response<ProxyBody>, GatewayError>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let route = snapshot.route(idx);
    let server = &snapshot.config.server;
    let limit = server.max_body_bytes;
    let (mut parts, body) = req.into_parts();

    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) {
        return Err(GatewayError::PayloadTooLarge { limit });
    }
    let body = Limited::new(body, limit)
        .collect()
        .await
        .map_err(|e| {
            if e.is::<http_body_util::LengthLimitError>() {
                GatewayError::PayloadTooLarge { limit }
            } else {
                GatewayError::BadRequest(e.to_string())
            }
        })?
        .to_bytes();

    let client_ip = client_ip(&parts.headers, peer, server.trust_forwarded_for);

    if route.config.strip_prefix {
        let path = strip_route_prefix(&route.config.path_prefix, parts.uri.path());
        let pq = match parts.uri.query() {
            Some(q) => format!("{path}?{q}"),
            None => path,
        };
        parts.uri = Uri::builder()
            .path_and_query(pq)
            .build()
            .map_err(|e| GatewayError::BadRequest(e.to_string()))?;
    }

    let headers = &mut parts.headers;
    strip_hop_by_hop(headers);
    headers.remove(header::UPGRADE);
    headers.remove(header::HOST);
    append_forwarded_for(headers, peer.ip());
    if let Some(h) = host.as_deref().and_then(|h| HeaderValue::from_str(h).ok()) {
        headers.insert(X_FORWARDED_HOST, h);
    }
    headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
    if let Ok(v) = HeaderValue::from_str(request_id) {
        headers.insert(REQUEST_ID, v);
    }
    parts.extensions.insert(ClientIp(client_ip));
    parts.extensions.insert(RequestId(request_id.to_string()));

    let outbound = Request::from_parts(parts, body);
    match tokio::time::timeout(
        route.config.timeout,
        route.service.clone().oneshot(outbound),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => Err(GatewayError::RouteTimeout),
    }
}

/// Reuses a well-formed incoming request id so traces join up across hops.
fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

fn request_host<B>(req: &Request<B>) -> Option<&str> {
    req.uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| req.headers().get(header::HOST)?.to_str().ok())
}

/// The peer address, or the right-most X-Forwarded-For entry when the gateway
/// sits behind a trusted proxy that appends it.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, trust_forwarded_for: bool) -> IpAddr {
    if trust_forwarded_for {
        let forwarded = headers
            .get_all(X_FORWARDED_FOR)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .next_back()
            .and_then(|s| s.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip;
        }
    }
    peer.ip()
}

fn append_forwarded_for(headers: &mut HeaderMap, ip: IpAddr) {
    let value = match headers.get(X_FORWARDED_FOR).and_then(|v| v.to_str().ok()) {
        Some(prior) if !prior.is_empty() => format!("{prior}, {ip}"),
        _ => ip.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.insert(X_FORWARDED_FOR, v);
    }
}

pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for name in listed.iter().chain(HOP_BY_HOP.iter()) {
        headers.remove(name);
    }
}

fn method_label(m: &Method) -> &'static str {
    match *m {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::PATCH => "PATCH",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_valid_request_ids_and_replaces_bad_ones() {
        let mut h = HeaderMap::new();
        h.insert(REQUEST_ID, HeaderValue::from_static("abc-123_x.y"));
        assert_eq!(request_id(&h), "abc-123_x.y");
        h.insert(REQUEST_ID, HeaderValue::from_static("has space"));
        let generated = request_id(&h);
        assert_ne!(generated, "has space");
        assert!(uuid::Uuid::parse_str(&generated).is_ok());
    }

    #[test]
    fn client_ip_honours_trust_setting() {
        let peer: SocketAddr = "10.1.1.1:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );
        assert_eq!(client_ip(&h, peer, false), peer.ip());
        assert_eq!(
            client_ip(&h, peer, true),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
        h.insert(X_FORWARDED_FOR, HeaderValue::from_static("garbage"));
        assert_eq!(client_ip(&h, peer, true), peer.ip());
    }

    #[test]
    fn strips_hop_by_hop_and_connection_listed_headers() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("close, x-private"),
        );
        h.insert("x-private", HeaderValue::from_static("1"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        h.insert("x-public", HeaderValue::from_static("1"));
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-public"));
    }

    #[test]
    fn appends_to_forwarded_for() {
        let mut h = HeaderMap::new();
        append_forwarded_for(&mut h, "1.1.1.1".parse().unwrap());
        append_forwarded_for(&mut h, "2.2.2.2".parse().unwrap());
        assert_eq!(h[X_FORWARDED_FOR], "1.1.1.1, 2.2.2.2");
    }
}
