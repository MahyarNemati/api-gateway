mod common;

use std::collections::HashSet;
use std::time::Duration;

use api_gateway::server;
use common::{client, closed_port, eventually, Behavior, MockUpstream, TestGateway};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn forwards_with_prefix_stripping_and_forwarding_headers() {
    let up = MockUpstream::with(Behavior {
        body: "hello".into(),
        ..Behavior::default()
    })
    .await;
    let gw = TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
upstreams: [{{ name: svc, endpoints: ["{}"] }}]
routes:
  - {{ name: api, path_prefix: /api/v1, upstream: svc, strip_prefix: true }}
"#,
        up.url()
    ))
    .await;

    let resp = client()
        .post(gw.url("/api/v1/orders?limit=5"))
        .header("x-request-id", "req-123")
        .header("connection", "keep-alive, x-secret")
        .header("x-secret", "drop-me")
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["x-request-id"], "req-123");
    assert_eq!(resp.text().await.unwrap(), "hello");

    let seen = up.last();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.uri, "/orders?limit=5");
    assert_eq!(seen.body.as_ref(), b"payload");
    assert_eq!(seen.headers["x-request-id"], "req-123");
    assert_eq!(seen.headers["x-forwarded-for"], "127.0.0.1");
    assert_eq!(seen.headers["x-forwarded-proto"], "http");
    assert_eq!(seen.headers["x-forwarded-host"], gw.addr.to_string());
    assert!(!seen.headers.contains_key("x-secret"));
}

#[tokio::test]
async fn generates_request_id_and_returns_json_errors() {
    let up = MockUpstream::start().await;
    let gw = TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
server: {{ max_body_bytes: 16 }}
upstreams: [{{ name: svc, endpoints: ["{}"] }}]
routes: [{{ name: api, path_prefix: /api, upstream: svc, methods: [GET, POST] }}]
"#,
        up.url()
    ))
    .await;
    let c = client();

    let resp = c.get(gw.url("/elsewhere")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
    let id = resp.headers()["x-request-id"].to_str().unwrap().to_string();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "no_route");
    assert_eq!(body["request_id"], id.as_str());

    let resp = c.delete(gw.url("/api/x")).send().await.unwrap();
    assert_eq!(resp.status(), 404, "method not allowed on the only route");

    let resp = c
        .post(gw.url("/api/x"))
        .body(vec![b'a'; 64])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    assert_eq!(up.hits(), 0);
}

#[tokio::test]
async fn round_robin_spreads_load() {
    let a = MockUpstream::start().await;
    let b = MockUpstream::start().await;
    let c = MockUpstream::start().await;
    let gw = TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
upstreams: [{{ name: svc, endpoints: ["{}", "{}", "{}"] }}]
routes: [{{ name: all, upstream: svc }}]
"#,
        a.url(),
        b.url(),
        c.url()
    ))
    .await;
    let http = client();
    for _ in 0..30 {
        assert_eq!(http.get(gw.url("/")).send().await.unwrap().status(), 200);
    }
    assert_eq!((a.hits(), b.hits(), c.hits()), (10, 10, 10));
}

#[tokio::test]
async fn retries_idempotent_requests_only() {
    let bad = MockUpstream::with(Behavior {
        status: 503,
        ..Behavior::default()
    })
    .await;
    let good = MockUpstream::start().await;
    let gw = TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
upstreams: [{{ name: svc, endpoints: ["{}", "{}"] }}]
routes:
  - name: all
    upstream: svc
    retry: {{ attempts: 3, base_backoff: 1ms, max_backoff: 5ms }}
"#,
        bad.url(),
        good.url()
    ))
    .await;
    let http = client();
    for _ in 0..6 {
        assert_eq!(http.get(gw.url("/")).send().await.unwrap().status(), 200);
    }
    assert_eq!(good.hits(), 6);

    let mut statuses = HashSet::new();
    for _ in 0..4 {
        statuses.insert(
            http.post(gw.url("/"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
        );
    }
    assert_eq!(statuses, HashSet::from([200, 503]), "POST is never retried");

    let metrics = gw.gateway.metrics().render();
    assert!(
        metrics.contains("gateway_retries_total{route=\"all\"}"),
        "{metrics}"
    );
}

#[tokio::test]
async fn circuit_breaker_opens_and_recovers() {
    let up = MockUpstream::with(Behavior {
        status: 500,
        ..Behavior::default()
    })
    .await;
    let gw = TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
upstreams:
  - name: svc
    endpoints: ["{}"]
    circuit_breaker: {{ failure_threshold: 3, open_duration: 200ms }}
routes: [{{ name: all, upstream: svc }}]
"#,
        up.url()
    ))
    .await;
    let http = client();
    for _ in 0..3 {
        assert_eq!(http.get(gw.url("/")).send().await.unwrap().status(), 500);
    }
    let resp = http.get(gw.url("/")).send().await.unwrap();
    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "circuit_open");
    assert_eq!(up.hits(), 3, "open breaker short-circuits");

    up.set(|b| b.status = 200);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(http.get(gw.url("/")).send().await.unwrap().status(), 200);
    assert_eq!(http.get(gw.url("/")).send().await.unwrap().status(), 200);
    assert!(gw
        .gateway
        .metrics()
        .render()
        .contains("gateway_circuit_breaker_state{upstream=\"svc\"} 0"));
}

#[tokio::test]
async fn rate_limits_per_header_key() {
    let up = MockUpstream::start().await;
    let gw = TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
upstreams: [{{ name: svc, endpoints: ["{}"] }}]
routes:
  - name: all
    upstream: svc
    rate_limit: {{ requests_per_second: 1, burst: 2, key: "header:x-api-key" }}
"#,
        up.url()
    ))
    .await;
    let http = client();
    let send = |key: &'static str| http.get(gw.url("/")).header("x-api-key", key).send();
    assert_eq!(send("alpha").await.unwrap().status(), 200);
    assert_eq!(send("alpha").await.unwrap().status(), 200);
    let limited = send("alpha").await.unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(limited.headers()["retry-after"], "1");
    assert_eq!(send("beta").await.unwrap().status(), 200);
    assert_eq!(up.hits(), 3);
}

#[tokio::test]
async fn timeouts_and_connection_failures_map_to_gateway_errors() {
    let slow = MockUpstream::with(Behavior {
        delay: Duration::from_millis(500),
        ..Behavior::default()
    })
    .await;
    let dead = closed_port().await;
    let gw = TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
upstreams:
  - {{ name: slow, endpoints: ["{}"], request_timeout: 100ms }}
  - {{ name: dead, endpoints: ["http://{}"] }}
  - {{ name: slow-route, endpoints: ["{}"] }}
routes:
  - {{ name: slow, path_prefix: /slow, upstream: slow }}
  - {{ name: dead, path_prefix: /dead, upstream: dead }}
  - {{ name: deadline, path_prefix: /deadline, upstream: slow-route, timeout: 100ms }}
"#,
        slow.url(),
        dead,
        slow.url()
    ))
    .await;
    let http = client();
    let check = |path: &'static str, status: u16, kind: &'static str| {
        let http = http.clone();
        let url = gw.url(path);
        async move {
            let resp = http.get(url).send().await.unwrap();
            assert_eq!(resp.status(), status, "{path}");
            let body: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(body["error"], kind, "{path}");
        }
    };
    check("/slow", 504, "upstream_timeout").await;
    check("/dead", 502, "upstream_error").await;
    check("/deadline", 504, "route_timeout").await;
}

#[tokio::test]
async fn health_checks_eject_failing_endpoints() {
    let sick = MockUpstream::with(Behavior {
        status: 500,
        ..Behavior::default()
    })
    .await;
    let healthy = MockUpstream::start().await;
    let gw = TestGateway::start(&format!(
        r#"
listen: 127.0.0.1:0
upstreams:
  - name: svc
    endpoints: ["{}", "{}"]
    health_check: {{ path: /healthz, interval: 20ms, timeout: 100ms, healthy_threshold: 1, unhealthy_threshold: 1 }}
routes: [{{ name: all, upstream: svc }}]
"#,
        sick.url(),
        healthy.url()
    ))
    .await;
    assert!(
        eventually(Duration::from_secs(3), || async {
            gw.gateway.metrics().render().contains(&format!(
                "gateway_upstream_endpoint_healthy{{endpoint=\"{}\",upstream=\"svc\"}} 0",
                sick.addr
            ))
        })
        .await
    );
    let http = client();
    for _ in 0..10 {
        assert_eq!(
            http.get(gw.url("/work")).send().await.unwrap().status(),
            200
        );
    }
    assert!(
        sick.traffic().is_empty(),
        "no user traffic reaches the sick endpoint"
    );

    sick.set(|b| b.status = 200);
    assert!(
        eventually(Duration::from_secs(3), || async {
            gw.gateway.metrics().render().contains(&format!(
                "gateway_upstream_endpoint_healthy{{endpoint=\"{}\",upstream=\"svc\"}} 1",
                sick.addr
            ))
        })
        .await
    );
}

#[tokio::test]
async fn admin_exposes_metrics_and_readiness() {
    let up = MockUpstream::start().await;
    let gw = TestGateway::start(&format!(
        "listen: 127.0.0.1:0\nupstreams: [{{ name: svc, endpoints: [\"{}\"] }}]\nroutes: [{{ name: all, upstream: svc }}]\n",
        up.url()
    ))
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    tokio::spawn(server::serve_admin(
        listener,
        gw.gateway.clone(),
        stop.clone(),
    ));

    let http = client();
    http.get(gw.url("/x")).send().await.unwrap();
    let metrics = http
        .get(format!("http://{admin}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("gateway_requests_total{method=\"GET\",route=\"all\",status=\"200\"} 1")
    );
    assert!(metrics.contains("gateway_request_duration_seconds_bucket"));
    let ready = |http: reqwest::Client| async move {
        http.get(format!("http://{admin}/readyz"))
            .send()
            .await
            .unwrap()
            .status()
    };
    assert_eq!(ready(http.clone()).await, 200);
    gw.gateway.set_draining();
    assert_eq!(ready(http.clone()).await, 503);
    stop.cancel();
}

#[tokio::test]
async fn graceful_shutdown_drains_in_flight_requests() {
    let up = MockUpstream::with(Behavior {
        delay: Duration::from_millis(300),
        body: "done".into(),
        ..Behavior::default()
    })
    .await;
    let mut gw = TestGateway::start(&format!(
        "listen: 127.0.0.1:0\nserver: {{ shutdown_grace: 5s }}\nupstreams: [{{ name: svc, endpoints: [\"{}\"] }}]\nroutes: [{{ name: all, upstream: svc }}]\n",
        up.url()
    ))
    .await;
    let http = client();
    let url = gw.url("/slow");
    let in_flight = tokio::spawn(async move { http.get(url).send().await });
    assert!(eventually(Duration::from_secs(2), || async { up.hits() == 1 }).await);

    gw.shutdown.cancel();
    let resp = in_flight.await.unwrap().unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "done");
    tokio::time::timeout(Duration::from_secs(2), gw.task.take().unwrap())
        .await
        .expect("server exits after draining")
        .unwrap();
    assert!(tokio::net::TcpStream::connect(gw.addr).await.is_err());
}
