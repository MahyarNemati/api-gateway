mod common;

use std::time::Duration;

use api_gateway::{reload, Config};
use common::{client, eventually, Behavior, MockUpstream, TestGateway};
use tokio_util::sync::CancellationToken;

fn config(upstream: &str, extra: &str) -> String {
    format!(
        "listen: 127.0.0.1:0\nupstreams: [{{ name: svc, endpoints: [\"{upstream}\"] }}]\nroutes: [{{ name: all, upstream: svc{extra} }}]\n"
    )
}

async fn body(gw: &TestGateway) -> String {
    client()
        .get(gw.url("/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

#[tokio::test]
async fn applies_valid_changes_and_rejects_invalid_ones() {
    let blue = MockUpstream::with(Behavior {
        body: "blue".into(),
        ..Behavior::default()
    })
    .await;
    let green = MockUpstream::with(Behavior {
        body: "green".into(),
        ..Behavior::default()
    })
    .await;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, config(&blue.url(), "")).unwrap();

    let gw = TestGateway::start_config(Config::from_path(&path).unwrap()).await;
    let cancel = CancellationToken::new();
    let _watcher = reload::watch(path.clone(), gw.gateway.clone(), cancel.clone()).unwrap();
    assert_eq!(body(&gw).await, "blue");

    // Write-to-temp then rename, the way editors and config management do it.
    let tmp = dir.path().join(".gateway.yaml.tmp");
    std::fs::write(&tmp, config(&green.url(), "")).unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    assert!(
        eventually(Duration::from_secs(5), || async {
            body(&gw).await == "green"
        })
        .await
    );

    std::fs::write(
        &path,
        config(
            &blue.url(),
            ", rate_limit: { requests_per_second: -1, burst: 0 }",
        ),
    )
    .unwrap();
    let metrics = gw.gateway.metrics().clone();
    assert!(
        eventually(Duration::from_secs(5), || async {
            metrics
                .render()
                .contains("gateway_config_reloads_total{result=\"error\"}")
        })
        .await
    );
    assert_eq!(
        body(&gw).await,
        "green",
        "invalid config keeps the previous one"
    );
    cancel.cancel();
}

#[tokio::test]
async fn reload_preserves_component_state_when_unchanged() {
    let up = MockUpstream::with(Behavior {
        status: 500,
        ..Behavior::default()
    })
    .await;
    let other = MockUpstream::start().await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstreams:\n  - {{ name: svc, endpoints: [\"{}\"], circuit_breaker: {{ failure_threshold: 1, open_duration: 1h }} }}\n  - {{ name: other, endpoints: [\"{}\"] }}\nroutes: [{{ name: all, upstream: svc }}]\n",
        up.url(),
        other.url()
    );
    let gw = TestGateway::start(&yaml).await;
    let http = client();
    assert_eq!(http.get(gw.url("/")).send().await.unwrap().status(), 500);
    assert_eq!(http.get(gw.url("/")).send().await.unwrap().status(), 503);

    // Adding an unrelated route must not reset the open breaker.
    let more = yaml.replace(
        "routes: [{ name: all, upstream: svc }]",
        "routes: [{ name: all, upstream: svc }, { name: o, path_prefix: /o, upstream: other }]",
    );
    gw.gateway.apply(Config::from_yaml(&more).unwrap()).unwrap();
    assert_eq!(http.get(gw.url("/")).send().await.unwrap().status(), 503);
    assert_eq!(http.get(gw.url("/o")).send().await.unwrap().status(), 200);
    assert_eq!(up.hits(), 1);
}
