//! Black-box client -> LB binary -> regional node HTTP integration.
//!
//! Run with `cargo test --test proxy_binary_e2e` after checking out the
//! sibling fiducia-routing.rs and fiducia-interfaces dependencies.
//! Uses the actual LB binary, real TCP sockets and ephemeral local test nodes.

use std::{
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

const INTERNAL_SECRET: &str = "test-internal-hop-secret-unique-for-local-e2e";

#[derive(Debug, Clone)]
struct Observation {
    method: String,
    path: String,
    internal_auth: Option<String>,
    edge_auth: Option<String>,
    org: Option<String>,
    scopes: Option<String>,
    authorization: Option<String>,
    cookie: Option<String>,
}

#[derive(Clone)]
struct NodeFixture {
    leader_hint: Option<String>,
    observations: Arc<Mutex<Vec<Observation>>>,
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

async fn node_handler(
    State(state): State<NodeFixture>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    _body: Bytes,
) -> Response {
    state
        .observations
        .lock()
        .expect("observations lock")
        .push(Observation {
            method: method.to_string(),
            path: uri.to_string(),
            internal_auth: header(&headers, "x-fiducia-internal-auth"),
            edge_auth: header(&headers, "x-fiducia-edge-auth"),
            org: header(&headers, "x-fiducia-org-id"),
            scopes: header(&headers, "x-fiducia-scopes"),
            authorization: header(&headers, "authorization"),
            cookie: header(&headers, "cookie"),
        });

    if let Some(target) = &state.leader_hint {
        let mut response = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": {"reason": "not_leader", "retryable": true}})),
        )
            .into_response();
        response.headers_mut().insert(
            "x-fiducia-not-leader",
            "true".parse().expect("header value"),
        );
        response
            .headers_mut()
            .insert("x-fiducia-leader", target.parse().expect("leader header"));
        response
    } else {
        Json(json!({"committed": true, "source": "leader-node"})).into_response()
    }
}

async fn spawn_node(
    leader_hint: Option<String>,
) -> (String, Arc<Mutex<Vec<Observation>>>, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind node");
    let url = format!("http://{}", listener.local_addr().expect("node address"));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn({
        let fixture = NodeFixture {
            leader_hint,
            observations: observations.clone(),
        };
        async move {
            axum::serve(
                listener,
                Router::new().fallback(node_handler).with_state(fixture),
            )
            .await
            .expect("serve node")
        }
    });
    (url, observations, server)
}

struct LoadBalancer(Child);

impl Drop for LoadBalancer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch_lb(nodes: &[&str]) -> (String, LoadBalancer) {
    // The LB binds PORT itself; reserve and release an ephemeral port before
    // spawning to avoid a hard-coded port collision across CI jobs.
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve LB port");
    let port = reserved.local_addr().expect("LB address").port();
    drop(reserved);

    let child = Command::new(env!("CARGO_BIN_EXE_fiducia-load-balance"))
        .env("PORT", port.to_string())
        .env("FIDUCIA_NODES", nodes.join(","))
        .env("FIDUCIA_SHARD_COUNT", "1")
        .env("FIDUCIA_AUTH_REQUIRED", "true")
        .env("FIDUCIA_INTERNAL_SECRET", INTERNAL_SECRET)
        .env("FIDUCIA_BRAIN_URL", "http://127.0.0.1:1")
        .env_remove("FIDUCIA_TLS_CERT_PATH")
        .env_remove("FIDUCIA_TLS_KEY_PATH")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("launch real LB binary");
    (format!("http://127.0.0.1:{port}"), LoadBalancer(child))
}

async fn await_lb(url: &str) {
    let client = reqwest::Client::new();
    for _ in 0..150 {
        if let Ok(response) = client.get(format!("{url}/readyz")).send().await {
            if response.status() == reqwest::StatusCode::OK {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("real LB binary did not become ready within 3.75 seconds");
}

#[tokio::test]
async fn verified_client_crosses_real_lb_and_follower_to_leader_without_header_spoofing() {
    let (leader_url, leader_seen, leader_server) = spawn_node(None).await;
    let (follower_url, follower_seen, follower_server) = spawn_node(Some(leader_url.clone())).await;
    let (lb_url, _lb) = launch_lb(&[&follower_url, &leader_url]);
    await_lb(&lb_url).await;

    let client = reqwest::Client::new();
    // Without the shared proof the untrusted org metadata must not grant
    // access or reach a regional server.
    let rejected = client
        .get(format!("{lb_url}/v1/kv?key=orders%2F42"))
        .header("x-fiducia-org-id", "tenant-forged")
        .header("x-fiducia-scopes", "kv:read")
        .header("x-fiducia-edge-auth", "wrong-proof")
        .send()
        .await
        .expect("HTTP LB rejects untrusted identity");
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert!(follower_seen.lock().unwrap().is_empty());
    assert!(leader_seen.lock().unwrap().is_empty());

    let invoke = || {
        client
            .get(format!("{lb_url}/v1/kv?key=orders%2F42"))
            .header("x-fiducia-edge-auth", INTERNAL_SECRET)
            .header("x-fiducia-auth-kind", "api_key")
            .header("x-fiducia-org-id", "tenant-verified")
            .header("x-fiducia-scopes", "kv:read")
            .header("x-fiducia-internal-auth", "client-forged-node-proof")
            .header("authorization", "Bearer untrusted-client-token")
            .header("cookie", "session=untrusted-client-cookie")
    };
    let first = invoke().send().await.expect("LB to follower to leader");
    assert_eq!(first.status(), StatusCode::OK);
    let body: Value = first.json().await.expect("leader JSON");
    assert_eq!(body["source"], "leader-node");

    let second = invoke().send().await.expect("LB cached leader route");
    assert_eq!(second.status(), StatusCode::OK);
    let body: Value = second.json().await.expect("leader JSON");
    assert_eq!(body["source"], "leader-node");

    let followers = follower_seen.lock().unwrap().clone();
    let leaders = leader_seen.lock().unwrap().clone();
    assert_eq!(
        followers.len(),
        1,
        "only the initial stale route should hit follower"
    );
    assert_eq!(
        leaders.len(),
        2,
        "both requests ultimately reach the leader"
    );

    for observation in followers.iter().chain(leaders.iter()) {
        assert_eq!(observation.method, "GET");
        assert_eq!(observation.path, "/v1/kv?key=orders%2F42");
        assert_eq!(observation.internal_auth.as_deref(), Some(INTERNAL_SECRET));
        assert_eq!(observation.org.as_deref(), Some("tenant-verified"));
        assert_eq!(observation.scopes.as_deref(), Some("kv:read"));
        assert_eq!(observation.edge_auth, None);
        assert_eq!(observation.authorization, None);
        assert_eq!(observation.cookie, None);
    }
    follower_server.abort();
    leader_server.abort();
}
