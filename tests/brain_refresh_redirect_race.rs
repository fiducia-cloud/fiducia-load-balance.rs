//! Control-plane -> load-balancer HTTP regressions using real loopback sockets.
//! A brain response is untrusted until validated. In particular, the internal
//! trusted-hop secret must never be replayed to a URL from a 3xx Location.
use std::{
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    time::Duration,
};

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header::LOCATION},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};

mod routing {
    pub type ShardId = u32;
}
mod proxy {
    pub const INTERNAL_AUTH_HEADER: &str = "x-fiducia-internal-auth";
    pub fn internal_secret() -> Option<&'static str> { Some("private-brain-hop-secret") }
}
#[path = "../src/table.rs"]
mod table;

async fn serve(app: Router) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await.expect("bind brain fixture");
    let addr = listener.local_addr().expect("fixture address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("brain fixture server");
    });
    (format!("http://{addr}"), task)
}

#[derive(Clone)]
struct SlowBrain {
    placement_entered: Arc<Notify>,
    release_placement: Arc<Notify>,
}

async fn nodes(State(_): State<SlowBrain>, headers: HeaderMap) -> Json<Value> {
    assert_eq!(
        headers.get(proxy::INTERNAL_AUTH_HEADER).and_then(|v| v.to_str().ok()),
        proxy::internal_secret(),
        "node membership lookup must authenticate to brain",
    );
    Json(json!({
        "nodes": [
            {"node_id": "a", "address": "127.0.0.1:9101", "health": "healthy"},
            {"node_id": "b", "address": "127.0.0.1:9102", "health": "healthy"}
        ]
    }))
}

async fn placement(State(state): State<SlowBrain>, headers: HeaderMap) -> Json<Value> {
    assert_eq!(
        headers.get(proxy::INTERNAL_AUTH_HEADER).and_then(|v| v.to_str().ok()),
        proxy::internal_secret(),
        "placement lookup must authenticate to brain",
    );
    state.placement_entered.notify_one();
    state.release_placement.notified().await;
    Json(json!({
        "shards": [{"shard_id": 0, "replicas": ["a", "b"], "preferred_leader": "a"}]
    }))
}

#[tokio::test]
async fn leader_redirect_learned_during_brain_io_wins_over_stale_snapshot() {
    let fixture = SlowBrain {
        placement_entered: Arc::new(Notify::new()),
        release_placement: Arc::new(Notify::new()),
    };
    let app = Router::new()
        .route("/v1/nodes", get(nodes))
        .route("/v1/placement", get(placement))
        .with_state(fixture.clone());
    let (url, server) = serve(app).await;

    let table = Arc::new(table::RouteTable::new(1, vec![
        "http://127.0.0.1:9101".into(),
        "http://127.0.0.1:9102".into(),
    ]));
    let refresh_table = table.clone();
    let refresh = tokio::spawn(async move {
        refresh_table.refresh_from_brain(&url).await;
    });
    tokio::time::timeout(Duration::from_secs(3), fixture.placement_entered.notified())
        .await.expect("brain placement request never arrived");

    assert_eq!(
        table.accept_leader_hint(0, "http://127.0.0.1:9102").as_deref(),
        Some("http://127.0.0.1:9102"),
        "the data plane reported a newly elected leader",
    );
    fixture.release_placement.notify_one();
    tokio::time::timeout(Duration::from_secs(3), refresh)
        .await.expect("refresh stalled").expect("refresh task failed");
    assert_eq!(
        table.leader_for(0).as_deref(),
        Some("http://127.0.0.1:9102"),
        "older control-plane placement cannot undo the newer data-plane correction",
    );
    server.abort();
}

async fn count_redirect_attempts(
    State(hits): State<Arc<AtomicUsize>>,
    _headers: HeaderMap,
) -> StatusCode {
    hits.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

#[tokio::test]
async fn malicious_brain_redirect_does_not_exfiltrate_trusted_hop_credential() {
    let hits = Arc::new(AtomicUsize::new(0));
    let destination = Router::new()
        .route("/collect", get(count_redirect_attempts))
        .with_state(hits.clone());
    let (attacker_url, attacker_server) = serve(destination).await;

    let location = HeaderValue::from_str(&format!("{attacker_url}/collect"))
        .expect("safe fixture redirect header");
    let brain = Router::new()
        .route("/v1/nodes", get(move || {
            let location = location.clone();
            async move { (StatusCode::TEMPORARY_REDIRECT, [(LOCATION, location)]) }
        }))
        .route("/v1/placement", get(|| async {
            Json(json!({"shards": [{"shard_id": 0, "replicas": ["a"], "preferred_leader": "a"}]}))
        }));
    let (brain_url, brain_server) = serve(brain).await;

    let table = table::RouteTable::new(1, vec!["http://127.0.0.1:9101".into()]);
    let before = table.snapshot();
    table.refresh_from_brain(&brain_url).await;
    assert_eq!(
        hits.load(Ordering::SeqCst), 0,
        "brain Location is attacker data; no HTTP request may follow it",
    );
    assert_eq!(table.snapshot(), before, "untrusted redirect may not update routing state");
    brain_server.abort();
    attacker_server.abort();
}
