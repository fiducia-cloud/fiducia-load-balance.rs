//! Integration tests for the LB -> brain HTTP control-plane boundary under
//! failures and overlapping leader corrections. The production RouteTable makes
//! real requests to an ephemeral Axum server; no replacement HTTP client is used.
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use tokio::{sync::{Notify, Semaphore}, task::JoinHandle};

mod routing {
    pub type ShardId = u32;
}
mod proxy {
    pub const INTERNAL_AUTH_HEADER: &str = "x-fiducia-internal-auth";
    pub fn internal_secret() -> Option<&'static str> {
        Some("failure-recovery-test-secret")
    }
}
#[path = "../src/table.rs"]
mod table;

#[derive(Clone)]
struct Brain {
    nodes: Value,
    placement: Arc<Mutex<Value>>,
    // 0=healthy, 1=503, 2=malformed JSON
    failure: Arc<AtomicU8>,
    hold_placement: Arc<AtomicBool>,
    entered: Arc<Notify>,
    release: Arc<Semaphore>,
    requests: Arc<Mutex<Vec<(String, Option<String>)>>>,
}
impl Brain {
    fn new() -> Self {
        Self {
            nodes: json!({"nodes": [
                {"node_id":"a", "address":"10.12.0.1:8090", "health":"healthy",
                 "cluster_id":"region-a"},
                {"node_id":"b", "address":"10.12.0.2:8090", "health":"healthy",
                 "cluster_id":"region-b"}
            ]}),
            placement: Arc::new(Mutex::new(placement("a"))),
            failure: Arc::new(AtomicU8::new(0)),
            hold_placement: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Semaphore::new(0)),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn observe(&self, path: &str, headers: &HeaderMap) {
        let secret = headers
            .get(proxy::INTERNAL_AUTH_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        self.requests.lock().unwrap().push((path.to_owned(), secret));
    }
}
fn placement(leader: &str) -> Value {
    json!({"shards": [{"shard_id":0, "replicas":["a","b"],
                        "preferred_leader":leader}]})
}
async fn nodes_handler(State(brain): State<Brain>, headers: HeaderMap) -> Response {
    brain.observe("/v1/nodes", &headers);
    Json(brain.nodes).into_response()
}
async fn placement_handler(State(brain): State<Brain>, headers: HeaderMap) -> Response {
    brain.observe("/v1/placement", &headers);
    // Clone the response *before* blocking to model a snapshot already read by
    // the brain when a fresher NotLeader correction arrives at the LB.
    let old_snapshot = brain.placement.lock().unwrap().clone();
    if brain.hold_placement.load(Ordering::SeqCst) {
        brain.entered.notify_one();
        brain.release.acquire().await.expect("test semaphore closed").forget();
    }
    match brain.failure.load(Ordering::SeqCst) {
        1 => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"unavailable"}))).into_response(),
        2 => (
            StatusCode::OK,
            [("content-type", "application/json")],
            "{corrupt-json",
        ).into_response(),
        _ => Json(old_snapshot).into_response(),
    }
}
async fn spawn_brain(brain: Brain) -> (String, JoinHandle<()>) {
    let app = Router::new()
        .route("/v1/nodes", get(nodes_handler))
        .route("/v1/placement", get(placement_handler))
        .with_state(brain);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await.expect("bind brain fixture");
    let addr = listener.local_addr().expect("brain listener address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("brain fixture server");
    });
    (format!("http://{addr}"), task)
}

#[tokio::test]
async fn failed_brain_hops_do_not_poison_routes_and_next_complete_snapshot_recovers() {
    let brain = Brain::new();
    let (url, server) = spawn_brain(brain.clone()).await;
    let routes = table::RouteTable::new(1, vec![]);

    routes.refresh_from_brain(&url).await;
    assert_eq!(routes.leader_for(0).as_deref(), Some("http://10.12.0.1:8090"));
    let before = routes.snapshot();

    brain.failure.store(1, Ordering::SeqCst);
    routes.refresh_from_brain(&url).await;
    assert_eq!(routes.snapshot(), before, "503 placement must not install half a snapshot");

    brain.failure.store(2, Ordering::SeqCst);
    routes.refresh_from_brain(&url).await;
    assert_eq!(routes.snapshot(), before, "invalid JSON must not install half a snapshot");

    *brain.placement.lock().unwrap() = placement("b");
    brain.failure.store(0, Ordering::SeqCst);
    routes.refresh_from_brain(&url).await;
    assert_eq!(routes.leader_for(0).as_deref(), Some("http://10.12.0.2:8090"));
    assert!(routes.is_hydrated());

    let calls = brain.requests.lock().unwrap().clone();
    assert_eq!(calls.len(), 8, "all four refreshes must make both brain HTTP hops");
    for (path, secret) in calls {
        assert!(path == "/v1/nodes" || path == "/v1/placement");
        assert_eq!(secret.as_deref(), Some("failure-recovery-test-secret"),
            "trusted-hop auth must survive failure and recovery");
    }
    server.abort();
}

#[tokio::test]
async fn not_leader_hint_received_during_inflight_brain_read_beats_stale_snapshot() {
    let brain = Brain::new();
    let (url, server) = spawn_brain(brain.clone()).await;
    let routes = Arc::new(table::RouteTable::new(1, vec![]));
    routes.refresh_from_brain(&url).await;
    assert_eq!(routes.leader_for(0).as_deref(), Some("http://10.12.0.1:8090"));

    brain.hold_placement.store(true, Ordering::SeqCst);
    let table_for_refresh = routes.clone();
    let url_for_refresh = url.clone();
    let refresh = tokio::spawn(async move {
        table_for_refresh.refresh_from_brain(&url_for_refresh).await;
    });
    tokio::time::timeout(Duration::from_secs(5), brain.entered.notified())
        .await.expect("brain never received placement request");

    // The brain response is frozen with leader a, while the data plane
    // independently proves that b is now leader.
    assert_eq!(
        routes.accept_leader_hint(0, "http://10.12.0.2:8090").as_deref(),
        Some("http://10.12.0.2:8090")
    );
    brain.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), refresh)
        .await.expect("inflight brain refresh stuck").expect("refresh panicked");
    assert_eq!(
        routes.leader_for(0).as_deref(),
        Some("http://10.12.0.2:8090"),
        "older brain snapshot must not clobber a new data-plane leader correction"
    );

    // The next independently started refresh is newer than the hint and may
    // legitimately supersede it. This also proves the hold was not leaked.
    brain.hold_placement.store(false, Ordering::SeqCst);
    routes.refresh_from_brain(&url).await;
    assert_eq!(routes.leader_for(0).as_deref(), Some("http://10.12.0.1:8090"));
    server.abort();
}
