//! Real-HTTP contract tests for the load balancer's brain refresh boundary.
//!
//! The production crate is a binary, so this integration target includes the
//! routing-table module directly and supplies only the two crate-level seams it
//! consumes (`routing::ShardId` and the trusted-hop secret accessor). The tests
//! then exercise `RouteTable::refresh_from_brain` over an actual ephemeral Axum
//! server instead of calling the private snapshot application helper.

use std::sync::{Arc, Mutex};

use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

mod routing {
    pub type ShardId = u32;
}

mod proxy {
    pub const INTERNAL_AUTH_HEADER: &str = "x-fiducia-internal-auth";
    pub fn internal_secret() -> Option<&'static str> {
        Some("brain-refresh-contract-secret")
    }
}

#[path = "../src/table.rs"]
mod table;

const EXPECTED_SECRET: &str = "brain-refresh-contract-secret";

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestObservation {
    path: &'static str,
    internal_secret: Option<String>,
}

#[derive(Clone)]
struct BrainFixture {
    nodes: Value,
    placement: Value,
    requests: Arc<Mutex<Vec<RequestObservation>>>,
}

async fn nodes_handler(
    State(state): State<BrainFixture>,
    headers: HeaderMap,
) -> Json<Value> {
    observe(&state, "/v1/nodes", &headers);
    Json(state.nodes)
}

async fn placement_handler(
    State(state): State<BrainFixture>,
    headers: HeaderMap,
) -> Json<Value> {
    observe(&state, "/v1/placement", &headers);
    Json(state.placement)
}

fn observe(state: &BrainFixture, path: &'static str, headers: &HeaderMap) {
    let internal_secret = headers
        .get(proxy::INTERNAL_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    state
        .requests
        .lock()
        .expect("request observation lock")
        .push(RequestObservation {
            path,
            internal_secret,
        });
}

async fn spawn_brain(
    nodes: Value,
    placement: Value,
) -> (String, Arc<Mutex<Vec<RequestObservation>>>, JoinHandle<()>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v1/nodes", get(nodes_handler))
        .route("/v1/placement", get(placement_handler))
        .with_state(BrainFixture {
            nodes,
            placement,
            requests: requests.clone(),
        });

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind brain fixture");
    let address = listener.local_addr().expect("brain fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("brain fixture server");
    });

    (format!("http://{address}"), requests, server)
}

#[tokio::test]
async fn complete_snapshot_refreshes_over_http_and_authenticates_both_requests() {
    let (brain_url, requests, server) = spawn_brain(
        json!({
            "nodes": [
                {
                    "node_id": "a",
                    "address": "10.0.0.1:8090",
                    "health": "healthy",
                    "cloud_provider": "aws",
                    "region": "us-east-1",
                    "cluster_id": "aws-prod"
                },
                {
                    "node_id": "b",
                    "address": "https://10.0.0.2:8443",
                    "health": "healthy",
                    "cloud_provider": "gcp",
                    "region": "us-central1",
                    "cluster_id": "gcp-prod"
                }
            ]
        }),
        json!({
            "shards": [
                {
                    "shard_id": 0,
                    "replicas": ["a", "b"],
                    "preferred_leader": "a"
                },
                {
                    "shard_id": 1,
                    "replicas": ["a", "b"],
                    "preferred_leader": "b"
                }
            ]
        }),
    )
    .await;

    let table = table::RouteTable::new(2, vec![]);
    table.refresh_from_brain(&brain_url).await;

    assert_eq!(table.leader_for(0).as_deref(), Some("http://10.0.0.1:8090"));
    assert_eq!(
        table.leader_for(1).as_deref(),
        Some("https://10.0.0.2:8443")
    );
    assert!(table.is_hydrated());

    let snapshot = table.snapshot();
    assert_eq!(
        snapshot["nodes"],
        json!(["http://10.0.0.1:8090", "https://10.0.0.2:8443"])
    );
    assert_eq!(snapshot["node_metadata"][0]["cloud_provider"], "aws");
    assert_eq!(snapshot["node_metadata"][1]["cluster_id"], "gcp-prod");

    assert_eq!(
        *requests.lock().expect("request observations"),
        vec![
            RequestObservation {
                path: "/v1/nodes",
                internal_secret: Some(EXPECTED_SECRET.to_string()),
            },
            RequestObservation {
                path: "/v1/placement",
                internal_secret: Some(EXPECTED_SECRET.to_string()),
            },
        ],
        "the trusted-hop secret must authenticate both control-plane reads"
    );

    server.abort();
}

#[tokio::test]
async fn partial_http_snapshot_preserves_the_last_known_good_routes() {
    let table = table::RouteTable::new(
        2,
        vec![
            "http://seed-a:8090".to_string(),
            "http://seed-b:8090".to_string(),
        ],
    );
    let before = table.snapshot();

    let (brain_url, requests, server) = spawn_brain(
        json!({
            "nodes": [{
                "node_id": "brain-a",
                "address": "brain-a:8090",
                "health": "healthy"
            }]
        }),
        json!({
            "shards": [{
                "shard_id": 0,
                "replicas": ["brain-a"],
                "preferred_leader": "brain-a"
            }]
        }),
    )
    .await;

    table.refresh_from_brain(&brain_url).await;

    assert_eq!(
        table.snapshot(),
        before,
        "an incomplete placement must never replace a complete route table"
    );
    assert_eq!(
        requests.lock().expect("request observations").len(),
        2,
        "both snapshots are fetched before completeness is evaluated"
    );

    server.abort();
}

#[tokio::test]
async fn malformed_member_isolated_without_poisoning_a_complete_http_snapshot() {
    let (brain_url, _requests, server) = spawn_brain(
        json!({
            "nodes": [
                {
                    "node_id": "a",
                    "address": "10.0.0.1:8090",
                    "health": "healthy"
                },
                {
                    "node_id": "bad",
                    "address": "",
                    "health": "healthy"
                },
                {
                    "node_id": "c",
                    "address": "10.0.0.3:8090",
                    "health": "healthy"
                }
            ]
        }),
        json!({
            "shards": [
                {
                    "shard_id": 0,
                    "replicas": ["a"],
                    "preferred_leader": "a"
                },
                {
                    "shard_id": 1,
                    "replicas": ["bad", "c"],
                    "preferred_leader": "bad"
                }
            ]
        }),
    )
    .await;

    let table = table::RouteTable::new(2, vec![]);
    table.refresh_from_brain(&brain_url).await;

    assert_eq!(table.leader_for(0).as_deref(), Some("http://10.0.0.1:8090"));
    assert_eq!(table.leader_for(1).as_deref(), Some("http://10.0.0.3:8090"));
    assert_eq!(
        table.snapshot()["nodes"],
        json!(["http://10.0.0.1:8090", "http://10.0.0.3:8090"]),
        "an unusable heartbeat address must cost only that member"
    );

    server.abort();
}
