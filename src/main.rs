//! fiducia-load-balance — edge, key-aware router for the coordination API.
//!
//! HTTP is the first-class client protocol. End clients hit this load balancer;
//! it extracts the routing key from the request path, hashes it to a shard, and
//! forwards to that shard's **current leader**. Its `shard → leader` cache is
//! seeded from the control plane (`fiducia-brain`) and self-corrects when a node
//! redirects (`NotLeader`) — so a leader change is just a redirect on the next
//! stateless request, nothing to migrate.
//!
//! Two distinct planes meet here, and they use different transports:
//!   * **client ↔ LB ↔ node** — stateless **HTTP** (this crate): redirect-friendly,
//!     edge-friendly, long-poll for blocking lock acquires.
//!   * **node ↔ node** (Raft replication) — a persistent, multiplexed streaming
//!     transport (gRPC/raw TCP), **not** this. See `fiducia-node`'s `Transport`.
//!
//! The forwarding path follows node `NotLeader` redirects and self-corrects its
//! cache; the control-plane refresh is still stubbed (see `table.rs`). The LB is
//! stateless, so run as many instances as you like behind a plain L4 balancer.

mod proxy;
mod routing;
mod table;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, Method, Uri},
    response::Response,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::{catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};

use routing::{routing_key, shard_for};
use table::RouteTable;

const SERVICE: &str = "fiducia-load-balance";

/// Cap request bodies forwarded through the LB (KV values). NOTE: deliberately
/// **no request timeout** — the LB proxies blocking lock acquires / long-poll.
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fiducia_telemetry::init(SERVICE);

    let shard_count: u32 = std::env::var("FIDUCIA_SHARD_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);

    // Seed node list (provisional leaders, round-robin) until the brain refresh
    // / redirects fill in the real shard→leader map.
    let nodes: Vec<String> = std::env::var("FIDUCIA_NODES")
        .ok()
        .map(|s| {
            s.split(',')
                .filter(|n| !n.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let brain_url =
        std::env::var("FIDUCIA_BRAIN_URL").unwrap_or_else(|_| "http://localhost:8095".to_string());

    let table = Arc::new(RouteTable::new(shard_count, nodes));

    // Background: keep the shard→leader map fresh from the control plane.
    {
        let table = table.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                table.refresh_from_brain(&brain_url).await;
            }
        });
    }

    let app = Router::new()
        // LB's own liveness (not proxied).
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        // Operator/debug surface under /_lb (kept off the proxied namespace).
        .route("/_lb/routes", get(routes_dump))
        .route("/_lb/resolve", get(resolve))
        // Everything else is a client request to be routed to a shard leader.
        .fallback(proxy_fallback)
        .with_state(table)
        // Hardening (outermost last): catch handler panics → 500 and cap body
        // size. No TimeoutLayer — the LB proxies long-poll/blocking acquires.
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(CatchPanicLayer::new());

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8088);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!("{SERVICE} listening on http://{addr} (shards={shard_count})");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "service": SERVICE }))
}

/// Catch-all: route a client request to the owning shard's leader.
async fn proxy_fallback(
    State(table): State<Arc<RouteTable>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    proxy::route(table, method, uri, headers, body).await
}

/// `GET /_lb/routes` — dump the current shard→leader cache.
async fn routes_dump(State(table): State<Arc<RouteTable>>) -> Json<Value> {
    Json(table.snapshot())
}

#[derive(Debug, Deserialize)]
struct ResolveParams {
    path: String,
}

/// `GET /_lb/resolve?path=/v1/kv/foo` — show the routing decision without
/// forwarding. Handy for verifying key extraction and shard math.
async fn resolve(
    State(table): State<Arc<RouteTable>>,
    Query(p): Query<ResolveParams>,
) -> Json<Value> {
    let key = routing_key_from_path(&p.path);
    let shard = key.as_ref().map(|k| shard_for(k, table.shard_count()));
    let target = match shard {
        Some(s) => table.leader_for(s),
        None => table.any_node(),
    };
    Json(json!({
        "path": p.path,
        "key": key,
        "shard": shard,
        "target": target,
    }))
}
