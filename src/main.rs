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

mod auth;
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

#[derive(Debug, Clone)]
struct TlsSettings {
    cert_path: String,
    key_path: String,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fiducia_telemetry::init(SERVICE);
    let _ = rustls::crypto::ring::default_provider().install_default();

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

    let app = build_app(table);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8088);
    let http_addr = SocketAddr::from(([0, 0, 0, 0], port));
    let http = serve_http(http_addr, app.clone());

    if let Some(tls) = tls_settings()? {
        let tls_addr = SocketAddr::from(([0, 0, 0, 0], tls.port));
        let https = serve_https(tls_addr, app, tls);
        tokio::select! {
            result = http => result?,
            result = https => result?,
        }
    } else {
        http.await?;
    }

    Ok(())
}

fn build_app(table: Arc<RouteTable>) -> Router {
    // Edge auth (offline JWT verify + cached introspection). Permissive unless
    // FIDUCIA_AUTH_MODE=enforce, so this rolls out without breaking clients.
    let authn = Arc::new(auth::Authenticator::from_env());
    Router::new()
        // LB's own liveness (not proxied).
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        // Operator/debug surface under /_lb (kept off the proxied namespace).
        .route("/_lb/routes", get(routes_dump))
        .route("/_lb/resolve", get(resolve))
        // Everything else is a client request to be routed to a shard leader.
        .fallback(proxy_fallback)
        .layer(axum::Extension(authn))
        .with_state(table)
        // Hardening (outermost last): catch handler panics → 500 and cap body
        // size. No TimeoutLayer — the LB proxies long-poll/blocking acquires.
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(CatchPanicLayer::new())
}

async fn serve_http(
    addr: SocketAddr,
    app: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("{SERVICE} listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_https(
    addr: SocketAddr,
    app: Router,
    tls: TlsSettings,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        tls.cert_path,
        tls.key_path,
    )
    .await?;
    tracing::info!("{SERVICE} listening on https://{addr}");
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

fn tls_settings() -> Result<Option<TlsSettings>, Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = std::env::var("FIDUCIA_TLS_CERT_PATH").ok();
    let key_path = std::env::var("FIDUCIA_TLS_KEY_PATH").ok();
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let port = std::env::var("TLS_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8443);
            Ok(Some(TlsSettings {
                cert_path,
                key_path,
                port,
            }))
        }
        (None, None) => Ok(None),
        _ => Err("set both FIDUCIA_TLS_CERT_PATH and FIDUCIA_TLS_KEY_PATH, or neither".into()),
    }
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

/// `GET /_lb/resolve?path=/v1/kv?key=foo` — show the routing decision without
/// forwarding. Handy for verifying key extraction and shard math. The `path`
/// value may include a query string (e.g. the KV `?key=`).
async fn resolve(
    State(table): State<Arc<RouteTable>>,
    Query(p): Query<ResolveParams>,
) -> Json<Value> {
    let uri: Uri = p.path.parse().unwrap_or_default();
    let key = routing_key(&uri);
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

#[cfg(test)]
mod interface_contract_tests {
    use super::*;
    use fiducia_interfaces::{LockAcquireManyRequest, ProposeErrorReason};

    #[test]
    fn generated_interfaces_are_importable() {
        let request = LockAcquireManyRequest {
            keys: vec!["orders/42".to_string(), "inventory/sku-7".to_string()],
            holder: Some("worker-a".to_string()),
            ttl_ms: Some(30_000),
            wait: Some(false),
        };

        assert_eq!(request.keys.len(), 2);
        assert!(matches!(
            ProposeErrorReason::NotLeader,
            ProposeErrorReason::NotLeader
        ));
    }

    #[test]
    fn tls_settings_require_cert_and_key_together() {
        std::env::remove_var("FIDUCIA_TLS_CERT_PATH");
        std::env::remove_var("FIDUCIA_TLS_KEY_PATH");
        std::env::remove_var("TLS_PORT");
        assert!(tls_settings().unwrap().is_none());

        std::env::set_var("FIDUCIA_TLS_CERT_PATH", "/tls/tls.crt");
        assert!(tls_settings().is_err());

        std::env::set_var("FIDUCIA_TLS_KEY_PATH", "/tls/tls.key");
        std::env::set_var("TLS_PORT", "9443");
        let settings = tls_settings().unwrap().unwrap();
        assert_eq!(settings.cert_path, "/tls/tls.crt");
        assert_eq!(settings.key_path, "/tls/tls.key");
        assert_eq!(settings.port, 9443);

        std::env::remove_var("FIDUCIA_TLS_CERT_PATH");
        std::env::remove_var("FIDUCIA_TLS_KEY_PATH");
        std::env::remove_var("TLS_PORT");
    }
}
