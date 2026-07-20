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
//! The forwarding path follows node `NotLeader` redirects, self-corrects its
//! cache, and refreshes placement from the control plane. The LB is stateless,
//! so run as many instances as you like behind a plain L4 balancer.

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
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::{catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};

use routing::{routing_key, shard_for};
use table::RouteTable;

const SERVICE: &str = "fiducia-load-balance";
const ADMIN_READ_SCOPES: &[&str] = &["admin:read", "admin:write"];

/// Cap request bodies forwarded through the LB (KV values). NOTE: deliberately
/// **no request timeout** — the LB proxies blocking lock acquires / long-poll.
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
struct TlsSettings {
    cert_path: String,
    key_path: String,
    port: u16,
}

struct AppState {
    auth: auth::AuthState,
    routes: Arc<RouteTable>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Hold the guard for the whole of `main`: v0.2.1's `init` returns a
    // `#[must_use]` TelemetryGuard that shuts the OTLP exporters down on drop.
    let _telemetry = fiducia_telemetry::init(SERVICE);
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
    let auth = auth::AuthState::from_env();

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

    let app = build_app(Arc::new(AppState {
        auth,
        routes: table,
    }));

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8088);
    let http_addr = SocketAddr::from(([0, 0, 0, 0], port));

    // Loud, explicit warning for the opt-in trust-boundary mode: with no shared
    // secret the LB will NOT trust edge-forwarded `x-fiducia-*` identities (they
    // are treated as anonymous and dropped) and sends no trusted-hop secret to
    // nodes/brain. Safe-by-default (scoped routes still fail closed), but any
    // multi-hop / production deploy must set it.
    if proxy::internal_secret().is_none() {
        tracing::warn!(
            "FIDUCIA_INTERNAL_SECRET is unset — edge-forwarded identity headers will \
             NOT be trusted and no trusted-hop secret is sent to nodes/brain; set it \
             for any multi-hop or production deployment"
        );
    }

    if let Some(tls) = tls_settings()? {
        // TLS is on, so the real proxy is served over HTTPS on TLS_PORT. The
        // plaintext PORT listener stays bound (k8s liveness/readiness probes and
        // the in-cluster ClusterIP still target it) but must NOT proxy application
        // traffic in cleartext: it only answers /healthz + /readyz and rejects
        // every other path with 426. Redirecting a credential-bearing mutation
        // using an untrusted Host header could exfiltrate its body, so the client
        // must retry an explicitly configured HTTPS URL itself.
        let tls_addr = SocketAddr::from(([0, 0, 0, 0], tls.port));
        tracing::info!(
            "TLS enabled — HTTPS proxy on port {tls}; plaintext port {port} serves only \
             /healthz + /readyz and rejects all other paths with 426 (no cleartext \
             proxying or Host-derived redirects)",
            tls = tls.port,
        );
        let guard = build_plaintext_guard_app();
        let http = serve_http(http_addr, guard);
        let https = serve_https(tls_addr, app, tls);
        tokio::select! {
            result = http => result?,
            result = https => result?,
        }
    } else {
        tracing::warn!(
            "TLS is disabled (FIDUCIA_TLS_CERT_PATH / FIDUCIA_TLS_KEY_PATH unset) — \
             serving plaintext HTTP only (full proxy on port {port}); terminate TLS here \
             or at a trusted hop before exposing the LB to untrusted networks"
        );
        let http = serve_http(http_addr, app);
        http.await?;
    }

    Ok(())
}

fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        // LB's own liveness (not proxied).
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        // Operator/debug surface under /_lb (kept off the proxied namespace).
        .route("/_lb/routes", get(routes_dump))
        .route("/_lb/resolve", get(resolve))
        // Everything else is a client request to be routed to a shard leader.
        .fallback(proxy_fallback)
        .with_state(state)
        // Hardening (outermost last): catch handler panics → 500 and cap body
        // size. No TimeoutLayer — the LB proxies long-poll/blocking acquires.
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(CatchPanicLayer::new())
}

/// The router served on the plaintext `PORT` **when TLS is enabled**. It keeps
/// the k8s probes answerable but refuses to proxy application traffic in
/// cleartext: every non-probe path is answered with `426 Upgrade Required`.
/// This carries no `AppState` — it never touches auth, the route table, an
/// upstream node, or an untrusted Host header.
fn build_plaintext_guard_app() -> Router {
    Router::new()
        // k8s liveness/readiness probes target these on the plaintext port.
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        // Everything else must speak HTTPS — never proxied or redirected using
        // caller-controlled authority data.
        .fallback(plaintext_upgrade_required)
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new())
}

async fn plaintext_upgrade_required() -> Response {
    (
        StatusCode::UPGRADE_REQUIRED,
        Json(json!({
            "error": "https_required",
            "detail": "cleartext proxying is disabled while TLS is enabled; retry the configured HTTPS endpoint",
        })),
    )
        .into_response()
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
    let config =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(tls.cert_path, tls.key_path).await?;
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
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let identity = match request_identity(&state.auth, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    proxy::route(state.routes.clone(), identity, method, uri, headers, body).await
}

/// `GET /_lb/routes` — dump the current shard→leader cache.
async fn routes_dump(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match request_identity(&state.auth, &headers).await {
        Ok(identity) => {
            if authorize_admin_read(identity.as_ref()).is_err() {
                return insufficient_admin_scope_response();
            }
            Json(state.routes.snapshot()).into_response()
        }
        Err(response) => response,
    }
}

#[derive(Debug, Deserialize)]
struct ResolveParams {
    path: String,
}

/// `GET /_lb/resolve?path=/v1/kv?key=foo` — show the routing decision without
/// forwarding. Handy for verifying key extraction and shard math. The `path`
/// value may include a query string (e.g. the KV `?key=`).
async fn resolve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(p): Query<ResolveParams>,
) -> Response {
    let identity = match request_identity(&state.auth, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };
    if authorize_admin_read(identity.as_ref()).is_err() {
        return insufficient_admin_scope_response();
    }

    // A malformed path must be a 400, not a silent fall-through to `Uri`'s
    // default ("/"): answering with "/"'s shard would hand the operator a
    // confidently wrong routing diagnosis.
    let uri: Uri = match p.path.parse() {
        Ok(uri) => uri,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "path is not a valid URI", "path": p.path })),
            )
                .into_response();
        }
    };
    // Resolve under the CALLER's org scope, exactly like the proxy path: an
    // org-owned key routes by its scoped form, so the answer shown here is the
    // shard the data plane will really use for this identity.
    let key = routing_key(&uri, identity.as_ref().map(|i| i.org_id.as_str()));
    let shard = key
        .as_ref()
        .map(|k| shard_for(k, state.routes.shard_count()));
    let target = match shard {
        Some(s) => state.routes.leader_for(s),
        None => state.routes.any_node(),
    };
    Json(json!({
        "path": p.path,
        "key": key,
        "shard": shard,
        "target": target,
    }))
    .into_response()
}

/// Authenticate either a raw end-client credential or an identity already
/// verified by the trusted edge. The edge deliberately strips raw credentials,
/// so its proof must be evaluated *before* `AuthState::authenticate`: a secure
/// release build otherwise returns `401 missing_credentials` before it ever sees
/// the valid `x-fiducia-edge-auth` proof.
///
/// A forged identity header cannot take this path: `trusted_edge_identity` only
/// returns a value after a constant-time comparison with `FIDUCIA_INTERNAL_SECRET`.
/// Requests without that proof retain the normal raw-credential policy, including
/// the secure release default of requiring authentication.
async fn request_identity(
    auth_state: &auth::AuthState,
    headers: &HeaderMap,
) -> Result<Option<auth::VerifiedIdentity>, Response> {
    request_identity_with_secret(auth_state, headers, proxy::internal_secret()).await
}

async fn request_identity_with_secret(
    auth_state: &auth::AuthState,
    headers: &HeaderMap,
    expected_secret: Option<&str>,
) -> Result<Option<auth::VerifiedIdentity>, Response> {
    if let Some(identity) = auth::trusted_edge_identity(headers, expected_secret) {
        return Ok(Some(identity));
    }
    auth_state.authenticate(headers).await
}

fn authorize_admin_read(identity: Option<&auth::VerifiedIdentity>) -> Result<(), ()> {
    // Fail CLOSED for an absent identity. `/_lb/routes` and `/_lb/resolve` expose
    // internal topology (node URLs/IPs, regions, cloud providers, cluster IDs, and
    // the shard→leader map), so an unauthenticated caller must not read them — the
    // same fail-closed rule the proxy path applies to scoped routes. (When
    // `FIDUCIA_AUTH_REQUIRED` is false, `authenticate` yields `None` for a
    // credential-less request; without this guard these debug routes would leak
    // cluster topology to any anonymous client, including one reaching the LB
    // through the edge.)
    let Some(identity) = identity else {
        return Err(());
    };

    if identity.scopes.iter().any(|scope| {
        let scope = scope.trim();
        scope == "*"
            || ADMIN_READ_SCOPES
                .iter()
                .any(|required| scope_matches(scope, required))
    }) {
        return Ok(());
    }

    Err(())
}

fn scope_matches(granted: &str, required: &str) -> bool {
    if granted == required {
        return true;
    }
    let Some(prefix) = granted.strip_suffix(":*") else {
        return false;
    };
    required
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.starts_with(':'))
}

fn insufficient_admin_scope_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "insufficient_scope",
            "detail": "credential scope does not permit this operator route",
            "required_scopes": ADMIN_READ_SCOPES,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod interface_contract_tests {
    use super::*;
    use fiducia_interfaces::{LockAcquireManyRequest, ProposeErrorReason};

    #[test]
    fn generated_interfaces_are_importable() {
        let request = LockAcquireManyRequest {
            keys: vec!["orders/42".to_string(), "inventory/sku-7".to_string()],
            holder: "worker-a".to_string(),
            request_id: None,
            ttl_ms: Some(30_000),
            wait: Some(false),
            wait_timeout_ms: None,
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

    #[test]
    fn lb_operator_routes_require_admin_read_scope_and_fail_closed_when_anonymous() {
        // An absent identity (anonymous, e.g. when FIDUCIA_AUTH_REQUIRED is off)
        // must NOT read the internal-topology debug routes — fail closed.
        assert!(authorize_admin_read(None).is_err());
        assert!(authorize_admin_read(Some(&test_identity(&["kv:read"]))).is_err());
        assert!(authorize_admin_read(Some(&test_identity(&["admin:read"]))).is_ok());
        assert!(authorize_admin_read(Some(&test_identity(&["admin:write"]))).is_ok());
        assert!(authorize_admin_read(Some(&test_identity(&["admin:*"]))).is_ok());
        assert!(authorize_admin_read(Some(&test_identity(&["*"]))).is_ok());
    }

    #[tokio::test]
    async fn valid_trusted_edge_identity_precedes_missing_raw_credentials() {
        // Release builds require a raw bearer credential by default. A trusted
        // edge has already authenticated the caller and intentionally strips
        // that credential, so its valid proof must still yield an identity.
        let auth_state = auth::AuthState::from_env();
        let mut headers = HeaderMap::new();
        headers.insert(auth::EDGE_AUTH_HEADER, "edge-secret".parse().unwrap());
        headers.insert("x-fiducia-org-id", "org_edge".parse().unwrap());
        headers.insert("x-fiducia-scopes", "kv:write".parse().unwrap());

        let identity = request_identity_with_secret(&auth_state, &headers, Some("edge-secret"))
            .await
            .expect("valid trusted edge must not be rejected as missing credentials")
            .expect("valid trusted edge must produce an identity");
        assert_eq!(identity.org_id, "org_edge");
        assert_eq!(identity.scopes, vec!["kv:write"]);
    }

    #[tokio::test]
    async fn plaintext_guard_serves_probes_but_rejects_everything_else() {
        let resp = plaintext_upgrade_required().await;
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);

        // The guard router only registers the two probe routes as real handlers;
        // building it must not panic.
        let _ = build_plaintext_guard_app();
    }

    fn test_identity(scopes: &[&str]) -> auth::VerifiedIdentity {
        auth::VerifiedIdentity {
            kind: auth::AuthKind::ApiKey,
            org_id: "org_test".to_string(),
            key_id: Some("key_test".to_string()),
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            require_idempotency: false,
        }
    }
}
