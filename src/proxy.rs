//! Forwarding with NotLeader redirect handling.
//!
//! HTTP is the first-class client protocol, so forwarding is a plain HTTP
//! reverse-proxy hop with one extra rule: if the chosen node turns out to be a
//! *follower* for the request's shard, it answers `NotLeader` (an HTTP `307` with
//! a `Location`/leader hint, or a JSON body), and we retry against the named
//! leader — updating the cache so the next request skips the bounce.
//!
//! This is why HTTP beats TCP here: a leader change is just a redirect on the
//! next stateless request, with nothing to migrate. (Blocking lock acquires use
//! HTTP long-poll; there is no persistent client socket to fail over.)
//!
//! The routing decision and redirect loop are both real. `NotLeader` is a
//! self-healing cache correction, not a client-visible failure.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{header::LOCATION, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::auth::{should_strip_client_auth_header, VerifiedIdentity};
use crate::routing::{routing_key_with_body, shard_for, ShardId};
use crate::table::RouteTable;

/// Max redirect/retry hops before giving up (defeats redirect loops).
const MAX_HOPS: usize = 4;
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const IDEMPOTENCY_REPLAYED_HEADER: &str = "idempotent-replayed";
const FIDUCIA_IDEMPOTENCY_HEADER: &str = "x-fiducia-idempotency";
/// Retention for a *completed* customer idempotency record — how long a duplicate
/// can still replay the stored response. `complete` extends the record's lease to
/// this once the upstream response is captured.
const CUSTOMER_IDEMPOTENCY_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// In-flight lease for a *claimed-but-not-completed* request. Sized to a few times
/// the ~5s upstream request timeout (× up to `MAX_HOPS`), so a crash between claim
/// and complete frees the key in ~2min instead of poisoning it for the full 24h
/// retention window. Comfortably larger than the worst-case upstream duration, so
/// the lease never lapses mid-flight (which would risk a duplicate re-executing).
const CUSTOMER_INFLIGHT_LEASE_MS: u64 = 120 * 1000;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;
/// Cap on the response body stored for idempotent replay. Kept small because a
/// completed record — body included — lives hex-encoded in the node's Raft state,
/// and the node log is not yet compacted (see the storage epic), so every stored
/// byte persists for the full retention window. Ordinary JSON mutation responses
/// fit comfortably; a larger response is served through once but not cached, so a
/// duplicate gets `409 idempotency_replay_unavailable` rather than a stale replay.
const MAX_REPLAY_BODY_BYTES: usize = 32 * 1024;
/// Hard ceiling on how much of an upstream response the LB will buffer while
/// making a request idempotent. Guards against a huge or malicious upstream body
/// OOMing the proxy. Well above `MAX_REPLAY_BODY_BYTES` so ordinary responses pass
/// through intact; a body larger than this cannot be made idempotent.
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
/// Every upstream response is bounded, not only responses captured for
/// idempotent replay. This prevents a chunked/missing-length node response from
/// growing the proxy process without limit.
const MAX_UPSTREAM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Deadline applied to everything on the streaming path that is NOT a confirmed
/// event-stream body: the header phase, and the buffered body of a response that
/// turned out not to be `text/event-stream`. Matches the ordinary client's request
/// timeout, since those phases are ordinary request work. Only the open SSE body
/// itself is allowed to run without a deadline.
const STREAM_NON_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const PUBLIC_SCOPES: &[&str] = &[];
const ADMIN_READ_SCOPES: &[&str] = &["admin:read", "admin:write"];
const ADMIN_WRITE_SCOPES: &[&str] = &["admin:write"];
const KV_READ_SCOPES: &[&str] = &["kv:read", "kv:write", "admin:read", "admin:write"];
const KV_WRITE_SCOPES: &[&str] = &["kv:write", "admin:write"];
const LOCKS_READ_SCOPES: &[&str] = &["locks:read", "locks:write", "admin:read", "admin:write"];
const LOCKS_WRITE_SCOPES: &[&str] = &["locks:write", "admin:write"];
const REQUESTS_READ_SCOPES: &[&str] = &[
    "requests:read",
    "requests:write",
    "admin:read",
    "admin:write",
];
const REQUESTS_WRITE_SCOPES: &[&str] = &["requests:write", "admin:write"];
const RATE_LIMIT_READ_SCOPES: &[&str] = &[
    "rate-limit:read",
    "rate-limit:write",
    "requests:read",
    "requests:write",
    "admin:read",
    "admin:write",
];
const RATE_LIMIT_WRITE_SCOPES: &[&str] = &["rate-limit:write", "requests:write", "admin:write"];
const CRON_READ_SCOPES: &[&str] = &[
    "cron:read",
    "cron:write",
    "requests:read",
    "requests:write",
    "admin:read",
    "admin:write",
];
const CRON_WRITE_SCOPES: &[&str] = &["cron:write", "requests:write", "admin:write"];
const ELECTIONS_READ_SCOPES: &[&str] = &[
    "elections:read",
    "elections:write",
    "locks:read",
    "locks:write",
    "admin:read",
    "admin:write",
];
const ELECTIONS_WRITE_SCOPES: &[&str] = &["elections:write", "locks:write", "admin:write"];
const SERVICES_READ_SCOPES: &[&str] = &[
    "services:read",
    "services:write",
    "admin:read",
    "admin:write",
];
const SERVICES_WRITE_SCOPES: &[&str] = &["services:write", "admin:write"];

/// Trusted-hop header carrying the shared cluster secret to the node/brain. They
/// require it on `/v1` when `FIDUCIA_INTERNAL_SECRET` is set, so only the LB
/// (and peer nodes) — not a direct caller — can present injected identity.
pub(crate) const INTERNAL_AUTH_HEADER: &str = "x-fiducia-internal-auth";

/// The shared internal secret, read once. `None` (unset/blank) means the node
/// and brain guards are also off, so we send nothing. Shared with `table.rs`
/// (brain refresh) so the LB presents one consistent trusted-hop secret.
pub(crate) fn internal_secret() -> Option<&'static str> {
    static SECRET: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    SECRET
        .get_or_init(|| {
            std::env::var("FIDUCIA_INTERNAL_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .as_deref()
}

/// What a single upstream attempt told us.
#[derive(Debug)]
enum Upstream {
    /// The node served the request (any normal status code).
    Served(Response),
    /// The node is a follower for the request's shard; retry against `leader`
    /// (from the `307 Location` / JSON hint) if it named one.
    NotLeader { leader: Option<String> },
    /// Request construction or connection establishment failed before an
    /// upstream could receive the request. Safe to retry on another node even
    /// for a mutation.
    NotSent,
    /// The connection was established but the request/response failed. Reads
    /// may try another node; mutations are ambiguous and must fail closed.
    AmbiguousTransport,
    /// The upstream exceeded the proxy's response body ceiling.
    ResponseTooLarge,
}

/// Entry point: resolve the target for a request and forward it.
#[tracing::instrument(name = "lb.route", skip_all, fields(method = %method, path = %uri.path()))]
pub async fn route(
    table: Arc<RouteTable>,
    identity: Option<VerifiedIdentity>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Dot segments are refused BEFORE the scope check — see `path_has_dot_segment`.
    if path_has_dot_segment(uri.path()) {
        return dot_segment_response(&uri);
    }
    if let Err(failure) = authorize_route(identity.as_ref(), &method, &uri) {
        return insufficient_scope_response(&method, &uri, failure.required);
    }

    let customer_idempotency = match CustomerIdempotency::from_request(
        identity.as_ref(),
        &method,
        &uri,
        &headers,
        &body,
    ) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    // Enforce the per-key policy (F1): a key configured `require_idempotency` may
    // not make a mutating call without an `Idempotency-Key`. `from_request`
    // yields `None` here only when the header is absent (a present-but-invalid key
    // already returned `Err` above), and the method/route checks exclude reads and
    // the idempotency primitives themselves.
    if customer_idempotency.is_none()
        && identity.as_ref().is_some_and(|id| id.require_idempotency)
        && method_supports_customer_idempotency(&method)
        && !is_idempotency_primitive(&uri)
    {
        return idempotency_key_required(&method, &uri);
    }
    if let Some(idempotency) = customer_idempotency {
        return route_with_customer_idempotency(
            table,
            identity,
            method,
            uri,
            headers,
            body,
            idempotency,
        )
        .await;
    }

    route_without_customer_idempotency(table, identity, method, uri, headers, body).await
}

struct ScopeFailure {
    required: &'static [&'static str],
}

/// Does the path contain a `.` or `..` segment?
///
/// Authorization matches on `uri.path()` **verbatim**, but the upstream request is
/// rebuilt through the `url` crate (`client.request(method, url)`), which collapses
/// dot segments. Those two views of "the path" must never disagree: without this
/// guard `GET /v1/locks/../observe/locks` authorizes as `locks:read` and still
/// reaches the admin-only observe inventory (which hands out holders' fencing
/// tokens — a capability), and `PUT /v1/locks/../kv?key=x` authorizes as
/// `locks:write` and performs a KV write.
///
/// No fiducia route needs a dot segment, so we refuse instead of normalizing. The
/// percent-encoded spellings the URL standard also treats as dot segments are
/// covered, since the `url` crate collapses those too.
fn path_has_dot_segment(path: &str) -> bool {
    path.split('/').any(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "." | "%2e" | ".." | ".%2e" | "%2e." | "%2e%2e"
        )
    })
}

fn dot_segment_response(uri: &Uri) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_path",
            "detail": "path may not contain a '.' or '..' segment",
            "path": uri.path(),
        })),
    )
        .into_response()
}

fn authorize_route(
    identity: Option<&VerifiedIdentity>,
    method: &Method,
    uri: &Uri,
) -> Result<(), ScopeFailure> {
    let required = required_scopes_for_route(method, uri);
    // Public / read-safe routes (no required scopes, e.g. healthz) stay open to
    // anonymous callers.
    if required.is_empty() {
        return Ok(());
    }

    // A scoped route with no verified identity fails CLOSED — regardless of
    // `FIDUCIA_AUTH_REQUIRED`. This closes the bypass where an edge-forwarded (or
    // otherwise credential-less) request would reach a mutating/admin route with
    // `identity = None` and previously be blanket-allowed, then forwarded to the
    // node under the LB's trusted internal secret.
    let Some(identity) = identity else {
        return Err(ScopeFailure { required });
    };
    if has_any_scope(identity, required) {
        return Ok(());
    }

    Err(ScopeFailure { required })
}

fn insufficient_scope_response(
    method: &Method,
    uri: &Uri,
    required: &'static [&'static str],
) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "insufficient_scope",
            "detail": "credential scope does not permit this route",
            "method": method.as_str(),
            "path": uri.path(),
            "required_scopes": required,
        })),
    )
        .into_response()
}

fn required_scopes_for_route(method: &Method, uri: &Uri) -> &'static [&'static str] {
    let read = is_read_method(method);
    let segs: Vec<_> = uri.path().split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        ["healthz"] | ["readyz"] => PUBLIC_SCOPES,
        ["v1", "status"] => ADMIN_READ_SCOPES,
        // Observability inventories (/v1/observe/{locks,semaphores,elections})
        // enumerate every holder + fencing token across the whole caller org — a
        // fencing token is a capability, so this is an ADMIN surface, never a
        // plain locks:read. Node-wide /observe/{shards,metrics} carry no tenant
        // identity and are also admin via the generic read catch-all below; this
        // arm makes the observe gate explicit so it can't be weakened by accident
        // (e.g. if an `observe` sub-path were ever added to the locks arm).
        ["v1", "observe", ..] => ADMIN_READ_SCOPES,
        ["v1", "kv"] if read => KV_READ_SCOPES,
        ["v1", "kv"] => KV_WRITE_SCOPES,
        ["v1", "locks", ..] | ["v1", "semaphores", ..] | ["v1", "rw", ..] if read => {
            LOCKS_READ_SCOPES
        }
        ["v1", "locks", ..] | ["v1", "semaphores", ..] | ["v1", "rw", ..] => LOCKS_WRITE_SCOPES,
        ["v1", "idempotency"] if read => REQUESTS_READ_SCOPES,
        ["v1", "idempotency"] | ["v1", "idempotency", ..] => REQUESTS_WRITE_SCOPES,
        ["v1", "rate-limit", ..] | ["v1", "ratelimit", ..] if read => RATE_LIMIT_READ_SCOPES,
        ["v1", "rate-limit", ..] | ["v1", "ratelimit", ..] => RATE_LIMIT_WRITE_SCOPES,
        ["v1", "cron", ..] if read => CRON_READ_SCOPES,
        ["v1", "cron", ..] => CRON_WRITE_SCOPES,
        ["v1", "elections", ..] if read => ELECTIONS_READ_SCOPES,
        ["v1", "elections", ..] => ELECTIONS_WRITE_SCOPES,
        ["v1", "services", ..] if read => SERVICES_READ_SCOPES,
        ["v1", "services", ..] => SERVICES_WRITE_SCOPES,
        // The remaining primitive families. Without an explicit arm they fall to
        // the admin catch-all below, and `admin:*` is NOT in fiducia-auth's
        // `ALLOWED_API_KEY_SCOPES` — so every customer API key would get a 403 on
        // them. Each family maps onto the issuable scope for the capability class
        // it really belongs to:
        //   counters — a keyed value in the KV plane           → kv:*
        //   barriers, handoffs, claims — mutual exclusion /
        //     ownership grants, the same capability as a lock  → locks:*
        //   tasks, effects, decisions — request-lifecycle
        //     primitives, the same capability as idempotency   → requests:*
        //   budgets — a spend quota, the same capability as
        //     a rate limit                                     → rate-limit:*
        ["v1", "counters", ..] if read => KV_READ_SCOPES,
        ["v1", "counters", ..] => KV_WRITE_SCOPES,
        ["v1", "barriers", ..] | ["v1", "handoffs", ..] | ["v1", "claims", ..] if read => {
            LOCKS_READ_SCOPES
        }
        ["v1", "barriers", ..] | ["v1", "handoffs", ..] | ["v1", "claims", ..] => {
            LOCKS_WRITE_SCOPES
        }
        ["v1", "tasks", ..] | ["v1", "effects", ..] | ["v1", "decisions", ..] if read => {
            REQUESTS_READ_SCOPES
        }
        ["v1", "tasks", ..] | ["v1", "effects", ..] | ["v1", "decisions", ..] => {
            REQUESTS_WRITE_SCOPES
        }
        ["v1", "budgets", ..] if read => RATE_LIMIT_READ_SCOPES,
        ["v1", "budgets", ..] => RATE_LIMIT_WRITE_SCOPES,
        _ if read => ADMIN_READ_SCOPES,
        _ => ADMIN_WRITE_SCOPES,
    }
}

fn is_read_method(method: &Method) -> bool {
    method == Method::GET || method == Method::HEAD || method == Method::OPTIONS
}

fn has_any_scope(identity: &VerifiedIdentity, required: &[&str]) -> bool {
    identity.scopes.iter().any(|granted| {
        let granted = granted.trim();
        granted == "*"
            || required
                .iter()
                .any(|required| scope_matches(granted, required))
    })
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

async fn route_without_customer_idempotency(
    table: Arc<RouteTable>,
    identity: Option<VerifiedIdentity>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Keyed request → shard's leader. Keyless (status / list) → any node.
    // (Locks/semaphores resolve to the lock-coordination shard inside routing.)
    // The verified org scopes the key exactly as the node will before hashing,
    // so the LB predicts the same shard the node actually commits on.
    let org_id = identity.as_ref().map(|identity| identity.org_id.as_str());
    let (shard, target) = match routing_key_with_body(&uri, &body, org_id) {
        Some(key) => {
            let shard = shard_for(&key, table.shard_count());
            (Some(shard), table.leader_for(shard))
        }
        None => (None, table.any_node()),
    };

    let Some(target) = target else {
        tracing::warn!(shard = ?shard, "lb: no known node for this request — returning 503");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "no_route", "detail": "no known node for this request", "shard": shard })),
        )
            .into_response();
    };

    tracing::debug!(shard = ?shard, target = %target, "lb: forwarding to node");
    forward_with_redirect(
        table,
        ForwardRequest {
            identity,
            target,
            shard,
            method,
            uri,
            headers,
            body,
        },
    )
    .await
}

async fn route_with_customer_idempotency(
    table: Arc<RouteTable>,
    identity: Option<VerifiedIdentity>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    idempotency: CustomerIdempotency,
) -> Response {
    let claim =
        match claim_customer_idempotency(table.clone(), identity.as_ref(), &idempotency).await {
            Ok(claim) => claim,
            Err(response) => return response,
        };

    if let Some(response) = response_for_duplicate_claim(&idempotency, &claim) {
        return response;
    }

    let Some(fencing_token) = claim.fencing_token else {
        tracing::warn!("customer idempotency claim committed without a fencing token");
        return idempotency_unavailable("claim did not return a fencing token");
    };

    let response = route_without_customer_idempotency(
        table.clone(),
        identity.clone(),
        method,
        uri,
        headers,
        body,
    )
    .await;

    // Bounded capture (F4): never buffer an unbounded upstream body. If the body
    // is too large to buffer it also can't be replayed, so release the claim so a
    // retry can re-run and surface a clear error instead of an empty response.
    let captured = match CapturedResponse::from_response(response).await {
        Ok(captured) => captured,
        Err(response) => {
            abandon_customer_idempotency(table, identity.as_ref(), &idempotency, fencing_token)
                .await;
            return response;
        }
    };

    // Cache only *final* responses (F3). A transient failure (5xx / 408 / 429)
    // must not be stored, or the client's correct retry would just replay the
    // cached failure for the whole retention window. Release the claim instead so
    // the retry actually re-executes the mutation.
    if !is_cacheable_idempotent_response(captured.status) {
        abandon_customer_idempotency(table, identity.as_ref(), &idempotency, fencing_token).await;
        let mut response = captured.into_response();
        response.headers_mut().insert(
            FIDUCIA_IDEMPOTENCY_HEADER,
            HeaderValue::from_static("not_stored"),
        );
        return response;
    }

    let stored = StoredIdempotencyResponse::from_captured(&idempotency, &captured);
    let completed = complete_customer_idempotency(
        table,
        identity.as_ref(),
        &idempotency,
        fencing_token,
        &stored,
    )
    .await;

    let mut response = captured.into_response();
    match completed {
        Ok(()) => {
            response.headers_mut().insert(
                FIDUCIA_IDEMPOTENCY_HEADER,
                HeaderValue::from_static("stored"),
            );
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to complete customer idempotency record");
            response.headers_mut().insert(
                FIDUCIA_IDEMPOTENCY_HEADER,
                HeaderValue::from_static("store_failed"),
            );
        }
    }
    response
}

/// Whether an upstream response is "final" and safe to store for idempotent
/// replay. Transient failures — any 5xx, plus `408 Request Timeout` and
/// `429 Too Many Requests` — are excluded so the client's retry re-executes the
/// mutation instead of replaying a stale failure for the retention window.
fn is_cacheable_idempotent_response(status: StatusCode) -> bool {
    if status.is_server_error() {
        return false;
    }
    !matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
    )
}

#[derive(Debug, Clone)]
struct CustomerIdempotency {
    key_hash: String,
    internal_key: String,
    owner: String,
    fingerprint: String,
    method: String,
    target: String,
    org_hash: String,
}

impl CustomerIdempotency {
    fn from_request(
        identity: Option<&VerifiedIdentity>,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Option<Self>, Box<Response>> {
        if !method_supports_customer_idempotency(method) || is_idempotency_primitive(uri) {
            return Ok(None);
        }
        let Some(raw_key) = headers.get(IDEMPOTENCY_KEY_HEADER) else {
            return Ok(None);
        };
        let raw_key = raw_key
            .to_str()
            .map_err(|_| Box::new(bad_idempotency_key("idempotency key must be visible ASCII")))?;
        let trimmed = raw_key.trim();
        if trimmed.is_empty() {
            return Err(Box::new(bad_idempotency_key(
                "idempotency key must not be empty",
            )));
        }
        if trimmed.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(Box::new(bad_idempotency_key("idempotency key is too long")));
        }
        if trimmed.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(Box::new(bad_idempotency_key(
                "idempotency key must not contain control characters",
            )));
        }

        let org_scope = identity
            .map(|identity| format!("org:{}", identity.org_id))
            .unwrap_or_else(|| "anonymous".to_string());
        let org_hash = sha256_hex(org_scope.as_bytes());
        let key_hash = sha256_hex(trimmed.as_bytes());
        let target = uri
            .path_and_query()
            .map(|path| path.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string());
        Ok(Some(CustomerIdempotency {
            internal_key: format!("customer/{org_hash}/{key_hash}"),
            owner: format!("customer/{org_hash}"),
            fingerprint: request_fingerprint(method, &target, headers, body),
            method: method.as_str().to_string(),
            target,
            key_hash,
            org_hash,
        }))
    }

    fn metadata(&self) -> HashMap<String, String> {
        HashMap::from([
            ("scope".to_string(), "customer".to_string()),
            ("org_hash".to_string(), self.org_hash.clone()),
            ("key_hash".to_string(), self.key_hash.clone()),
            ("fingerprint".to_string(), self.fingerprint.clone()),
            ("method".to_string(), self.method.clone()),
            ("target".to_string(), self.target.clone()),
        ])
    }
}

#[derive(Debug)]
struct IdempotencyClaim {
    claimed: bool,
    duplicate: bool,
    fencing_token: Option<u64>,
    record: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdempotencyResponse {
    fingerprint: String,
    status: u16,
    content_type: Option<String>,
    body_hex: String,
    truncated: bool,
}

impl StoredIdempotencyResponse {
    fn from_captured(idempotency: &CustomerIdempotency, captured: &CapturedResponse) -> Self {
        let body = if captured.body.len() <= MAX_REPLAY_BODY_BYTES {
            captured.body.as_ref()
        } else {
            &captured.body[..MAX_REPLAY_BODY_BYTES]
        };
        StoredIdempotencyResponse {
            fingerprint: idempotency.fingerprint.clone(),
            status: captured.status.as_u16(),
            content_type: captured
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            body_hex: to_hex(body),
            truncated: captured.body.len() > MAX_REPLAY_BODY_BYTES,
        }
    }

    fn into_replay_response(self) -> Response {
        if self.truncated {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "idempotency_replay_unavailable",
                    "detail": "stored response exceeded the replay body limit"
                })),
            )
                .into_response();
        }
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);
        // A stored body that no longer hex-decodes is corrupt: fail closed like
        // the truncated branch above. Replaying an empty body as if it were the
        // original response would silently hand the client wrong data.
        let Some(body) = hex_to_bytes(&self.body_hex) else {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "idempotency_replay_unavailable",
                    "detail": "stored response body failed to decode"
                })),
            )
                .into_response();
        };
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        if let Some(content_type) = self.content_type {
            if let Ok(value) = HeaderValue::from_str(&content_type) {
                response.headers_mut().insert("content-type", value);
            }
        }
        response.headers_mut().insert(
            IDEMPOTENCY_REPLAYED_HEADER,
            HeaderValue::from_static("true"),
        );
        response.headers_mut().insert(
            FIDUCIA_IDEMPOTENCY_HEADER,
            HeaderValue::from_static("replayed"),
        );
        response
    }
}

struct CapturedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl CapturedResponse {
    /// Buffer a response body up to [`MAX_CAPTURE_BYTES`]. Fails closed with a
    /// `502` when the body exceeds the cap: buffering it in full would risk an
    /// OOM, and previously the read-error path silently returned an *empty* body
    /// to the client. Callers release the idempotency claim on error so a retry
    /// can re-run.
    async fn from_response(response: Response) -> Result<Self, Response> {
        let (parts, body) = response.into_parts();
        let body = match to_bytes(body, MAX_CAPTURE_BYTES).await {
            Ok(body) => body,
            Err(_) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "upstream_response_too_large",
                        "detail": "upstream response exceeded the proxy capture limit and cannot be made idempotent",
                    })),
                )
                    .into_response());
            }
        };
        Ok(CapturedResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }

    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

async fn claim_customer_idempotency(
    table: Arc<RouteTable>,
    identity: Option<&VerifiedIdentity>,
    idempotency: &CustomerIdempotency,
) -> Result<IdempotencyClaim, Response> {
    let body = json!({
        "key": idempotency.internal_key,
        "owner": idempotency.owner,
        // Short in-flight lease so an abandoned claim frees the key quickly;
        // `complete` extends the record to the full retention window.
        "ttl_ms": CUSTOMER_INFLIGHT_LEASE_MS,
        "retention_ms": CUSTOMER_IDEMPOTENCY_TTL_MS,
        "metadata": idempotency.metadata(),
    });
    let response = route_without_customer_idempotency(
        table,
        identity.cloned(),
        Method::POST,
        "/v1/idempotency/claim".parse().unwrap(),
        json_headers(),
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default()),
    )
    .await;
    let captured = CapturedResponse::from_response(response)
        .await
        .map_err(|_| idempotency_unavailable("claim response was too large"))?;
    if !captured.status.is_success() {
        return Err(idempotency_unavailable("claim request failed"));
    }
    let value: Value = serde_json::from_slice(&captured.body)
        .map_err(|_| idempotency_unavailable("claim response was not valid json"))?;
    let output = value
        .get("result")
        .and_then(|result| result.get("output"))
        .ok_or_else(|| idempotency_unavailable("claim response omitted output"))?;
    Ok(IdempotencyClaim {
        claimed: output
            .get("claimed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        duplicate: output
            .get("duplicate")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        fencing_token: output.get("fencing_token").and_then(Value::as_u64),
        record: output.get("record").cloned(),
    })
}

async fn complete_customer_idempotency(
    table: Arc<RouteTable>,
    identity: Option<&VerifiedIdentity>,
    idempotency: &CustomerIdempotency,
    fencing_token: u64,
    stored: &StoredIdempotencyResponse,
) -> Result<(), &'static str> {
    let body = json!({
        "key": idempotency.internal_key,
        "owner": idempotency.owner,
        "fencing_token": fencing_token,
        "result": serde_json::to_value(stored).map_err(|_| "could not encode stored response")?,
    });
    let response = route_without_customer_idempotency(
        table,
        identity.cloned(),
        Method::POST,
        "/v1/idempotency/complete".parse().unwrap(),
        json_headers(),
        Bytes::from(serde_json::to_vec(&body).map_err(|_| "could not encode complete body")?),
    )
    .await;
    let captured = CapturedResponse::from_response(response)
        .await
        .map_err(|_| "complete response was too large")?;
    if !captured.status.is_success() {
        return Err("complete request failed");
    }
    let value: Value = serde_json::from_slice(&captured.body).map_err(|_| "invalid json")?;
    let completed = value
        .get("result")
        .and_then(|result| result.get("output"))
        .and_then(|output| output.get("completed"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    completed.then_some(()).ok_or("complete was rejected")
}

/// Release a still-claimed key after a transient upstream failure so the client's
/// retry can re-execute the mutation immediately, rather than getting
/// `409 in_progress` until the in-flight lease lapses. Best-effort: if the
/// release itself fails, the short lease still frees the key on expiry.
async fn abandon_customer_idempotency(
    table: Arc<RouteTable>,
    identity: Option<&VerifiedIdentity>,
    idempotency: &CustomerIdempotency,
    fencing_token: u64,
) {
    let body = json!({
        "key": idempotency.internal_key,
        "owner": idempotency.owner,
        "fencing_token": fencing_token,
    });
    let response = route_without_customer_idempotency(
        table,
        identity.cloned(),
        Method::POST,
        "/v1/idempotency/abandon".parse().unwrap(),
        json_headers(),
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default()),
    )
    .await;
    match CapturedResponse::from_response(response).await {
        Ok(captured) if captured.status.is_success() => {}
        _ => tracing::warn!(
            "failed to release customer idempotency claim after a non-final response; \
             the in-flight lease will free it on expiry"
        ),
    }
}

fn response_for_duplicate_claim(
    idempotency: &CustomerIdempotency,
    claim: &IdempotencyClaim,
) -> Option<Response> {
    if claim.claimed {
        return None;
    }
    if !claim.duplicate {
        return Some(idempotency_unavailable("claim was rejected"));
    }
    let Some(record) = claim.record.as_ref() else {
        return Some(idempotency_unavailable("duplicate claim omitted record"));
    };
    let metadata = record.get("metadata").and_then(Value::as_object);
    let recorded_fingerprint = metadata
        .and_then(|metadata| metadata.get("fingerprint"))
        .and_then(Value::as_str);
    if recorded_fingerprint != Some(idempotency.fingerprint.as_str()) {
        return Some(idempotency_conflict(
            "idempotency key was already used with a different request",
        ));
    }
    match record.get("status").and_then(Value::as_str) {
        Some("completed") => {
            let Some(result) = record.get("result") else {
                return Some(idempotency_unavailable("completed record omitted result"));
            };
            match serde_json::from_value::<StoredIdempotencyResponse>(result.clone()) {
                Ok(stored) if stored.fingerprint == idempotency.fingerprint => {
                    Some(stored.into_replay_response())
                }
                _ => Some(idempotency_unavailable(
                    "stored response was not replayable",
                )),
            }
        }
        _ => Some(
            (
                StatusCode::CONFLICT,
                [("retry-after", "1")],
                Json(json!({
                    "error": "idempotency_key_in_progress",
                    "detail": "a matching request is still in progress"
                })),
            )
                .into_response(),
        ),
    }
}

fn method_supports_customer_idempotency(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn is_idempotency_primitive(uri: &Uri) -> bool {
    uri.path().starts_with("/v1/idempotency")
}

fn request_fingerprint(method: &Method, target: &str, headers: &HeaderMap, body: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(method.as_str().as_bytes());
    digest.update([0]);
    digest.update(target.as_bytes());
    digest.update([0]);
    if let Some(content_type) = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
    {
        digest.update(content_type.as_bytes());
    }
    digest.update([0]);
    digest.update(body);
    to_hex(&digest.finalize())
}

fn sha256_hex(value: &[u8]) -> String {
    to_hex(&Sha256::digest(value))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

fn hex_to_bytes(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

fn bad_idempotency_key(reason: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "bad_idempotency_key",
            "detail": reason,
        })),
    )
        .into_response()
}

fn idempotency_key_required(method: &Method, uri: &Uri) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "idempotency_key_required",
            "detail": "this API key requires an Idempotency-Key header on mutating requests",
            "method": method.as_str(),
            "path": uri.path(),
        })),
    )
        .into_response()
}

fn idempotency_conflict(detail: &'static str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": "idempotency_key_conflict",
            "detail": detail,
        })),
    )
        .into_response()
}

fn idempotency_unavailable(detail: &'static str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": "idempotency_unavailable",
            "detail": detail,
        })),
    )
        .into_response()
}

fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers
}

struct ForwardRequest {
    identity: Option<VerifiedIdentity>,
    target: String,
    shard: Option<ShardId>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

/// Forward to `target`, following `NotLeader` redirects up to [`MAX_HOPS`].
async fn forward_with_redirect(table: Arc<RouteTable>, mut request: ForwardRequest) -> Response {
    let mut attempted_targets = HashSet::new();
    for hop in 0..MAX_HOPS {
        attempted_targets.insert(request.target.clone());
        table.record_region_request(&request.target);
        match forward_once(
            &request.target,
            request.identity.as_ref(),
            &request.method,
            &request.uri,
            &request.headers,
            request.body.clone(),
        )
        .await
        {
            Upstream::Served(resp) => {
                if hop > 0 {
                    tracing::debug!(shard = ?request.shard, hops = hop, target = %request.target, "lb: served after redirect/retry");
                }
                return resp;
            }
            Upstream::NotLeader {
                leader: Some(leader),
            } => match redirected_leader_target(&table, request.shard, &leader) {
                Some(target) if !attempted_targets.contains(&target) => {
                    tracing::info!(shard = ?request.shard, hop, from = %request.target, to = %target, "lb: follower redirect — retrying validated leader, refreshing cache");
                    request.target = target;
                }
                Some(target) => {
                    tracing::warn!(shard = ?request.shard, hop, from = %request.target, hinted = %target, "lb: follower redirected to a target already attempted — trying an untried member");
                    match table.any_node_excluding(&attempted_targets) {
                        Some(next) => request.target = next,
                        None => break,
                    }
                }
                None => {
                    tracing::warn!(shard = ?request.shard, hop, from = %request.target, hinted = %leader, "lb: rejected leader hint outside known membership");
                    match table.any_node_excluding(&attempted_targets) {
                        Some(next) => request.target = next,
                        None => break,
                    }
                }
            },
            Upstream::NotLeader { leader: None } => {
                // An explicit NotLeader response means the request was not
                // applied, so retrying another known node is safe for writes.
                tracing::warn!(shard = ?request.shard, hop, target = %request.target, "lb: follower gave no leader hint — trying another known node");
                match table.any_node_excluding(&attempted_targets) {
                    Some(next) => request.target = next,
                    None => break,
                }
            }
            Upstream::NotSent => {
                tracing::warn!(shard = ?request.shard, hop, target = %request.target, method = %request.method, "lb: upstream connection failed before send — trying another known node");
                match table.any_node_excluding(&attempted_targets) {
                    Some(next) => request.target = next,
                    None => break,
                }
            }
            Upstream::AmbiguousTransport if method_is_replay_safe(&request.method) => {
                tracing::warn!(shard = ?request.shard, hop, target = %request.target, "lb: read transport failed — failing over to another known node");
                match table.any_node_excluding(&attempted_targets) {
                    Some(next) => request.target = next,
                    None => break,
                }
            }
            Upstream::AmbiguousTransport => {
                tracing::warn!(shard = ?request.shard, hop, target = %request.target, method = %request.method, "lb: mutation transport outcome is ambiguous — refusing automatic replay");
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "ambiguous_upstream_result",
                        "detail": "the mutation may have committed; retry only with the same Idempotency-Key",
                    })),
                )
                    .into_response();
            }
            Upstream::ResponseTooLarge => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "upstream_response_too_large",
                        "detail": "the node response exceeded the load balancer limit",
                    })),
                )
                    .into_response();
            }
        }
    }
    tracing::error!(shard = ?request.shard, max_hops = MAX_HOPS, "lb: exhausted redirects/retries — returning 502");
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": "no_leader", "detail": "exhausted redirects/retries" })),
    )
        .into_response()
}

fn redirected_leader_target(
    table: &RouteTable,
    shard: Option<ShardId>,
    leader: &str,
) -> Option<String> {
    if let Some(s) = shard {
        table.accept_leader_hint(s, leader)
    } else {
        table.validate_node_hint(leader)
    }
}

fn method_is_replay_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Forward one request to one node and classify the result.
///
/// NotLeader contract: followers may answer either `307` with a `Location`
/// header or `421` with `x-fiducia-leader`/JSON leader hints. In both cases the
/// Shared proxy client with redirect-following **disabled on purpose**.
///
/// A follower answers a write with `307`/`421` + an `x-fiducia-leader` hint, and
/// we handle that hop ourselves in [`classify`] — re-issuing the *original*
/// request path against the leader. If we let reqwest auto-follow, it would chase
/// the node's `Location` header, which is the nest-stripped path (`/acquire`, not
/// `/v1/locks/acquire`, since the handler runs under a nested router) and 404 —
/// exactly the failure seen when the LB's cached leader is stale. Keeping the hop
/// in our hands means we always retry with the path *we* received.
fn proxy_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Bounded timeouts so an UNRESPONSIVE (frozen, not crashed) node is
            // shed quickly: a frozen leader keeps its TCP socket open, so without
            // a request timeout the LB would hang on it forever instead of failing
            // over to the new leader. Connect timeout catches a truly dead host
            // fast; the request timeout catches the connected-but-silent case.
            // NOTE: these bound EVERY proxied request, so when real long-poll lock
            // waits / KV watch streams land, route those through a separate
            // long-timeout client.
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Client for long-lived server streams. It keeps the same short connect
/// timeout as ordinary forwarding, but deliberately has no total request
/// timeout: an SSE watch is successful precisely because its response body may
/// stay open indefinitely. `forward_once` only exposes the body as a stream
/// after the upstream has returned a successful `text/event-stream` response;
/// redirects and error bodies still use the ordinary bounded classifier.
fn streaming_proxy_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

fn is_streaming_request(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    if method != Method::GET {
        return false;
    }
    let accepts_events = headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("text/event-stream"))
        });
    let watch_query = uri.query().is_some_and(|query| {
        query.split('&').any(|pair| {
            let mut parts = pair.splitn(2, '=');
            parts.next() == Some("watch") && parts.next() == Some("true")
        })
    });
    accepts_events || watch_query
}

fn is_event_stream_response(status: StatusCode, headers: &HeaderMap) -> bool {
    status.is_success()
        && headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// LB updates its stale shard→leader cache and retries the request.
async fn forward_once(
    node_url: &str,
    identity: Option<&VerifiedIdentity>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Upstream {
    forward_once_with_stream_budget(
        node_url,
        identity,
        method,
        uri,
        headers,
        body,
        STREAM_NON_BODY_TIMEOUT,
    )
    .await
}

/// `forward_once` with the streaming budget injected, so tests don't have to wait
/// out the real one.
async fn forward_once_with_stream_budget(
    node_url: &str,
    identity: Option<&VerifiedIdentity>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    stream_budget: std::time::Duration,
) -> Upstream {
    let Some(url) = upstream_url(node_url, uri) else {
        return Upstream::NotSent;
    };
    let streaming = is_streaming_request(method, uri, headers);
    let Ok(method) = reqwest::Method::from_bytes(method.as_str().as_bytes()) else {
        return Upstream::NotSent;
    };

    let client = if streaming {
        streaming_proxy_client()
    } else {
        proxy_client()
    };
    let mut request = client.request(method, url).body(body);
    for (name, value) in headers {
        if is_hop_by_hop(name.as_str())
            || should_strip_client_auth_header(name.as_str())
            || name.as_str().eq_ignore_ascii_case(IDEMPOTENCY_KEY_HEADER)
        {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            request = request.header(name, value);
        }
    }
    if let Some(identity) = identity {
        request = request
            .header("x-fiducia-auth-kind", identity.kind_header())
            .header("x-fiducia-org-id", identity.org_id.as_str())
            .header("x-fiducia-scopes", identity.scopes_header());
        if let Some(key_id) = identity.key_id.as_deref() {
            request = request.header("x-fiducia-key-id", key_id);
        }
    }
    // Prove to the node that this request comes from the LB (a trusted hop), so
    // it can trust the identity headers above. The matching client-supplied header
    // is stripped by `should_strip_client_auth_header`, so a caller can't forge it.
    if let Some(secret) = internal_secret() {
        request = request.header(INTERNAL_AUTH_HEADER, secret);
    }

    // The streaming client has no total request timeout, and `streaming` is chosen
    // from CLIENT input (Accept / ?watch=true) before the upstream response type is
    // known. Bound its header phase here so merely *asking* for a stream can't pin
    // an untimed LB task/socket; only a confirmed `text/event-stream` body below is
    // allowed to run unbounded.
    let sent = if streaming {
        match tokio::time::timeout(stream_budget, request.send()).await {
            Ok(sent) => sent,
            Err(_) => return Upstream::AmbiguousTransport,
        }
    } else {
        request.send().await
    };
    let mut response = match sent {
        Ok(response) => response,
        Err(error) if error.is_connect() => return Upstream::NotSent,
        Err(_) => return Upstream::AmbiguousTransport,
    };
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response_headers = HeaderMap::new();
    for (name, value) in response.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(name.as_str().as_bytes()),
            axum::http::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            response_headers.insert(name, value);
        }
    }
    if is_event_stream_response(status, &response_headers) {
        let upstream = node_url.to_string();
        let stream = response.bytes_stream().map(move |item| {
            item.map_err(|error| {
                tracing::warn!(upstream = %upstream, error = %error, "lb: upstream event stream terminated with an error");
                error
            })
        });
        let mut downstream = Response::new(Body::from_stream(stream));
        *downstream.status_mut() = status;
        *downstream.headers_mut() = response_headers;
        return Upstream::Served(downstream);
    }
    // Not an event stream, so this is an ordinary buffered response — even if the
    // caller asked for a stream. Fall back to the timed path: the streaming client
    // would otherwise drain this body with no deadline at all.
    let drained = if streaming {
        match tokio::time::timeout(stream_budget, drain_upstream_body(&mut response)).await {
            Ok(drained) => drained,
            Err(_) => return Upstream::AmbiguousTransport,
        }
    } else {
        drain_upstream_body(&mut response).await
    };
    let body = match drained {
        Ok(body) => body,
        Err(upstream) => return upstream,
    };

    classify_upstream_response(status, response_headers, Bytes::from(body))
}

/// Buffer an upstream response body, bounded by [`MAX_UPSTREAM_RESPONSE_BYTES`].
async fn drain_upstream_body(response: &mut reqwest::Response) -> Result<Vec<u8>, Upstream> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk))
                if body.len().saturating_add(chunk.len()) <= MAX_UPSTREAM_RESPONSE_BYTES =>
            {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) => return Err(Upstream::ResponseTooLarge),
            Ok(None) => break,
            Err(_) => return Err(Upstream::AmbiguousTransport),
        }
    }
    Ok(body)
}

fn classify_upstream_response(status: StatusCode, headers: HeaderMap, body: Bytes) -> Upstream {
    if status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::MISDIRECTED_REQUEST {
        let leader = header_value(&headers, "x-fiducia-leader").or_else(|| {
            header_value(&headers, LOCATION.as_str()).and_then(|v| leader_base_url(&v))
        });
        return Upstream::NotLeader { leader };
    }

    if let Some(leader) = json_not_leader_hint(&body) {
        return Upstream::NotLeader {
            leader: Some(leader),
        };
    }

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    for (name, value) in headers {
        if let Some(name) = name {
            response.headers_mut().insert(name, value);
        }
    }
    Upstream::Served(response)
}

fn upstream_url(node_url: &str, uri: &Uri) -> Option<String> {
    if !(node_url.starts_with("http://") || node_url.starts_with("https://")) {
        return None;
    }
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{}", node_url.trim_end_matches('/'), path);
    // Defence in depth for the dot-segment escalation `route` already rejects: the
    // path reqwest will actually request (after `url`'s normalization) must be
    // EXACTLY the path that was authorized. If they differ at all, don't send.
    let parsed = reqwest::Url::parse(&url).ok()?;
    if parsed.path() != uri.path() {
        tracing::warn!(
            authorized = %uri.path(),
            upstream = %parsed.path(),
            "lb: refusing to forward — upstream URL path differs from the authorized path"
        );
        return None;
    }
    Some(url)
}

/// Parse a body-level `NotLeader` hint using the **shared** payload contract
/// (`fiducia_interfaces::ProposeError`), so the LB and node can't drift on the
/// redirect shape. The node nests the error under `"error"`; a bare error is
/// also accepted.
fn json_not_leader_hint(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error").cloned().unwrap_or(value);
    let parsed: fiducia_interfaces::ProposeError = serde_json::from_value(error).ok()?;
    match parsed.reason {
        fiducia_interfaces::ProposeErrorReason::NotLeader => parsed.leader,
        fiducia_interfaces::ProposeErrorReason::Unavailable => None,
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

fn leader_base_url(location: &str) -> Option<String> {
    let uri: Uri = location.parse().ok()?;
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    Some(format!("{scheme}://{authority}"))
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State as AxumState, routing::get, Router};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn truncated_response_upstream() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx")
                .await
                .unwrap();
        });
        format!("http://{address}")
    }

    async fn event_stream_upstream() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/v1/kv",
            get(|| async {
                let stream = futures_util::stream::once(async {
                    Ok::<Bytes, Infallible>(Bytes::from_static(
                        b"event: put\ndata: {\"value\":\"on\"}\n\n",
                    ))
                })
                .chain(futures_util::stream::pending());
                let mut response = Response::new(Body::from_stream(stream));
                response.headers_mut().insert(
                    "content-type",
                    HeaderValue::from_static("text/event-stream; charset=utf-8"),
                );
                response
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), server)
    }

    async fn spawn_test_router(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), server)
    }

    fn identity_with_scopes(scopes: &[&str]) -> VerifiedIdentity {
        VerifiedIdentity {
            kind: crate::auth::AuthKind::ApiKey,
            org_id: "org_test".to_string(),
            key_id: Some("key_test".to_string()),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            require_idempotency: false,
        }
    }

    #[test]
    fn observe_inventory_routes_require_an_admin_scope() {
        for path in [
            "/v1/observe/locks",
            "/v1/observe/semaphores",
            "/v1/observe/elections",
            "/v1/observe/shards",
            "/v1/observe/metrics",
        ] {
            let uri: Uri = path.parse().unwrap();
            assert_eq!(
                required_scopes_for_route(&Method::GET, &uri),
                ADMIN_READ_SCOPES,
                "{path} must be admin-gated"
            );
            // A plain locks:read key — the enumeration threat — is rejected.
            let locks_read = identity_with_scopes(&["locks:read"]);
            assert!(authorize_route(Some(&locks_read), &Method::GET, &uri).is_err());
            // An admin:read key is allowed.
            let admin = identity_with_scopes(&["admin:read"]);
            assert!(authorize_route(Some(&admin), &Method::GET, &uri).is_ok());
        }
    }

    #[test]
    fn plain_lock_reads_still_accept_locks_read() {
        // Guard against over-tightening: the per-key lock read (/v1/locks?key=)
        // must still work with a locks:read key.
        let uri: Uri = "/v1/locks?key=orders%2F42".parse().unwrap();
        assert_eq!(
            required_scopes_for_route(&Method::GET, &uri),
            LOCKS_READ_SCOPES
        );
        let locks_read = identity_with_scopes(&["locks:read"]);
        assert!(authorize_route(Some(&locks_read), &Method::GET, &uri).is_ok());
    }

    #[test]
    fn coordination_renew_and_cancel_require_lock_write_scope() {
        let locks_read = identity_with_scopes(&["locks:read"]);
        let locks_write = identity_with_scopes(&["locks:write"]);
        let admin_read = identity_with_scopes(&["admin:read"]);
        let admin_write = identity_with_scopes(&["admin:write"]);

        for path in [
            "/v1/locks/renew",
            "/v1/locks/cancel",
            "/v1/semaphores/renew",
            "/v1/semaphores/cancel",
        ] {
            let uri: Uri = path.parse().unwrap();
            assert_eq!(
                required_scopes_for_route(&Method::POST, &uri),
                LOCKS_WRITE_SCOPES,
                "{path} must stay a write-capability route"
            );
            assert!(authorize_route(None, &Method::POST, &uri).is_err());
            assert!(authorize_route(Some(&locks_read), &Method::POST, &uri).is_err());
            assert!(authorize_route(Some(&admin_read), &Method::POST, &uri).is_err());
            assert!(authorize_route(Some(&locks_write), &Method::POST, &uri).is_ok());
            assert!(authorize_route(Some(&admin_write), &Method::POST, &uri).is_ok());
        }
    }

    #[test]
    fn event_stream_detection_is_explicit_and_read_only() {
        let empty = HeaderMap::new();
        let mut accepts_sse = HeaderMap::new();
        accepts_sse.insert(
            "accept",
            "application/json, text/event-stream".parse().unwrap(),
        );
        assert!(is_streaming_request(
            &Method::GET,
            &"/v1/kv?key=x&watch=true".parse().unwrap(),
            &empty,
        ));
        assert!(is_streaming_request(
            &Method::GET,
            &"/v1/elections/x/watch".parse().unwrap(),
            &accepts_sse,
        ));
        assert!(!is_streaming_request(
            &Method::GET,
            &"/v1/kv?key=x&watch=false".parse().unwrap(),
            &empty,
        ));
        assert!(!is_streaming_request(
            &Method::POST,
            &"/v1/kv?key=x&watch=true".parse().unwrap(),
            &accepts_sse,
        ));
    }

    #[tokio::test]
    async fn successful_event_stream_is_forwarded_without_waiting_for_eof() {
        let (upstream, server) = event_stream_upstream().await;
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("text/event-stream"));
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            forward_once(
                &upstream,
                None,
                &Method::GET,
                &"/v1/kv?key=x&watch=true".parse().unwrap(),
                &headers,
                Bytes::new(),
            ),
        )
        .await
        .expect("LB must return SSE response headers without buffering its unbounded body");

        let Upstream::Served(response) = result else {
            panic!("expected a served event stream, got {result:?}");
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream; charset=utf-8")
        );
        let mut stream = response.into_body().into_data_stream();
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .expect("first SSE chunk must reach the downstream immediately")
            .expect("event stream ended before its first event")
            .expect("first event-stream chunk must be readable");
        assert_eq!(
            first,
            Bytes::from_static(b"event: put\ndata: {\"value\":\"on\"}\n\n")
        );
        server.abort();
    }

    #[tokio::test]
    async fn retry_loop_does_not_revisit_a_dead_stale_leader_before_trying_every_member() {
        // Reserve then release a port to obtain a valid but unreachable member.
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = format!("http://{}", dead_listener.local_addr().unwrap());
        drop(dead_listener);

        let stale_hint = dead.clone();
        let redirecting = Router::new().fallback(move || {
            let stale_hint = stale_hint.clone();
            async move {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
                response.headers_mut().insert(
                    "x-fiducia-leader",
                    HeaderValue::from_str(&stale_hint).unwrap(),
                );
                response
            }
        });
        let (follower, follower_server) = spawn_test_router(redirecting).await;
        let healthy = Router::new().fallback(|| async {
            (
                StatusCode::OK,
                Json(json!({ "served_by": "healthy-third-member" })),
            )
        });
        let (healthy, healthy_server) = spawn_test_router(healthy).await;

        let table = Arc::new(RouteTable::new(1, vec![dead.clone(), follower, healthy]));
        let response = forward_with_redirect(
            table,
            ForwardRequest {
                identity: None,
                target: dead,
                shard: Some(0),
                method: Method::GET,
                uri: "/v1/kv?key=x".parse().unwrap(),
                headers: HeaderMap::new(),
                body: Bytes::new(),
            },
        )
        .await;
        let (status, _headers, body) = json_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["served_by"], "healthy-third-member");
        follower_server.abort();
        healthy_server.abort();
    }

    #[test]
    fn classifies_node_not_leader_redirect_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-fiducia-not-leader", "true".parse().unwrap());
        headers.insert("x-fiducia-leader", "http://leader-a:8090".parse().unwrap());
        headers.insert(
            LOCATION,
            "http://leader-a:8090/v1/kv/orders".parse().unwrap(),
        );

        match classify_upstream_response(StatusCode::TEMPORARY_REDIRECT, headers, Bytes::new()) {
            Upstream::NotLeader { leader } => {
                assert_eq!(leader.as_deref(), Some("http://leader-a:8090"));
            }
            other => panic!("unexpected upstream result: {other:?}"),
        }
    }

    #[test]
    fn follower_without_a_leader_hint_yields_none_so_the_lb_round_robins() {
        // A follower knows it isn't the leader but doesn't know who is: a 307 with
        // no leader header/Location. The LB gets NotLeader{None} and falls back to
        // any_node() (round-robin) in forward_with_redirect.
        match classify_upstream_response(
            StatusCode::TEMPORARY_REDIRECT,
            HeaderMap::new(),
            Bytes::new(),
        ) {
            Upstream::NotLeader { leader: None } => {}
            other => panic!("expected NotLeader{{leader:None}}, got {other:?}"),
        }
    }

    #[test]
    fn classifies_json_not_leader_fallback() {
        let body = Bytes::from_static(
            br#"{"committed":false,"error":{"reason":"not_leader","shard":9,"leader":"http://leader-b:8090"}}"#,
        );

        match classify_upstream_response(StatusCode::OK, HeaderMap::new(), body) {
            Upstream::NotLeader { leader } => {
                assert_eq!(leader.as_deref(), Some("http://leader-b:8090"));
            }
            other => panic!("unexpected upstream result: {other:?}"),
        }
    }

    #[test]
    fn route_scope_matrix_enforces_read_write_boundaries() {
        let services_read = test_identity_with_scopes("org_1", &["services:read"]);
        let services_write = test_identity_with_scopes("org_1", &["services:write"]);
        let admin_read = test_identity_with_scopes("org_1", &["admin:read"]);
        let admin_write = test_identity_with_scopes("org_1", &["admin:write"]);
        let wildcard = test_identity_with_scopes("org_1", &["services:*"]);
        let read_uri: Uri = "/v1/services/api".parse().unwrap();
        let write_uri: Uri = "/v1/services/api/instances/i-1".parse().unwrap();

        assert!(authorize_route(Some(&services_read), &Method::GET, &read_uri).is_ok());
        assert!(authorize_route(Some(&services_read), &Method::PUT, &write_uri).is_err());
        assert!(authorize_route(Some(&services_write), &Method::PUT, &write_uri).is_ok());
        assert!(authorize_route(Some(&wildcard), &Method::PUT, &write_uri).is_ok());
        assert!(authorize_route(Some(&admin_read), &Method::GET, &read_uri).is_ok());
        assert!(authorize_route(Some(&admin_read), &Method::PUT, &write_uri).is_err());
        assert!(authorize_route(Some(&admin_write), &Method::PUT, &write_uri).is_ok());
        // Anonymous callers are allowed on public routes only; a scoped route now
        // fails closed instead of blanket-allowing an absent identity.
        assert!(authorize_route(None, &Method::PUT, &write_uri).is_err());
        assert!(authorize_route(None, &Method::GET, &read_uri).is_err());
        assert!(authorize_route(None, &Method::GET, &"/healthz".parse().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn edge_forwarded_request_with_secret_is_trusted_and_scope_checked() {
        let (table, fake, server) = fake_cluster().await;
        let secret = "edge-secret";

        // The edge presents a pre-verified identity plus the shared secret. The
        // identity is trusted, but `kv:read` cannot perform a KV write → 403, and
        // nothing reaches the node.
        let mut read_only = HeaderMap::new();
        read_only.insert(crate::auth::EDGE_AUTH_HEADER, secret.parse().unwrap());
        read_only.insert("x-fiducia-auth-kind", "api_key".parse().unwrap());
        read_only.insert("x-fiducia-org-id", "org_1".parse().unwrap());
        read_only.insert("x-fiducia-scopes", "kv:read".parse().unwrap());
        let identity = crate::auth::trusted_edge_identity(&read_only, Some(secret));
        assert!(
            identity.is_some(),
            "valid secret must yield a trusted identity"
        );
        let denied = route(
            table.clone(),
            identity,
            Method::PUT,
            "/v1/kv?key=orders%2F1".parse().unwrap(),
            read_only,
            Bytes::from_static(br#"{"value":"x"}"#),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(fake.mutation_count(), 0);

        // Same trusted hop, now with `kv:write` → the write is authorized and
        // forwarded to the node.
        let mut writable = HeaderMap::new();
        writable.insert(crate::auth::EDGE_AUTH_HEADER, secret.parse().unwrap());
        writable.insert("x-fiducia-org-id", "org_1".parse().unwrap());
        writable.insert("x-fiducia-scopes", "kv:write".parse().unwrap());
        let identity = crate::auth::trusted_edge_identity(&writable, Some(secret));
        let allowed = route(
            table,
            identity,
            Method::PUT,
            "/v1/kv?key=orders%2F1".parse().unwrap(),
            writable,
            Bytes::from_static(br#"{"value":"x"}"#),
        )
        .await;

        server.abort();
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(fake.mutation_count(), 1);
    }

    #[tokio::test]
    async fn edge_headers_without_the_secret_are_anonymous_and_rejected_for_scoped_route() {
        let (table, fake, server) = fake_cluster().await;

        // Forged identity headers, but no valid edge secret → not trusted, so the
        // request is anonymous and a scoped write fails closed with no node hit.
        let mut spoofed = HeaderMap::new();
        spoofed.insert("x-fiducia-org-id", "org_evil".parse().unwrap());
        spoofed.insert("x-fiducia-scopes", "admin:write".parse().unwrap());
        let identity = crate::auth::trusted_edge_identity(&spoofed, Some("real-secret"));
        assert!(identity.is_none(), "missing secret must not be trusted");

        let response = route(
            table,
            identity,
            Method::PUT,
            "/v1/kv?key=orders%2F1".parse().unwrap(),
            spoofed,
            Bytes::from_static(br#"{"value":"x"}"#),
        )
        .await;

        server.abort();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(fake.mutation_count(), 0);
    }

    #[tokio::test]
    async fn insufficient_scope_is_denied_before_forwarding() {
        let (table, fake, server) = fake_cluster().await;
        let response = route(
            table,
            Some(test_identity_with_scopes("org_1", &["kv:read"])),
            Method::PUT,
            "/v1/kv?key=orders%2F42".parse().unwrap(),
            HeaderMap::new(),
            Bytes::from_static(br#"{"value":"paid"}"#),
        )
        .await;
        let (status, _headers, body_json) = json_response(response).await;

        server.abort();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body_json["error"], "insufficient_scope");
        assert_eq!(body_json["required_scopes"][0], "kv:write");
        assert_eq!(fake.mutation_count(), 0);
    }

    #[test]
    fn classifies_not_leader_without_hint_for_round_robin_retry() {
        match classify_upstream_response(
            StatusCode::TEMPORARY_REDIRECT,
            HeaderMap::new(),
            Bytes::new(),
        ) {
            Upstream::NotLeader { leader } => {
                assert_eq!(leader, None);
            }
            other => panic!("unexpected upstream result: {other:?}"),
        }
    }

    #[test]
    fn redirect_hint_updates_route_table_before_retry() {
        let table = RouteTable::new(
            16,
            vec![
                "http://old-leader:8090".to_string(),
                "http://new-leader:8090".to_string(),
            ],
        );
        let next = redirected_leader_target(&table, Some(3), "http://new-leader:8090");

        assert_eq!(next.as_deref(), Some("http://new-leader:8090"));
        assert_eq!(
            table.leader_for(3).as_deref(),
            Some("http://new-leader:8090")
        );
    }

    #[test]
    fn redirect_hint_outside_membership_is_rejected() {
        let table = RouteTable::new(16, vec!["http://known:8090".to_string()]);
        assert_eq!(
            redirected_leader_target(&table, Some(3), "https://evil.example"),
            None
        );
        assert_ne!(table.leader_for(3).as_deref(), Some("https://evil.example"));
    }

    #[test]
    fn only_read_methods_are_safe_for_transport_failover() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(method_is_replay_safe(&method));
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!method_is_replay_safe(&method));
        }
    }

    #[tokio::test]
    async fn customer_idempotency_stores_and_replays_completed_mutation() {
        let (table, fake, server) = fake_cluster().await;
        let headers = idempotency_headers("cust-key-1");
        let body = Bytes::from_static(br#"{"value":"paid"}"#);

        let first = route(
            table.clone(),
            Some(test_identity("org_1")),
            Method::PUT,
            "/v1/kv?key=orders%2F42".parse().unwrap(),
            headers.clone(),
            body.clone(),
        )
        .await;
        let (status, headers, body_json) = json_response(first).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(FIDUCIA_IDEMPOTENCY_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("stored")
        );
        assert_eq!(body_json["mutation_count"], 1);
        assert_eq!(fake.mutation_count(), 1);
        assert!(fake
            .last_mutation_headers()
            .get(IDEMPOTENCY_KEY_HEADER)
            .is_none());

        let second = route(
            table,
            Some(test_identity("org_1")),
            Method::PUT,
            "/v1/kv?key=orders%2F42".parse().unwrap(),
            idempotency_headers("cust-key-1"),
            body,
        )
        .await;
        let (status, headers, replayed_json) = json_response(second).await;

        server.abort();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(IDEMPOTENCY_REPLAYED_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(replayed_json, body_json);
        assert_eq!(fake.mutation_count(), 1);
    }

    #[test]
    fn only_final_responses_are_cacheable_for_idempotent_replay() {
        use StatusCode as S;
        // Final responses are safe to store and replay.
        for status in [S::OK, S::CREATED, S::BAD_REQUEST, S::NOT_FOUND, S::CONFLICT] {
            assert!(is_cacheable_idempotent_response(status), "{status}");
        }
        // Transient responses must re-execute on retry, never be cached.
        for status in [
            S::INTERNAL_SERVER_ERROR,
            S::BAD_GATEWAY,
            S::SERVICE_UNAVAILABLE,
            S::GATEWAY_TIMEOUT,
            S::REQUEST_TIMEOUT,
            S::TOO_MANY_REQUESTS,
        ] {
            assert!(!is_cacheable_idempotent_response(status), "{status}");
        }
    }

    #[tokio::test]
    async fn customer_idempotency_does_not_cache_transient_failures_and_retry_reexecutes() {
        let (table, fake, server) = fake_cluster().await;
        // The first upstream attempt fails transiently (503); the retry must re-run.
        fake.queue_mutation_status(StatusCode::SERVICE_UNAVAILABLE);

        let first = route(
            table.clone(),
            Some(test_identity("org_1")),
            Method::PUT,
            "/v1/kv?key=orders%2F99".parse().unwrap(),
            idempotency_headers("cust-key-transient"),
            Bytes::from_static(br#"{"value":"paid"}"#),
        )
        .await;
        let (status, headers, _body) = json_response(first).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            headers
                .get(FIDUCIA_IDEMPOTENCY_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("not_stored")
        );
        // The transient failure released the claim, so the key is re-claimable.
        assert_eq!(fake.abandon_count(), 1);
        assert_eq!(fake.mutation_count(), 1);

        // Same key, same request: because the failure was not cached, this
        // RE-EXECUTES the mutation rather than replaying the cached 503.
        let second = route(
            table,
            Some(test_identity("org_1")),
            Method::PUT,
            "/v1/kv?key=orders%2F99".parse().unwrap(),
            idempotency_headers("cust-key-transient"),
            Bytes::from_static(br#"{"value":"paid"}"#),
        )
        .await;
        let (status, headers, body_json) = json_response(second).await;

        server.abort();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(FIDUCIA_IDEMPOTENCY_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("stored")
        );
        // Re-executed, not replayed: the upstream saw the mutation a second time.
        assert_eq!(fake.mutation_count(), 2);
        assert_eq!(body_json["mutation_count"], 2);
    }

    #[tokio::test]
    async fn require_idempotency_rejects_keyless_mutation_before_routing() {
        // Enforcement happens before routing, so no upstream is needed.
        let table = Arc::new(RouteTable::new(4, vec![]));
        let response = route(
            table,
            Some(test_identity_requiring_idempotency("org_1")),
            Method::PUT,
            "/v1/kv?key=orders%2F7".parse().unwrap(),
            HeaderMap::new(), // no Idempotency-Key
            Bytes::from_static(br#"{"value":"x"}"#),
        )
        .await;
        let (status, _headers, body_json) = json_response(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json["error"], "idempotency_key_required");
    }

    #[tokio::test]
    async fn require_idempotency_does_not_gate_reads() {
        let (table, _fake, server) = fake_cluster().await;
        let response = route(
            table,
            Some(test_identity_requiring_idempotency("org_1")),
            Method::GET,
            "/v1/kv?key=orders%2F7".parse().unwrap(),
            HeaderMap::new(), // no key, but a read is never gated
            Bytes::new(),
        )
        .await;
        server.abort();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_idempotency_allows_mutation_carrying_a_key() {
        let (table, fake, server) = fake_cluster().await;
        let response = route(
            table,
            Some(test_identity_requiring_idempotency("org_1")),
            Method::PUT,
            "/v1/kv?key=orders%2F7".parse().unwrap(),
            idempotency_headers("cust-key-required"),
            Bytes::from_static(br#"{"value":"x"}"#),
        )
        .await;
        let (status, headers, _body) = json_response(response).await;

        server.abort();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(FIDUCIA_IDEMPOTENCY_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("stored")
        );
        assert_eq!(fake.mutation_count(), 1);
    }

    #[tokio::test]
    async fn customer_idempotency_rejects_same_key_with_different_fingerprint() {
        let (table, fake, server) = fake_cluster().await;

        let first = route(
            table.clone(),
            Some(test_identity("org_1")),
            Method::PUT,
            "/v1/kv?key=flags%2Fcheckout".parse().unwrap(),
            idempotency_headers("same-key"),
            Bytes::from_static(br#"{"value":"on"}"#),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = route(
            table,
            Some(test_identity("org_1")),
            Method::PUT,
            "/v1/kv?key=flags%2Fcheckout".parse().unwrap(),
            idempotency_headers("same-key"),
            Bytes::from_static(br#"{"value":"off"}"#),
        )
        .await;
        let (status, _headers, body_json) = json_response(second).await;

        server.abort();
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body_json["error"], "idempotency_key_conflict");
        assert_eq!(fake.mutation_count(), 1);
    }

    #[tokio::test]
    async fn customer_idempotency_rejects_blank_or_oversized_keys_before_routing() {
        let table = Arc::new(RouteTable::new(4, vec![]));
        // A scoped write is now rejected for an anonymous caller before key
        // validation, so use an authorized identity to reach that validation.
        let locks_writer = test_identity_with_scopes("org_1", &["locks:write"]);
        let mut blank = HeaderMap::new();
        blank.insert(IDEMPOTENCY_KEY_HEADER, "   ".parse().unwrap());
        let response = route(
            table.clone(),
            Some(locks_writer.clone()),
            Method::POST,
            "/v1/locks/acquire".parse().unwrap(),
            blank,
            Bytes::from_static(br#"{"key":"orders/42"}"#),
        )
        .await;
        let (status, _headers, body_json) = json_response(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json["error"], "bad_idempotency_key");

        let mut long = HeaderMap::new();
        let key = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1);
        long.insert(IDEMPOTENCY_KEY_HEADER, key.parse().unwrap());
        let response = route(
            table.clone(),
            Some(locks_writer.clone()),
            Method::POST,
            "/v1/locks/acquire".parse().unwrap(),
            long,
            Bytes::from_static(br#"{"key":"orders/42"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut non_text = HeaderMap::new();
        non_text.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        let response = route(
            table,
            Some(locks_writer),
            Method::POST,
            "/v1/locks/acquire".parse().unwrap(),
            non_text,
            Bytes::from_static(br#"{"key":"orders/42"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn customer_idempotency_reports_in_progress_duplicates() {
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, "cust-key-2".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        let idempotency = CustomerIdempotency::from_request(
            Some(&test_identity("org_1")),
            &Method::POST,
            &"/v1/locks/acquire".parse().unwrap(),
            &headers,
            br#"{"key":"orders/42"}"#,
        )
        .unwrap()
        .unwrap();
        let response = response_for_duplicate_claim(
            &idempotency,
            &IdempotencyClaim {
                claimed: false,
                duplicate: true,
                fencing_token: None,
                record: Some(json!({
                    "status": "claimed",
                    "metadata": { "fingerprint": idempotency.fingerprint },
                })),
            },
        )
        .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
    }

    #[test]
    fn customer_idempotency_scopes_keys_by_org_and_hashes_raw_key() {
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, "order-create-123".parse().unwrap());
        let uri = "/v1/kv?key=orders%2F123".parse().unwrap();
        let a = CustomerIdempotency::from_request(
            Some(&test_identity("org_a")),
            &Method::PUT,
            &uri,
            &headers,
            br#"{"value":"one"}"#,
        )
        .unwrap()
        .unwrap();
        let b = CustomerIdempotency::from_request(
            Some(&test_identity("org_b")),
            &Method::PUT,
            &uri,
            &headers,
            br#"{"value":"one"}"#,
        )
        .unwrap()
        .unwrap();

        assert_ne!(a.internal_key, b.internal_key);
        assert!(!a.internal_key.contains("order-create-123"));
        assert_eq!(a.key_hash.len(), 64);
    }

    #[tokio::test]
    async fn retries_a_down_known_node_against_another_known_node() {
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_node = format!("http://{}", dead_listener.local_addr().unwrap());
        drop(dead_listener);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().fallback(|| async { (StatusCode::OK, "live node") });
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let live_node = format!("http://{addr}");
        let table = Arc::new(RouteTable::new(4, vec![dead_node.clone(), live_node]));
        let response = forward_with_redirect(
            table,
            ForwardRequest {
                identity: None,
                target: dead_node,
                shard: Some(0),
                method: Method::GET,
                uri: "/v1/status".parse().unwrap(),
                headers: HeaderMap::new(),
                body: Bytes::new(),
            },
        )
        .await;

        server.abort();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn retries_a_mutation_when_connection_failure_proves_it_was_not_sent() {
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_node = format!("http://{}", dead_listener.local_addr().unwrap());
        drop(dead_listener);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().fallback(|| async { (StatusCode::OK, "committed") });
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let live_node = format!("http://{addr}");
        let table = Arc::new(RouteTable::new(4, vec![dead_node.clone(), live_node]));
        let response = forward_with_redirect(
            table,
            ForwardRequest {
                identity: None,
                target: dead_node,
                shard: Some(0),
                method: Method::PUT,
                uri: "/v1/kv?key=failover".parse().unwrap(),
                headers: HeaderMap::new(),
                body: Bytes::from_static(br#"{"value":"safe"}"#),
            },
        )
        .await;

        server.abort();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ambiguous_mutation_transport_fails_closed_without_replaying() {
        assert_ambiguous_mutation_not_replayed(
            Method::PUT,
            "/v1/kv?key=ambiguous",
            Bytes::from_static(br#"{"value":"one"}"#),
        )
        .await;
    }

    #[tokio::test]
    async fn ambiguous_lock_renew_transport_fails_closed_without_replaying() {
        assert_ambiguous_mutation_not_replayed(
            Method::POST,
            "/v1/locks/renew",
            Bytes::from_static(
                br#"{"keys":["orders/42"],"holder":"worker-1","fencing_token":7,"ttl_ms":30000}"#,
            ),
        )
        .await;
    }

    async fn assert_ambiguous_mutation_not_replayed(method: Method, uri: &str, body: Bytes) {
        let ambiguous = truncated_response_upstream().await;
        let hits = Arc::new(AtomicUsize::new(0));
        let live_hits = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback(move || {
            let hits = live_hits.clone();
            async move {
                hits.fetch_add(1, Ordering::Relaxed);
                (StatusCode::OK, "would-commit")
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let table = Arc::new(RouteTable::new(4, vec![ambiguous.clone(), live]));

        let response = forward_with_redirect(
            table,
            ForwardRequest {
                identity: None,
                target: ambiguous,
                shard: Some(0),
                method,
                uri: uri.parse().unwrap(),
                headers: HeaderMap::new(),
                body,
            },
        )
        .await;

        server.abort();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(hits.load(Ordering::Relaxed), 0, "mutation was not replayed");
    }

    #[tokio::test]
    async fn ambiguous_read_transport_retries_another_known_node() {
        let ambiguous = truncated_response_upstream().await;
        let hits = Arc::new(AtomicUsize::new(0));
        let live_hits = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback(move || {
            let hits = live_hits.clone();
            async move {
                hits.fetch_add(1, Ordering::Relaxed);
                (StatusCode::OK, "safe-read")
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let table = Arc::new(RouteTable::new(4, vec![ambiguous.clone(), live]));

        let response = forward_with_redirect(
            table,
            ForwardRequest {
                identity: None,
                target: ambiguous,
                shard: Some(0),
                method: Method::GET,
                uri: "/v1/kv?key=ambiguous".parse().unwrap(),
                headers: HeaderMap::new(),
                body: Bytes::new(),
            },
        )
        .await;

        server.abort();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn location_header_can_supply_leader_base_url() {
        assert_eq!(
            leader_base_url("http://leader-c:8090/v1/kv/orders?x=1").as_deref(),
            Some("http://leader-c:8090")
        );
    }

    #[derive(Default)]
    struct FakeNode {
        records: Mutex<HashMap<String, FakeRecord>>,
        mutations: Mutex<Vec<FakeMutation>>,
        /// Status codes to return for successive mutations (FIFO). Empty → 200.
        /// Lets a test script a transient failure followed by a success.
        mutation_statuses: Mutex<std::collections::VecDeque<u16>>,
        /// Keys released via `/v1/idempotency/abandon`.
        abandons: Mutex<Vec<String>>,
    }

    #[derive(Clone)]
    struct FakeRecord {
        key: String,
        owner: String,
        fencing_token: u64,
        status: String,
        metadata: HashMap<String, String>,
        result: Option<Value>,
    }

    struct FakeMutation {
        headers: HeaderMap,
    }

    impl FakeNode {
        fn mutation_count(&self) -> usize {
            self.mutations.lock().unwrap().len()
        }

        fn queue_mutation_status(&self, status: StatusCode) {
            self.mutation_statuses
                .lock()
                .unwrap()
                .push_back(status.as_u16());
        }

        fn abandon_count(&self) -> usize {
            self.abandons.lock().unwrap().len()
        }

        fn last_mutation_headers(&self) -> HeaderMap {
            self.mutations
                .lock()
                .unwrap()
                .last()
                .map(|mutation| mutation.headers.clone())
                .unwrap_or_default()
        }
    }

    async fn fake_cluster() -> (Arc<RouteTable>, Arc<FakeNode>, tokio::task::JoinHandle<()>) {
        let state = Arc::new(FakeNode::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .fallback(fake_node_handler)
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let table = Arc::new(RouteTable::new(4, vec![format!("http://{addr}")]));
        (table, state, server)
    }

    async fn fake_node_handler(
        AxumState(state): AxumState<Arc<FakeNode>>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        match (method.as_str(), uri.path()) {
            ("POST", "/v1/idempotency/claim") => fake_claim(state, &headers, &body),
            ("POST", "/v1/idempotency/complete") => fake_complete(state, &headers, &body),
            ("POST", "/v1/idempotency/abandon") => fake_abandon(state, &body),
            _ => {
                let mut mutations = state.mutations.lock().unwrap();
                mutations.push(FakeMutation { headers });
                let status = state
                    .mutation_statuses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .and_then(|code| StatusCode::from_u16(code).ok())
                    .unwrap_or(StatusCode::OK);
                (
                    status,
                    Json(json!({
                        "ok": status.is_success(),
                        "method": method.as_str(),
                        "target": uri.path_and_query().map(|value| value.as_str()).unwrap_or(uri.path()),
                        "mutation_count": mutations.len(),
                    })),
                )
                    .into_response()
            }
        }
    }

    fn fake_abandon(state: Arc<FakeNode>, body: &[u8]) -> Response {
        let value: Value = serde_json::from_slice(body).unwrap();
        let key = value["key"].as_str().unwrap().to_string();
        let token = value["fencing_token"].as_u64().unwrap();
        let mut records = state.records.lock().unwrap();
        match records.get(&key) {
            Some(record) if record.fencing_token == token && record.status != "completed" => {
                records.remove(&key);
                state.abandons.lock().unwrap().push(key.clone());
                committed_output(json!({ "abandoned": true, "key": key, "revision": 3 }))
            }
            Some(_) => committed_output(
                json!({ "abandoned": false, "reason": "not_holder", "key": key, "revision": 3 }),
            ),
            None => committed_output(
                json!({ "abandoned": false, "reason": "not_found", "key": key, "revision": 3 }),
            ),
        }
    }

    fn fake_claim(state: Arc<FakeNode>, headers: &HeaderMap, body: &[u8]) -> Response {
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let value: Value = serde_json::from_slice(body).unwrap();
        let key = value["key"].as_str().unwrap().to_string();
        let owner = value["owner"].as_str().unwrap().to_string();
        let metadata = value["metadata"]
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
            .collect::<HashMap<_, _>>();
        let mut records = state.records.lock().unwrap();
        let output = if let Some(record) = records.get(&key) {
            json!({
                "claimed": false,
                "duplicate": true,
                "key": key,
                "record": record_json(record),
                "revision": 2,
            })
        } else {
            let record = FakeRecord {
                key: key.clone(),
                owner,
                fencing_token: 99,
                status: "claimed".to_string(),
                metadata,
                result: None,
            };
            records.insert(key.clone(), record.clone());
            json!({
                "claimed": true,
                "duplicate": false,
                "key": key,
                "fencing_token": 99,
                "record": record_json(&record),
                "revision": 1,
            })
        };
        committed_output(output)
    }

    fn fake_complete(state: Arc<FakeNode>, headers: &HeaderMap, body: &[u8]) -> Response {
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let value: Value = serde_json::from_slice(body).unwrap();
        let key = value["key"].as_str().unwrap().to_string();
        let owner = value["owner"].as_str().unwrap();
        let token = value["fencing_token"].as_u64().unwrap();
        let result = value.get("result").cloned();
        let mut records = state.records.lock().unwrap();
        let Some(record) = records.get_mut(&key) else {
            return committed_output(json!({
                "completed": false,
                "reason": "not_found",
                "key": key,
                "revision": 3,
            }));
        };
        if record.owner != owner || record.fencing_token != token {
            return committed_output(json!({
                "completed": false,
                "reason": "not_holder",
                "key": key,
                "revision": 3,
            }));
        }
        record.status = "completed".to_string();
        record.result = result;
        committed_output(json!({
            "completed": true,
            "duplicate": false,
            "key": key,
            "record": record_json(record),
            "revision": 3,
        }))
    }

    fn record_json(record: &FakeRecord) -> Value {
        json!({
            "key": record.key,
            "owner": record.owner,
            "fencing_token": record.fencing_token,
            "status": record.status,
            "first_seen_ms": 1,
            "lease_expires_ms": 2,
            "metadata": record.metadata,
            "result": record.result,
        })
    }

    fn committed_output(output: Value) -> Response {
        Json(json!({
            "committed": true,
            "result": {
                "shard": 0,
                "log_index": 1,
                "revision": 1,
                "output": output,
            }
        }))
        .into_response()
    }

    fn idempotency_headers(key: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, key.parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        headers
    }

    fn test_identity(org_id: &str) -> VerifiedIdentity {
        test_identity_with_scopes(org_id, &["kv:write"])
    }

    fn test_identity_with_scopes(org_id: &str, scopes: &[&str]) -> VerifiedIdentity {
        VerifiedIdentity {
            kind: crate::auth::AuthKind::ApiKey,
            org_id: org_id.to_string(),
            key_id: Some("key_1".to_string()),
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            require_idempotency: false,
        }
    }

    fn test_identity_requiring_idempotency(org_id: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            require_idempotency: true,
            ..test_identity(org_id)
        }
    }

    async fn json_response(response: Response) -> (StatusCode, HeaderMap, Value) {
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), MAX_REPLAY_BODY_BYTES + 1)
            .await
            .unwrap();
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, headers, value)
    }

    /// A dot segment lets the authorized path and the path the `url` crate
    /// actually requests disagree — `/v1/locks/../observe/locks` authorizes as
    /// `locks:read` but reaches the admin-only observe inventory. Refuse it.
    #[tokio::test]
    async fn dot_segment_paths_are_rejected_before_authorization() {
        let table = Arc::new(RouteTable::new(4, vec!["http://node-a:8090".to_string()]));
        for (method, path) in [
            (Method::GET, "/v1/locks/../observe/locks"),
            (Method::GET, "/v1/locks/%2e%2e/observe/locks"),
            (Method::PUT, "/v1/locks/../kv?key=x"),
            (Method::GET, "/v1/locks/./status"),
        ] {
            let uri: Uri = path.parse().unwrap();
            let response = route(
                table.clone(),
                Some(test_identity("org_1")),
                method.clone(),
                uri,
                HeaderMap::new(),
                Bytes::new(),
            )
            .await;
            let (status, _, body) = json_response(response).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path} must be refused");
            assert_eq!(body["error"], "invalid_path");
        }
    }

    /// Defence in depth for the same escalation: whatever the caller sends, the
    /// path reqwest would request must equal the path that was authorized.
    #[test]
    fn upstream_url_refuses_a_path_the_url_crate_would_rewrite() {
        let uri: Uri = "/v1/locks/../observe/locks".parse().unwrap();
        assert_eq!(upstream_url("http://node-a:8090", &uri), None);

        // The ordinary case is untouched, query string included.
        let uri: Uri = "/v1/kv?key=orders%2F42".parse().unwrap();
        assert_eq!(
            upstream_url("http://node-a:8090/", &uri).as_deref(),
            Some("http://node-a:8090/v1/kv?key=orders%2F42")
        );
    }

    /// Every family the router knows must resolve to a scope a customer API key
    /// can actually be issued — otherwise the family is unreachable for every
    /// customer. `admin:*` is the operator escape hatch and is deliberately NOT
    /// issuable, so it doesn't count towards reachability.
    #[test]
    fn every_routed_family_is_reachable_with_an_issuable_api_key_scope() {
        // Mirrors `ALLOWED_API_KEY_SCOPES` in fiducia-auth.rs/src/main.rs — the
        // only scopes an API key can ever carry.
        const ISSUABLE: &[&str] = &[
            "requests:read",
            "requests:write",
            "locks:read",
            "locks:write",
            "kv:read",
            "kv:write",
            "services:read",
            "services:write",
            "elections:read",
            "elections:write",
            "cron:read",
            "cron:write",
            "rate-limit:read",
            "rate-limit:write",
        ];
        const FAMILIES: &[&str] = &[
            "kv",
            "locks",
            "semaphores",
            "rw",
            "idempotency",
            "rate-limit",
            "cron",
            "elections",
            "services",
            "counters",
            "barriers",
            "tasks",
            "effects",
            "handoffs",
            "decisions",
            "budgets",
            "claims",
        ];

        for family in FAMILIES {
            for method in [Method::GET, Method::POST] {
                let uri: Uri = format!("/v1/{family}").parse().unwrap();
                let required = required_scopes_for_route(&method, &uri);
                let issuable: Vec<_> = required
                    .iter()
                    .filter(|scope| !scope.starts_with("admin:"))
                    .collect();
                assert!(
                    !issuable.is_empty(),
                    "/v1/{family} ({method}) requires only non-issuable scopes: {required:?}"
                );
                for scope in issuable {
                    assert!(
                        ISSUABLE.contains(scope),
                        "/v1/{family} ({method}) requires {scope}, which fiducia-auth cannot issue"
                    );
                }
                // And a key holding that scope really passes the gate.
                let granted = required.iter().find(|s| !s.starts_with("admin:")).unwrap();
                let identity = identity_with_scopes(&[granted]);
                assert!(
                    authorize_route(Some(&identity), &method, &uri).is_ok(),
                    "/v1/{family} ({method}) must admit a {granted} key"
                );
            }
        }
    }

    /// The eight families that used to fall through to the admin catch-all are
    /// closed to a customer key no matter what scope it holds.
    #[test]
    fn previously_unreachable_families_no_longer_require_admin() {
        for (path, read_scope, write_scope) in [
            ("/v1/counters/hits", "kv:read", "kv:write"),
            ("/v1/barriers/b1", "locks:read", "locks:write"),
            ("/v1/handoffs/h1", "locks:read", "locks:write"),
            ("/v1/claims/c1", "locks:read", "locks:write"),
            ("/v1/tasks/t1", "requests:read", "requests:write"),
            ("/v1/effects/e1", "requests:read", "requests:write"),
            ("/v1/decisions/d1", "requests:read", "requests:write"),
            ("/v1/budgets/b1", "rate-limit:read", "rate-limit:write"),
        ] {
            let uri: Uri = path.parse().unwrap();
            let reader = identity_with_scopes(&[read_scope]);
            let writer = identity_with_scopes(&[write_scope]);
            assert!(authorize_route(Some(&reader), &Method::GET, &uri).is_ok());
            assert!(authorize_route(Some(&writer), &Method::POST, &uri).is_ok());
            // A read-only key still can't mutate.
            assert!(authorize_route(Some(&reader), &Method::POST, &uri).is_err());
        }
    }

    /// A client can ASK for a stream (`Accept`/`?watch=true`) and get an ordinary
    /// response back. The streaming client has no request timeout, so without a
    /// bound on the header + non-stream body phases any caller could pin an LB
    /// task forever on an upstream that simply never finishes its body.
    #[tokio::test]
    async fn a_streaming_request_answered_with_a_non_stream_body_is_still_timed() {
        // Upstream promises 100 bytes, sends one, and holds the socket open.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nx")
                .await
                .unwrap();
            futures_util::future::pending::<()>().await;
        });
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("text/event-stream"));

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            forward_once_with_stream_budget(
                &format!("http://{address}"),
                None,
                &Method::GET,
                &"/v1/kv?key=x&watch=true".parse().unwrap(),
                &headers,
                Bytes::new(),
                std::time::Duration::from_millis(200),
            ),
        )
        .await
        .expect("a non-SSE response on the streaming path must not hang the LB");
        assert!(
            matches!(result, Upstream::AmbiguousTransport),
            "expected the stream budget to fire, got {result:?}"
        );
        server.abort();
    }

    /// The same budget bounds the header phase, before any response type is known.
    #[tokio::test]
    async fn a_streaming_request_with_a_silent_upstream_is_bounded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            futures_util::future::pending::<()>().await;
        });
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("text/event-stream"));

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            forward_once_with_stream_budget(
                &format!("http://{address}"),
                None,
                &Method::GET,
                &"/v1/kv?key=x".parse().unwrap(),
                &headers,
                Bytes::new(),
                std::time::Duration::from_millis(200),
            ),
        )
        .await
        .expect("a silent upstream on the streaming path must not hang the LB");
        assert!(
            matches!(result, Upstream::AmbiguousTransport),
            "expected the stream budget to fire, got {result:?}"
        );
        server.abort();
    }
}

#[cfg(test)]
mod replay_integrity_tests {
    use axum::body::to_bytes;

    use super::StoredIdempotencyResponse;

    fn stored(body_hex: &str) -> StoredIdempotencyResponse {
        StoredIdempotencyResponse {
            fingerprint: "fp".to_string(),
            status: 200,
            content_type: Some("application/json".to_string()),
            body_hex: body_hex.to_string(),
            truncated: false,
        }
    }

    /// A stored replay body that no longer hex-decodes is CORRUPT state. It
    /// must fail closed (409 idempotency_replay_unavailable) exactly like the
    /// truncated branch — replaying an empty or partial body as if it were the
    /// original response silently hands the client wrong data.
    #[tokio::test]
    async fn corrupt_stored_body_fails_closed_instead_of_replaying_empty() {
        for corrupt in ["zz", "abc", "0g"] {
            let response = stored(corrupt).into_replay_response();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::CONFLICT,
                "corrupt hex {corrupt:?} must be refused"
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["error"], "idempotency_replay_unavailable");
        }
    }

    /// The healthy path still replays byte-for-byte with the replay markers.
    #[tokio::test]
    async fn intact_stored_body_replays_verbatim() {
        let response = stored("7b7d").into_replay_response(); // "{}"
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(super::IDEMPOTENCY_REPLAYED_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"{}");
    }
}
