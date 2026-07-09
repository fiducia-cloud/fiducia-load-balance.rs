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

use std::{collections::HashMap, sync::Arc};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{header::LOCATION, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
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
const MAX_REPLAY_BODY_BYTES: usize = 256 * 1024;
/// Hard ceiling on how much of an upstream response the LB will buffer while
/// making a request idempotent. Guards against a huge or malicious upstream body
/// OOMing the proxy. Well above `MAX_REPLAY_BODY_BYTES` so ordinary responses pass
/// through intact; a body larger than this cannot be made idempotent.
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
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
    /// Transport failure; try a different node.
    Unreachable,
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

fn authorize_route(
    identity: Option<&VerifiedIdentity>,
    method: &Method,
    uri: &Uri,
) -> Result<(), ScopeFailure> {
    let required = required_scopes_for_route(method, uri);
    if required.is_empty() || identity.is_none() {
        return Ok(());
    }

    let identity = identity.expect("checked is_some");
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
    let (shard, target) = match routing_key_with_body(&uri, &body) {
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
        let body = hex_to_bytes(&self.body_hex).unwrap_or_default();
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
    let captured = CapturedResponse::from_response(response).await;
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
    let captured = CapturedResponse::from_response(response).await;
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
    for hop in 0..MAX_HOPS {
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
            } => {
                tracing::info!(shard = ?request.shard, hop, from = %request.target, to = %leader, "lb: follower redirect — retrying leader, refreshing cache");
                request.target = redirected_leader_target(&table, request.shard, leader);
            }
            Upstream::NotLeader { leader: None } | Upstream::Unreachable => {
                // No hint / dead node: pick another and retry.
                tracing::warn!(shard = ?request.shard, hop, target = %request.target, "lb: node unreachable / no leader hint — failing over to another node");
                match table.any_node() {
                    Some(next) => request.target = next,
                    None => break,
                }
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

fn redirected_leader_target(table: &RouteTable, shard: Option<ShardId>, leader: String) -> String {
    if let Some(s) = shard {
        table.note_leader(s, leader.clone());
    }
    leader
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

/// LB updates its stale shard→leader cache and retries the request.
async fn forward_once(
    node_url: &str,
    identity: Option<&VerifiedIdentity>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Upstream {
    let Some(url) = upstream_url(node_url, uri) else {
        return Upstream::Unreachable;
    };
    let Ok(method) = reqwest::Method::from_bytes(method.as_str().as_bytes()) else {
        return Upstream::Unreachable;
    };

    let client = proxy_client();
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

    let Ok(response) = request.send().await else {
        return Upstream::Unreachable;
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
    let Ok(body) = response.bytes().await else {
        return Upstream::Unreachable;
    };

    classify_upstream_response(status, response_headers, body)
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
    Some(format!("{}{}", node_url.trim_end_matches('/'), path))
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
    use axum::extract::State as AxumState;
    use std::sync::Mutex;

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
        assert!(authorize_route(None, &Method::PUT, &write_uri).is_ok());
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
        let table = RouteTable::new(16, vec!["http://old-leader:8090".to_string()]);
        let next = redirected_leader_target(&table, Some(3), "http://new-leader:8090".to_string());

        assert_eq!(next, "http://new-leader:8090");
        assert_eq!(
            table.leader_for(3).as_deref(),
            Some("http://new-leader:8090")
        );
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
        let mut blank = HeaderMap::new();
        blank.insert(IDEMPOTENCY_KEY_HEADER, "   ".parse().unwrap());
        let response = route(
            table.clone(),
            None,
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
            None,
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
            None,
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
            _ => {
                let mut mutations = state.mutations.lock().unwrap();
                mutations.push(FakeMutation { headers });
                Json(json!({
                    "ok": true,
                    "method": method.as_str(),
                    "target": uri.path_and_query().map(|value| value.as_str()).unwrap_or(uri.path()),
                    "mutation_count": mutations.len(),
                }))
                .into_response()
            }
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
}
