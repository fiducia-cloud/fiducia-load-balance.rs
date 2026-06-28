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

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    http::{header::LOCATION, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::routing::{routing_key, shard_for, ShardId};
use crate::table::RouteTable;

/// Max redirect/retry hops before giving up (defeats redirect loops).
const MAX_HOPS: usize = 4;

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
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Keyed request → shard's leader. Keyless (status / list) → any node.
    // (Locks/semaphores resolve to the lock-coordination shard inside `routing_key`.)
    let (shard, target) = match routing_key(&uri) {
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
    forward_with_redirect(table, target, shard, method, uri, headers, body).await
}

/// Forward to `target`, following `NotLeader` redirects up to [`MAX_HOPS`].
async fn forward_with_redirect(
    table: Arc<RouteTable>,
    mut target: String,
    shard: Option<ShardId>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    for hop in 0..MAX_HOPS {
        match forward_once(&target, &method, &uri, &headers, body.clone()).await {
            Upstream::Served(resp) => {
                if hop > 0 {
                    tracing::debug!(shard = ?shard, hops = hop, target = %target, "lb: served after redirect/retry");
                }
                return resp;
            }
            Upstream::NotLeader {
                leader: Some(leader),
            } => {
                tracing::info!(shard = ?shard, hop, from = %target, to = %leader, "lb: follower redirect — retrying leader, refreshing cache");
                target = redirected_leader_target(&table, shard, leader);
            }
            Upstream::NotLeader { leader: None } | Upstream::Unreachable => {
                // No hint / dead node: pick another and retry.
                tracing::warn!(shard = ?shard, hop, target = %target, "lb: node unreachable / no leader hint — failing over to another node");
                match table.any_node() {
                    Some(next) => target = next,
                    None => break,
                }
            }
        }
    }
    tracing::error!(shard = ?shard, max_hops = MAX_HOPS, "lb: exhausted redirects/retries — returning 502");
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
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// LB updates its stale shard→leader cache and retries the request.
async fn forward_once(
    node_url: &str,
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
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            request = request.header(name, value);
        }
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

    #[test]
    fn location_header_can_supply_leader_base_url() {
        assert_eq!(
            leader_base_url("http://leader-c:8090/v1/kv/orders?x=1").as_deref(),
            Some("http://leader-c:8090")
        );
    }
}
