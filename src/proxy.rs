//! Forwarding with NotLeader redirect handling (skeleton).
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
//! Skeleton: the routing *decision* and the redirect *loop shape* are real; the
//! actual byte-forwarding ([`forward_once`]) is stubbed pending an HTTP client.

use std::sync::Arc;

use axum::{
    http::{Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::routing::{routing_key_from_path, shard_for, ShardId};
use crate::table::RouteTable;

/// Max redirect/retry hops before giving up (defeats redirect loops).
const MAX_HOPS: usize = 4;

/// What a single upstream attempt told us.
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
pub async fn route(table: Arc<RouteTable>, method: Method, uri: Uri) -> Response {
    let path = uri.path();

    // Keyed request → shard's leader. Keyless (status / list) → any node.
    let (shard, target) = match routing_key_from_path(path) {
        Some(key) => {
            let shard = shard_for(&key, table.shard_count());
            (Some(shard), table.leader_for(shard))
        }
        None => (None, table.any_node()),
    };

    let Some(target) = target else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "no_route", "detail": "no known node for this request", "shard": shard })),
        )
            .into_response();
    };

    forward_with_redirect(table, target, shard, method, uri).await
}

/// Forward to `target`, following `NotLeader` redirects up to [`MAX_HOPS`].
async fn forward_with_redirect(
    table: Arc<RouteTable>,
    mut target: String,
    shard: Option<ShardId>,
    method: Method,
    uri: Uri,
) -> Response {
    for _ in 0..MAX_HOPS {
        match forward_once(&target, &method, &uri).await {
            Upstream::Served(resp) => return resp,
            Upstream::NotLeader { leader: Some(leader) } => {
                // Cache the correction (for the request's shard) so the next
                // request skips the bounce.
                if let Some(s) = shard {
                    table.note_leader(s, leader.clone());
                }
                target = leader;
            }
            Upstream::NotLeader { leader: None } | Upstream::Unreachable => {
                // No hint / dead node: pick another and retry.
                match table.any_node() {
                    Some(next) => target = next,
                    None => break,
                }
            }
        }
    }
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": "no_leader", "detail": "exhausted redirects/retries" })),
    )
        .into_response()
}

/// Forward one request to one node and classify the result.
///
/// NotLeader contract (must match `fiducia-node`'s `propose_response`): a follower
/// answers **HTTP 421 Misdirected Request** with the shard's leader in the
/// `x-fiducia-leader` header (and a `{"reason":"not_leader","leader":...}` body).
/// The follower knows the leader from its own Raft state, so this corrects a
/// stale LB cache.
///
/// TODO: with an HTTP client, send `method` + `uri.path_and_query()` + headers +
/// body to `{node_url}{path}`, stream the response back, and map:
///   * `421` + `x-fiducia-leader` (or the JSON hint) → `Upstream::NotLeader { leader }`
///   * a connection error                            → `Upstream::Unreachable`
///   * anything else                                 → `Upstream::Served`
async fn forward_once(node_url: &str, method: &Method, uri: &Uri) -> Upstream {
    // Skeleton: describe the routing decision instead of forwarding bytes.
    Upstream::Served(
        Json(json!({
            "lb": "fiducia-load-balance",
            "note": "forwarding is stubbed; this is the routing decision",
            "would_forward": {
                "method": method.as_str(),
                "path": uri.path(),
                "to": node_url,
            },
        }))
        .into_response(),
    )
}
