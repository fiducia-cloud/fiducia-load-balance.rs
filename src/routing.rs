//! Request → routing-key extraction.
//!
//! The load balancer's job starts here: given an incoming request, find its
//! **routing key**, hash it to a **shard** (via the shared `fiducia-routing`
//! crate, so the LB and data plane can never disagree on `key → shard`), and
//! (elsewhere) look up that shard's leader.
//!
//! The key must be computed exactly as the node's `Command::routing_key` does:
//!
//! | Request                                  | Routing key                         |
//! |------------------------------------------|-------------------------------------|
//! | `GET/PUT/DELETE /v1/kv?key=K`            | `K` (query param — slash-safe)      |
//! | `/v1/locks/*`, `/v1/semaphores/*`        | **`LOCK_COORDINATION_KEY`** (always — see below) |
//! | `GET /v1/idempotency?key=K`              | `K` (query param — slash-safe)      |
//! | `POST /v1/idempotency/{claim,complete}`  | JSON body `key`                     |
//! | `/v1/rate-limit/{tenant}/{key}/...`      | `{key}`                             |
//! | `/v1/cron/schedules/{name}/...`          | `{name}`                            |
//! | `/v1/elections/{name}/...`               | `{name}`                            |
//! | `/v1/services...`                        | **`SERVICE_DISCOVERY_KEY`**         |
//! | `/v1/kv` (no key), `/v1/status`, health  | none (any node)                     |
//!
//! **Locks/semaphores never route by their user key.** A multi-key *union* lock
//! must be granted atomically and conflict-checked across every member key, which
//! requires one state machine to see them together — so the node routes *all*
//! lock/semaphore commands to a single coordinator shard. The LB must do the
//! same, or a single-key acquire on `B` could land on a different shard than an
//! active composite lock on `[A, B]` and miss the conflict.

use axum::http::Uri;

// Single source of truth for `ShardId`, the hash, and coordination keys.
#[cfg(test)]
pub use fiducia_routing::{lock_coordination_shard, service_discovery_shard};
pub use fiducia_routing::{shard_for, ShardId, LOCK_COORDINATION_KEY, SERVICE_DISCOVERY_KEY};

/// Extract the routing key from a request, mirroring the node's API shape.
///
/// Returns `None` for requests that don't address a single shard (health,
/// status, and cross-shard list endpoints) — those can go to any node.
pub fn routing_key(uri: &Uri) -> Option<String> {
    let segs: Vec<&str> = uri
        .path()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    match segs.as_slice() {
        // KV: the key is a `?key=` query parameter (slash-safe). No key → list.
        ["v1", "kv"] => query_param(uri, "key"),
        // Locks + semaphores ALWAYS route to the one lock-coordination shard,
        // regardless of the user key (atomic multi-key union needs one SM).
        ["v1", "locks", ..] | ["v1", "semaphores", ..] => Some(LOCK_COORDINATION_KEY.to_string()),
        // Idempotency inspection carries the key in the query string.
        ["v1", "idempotency"] => query_param(uri, "key"),
        // Rate limit: /v1/rate-limit/{tenant}/{key}/... → key.
        ["v1", "rate-limit", _tenant, key, ..] | ["v1", "ratelimit", _tenant, key, ..] => {
            Some(decode_path(key))
        }
        // Cron: /v1/cron/schedules/{name}/... → name.
        ["v1", "cron", "schedules", name, ..] => Some(decode_path(name)),
        // Elections: /v1/elections/{name}/... → name.
        ["v1", "elections", name, ..] => Some(decode_path(name)),
        // Service discovery routes through one registry coordinator so service
        // names can be listed linearizably without cross-shard scatter-gather.
        ["v1", "services", ..] => Some(SERVICE_DISCOVERY_KEY.to_string()),
        // Counters: `?key=` inspection (writes carry the key in the body — see
        // `routing_key_with_body`).
        ["v1", "counters"] => query_param(uri, "key"),
        // Name-keyed primitives: `?name=` inspection; writes carry `name` in
        // the body. These MUST route by that name exactly as the node's
        // `Command::routing_key` does, or a read could land on a node that is
        // not the owning shard's leader.
        ["v1", "barriers"]
        | ["v1", "tasks"]
        | ["v1", "effects"]
        | ["v1", "handoffs"]
        | ["v1", "decisions"]
        | ["v1", "budgets"]
        | ["v1", "claims"] => query_param(uri, "name"),
        // status / health / unknown → any node.
        _ => None,
    }
}

/// Extract a routing key from URI plus body for endpoints whose key is JSON-only.
pub fn routing_key_with_body(uri: &Uri, body: &[u8]) -> Option<String> {
    routing_key(uri).or_else(|| {
        let segs: Vec<&str> = uri
            .path()
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        match segs.as_slice() {
            ["v1", "idempotency", "claim"] | ["v1", "idempotency", "complete"] => {
                json_body_field(body, "key")
            }
            // Counter writes carry the routing key in the JSON body.
            ["v1", "counters", _op] => json_body_field(body, "key"),
            // Name-keyed primitive writes carry `name` in the JSON body; route
            // by it exactly as the node's `Command::routing_key` does.
            ["v1", "barriers", _op]
            | ["v1", "tasks", _op]
            | ["v1", "effects", _op]
            | ["v1", "handoffs", _op]
            | ["v1", "decisions", _op]
            | ["v1", "budgets", _op]
            | ["v1", "claims", _op] => json_body_field(body, "name"),
            _ => None,
        }
    })
}

/// Hash a request straight to its shard, or `None` for keyless requests.
#[cfg(test)]
fn shard_for_request(uri: &Uri, shard_count: u32) -> Option<ShardId> {
    routing_key(uri).map(|key| shard_for(&key, shard_count))
}

/// Read a query parameter, decoded as `application/x-www-form-urlencoded`
/// (`+`→space) — matching how the node's axum `Query` extractor
/// (serde_urlencoded) decodes the same parameter.
fn query_param(uri: &Uri, name: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| decode(v, true))
    })
}

fn json_body_field(body: &[u8], field: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get(field)?.as_str().map(ToOwned::to_owned)
}

/// Decode a PATH segment: `%XX` only. axum's `Path` extractor keeps a literal
/// `+` as `+` (the `+`→space rule is a query-string convention), so the LB
/// must too — decoding `+` here would hash `a+b` to a different shard than the
/// node computes for the same request, misrouting it away from its leader.
fn decode_path(s: &str) -> String {
    decode(s, false)
}

/// Percent-decode; `plus_is_space` selects the query-string convention.
fn decode(s: &str, plus_is_space: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }
    fn key(s: &str) -> Option<String> {
        routing_key(&uri(s))
    }
    fn key_with_body(s: &str, body: &[u8]) -> Option<String> {
        routing_key_with_body(&uri(s), body)
    }

    #[test]
    fn kv_key_comes_from_the_query_param_and_is_slash_safe() {
        assert_eq!(key("/v1/kv?key=orders").as_deref(), Some("orders"));
        assert_eq!(
            key("/v1/kv?key=flags/checkout").as_deref(),
            Some("flags/checkout")
        );
        assert_eq!(key("/v1/kv?key=a%2Fb").as_deref(), Some("a/b")); // encoded slash
        assert_eq!(key("/v1/kv?watch=true&key=x").as_deref(), Some("x")); // any position
        assert_eq!(key("/v1/kv"), None); // no key → keyless (list / any node)
    }

    #[test]
    fn idempotency_routes_by_query_or_body_key() {
        assert_eq!(
            key("/v1/idempotency?key=stripe-webhook/event_123").as_deref(),
            Some("stripe-webhook/event_123")
        );
        assert_eq!(
            key_with_body(
                "/v1/idempotency/claim",
                br#"{"key":"stripe-webhook/event_123","ttl":"24h"}"#
            )
            .as_deref(),
            Some("stripe-webhook/event_123")
        );
        assert_eq!(
            key_with_body(
                "/v1/idempotency/complete",
                br#"{"key":"stripe-webhook/event_123","fencing_token":7}"#
            )
            .as_deref(),
            Some("stripe-webhook/event_123")
        );
        assert_eq!(key("/v1/idempotency/claim"), None);
    }

    #[test]
    fn idempotency_body_routing_rejects_malformed_or_non_string_keys() {
        assert_eq!(
            key_with_body("/v1/idempotency/claim", br#"{"key":7}"#),
            None
        );
        assert_eq!(
            key_with_body("/v1/idempotency/complete", br#"{"owner":"worker"}"#),
            None
        );
        assert_eq!(key_with_body("/v1/idempotency/claim", b"not-json"), None);
    }

    #[test]
    fn routing_decodes_plus_and_percent_escapes_in_keys() {
        // Query strings follow the form-urlencoded convention: `+` is a space
        // (this is how the node's axum Query extractor reads the same param).
        assert_eq!(
            key("/v1/kv?key=tenant+space%2Fcheckout").as_deref(),
            Some("tenant space/checkout")
        );
        // PATH segments do NOT use the `+`→space rule: axum's Path extractor
        // keeps a literal `+`. The LB must match, or `a+b` hashes to a
        // different shard here than on the node.
        assert_eq!(
            key("/v1/rate-limit/acme/tenant+plus%2Fcheckout/check").as_deref(),
            Some("tenant+plus/checkout")
        );
        assert_eq!(
            key("/v1/elections/prod%2Fjob+runner%2Fleader").as_deref(),
            Some("prod/job+runner/leader")
        );
    }

    #[test]
    fn new_primitives_route_by_query_or_body_exactly_like_the_node() {
        // Inspection: counters use `?key=`; the name-keyed primitives `?name=`.
        assert_eq!(
            key("/v1/counters?key=rollout%2Ffailures").as_deref(),
            Some("rollout/failures")
        );
        for family in [
            "barriers",
            "tasks",
            "effects",
            "handoffs",
            "decisions",
            "budgets",
            "claims",
        ] {
            assert_eq!(
                key(&format!("/v1/{family}?name=release-942%2Freviewers")).as_deref(),
                Some("release-942/reviewers"),
                "GET /v1/{family} must route by ?name="
            );
        }

        // Writes: the routing key rides in the JSON body (`key`/`name`),
        // mirroring the node's Command::routing_key.
        assert_eq!(
            key_with_body(
                "/v1/counters/add",
                br#"{"key":"rollout/failures","delta":1}"#
            )
            .as_deref(),
            Some("rollout/failures")
        );
        assert_eq!(
            key_with_body(
                "/v1/barriers/arrive",
                br#"{"name":"release-942/reviewers","participant":"w1"}"#
            )
            .as_deref(),
            Some("release-942/reviewers")
        );
        assert_eq!(
            key_with_body(
                "/v1/tasks/claim",
                br#"{"name":"repo/acme/issue/482","worker":"w1"}"#
            )
            .as_deref(),
            Some("repo/acme/issue/482")
        );
        assert_eq!(
            key_with_body(
                "/v1/budgets/reserve",
                br#"{"name":"org/acme","usd_micros":5}"#
            )
            .as_deref(),
            Some("org/acme")
        );

        // Keyless list/inspect without the param → any node, never a panic.
        assert_eq!(key("/v1/counters"), None);
        assert_eq!(key_with_body("/v1/tasks/create", b"not-json"), None);
    }

    #[test]
    fn all_lock_and_semaphore_requests_route_to_the_one_coordinator_shard() {
        // Whatever the path/verb, every lock/semaphore op shares the coordinator
        // key — so they all hash to the SAME shard (the whole point of union locks).
        let lock_paths = [
            "/v1/locks/acquire",
            "/v1/locks/release",
            "/v1/locks?key=orders/42",
            "/v1/semaphores/acquire",
            "/v1/semaphores/release",
            "/v1/semaphores?key=db-pool",
        ];
        for p in lock_paths {
            assert_eq!(key(p).as_deref(), Some(LOCK_COORDINATION_KEY));
        }
        // And that key resolves to the shared coordinator shard.
        for n in [4u32, 16, 256] {
            let s = shard_for_request(&uri("/v1/locks/acquire"), n).unwrap();
            assert_eq!(s, lock_coordination_shard(n));
            assert_eq!(
                s,
                shard_for_request(&uri("/v1/semaphores/acquire"), n).unwrap()
            );
        }
    }

    #[test]
    fn other_primitives_route_by_their_path_identifier() {
        assert_eq!(
            key("/v1/rate-limit/acme/checkout/check").as_deref(),
            Some("checkout")
        );
        assert_eq!(
            key("/v1/cron/schedules/nightly/history").as_deref(),
            Some("nightly")
        );
        assert_eq!(
            key("/v1/elections/cleanup/campaign").as_deref(),
            Some("cleanup")
        );
        // keyless / cross-shard / health
        assert_eq!(key("/v1/status"), None);
        assert_eq!(key("/healthz"), None);
    }

    #[test]
    fn service_discovery_routes_to_the_registry_coordinator() {
        for p in [
            "/v1/services",
            "/v1/services/api",
            "/v1/services/api/instances/i1",
            "/v1/services/api/watch",
        ] {
            assert_eq!(key(p).as_deref(), Some(SERVICE_DISCOVERY_KEY));
        }
        for n in [4u32, 16, 256] {
            assert_eq!(
                shard_for_request(&uri("/v1/services/api/instances/i1"), n).unwrap(),
                service_discovery_shard(n)
            );
        }
    }
}
