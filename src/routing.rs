//! Request → routing-key extraction.
//!
//! The load balancer's job starts here: given an incoming request, find its
//! **routing key**, hash it to a **shard** (via the shared `fiducia-routing`
//! crate, so the LB and data plane can never disagree on `key → shard`), and
//! (elsewhere) look up that shard's leader.
//!
//! The key must be computed exactly as the node's `Command::routing_key` does —
//! **including the caller's org scope**. The node namespaces every org-owned
//! key/name into `\x01{org}\x01{key}` (`fiducia_routing::org_scoped_key`)
//! before it reaches the state machine, so the SCOPED key is what gets hashed
//! to a shard. Hashing the raw caller key here would pick a different, wrong
//! shard for nearly every request and pay a NotLeader redirect each time.
//!
//! | Request                                  | Routing key                         |
//! |------------------------------------------|-------------------------------------|
//! | `GET/PUT/DELETE /v1/kv?key=K`            | `org_scoped_key(org, K)`            |
//! | `/v1/locks/*`, `/v1/semaphores/*`        | **`LOCK_COORDINATION_KEY`** (always — see below) |
//! | `GET /v1/idempotency?key=K`              | `org_scoped_key(org, K)`            |
//! | `POST /v1/idempotency/{claim,complete}`  | `org_scoped_key(org, body key)`     |
//! | `/v1/rate-limit/{tenant}/{key}/...`      | `org_scoped_key(org, key)`          |
//! | `/v1/cron/schedules/{name}/...`          | `org_scoped_key(org, name)`         |
//! | `/v1/elections/{name}/...`               | `org_scoped_key(org, name)`         |
//! | `/v1/services...`                        | **`SERVICE_DISCOVERY_KEY`**         |
//! | `/v1/kv` (no key), `/v1/status`, health  | none (any node)                     |
//!
//! (With no verified identity there is no org; the raw key is used, which is
//! also what the node would 400 on — routing precision doesn't matter there.)
//!
//! **Locks/semaphores never route by their user key.** A multi-key *union* lock
//! must be granted atomically and conflict-checked across every member key, which
//! requires one state machine to see them together — so the node routes *all*
//! lock/semaphore commands to a single coordinator shard. The LB must do the
//! same, or a single-key acquire on `B` could land on a different shard than an
//! active composite lock on `[A, B]` and miss the conflict. The coordinator
//! keys are cluster-reserved, not org-owned, so they are never org-scoped.

use axum::http::Uri;

// Single source of truth for `ShardId`, the hash, org scoping, and coordination keys.
use fiducia_routing::org_scoped_key;
#[cfg(test)]
pub use fiducia_routing::{lock_coordination_shard, service_discovery_shard};
pub use fiducia_routing::{shard_for, ShardId, LOCK_COORDINATION_KEY, SERVICE_DISCOVERY_KEY};

/// Extract the routing key from a request, mirroring the node's API shape.
/// `org_id` is the verified caller org (from the LB's auth layer): org-owned
/// keys are namespaced with it exactly like the node's `OrgScope::scope`.
///
/// Returns `None` for requests that don't address a single shard (health,
/// status, and cross-shard list endpoints) — those can go to any node.
pub fn routing_key(uri: &Uri, org_id: Option<&str>) -> Option<String> {
    let scoped = |key: String| match org_id {
        Some(org) => org_scoped_key(org, &key),
        None => key,
    };
    let segs: Vec<&str> = uri
        .path()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    match segs.as_slice() {
        // KV: the key is a `?key=` query parameter (slash-safe). No key → list.
        ["v1", "kv"] => query_param(uri, "key").map(scoped),
        // Locks + semaphores ALWAYS route to the one lock-coordination shard,
        // regardless of the user key (atomic multi-key union needs one SM).
        ["v1", "locks", ..] | ["v1", "semaphores", ..] => Some(LOCK_COORDINATION_KEY.to_string()),
        // Idempotency inspection carries the key in the query string.
        ["v1", "idempotency"] => query_param(uri, "key").map(scoped),
        // Rate limit: /v1/rate-limit/{tenant}/{key}/... → key.
        ["v1", "rate-limit", _tenant, key, ..] | ["v1", "ratelimit", _tenant, key, ..] => {
            Some(scoped(percent_decode_path(key)))
        }
        // Cron: /v1/cron/schedules/{name}/... → name.
        ["v1", "cron", "schedules", name, ..] => Some(scoped(percent_decode_path(name))),
        // Elections: /v1/elections/{name}/... → name.
        ["v1", "elections", name, ..] => Some(scoped(percent_decode_path(name))),
        // Service discovery routes through one registry coordinator so service
        // names can be listed linearizably without cross-shard scatter-gather.
        ["v1", "services", ..] => Some(SERVICE_DISCOVERY_KEY.to_string()),
        // status / health / unknown → any node.
        _ => None,
    }
}

/// Extract a routing key from URI plus body for endpoints whose key is JSON-only.
pub fn routing_key_with_body(uri: &Uri, body: &[u8], org_id: Option<&str>) -> Option<String> {
    routing_key(uri, org_id).or_else(|| {
        let segs: Vec<&str> = uri
            .path()
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        match segs.as_slice() {
            ["v1", "idempotency", "claim"] | ["v1", "idempotency", "complete"] => {
                json_body_key(body).map(|key| match org_id {
                    Some(org) => org_scoped_key(org, &key),
                    None => key,
                })
            }
            _ => None,
        }
    })
}

/// Hash a request straight to its shard, or `None` for keyless requests.
#[cfg(test)]
fn shard_for_request(uri: &Uri, shard_count: u32) -> Option<ShardId> {
    routing_key(uri, None).map(|key| shard_for(&key, shard_count))
}

/// Read a query parameter, percent-decoded.
fn query_param(uri: &Uri, name: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| percent_decode_query(v))
    })
}

fn json_body_key(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("key")?.as_str().map(ToOwned::to_owned)
}

/// Minimal `application/x-www-form-urlencoded` query decode (`+`→space,
/// `%XX`→byte), matching Axum's `Query` extractor.
fn percent_decode_query(s: &str) -> String {
    percent_decode(s, true)
}

/// Minimal URL-path segment decode (`%XX`→byte). A literal `+` stays a
/// plus: unlike a form/query value, RFC 3986 path segments do not treat `+` as
/// a space, and Axum's `Path` extractor preserves it. Collapsing the two decode
/// rules makes the LB hash a different key than the node for names such as
/// `jobs+cold`, causing an avoidable NotLeader hop (or a failed route).
fn percent_decode_path(s: &str) -> String {
    percent_decode(s, false)
}

fn percent_decode(s: &str, plus_as_space: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if plus_as_space => {
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
    // Anonymous (org-less) forms: exercise the raw key extraction.
    fn key(s: &str) -> Option<String> {
        routing_key(&uri(s), None)
    }
    fn key_with_body(s: &str, body: &[u8]) -> Option<String> {
        routing_key_with_body(&uri(s), body, None)
    }

    /// The verified org scopes every org-owned routing key exactly like the
    /// node's `OrgScope::scope`, so the LB hashes the same key the node commits
    /// under. Before this, the LB hashed the RAW key and predicted the wrong
    /// shard for essentially every org-scoped request (a NotLeader redirect
    /// per first touch, forever).
    #[test]
    fn org_owned_keys_are_scoped_with_the_callers_org() {
        let org = Some("org_1");
        let scoped = |k: &str| fiducia_routing::org_scoped_key("org_1", k);
        assert_eq!(
            routing_key(&uri("/v1/kv?key=orders/checkout"), org).as_deref(),
            Some(scoped("orders/checkout").as_str()),
        );
        assert_eq!(
            routing_key(&uri("/v1/idempotency?key=req-1"), org).as_deref(),
            Some(scoped("req-1").as_str()),
        );
        assert_eq!(
            routing_key(&uri("/v1/rate-limit/acme/checkout/check"), org).as_deref(),
            Some(scoped("checkout").as_str()),
        );
        assert_eq!(
            routing_key(&uri("/v1/cron/schedules/nightly/history"), org).as_deref(),
            Some(scoped("nightly").as_str()),
        );
        assert_eq!(
            routing_key(&uri("/v1/elections/cleanup/campaign"), org).as_deref(),
            Some(scoped("cleanup").as_str()),
        );
        assert_eq!(
            routing_key_with_body(&uri("/v1/idempotency/claim"), br#"{"key":"req-9"}"#, org)
                .as_deref(),
            Some(scoped("req-9").as_str()),
        );
    }

    /// Cluster-reserved coordinator keys are NOT org-owned: every org's lock
    /// and discovery traffic must meet on the same shard, so the org never
    /// touches them.
    #[test]
    fn coordinator_keys_are_never_org_scoped() {
        let org = Some("org_1");
        assert_eq!(
            routing_key(&uri("/v1/locks/acquire"), org).as_deref(),
            Some(LOCK_COORDINATION_KEY),
        );
        assert_eq!(
            routing_key(&uri("/v1/semaphores/acquire"), org).as_deref(),
            Some(LOCK_COORDINATION_KEY),
        );
        assert_eq!(
            routing_key(&uri("/v1/services/api"), org).as_deref(),
            Some(SERVICE_DISCOVERY_KEY),
        );
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
        assert_eq!(
            key("/v1/kv?key=tenant+space%2Fcheckout").as_deref(),
            Some("tenant space/checkout")
        );
        assert_eq!(
            key("/v1/rate-limit/acme/tenant+space%2Fcheckout/check").as_deref(),
            Some("tenant+space/checkout")
        );
        assert_eq!(
            key("/v1/cron/schedules/nightly+backup/history").as_deref(),
            Some("nightly+backup")
        );
        assert_eq!(
            key("/v1/elections/worker%2Bprimary/campaign").as_deref(),
            Some("worker+primary")
        );
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
