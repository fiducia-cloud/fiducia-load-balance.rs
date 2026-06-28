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
//! | `/v1/rate-limit/{tenant}/{key}/...`      | `{key}`                             |
//! | `/v1/cron/schedules/{name}/...`          | `{name}`                            |
//! | `/v1/elections/{name}/...`               | `{name}`                            |
//! | `/v1/services/{service}/...`             | `{service}`                         |
//! | `/v1/services` (list all)                | none (any node fans out)            |
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
pub use fiducia_routing::{
    lock_coordination_shard, service_discovery_shard, shard_for, ShardId, LOCK_COORDINATION_KEY,
    SERVICE_DISCOVERY_KEY,
};

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
        // Rate limit: /v1/rate-limit/{tenant}/{key}/... → key.
        ["v1", "rate-limit", _tenant, key, ..] | ["v1", "ratelimit", _tenant, key, ..] => {
            Some(percent_decode(key))
        }
        // Cron: /v1/cron/schedules/{name}/... → name.
        ["v1", "cron", "schedules", name, ..] => Some(percent_decode(name)),
        // Elections: /v1/elections/{name}/... → name.
        ["v1", "elections", name, ..] => Some(percent_decode(name)),
        // Service discovery routes through one registry coordinator so service
        // names can be listed linearizably without cross-shard scatter-gather.
        ["v1", "services", ..] => Some(SERVICE_DISCOVERY_KEY.to_string()),
        // status / health / unknown → any node.
        _ => None,
    }
}

/// Hash a request straight to its shard, or `None` for keyless requests.
pub fn shard_for_request(uri: &Uri, shard_count: u32) -> Option<ShardId> {
    routing_key(uri).map(|key| shard_for(&key, shard_count))
}

/// Read a query parameter, percent-decoded.
fn query_param(uri: &Uri, name: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| percent_decode(v))
    })
}

/// Minimal `application/x-www-form-urlencoded` decode (`+`→space, `%XX`→byte),
/// matching how the node's axum `Query`/path extractors decode keys.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
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
