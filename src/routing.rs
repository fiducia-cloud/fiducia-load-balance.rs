//! Request → shard routing (skeleton).
//!
//! The load balancer's job starts here: given an incoming request path, find the
//! **routing key**, hash it to a **shard**, and (elsewhere) look up that shard's
//! leader. The key extraction must agree with each primitive's
//! `Command::routing_key` on the node, and the hash must be byte-for-byte the
//! same as the node's `shard_for`.
//!
//! The `key → shard` mapping itself comes from the shared `fiducia-routing`
//! crate, so the LB and the data plane can never disagree on where a key lives.
//! Only request-shape parsing (`routing_key_from_path` plus body-key aliases)
//! is LB-specific.

use serde_json::Value;

// Single source of truth for `ShardId` + `shard_for` (the hash).
pub use fiducia_routing::{shard_for, ShardId};

/// Extract the routing key from a request path, mirroring the node's API shape.
///
/// Returns `None` for paths that don't address a single key (health, status, and
/// cross-shard list endpoints) — those can go to any node.
///
/// | Path                                   | Key            |
/// |----------------------------------------|----------------|
/// | `/v1/kv/{key}`                         | `{key}`        |
/// | `/v1/locks/{key}` (+ `/info`)         | `{key}`        |
/// | `/v1/locks/acquire` + JSON `key`       | body `key`     |
/// | `/v1/rate-limit/{tenant}/{key}/...`   | `{key}`        |
/// | `/v1/cron/schedules/{name}/...`       | `{name}`       |
/// | `/v1/rw/{key}/read|write` (+ `/end`)  | `{key}`        |
/// | `/v1/elections/{name}/...`            | `{name}`       |
/// | `/v1/services/{service}/...`          | `{service}`    |
/// | `/v1/kv`, `/v1/services`, `/v1/status`| none (any node)|
pub fn routing_key_from_path(path: &str) -> Option<String> {
    let segs: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    // All keyed routes are `/v1/<primitive>/<key>/...`.
    match segs.as_slice() {
        ["v1", "kv", key, ..] => Some(decode(key)),
        ["v1", "locks", "acquire"] => None,
        ["v1", "locks", key, ..] => Some(decode(key)),
        ["v1", "rate-limit", _tenant, key, ..] => Some(decode(key)),
        ["v1", "cron", "schedules", name, ..] => Some(decode(name)),
        ["v1", "rw", key, ..] => Some(decode(key)),
        ["v1", "elections", name, ..] => Some(decode(name)),
        ["v1", "services", service, ..] => Some(decode(service)),
        _ => None,
    }
}

/// Extract the routing key from JSON bodies for advertised body-key aliases.
pub fn routing_key_from_json_body(path: &str, body: &[u8]) -> Option<String> {
    let segs: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    match segs.as_slice() {
        ["v1", "locks", "acquire"] => {
            let value: Value = serde_json::from_slice(body).ok()?;
            value.get("key")?.as_str().map(ToOwned::to_owned)
        }
        _ => None,
    }
}

/// Minimal percent-decode for the single path segment we route on.
///
/// TODO: full RFC-3986 decoding (or take the key from the matched route param
/// once the LB forwards through a real router rather than a path string).
fn decode(seg: &str) -> String {
    seg.replace("%2F", "/").replace("%2f", "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_extraction() {
        assert_eq!(
            routing_key_from_path("/v1/kv/orders").as_deref(),
            Some("orders")
        );
        assert_eq!(
            routing_key_from_path("/v1/locks/checkout/info").as_deref(),
            Some("checkout")
        );
        assert_eq!(routing_key_from_path("/v1/locks/acquire"), None);
        assert_eq!(
            routing_key_from_path("/v1/rate-limit/acme/checkout/check").as_deref(),
            Some("checkout")
        );
        assert_eq!(
            routing_key_from_path("/v1/cron/schedules/nightly/history").as_deref(),
            Some("nightly")
        );
        assert_eq!(
            routing_key_from_path("/v1/rw/report/read").as_deref(),
            Some("report")
        );
        assert_eq!(
            routing_key_from_path("/v1/elections/cleanup/campaign").as_deref(),
            Some("cleanup")
        );
        assert_eq!(
            routing_key_from_path("/v1/services/api/instances/i1").as_deref(),
            Some("api")
        );
        // keyless / cross-shard
        assert_eq!(routing_key_from_path("/v1/kv"), None);
        assert_eq!(routing_key_from_path("/v1/services"), None);
        assert_eq!(routing_key_from_path("/healthz"), None);
    }

    #[test]
    fn body_key_extraction_for_advertised_lock_acquire_alias() {
        let body = br#"{"key":"orders/checkout","ttl":"30s"}"#;
        assert_eq!(
            routing_key_from_json_body("/v1/locks/acquire", body).as_deref(),
            Some("orders/checkout")
        );
        assert_eq!(routing_key_from_json_body("/v1/kv", body), None);
    }
}
