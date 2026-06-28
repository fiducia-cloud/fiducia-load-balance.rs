//! Shard → leader routing table (skeleton).
//!
//! The LB's cache of "who leads shard N right now". It is **allowed to be
//! stale**: the fast path uses it to route straight to a leader, and when it's
//! wrong the node redirects (`NotLeader`) and we self-correct via
//! [`note_leader`](RouteTable::note_leader). Seeded from the control plane
//! (`fiducia-brain`'s `/v1/placement`) and refreshed periodically.
//!
//! Stateless w.r.t. consensus — just a cache — so any number of LB instances can
//! run behind a plain L4 balancer.

use std::collections::HashMap;
use std::sync::RwLock;

use serde_json::{json, Value};

use crate::routing::ShardId;

struct Inner {
    /// Node base URLs known to the cluster (e.g. `http://10.0.0.1:8090`).
    nodes: Vec<String>,
    /// Best-known leader per shard. May be stale; corrected on redirect.
    leaders: HashMap<ShardId, String>,
    /// Round-robin cursor for keyless ("any node") requests.
    cursor: usize,
}

pub struct RouteTable {
    shard_count: u32,
    inner: RwLock<Inner>,
}

impl RouteTable {
    /// Build the table from a seed list of node URLs, provisionally assigning
    /// leaders round-robin until the first brain refresh / redirect corrects them.
    pub fn new(shard_count: u32, nodes: Vec<String>) -> Self {
        let mut leaders = HashMap::new();
        if !nodes.is_empty() {
            for shard in 0..shard_count {
                leaders.insert(shard, nodes[(shard as usize) % nodes.len()].clone());
            }
        }
        RouteTable {
            shard_count,
            inner: RwLock::new(Inner {
                nodes,
                leaders,
                cursor: 0,
            }),
        }
    }

    pub fn shard_count(&self) -> u32 {
        self.shard_count
    }

    /// Best-known leader URL for a shard, if any node is known for it.
    pub fn leader_for(&self, shard: ShardId) -> Option<String> {
        self.inner.read().unwrap().leaders.get(&shard).cloned()
    }

    /// Record a corrected leader (learned from a `NotLeader` redirect).
    pub fn note_leader(&self, shard: ShardId, node_url: String) {
        let mut inner = self.inner.write().unwrap();
        if !inner.nodes.contains(&node_url) {
            inner.nodes.push(node_url.clone());
        }
        inner.leaders.insert(shard, node_url);
    }

    /// A node for keyless requests (status / cross-shard lists), round-robined.
    pub fn any_node(&self) -> Option<String> {
        let mut inner = self.inner.write().unwrap();
        if inner.nodes.is_empty() {
            return None;
        }
        let i = inner.cursor % inner.nodes.len();
        inner.cursor = inner.cursor.wrapping_add(1);
        Some(inner.nodes[i].clone())
    }

    /// Debug view of the current routing state.
    pub fn snapshot(&self) -> Value {
        let inner = self.inner.read().unwrap();
        let mut leaders: Vec<_> = inner.leaders.iter().collect();
        leaders.sort_by_key(|(s, _)| **s);
        json!({
            "shard_count": self.shard_count,
            "nodes": inner.nodes,
            "leaders": leaders.into_iter()
                .map(|(s, n)| json!({ "shard": s, "leader": n }))
                .collect::<Vec<_>>(),
        })
    }

    /// Refresh the shard map from the control plane.
    ///
    /// Pulls the brain's membership (`/v1/nodes`) to learn `node_id → address`,
    /// then its placement map (`/v1/placement`) to learn each shard's preferred
    /// leader, and repopulates `nodes`/`leaders`. The table stays *advisory*: a
    /// stale entry just costs one redirect, which [`note_leader`] then corrects.
    pub async fn refresh_from_brain(&self, brain_url: &str) {
        let base = brain_url.trim_end_matches('/');
        let client = reqwest::Client::new();

        // 1. node_id -> base URL, for healthy nodes only.
        let nodes_doc: Value = match client
            .get(format!("{base}/v1/nodes"))
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Ok(resp) => match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "brain refresh: /v1/nodes body not JSON");
                    return;
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, brain = %base, "brain refresh: /v1/nodes unreachable");
                return;
            }
        };

        let mut node_url: HashMap<String, String> = HashMap::new();
        let mut healthy_urls: Vec<String> = Vec::new();
        if let Some(arr) = nodes_doc.get("nodes").and_then(|v| v.as_array()) {
            for n in arr {
                let Some(id) = n.get("node_id").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(addr) = n.get("address").and_then(|v| v.as_str()) else {
                    continue;
                };
                if addr.is_empty() {
                    continue;
                }
                let url = normalize_url(addr);
                // "dead"/"draining" nodes stay routable as a last resort but are
                // never preferred; only healthy nodes seed the round-robin pool.
                let healthy = n
                    .get("health")
                    .and_then(|v| v.as_str())
                    .map(|h| h == "healthy")
                    .unwrap_or(true);
                if healthy {
                    healthy_urls.push(url.clone());
                }
                node_url.insert(id.to_string(), url);
            }
        }

        // 2. placement -> per-shard preferred leader (or first replica).
        let placement_doc: Value = match client
            .get(format!("{base}/v1/placement"))
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Ok(resp) => match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "brain refresh: /v1/placement body not JSON");
                    return;
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, brain = %base, "brain refresh: /v1/placement unreachable");
                return;
            }
        };

        let mut leaders: HashMap<ShardId, String> = HashMap::new();
        if let Some(shards) = placement_doc.get("shards").and_then(|v| v.as_array()) {
            for a in shards {
                let Some(shard) = a.get("shard_id").and_then(|v| v.as_u64()) else {
                    continue;
                };
                let shard = shard as ShardId;
                // Prefer the brain's chosen leader; fall back to any replica.
                let leader_id = a
                    .get("preferred_leader")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .or_else(|| {
                        a.get("replicas")
                            .and_then(|v| v.as_array())
                            .and_then(|r| r.first())
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    });
                if let Some(url) = leader_id.and_then(|id| node_url.get(&id).cloned()) {
                    leaders.insert(shard, url);
                }
            }
        }

        // 3. Install the refreshed view. Keep any nodes we already knew (e.g. from
        // redirects) so we never shrink the routable set on a partial brain view.
        let mut inner = self.inner.write().unwrap();
        for url in healthy_urls {
            if !inner.nodes.contains(&url) {
                inner.nodes.push(url);
            }
        }
        for url in node_url.values() {
            if !inner.nodes.contains(url) {
                inner.nodes.push(url.clone());
            }
        }
        if !leaders.is_empty() {
            inner.leaders = leaders;
        }
        tracing::debug!(
            nodes = inner.nodes.len(),
            leaders = inner.leaders.len(),
            "brain refresh: routing table updated"
        );
    }
}

/// Ensure a node address carries a scheme; the brain reports bare `host:port`.
fn normalize_url(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.to_string()
    } else {
        format!("http://{addr}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_node_round_robins_over_known_nodes() {
        // The fallback when a follower can't name the leader: cycle the nodes.
        let table = RouteTable::new(
            8,
            vec![
                "http://a:8090".to_string(),
                "http://b:8090".to_string(),
                "http://c:8090".to_string(),
            ],
        );
        let seq: Vec<String> = (0..6).map(|_| table.any_node().unwrap()).collect();
        assert_eq!(
            seq,
            vec![
                "http://a:8090",
                "http://b:8090",
                "http://c:8090",
                "http://a:8090",
                "http://b:8090",
                "http://c:8090",
            ],
        );
    }

    // Same round-robin fallback, kept from origin/main for its scenario-focused
    // name (step 4: follower can't name the leader → the LB round-robins).
    #[test]
    fn any_node_round_robins_when_leader_hint_is_missing() {
        let table = RouteTable::new(
            4,
            vec![
                "http://node-a:8090".to_string(),
                "http://node-b:8090".to_string(),
                "http://node-c:8090".to_string(),
            ],
        );

        assert_eq!(table.any_node().as_deref(), Some("http://node-a:8090"));
        assert_eq!(table.any_node().as_deref(), Some("http://node-b:8090"));
        assert_eq!(table.any_node().as_deref(), Some("http://node-c:8090"));
        assert_eq!(table.any_node().as_deref(), Some("http://node-a:8090"));
    }

    #[test]
    fn note_leader_corrects_the_cache_and_learns_unknown_nodes() {
        let table = RouteTable::new(8, vec!["http://a:8090".to_string()]);
        // A redirect hint to a node we didn't know about.
        table.note_leader(3, "http://new:8090".to_string());
        assert_eq!(table.leader_for(3).as_deref(), Some("http://new:8090"));
        // The learned node now participates in round-robin too.
        let nodes: Vec<String> = (0..2).map(|_| table.any_node().unwrap()).collect();
        assert!(nodes.contains(&"http://new:8090".to_string()));
    }

    #[test]
    fn empty_table_has_no_node_to_route_to() {
        let table = RouteTable::new(8, vec![]);
        assert!(table.any_node().is_none());
        assert!(table.leader_for(0).is_none());
    }
}
