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
    /// TODO: GET `{brain_url}/v1/placement`, then for each shard set the leader to
    /// its `preferred_leader` (or any replica) resolved to a node URL via the
    /// brain's membership view. Needs an HTTP client (see Cargo.toml note).
    pub async fn refresh_from_brain(&self, _brain_url: &str) {
        // TODO(cluster): pull placement + membership and repopulate `leaders`/`nodes`.
    }
}
