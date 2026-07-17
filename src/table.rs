//! Shard → leader routing table.
//!
//! The LB's cache of "who leads shard N right now". It is **allowed to be
//! stale**: the fast path uses it to route straight to a leader, and when it's
//! wrong the node redirects (`NotLeader`) and we self-correct via
//! a validated leader hint. Seeded from the control plane
//! (`fiducia-brain`'s `/v1/placement`) and refreshed periodically.
//!
//! Stateless w.r.t. consensus — just a cache — so any number of LB instances can
//! run behind a plain L4 balancer.

use std::collections::{HashMap, HashSet};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::routing::ShardId;

const DEFAULT_BRAIN_REFRESH_TIMEOUT_SECS: u64 = 2;

struct Inner {
    /// Node base URLs known to the cluster (e.g. `http://10.0.0.1:8090`).
    nodes: Vec<String>,
    /// Region/provider metadata by node URL, learned from brain membership.
    node_metadata: HashMap<String, NodeMetadata>,
    /// Best-known leader per shard. May be stale; corrected on redirect.
    leaders: HashMap<ShardId, String>,
    /// Best-effort routed request counts by leader region.
    region_requests: HashMap<String, u64>,
    /// Round-robin cursor for keyless ("any node") requests.
    cursor: usize,
}

#[derive(Debug, Clone)]
struct NodeMetadata {
    cloud_provider: String,
    region: String,
    cluster_id: String,
}

pub struct RouteTable {
    shard_count: u32,
    inner: RwLock<Inner>,
}

impl RouteTable {
    /// Build the table from a seed list of node URLs, provisionally assigning
    /// leaders round-robin until the first brain refresh / redirect corrects them.
    pub fn new(shard_count: u32, nodes: Vec<String>) -> Self {
        let mut seen = HashSet::new();
        let nodes: Vec<String> = nodes
            .into_iter()
            .filter_map(|node| {
                let normalized = normalize_node_url(&node);
                if normalized.is_none() {
                    tracing::warn!(node = %node, "ignoring invalid load-balancer seed node URL");
                }
                normalized
            })
            .filter(|node| seen.insert(node.clone()))
            .collect();
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
                node_metadata: HashMap::new(),
                leaders,
                region_requests: HashMap::new(),
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

    /// Accept a corrected leader only when it is already in the healthy
    /// membership learned from configuration/brain. Redirects are data-plane
    /// input; allowing one to add an arbitrary URL would forward the trusted-hop
    /// secret to an attacker-controlled host.
    pub fn accept_leader_hint(&self, shard: ShardId, node_url: &str) -> Option<String> {
        let normalized = normalize_node_url(node_url)?;
        let mut inner = self.inner.write().unwrap();
        let known = inner.nodes.iter().find_map(|node| {
            (normalize_node_url(node).as_deref() == Some(&normalized)).then(|| node.clone())
        })?;
        inner.leaders.insert(shard, known.clone());
        Some(known)
    }

    /// Validate a keyless redirect target without changing a shard entry.
    pub fn validate_node_hint(&self, node_url: &str) -> Option<String> {
        let normalized = normalize_node_url(node_url)?;
        let inner = self.inner.read().unwrap();
        inner.nodes.iter().find_map(|node| {
            (normalize_node_url(node).as_deref() == Some(&normalized)).then(|| node.clone())
        })
    }

    /// Count a routed request against the resolved leader's region.
    pub fn record_region_request(&self, node_url: &str) {
        let mut inner = self.inner.write().unwrap();
        let region = inner
            .node_metadata
            .get(node_url)
            .map(|m| {
                if m.region.is_empty() {
                    "unknown".to_string()
                } else {
                    m.region.clone()
                }
            })
            .unwrap_or_else(|| "unknown".to_string());
        *inner.region_requests.entry(region).or_default() += 1;
    }

    /// A node for keyless requests (status / cross-shard lists), round-robined.
    pub fn any_node(&self) -> Option<String> {
        self.any_node_excluding(&HashSet::new())
    }

    /// Round-robin over known nodes while avoiding targets already attempted by
    /// one proxy request. Without this, a stale leader hint can bounce the retry
    /// loop back to the same dead member until `MAX_HOPS` is exhausted, even
    /// though another healthy replica was never tried.
    pub fn any_node_excluding(&self, excluded: &HashSet<String>) -> Option<String> {
        let mut inner = self.inner.write().unwrap();
        if inner.nodes.is_empty() {
            return None;
        }
        for _ in 0..inner.nodes.len() {
            let i = inner.cursor % inner.nodes.len();
            inner.cursor = inner.cursor.wrapping_add(1);
            if !excluded.contains(&inner.nodes[i]) {
                return Some(inner.nodes[i].clone());
            }
        }
        None
    }

    /// Debug view of the current routing state.
    pub fn snapshot(&self) -> Value {
        let inner = self.inner.read().unwrap();
        let mut leaders: Vec<_> = inner.leaders.iter().collect();
        leaders.sort_by_key(|(s, _)| **s);
        let mut node_metadata: Vec<_> = inner.node_metadata.iter().collect();
        node_metadata.sort_by_key(|(url, _)| *url);
        let mut region_requests: Vec<_> = inner.region_requests.iter().collect();
        region_requests.sort_by_key(|(region, _)| *region);
        json!({
            "shard_count": self.shard_count,
            "nodes": inner.nodes,
            "node_metadata": node_metadata.into_iter()
                .map(|(url, m)| json!({
                    "url": url,
                    "cloud_provider": m.cloud_provider,
                    "region": m.region,
                    "cluster_id": m.cluster_id,
                }))
                .collect::<Vec<_>>(),
            "leaders": leaders.into_iter()
                .map(|(s, n)| json!({ "shard": s, "leader": n }))
                .collect::<Vec<_>>(),
            "metrics": {
                "region_requests": region_requests.into_iter()
                    .map(|(region, count)| json!({ "region": region, "requests": count }))
                    .collect::<Vec<_>>(),
            },
        })
    }

    /// Refresh the shard map from the control plane.
    pub async fn refresh_from_brain(&self, brain_url: &str) {
        let base = brain_url.trim_end_matches('/');
        let client = brain_client();
        // The brain's /v1 enforces the trusted-hop secret when configured.
        let auth = |req: reqwest::RequestBuilder| match crate::proxy::internal_secret() {
            Some(secret) => req.header(crate::proxy::INTERNAL_AUTH_HEADER, secret),
            None => req,
        };
        let nodes = match auth(client.get(format!("{base}/v1/nodes")))
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Ok(resp) => match resp.json::<BrainNodes>().await {
                Ok(nodes) => nodes,
                Err(err) => {
                    tracing::warn!(?err, "failed to parse brain node snapshot");
                    return;
                }
            },
            Err(err) => {
                tracing::warn!(?err, "failed to refresh brain node snapshot");
                return;
            }
        };
        let placement = match auth(client.get(format!("{base}/v1/placement")))
            .send()
            .await
            .and_then(|r| r.error_for_status())
        {
            Ok(resp) => match resp.json::<BrainPlacement>().await {
                Ok(placement) => placement,
                Err(err) => {
                    tracing::warn!(?err, "failed to parse brain placement snapshot");
                    return;
                }
            },
            Err(err) => {
                tracing::warn!(?err, "failed to refresh brain placement snapshot");
                return;
            }
        };
        let applied = self.apply_brain_snapshot(nodes.nodes, placement.shards);
        tracing::info!(
            metric.name = "fiducia.lb.brain_refresh",
            leaders = applied,
            "refreshed shard leaders from brain"
        );
    }

    fn apply_brain_snapshot(&self, nodes: Vec<BrainNode>, shards: Vec<BrainShard>) -> usize {
        let mut node_urls_by_id = HashMap::new();
        let mut node_metadata = HashMap::new();
        for node in nodes {
            if !node.health.eq_ignore_ascii_case("healthy") {
                continue;
            }
            let node_id = node.node_id.trim();
            if node_id.is_empty() {
                tracing::warn!("rejecting brain snapshot with an empty healthy node ID");
                return 0;
            }
            let Some(url) = normalize_node_url(&node.address) else {
                tracing::warn!(node_id, address = %node.address, "rejecting brain snapshot with an invalid healthy node URL");
                return 0;
            };
            if node_urls_by_id
                .insert(node_id.to_string(), url.clone())
                .is_some()
            {
                tracing::warn!(
                    node_id,
                    "rejecting brain snapshot with a duplicate healthy node ID"
                );
                return 0;
            }
            if node_metadata.contains_key(&url) {
                tracing::warn!(node_id, %url, "rejecting brain snapshot with a duplicate healthy node URL");
                return 0;
            }
            node_metadata.insert(
                url,
                NodeMetadata {
                    cloud_provider: node.cloud_provider.unwrap_or_default(),
                    region: node.region.unwrap_or_default(),
                    cluster_id: node.cluster_id.unwrap_or_default(),
                },
            );
        }
        if node_urls_by_id.is_empty() {
            tracing::warn!("brain snapshot had no routable healthy nodes");
            return 0;
        }

        let mut leaders = HashMap::new();
        for shard in shards {
            if shard.shard_id >= self.shard_count {
                tracing::warn!(
                    shard = shard.shard_id,
                    shard_count = self.shard_count,
                    "rejecting brain snapshot with an out-of-range shard"
                );
                return 0;
            }
            let target = shard
                .preferred_leader
                .as_ref()
                .and_then(|leader| node_urls_by_id.get(leader))
                .or_else(|| {
                    shard
                        .replicas
                        .iter()
                        .find_map(|replica| node_urls_by_id.get(replica))
                });
            let Some(url) = target else {
                tracing::warn!(
                    shard = shard.shard_id,
                    "rejecting brain snapshot with no healthy replica for a shard"
                );
                return 0;
            };
            if leaders.insert(shard.shard_id, url.clone()).is_some() {
                tracing::warn!(
                    shard = shard.shard_id,
                    "rejecting brain snapshot with a duplicate shard placement"
                );
                return 0;
            }
        }
        if leaders.len() != self.shard_count as usize {
            tracing::warn!(
                expected = self.shard_count,
                actual = leaders.len(),
                "rejecting partial brain snapshot; retaining last-known-good routes"
            );
            return 0;
        }

        let mut nodes: Vec<String> = node_urls_by_id.values().cloned().collect();
        nodes.sort();
        let applied = leaders.len();
        let mut inner = self.inner.write().unwrap();
        inner.nodes = nodes;
        inner.node_metadata = node_metadata;
        inner.leaders = leaders;
        applied
    }
}

fn brain_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(duration_from_env(
                "FIDUCIA_BRAIN_REFRESH_TIMEOUT_SECS",
                DEFAULT_BRAIN_REFRESH_TIMEOUT_SECS,
            ))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

fn duration_from_env(name: &str, default_secs: u64) -> Duration {
    duration_from_secs_value(std::env::var(name).ok().as_deref(), default_secs)
}

fn duration_from_secs_value(value: Option<&str>, default_secs: u64) -> Duration {
    let secs = value
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(default_secs);
    Duration::from_secs(secs)
}

#[derive(Debug, Deserialize)]
struct BrainNodes {
    nodes: Vec<BrainNode>,
}

#[derive(Debug, Deserialize)]
struct BrainNode {
    node_id: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    health: String,
    #[serde(default)]
    cloud_provider: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    cluster_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BrainPlacement {
    shards: Vec<BrainShard>,
}

#[derive(Debug, Deserialize)]
struct BrainShard {
    shard_id: ShardId,
    #[serde(default)]
    replicas: Vec<String>,
    #[serde(default)]
    preferred_leader: Option<String>,
}

fn normalize_node_url(address: &str) -> Option<String> {
    let address = address.trim();
    if address.is_empty() {
        return None;
    }
    let candidate = if address.starts_with("http://") || address.starts_with("https://") {
        address.to_string()
    } else {
        format!("http://{address}")
    };
    let parsed = reqwest::Url::parse(&candidate).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return None;
    }
    Some(parsed.as_str().trim_end_matches('/').to_string())
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

    #[test]
    fn any_node_excluding_never_revisits_attempted_members() {
        let table = RouteTable::new(
            8,
            vec![
                "http://a:8090".to_string(),
                "http://b:8090".to_string(),
                "http://c:8090".to_string(),
            ],
        );
        let mut excluded = HashSet::from(["http://a:8090".to_string()]);
        assert_eq!(
            table.any_node_excluding(&excluded).as_deref(),
            Some("http://b:8090")
        );
        excluded.insert("http://b:8090".to_string());
        assert_eq!(
            table.any_node_excluding(&excluded).as_deref(),
            Some("http://c:8090")
        );
        excluded.insert("http://c:8090".to_string());
        assert_eq!(table.any_node_excluding(&excluded), None);
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
    fn leader_hints_must_match_known_membership() {
        let table = RouteTable::new(
            8,
            vec!["http://a:8090".to_string(), "http://new:8090".to_string()],
        );
        assert_eq!(
            table.accept_leader_hint(3, "http://new:8090/"),
            Some("http://new:8090".to_string())
        );
        assert_eq!(table.leader_for(3).as_deref(), Some("http://new:8090"));

        assert_eq!(table.accept_leader_hint(3, "https://evil.example"), None);
        assert_eq!(table.leader_for(3).as_deref(), Some("http://new:8090"));
    }

    #[test]
    fn empty_table_has_no_node_to_route_to() {
        let table = RouteTable::new(8, vec![]);
        assert!(table.any_node().is_none());
        assert!(table.leader_for(0).is_none());
    }

    #[test]
    fn brain_snapshot_sets_preferred_leader_and_node_metadata() {
        let table = RouteTable::new(4, vec![]);
        let applied = table.apply_brain_snapshot(
            vec![
                BrainNode {
                    node_id: "a".to_string(),
                    address: "10.0.0.1:8090".to_string(),
                    health: "healthy".to_string(),
                    cloud_provider: Some("aws".to_string()),
                    region: Some("us-east-1".to_string()),
                    cluster_id: Some("aws-prod".to_string()),
                },
                BrainNode {
                    node_id: "b".to_string(),
                    address: "http://10.0.0.2:8090".to_string(),
                    health: "healthy".to_string(),
                    cloud_provider: Some("gcp".to_string()),
                    region: Some("us-central1".to_string()),
                    cluster_id: Some("gcp-prod".to_string()),
                },
            ],
            (0..4)
                .map(|shard_id| BrainShard {
                    shard_id,
                    replicas: vec!["a".to_string(), "b".to_string()],
                    preferred_leader: Some(if shard_id == 2 { "b" } else { "a" }.to_string()),
                })
                .collect(),
        );

        assert_eq!(applied, 4);
        assert_eq!(table.leader_for(2).as_deref(), Some("http://10.0.0.2:8090"));
        let snapshot = table.snapshot();
        assert_eq!(snapshot["node_metadata"][0]["cloud_provider"], "aws");
        assert_eq!(snapshot["node_metadata"][0]["cluster_id"], "aws-prod");
        assert_eq!(snapshot["node_metadata"][1]["region"], "us-central1");
    }

    /// When a shard names no usable preferred leader — unset, or pointing at a
    /// node that is not in the healthy membership — the snapshot must still
    /// route the shard by falling back to its first HEALTHY replica, and an
    /// unhealthy node must never become a route target at all.
    #[test]
    fn shard_without_a_usable_preferred_leader_falls_back_to_a_healthy_replica() {
        let table = RouteTable::new(2, vec![]);
        let node = |id: &str, addr: &str, health: &str| BrainNode {
            node_id: id.to_string(),
            address: addr.to_string(),
            health: health.to_string(),
            cloud_provider: None,
            region: None,
            cluster_id: None,
        };
        let applied = table.apply_brain_snapshot(
            vec![
                node("a", "10.0.0.1:8090", "healthy"),
                node("b", "10.0.0.2:8090", "unhealthy"),
                node("c", "10.0.0.3:8090", "healthy"),
            ],
            vec![
                // Preferred leader "b" is unhealthy: skip it, then skip the
                // equally-unhealthy first replica, and land on healthy "c".
                BrainShard {
                    shard_id: 0,
                    replicas: vec!["b".to_string(), "c".to_string()],
                    preferred_leader: Some("b".to_string()),
                },
                // No preferred leader at all: the first healthy replica leads.
                BrainShard {
                    shard_id: 1,
                    replicas: vec!["a".to_string(), "c".to_string()],
                    preferred_leader: None,
                },
            ],
        );

        assert_eq!(applied, 2);
        assert_eq!(table.leader_for(0).as_deref(), Some("http://10.0.0.3:8090"));
        assert_eq!(table.leader_for(1).as_deref(), Some("http://10.0.0.1:8090"));
        // The unhealthy node is not routable membership: it is neither an
        // any-node target nor an acceptable leader hint.
        let snapshot = table.snapshot();
        assert_eq!(
            snapshot["nodes"],
            json!(["http://10.0.0.1:8090", "http://10.0.0.3:8090"])
        );
        assert_eq!(table.accept_leader_hint(0, "http://10.0.0.2:8090"), None);
        assert_eq!(table.leader_for(0).as_deref(), Some("http://10.0.0.3:8090"));
    }

    #[test]
    fn region_requests_are_counted_by_leader_region() {
        let table = RouteTable::new(1, vec![]);
        table.apply_brain_snapshot(
            vec![BrainNode {
                node_id: "a".to_string(),
                address: "10.0.0.1:8090".to_string(),
                health: "healthy".to_string(),
                cloud_provider: Some("aws".to_string()),
                region: Some("us-east-1".to_string()),
                cluster_id: Some("aws-prod".to_string()),
            }],
            vec![BrainShard {
                shard_id: 0,
                replicas: vec!["a".to_string()],
                preferred_leader: Some("a".to_string()),
            }],
        );

        table.record_region_request("http://10.0.0.1:8090");
        table.record_region_request("http://10.0.0.1:8090");

        let snapshot = table.snapshot();
        assert_eq!(
            snapshot["metrics"]["region_requests"][0]["region"],
            "us-east-1"
        );
        assert_eq!(snapshot["metrics"]["region_requests"][0]["requests"], 2);
    }

    #[test]
    fn brain_refresh_timeout_rejects_invalid_or_zero_values() {
        assert_eq!(
            duration_from_secs_value(Some("7"), DEFAULT_BRAIN_REFRESH_TIMEOUT_SECS),
            Duration::from_secs(7)
        );
        assert_eq!(
            duration_from_secs_value(Some("0"), DEFAULT_BRAIN_REFRESH_TIMEOUT_SECS),
            Duration::from_secs(DEFAULT_BRAIN_REFRESH_TIMEOUT_SECS)
        );
        assert_eq!(
            duration_from_secs_value(Some("not-a-number"), DEFAULT_BRAIN_REFRESH_TIMEOUT_SECS),
            Duration::from_secs(DEFAULT_BRAIN_REFRESH_TIMEOUT_SECS)
        );
    }

    #[test]
    fn seed_nodes_are_validated_normalized_and_deduplicated() {
        let table = RouteTable::new(
            4,
            vec![
                " node-a:8090/ ".to_string(),
                "http://node-a:8090".to_string(),
                "https://node-b:8443/".to_string(),
                "ftp://node-c:21".to_string(),
                "http://user:secret@node-d:8090".to_string(),
                "http://node-e:8090/not-a-base".to_string(),
                "http://node-f:8090?token=secret".to_string(),
            ],
        );

        assert_eq!(
            table.snapshot()["nodes"],
            json!(["http://node-a:8090", "https://node-b:8443"])
        );
        assert_eq!(table.leader_for(0).as_deref(), Some("http://node-a:8090"));
        assert_eq!(table.leader_for(1).as_deref(), Some("https://node-b:8443"));
    }

    #[test]
    fn malicious_or_non_base_leader_hints_are_rejected() {
        let table = RouteTable::new(2, vec!["http://node-a:8090".to_string()]);
        let original = table.leader_for(0);

        for hint in [
            "ftp://node-a:8090",
            "http://attacker@node-a:8090",
            "http://node-a:8090/v1/status",
            "http://node-a:8090?redirect=attacker",
            "http://node-a:8090#attacker",
        ] {
            assert_eq!(table.accept_leader_hint(0, hint), None, "hint={hint}");
        }
        assert_eq!(table.leader_for(0), original);
    }

    #[test]
    fn partial_brain_snapshot_preserves_last_known_good_routes() {
        let table = RouteTable::new(
            3,
            vec![
                "http://seed-a:8090".to_string(),
                "http://seed-b:8090".to_string(),
            ],
        );
        let before = table.snapshot();
        let applied = table.apply_brain_snapshot(
            vec![BrainNode {
                node_id: "brain-a".to_string(),
                address: "brain-a:8090".to_string(),
                health: "healthy".to_string(),
                cloud_provider: None,
                region: None,
                cluster_id: None,
            }],
            vec![BrainShard {
                shard_id: 0,
                replicas: vec!["brain-a".to_string()],
                preferred_leader: Some("brain-a".to_string()),
            }],
        );

        assert_eq!(applied, 0);
        assert_eq!(table.snapshot(), before);
    }

    #[test]
    fn invalid_brain_placement_preserves_last_known_good_routes() {
        let table = RouteTable::new(1, vec!["http://seed-a:8090".to_string()]);
        let before = table.snapshot();
        let node = BrainNode {
            node_id: "brain-a".to_string(),
            address: "brain-a:8090".to_string(),
            health: "healthy".to_string(),
            cloud_provider: None,
            region: None,
            cluster_id: None,
        };

        let applied = table.apply_brain_snapshot(
            vec![node],
            vec![BrainShard {
                shard_id: 1,
                replicas: vec!["brain-a".to_string()],
                preferred_leader: Some("brain-a".to_string()),
            }],
        );

        assert_eq!(applied, 0);
        assert_eq!(table.snapshot(), before);
    }
}
