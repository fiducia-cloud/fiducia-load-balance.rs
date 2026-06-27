# fiducia-load-balance

The **edge, key-aware load balancer** for [fiducia.cloud](https://fiducia.cloud).
End clients speak **HTTP or HTTPS** to this service; it routes each request to the
**leader of the shard that owns the request's key**. This repository is a
**skeleton**: routing decisions and the redirect loop are real; byte-level
forwarding and the control-plane refresh are stubbed.

## Why it exists

The data plane is sharded multi-Raft — there is **no single leader**. Each shard
has its own leader, spread across all nodes. So this is not a "route to the
leader" proxy; it's a **per-key router**:

```
key  →  shard ( fnv1a(key) % shard_count )  →  that shard's current leader
```

It keeps a `shard → leader` cache that is **allowed to be stale**:

- **Fast path** — cache says who leads the shard; forward straight there.
- **Backstop** — if the cache is wrong and the request lands on a follower, the
  node replies `NotLeader` (HTTP `307` + leader hint); the LB follows it and
  updates the cache. Self-healing, the way etcd/TiKV clients work.
- **No-hint fallback** — if the follower does not know the leader yet, the LB
  round-robins another known node until a leader responds or the retry budget is
  exhausted.

The cache is seeded/refreshed from the control plane (`fiducia-brain`'s
`/v1/placement`). The LB holds **no consensus state** — it's just a cache — so
run as many instances as you want behind a plain L4 balancer / k8s Service.

## Edge Routing Plan

The public request path is:

```
client → Cloudflare/other edge → regional Fiducia LB → shard leader
```

Cloudflare should route to a healthy Fiducia LB, preferably the LB closest to the
customer-selected region. It should not try to route directly to a shard leader;
leader knowledge belongs to the LB/control-plane cache. The LB hashes the request
key to a shard, forwards to the best-known leader, and learns a newer leader from
node `NotLeader` redirects. If a follower cannot name the leader, the LB falls
back to the known-node round-robin pool.

TLS termination can happen at this LB: set `FIDUCIA_TLS_CERT_PATH` and
`FIDUCIA_TLS_KEY_PATH` and it will listen on `TLS_PORT` (default `8443`) with
Rustls while continuing to serve plain HTTP on `PORT` for in-cluster health
checks or private callers. If Cloudflare is later enabled in front of it, use
Cloudflare in "Full (strict)" mode and point the origin at the LB HTTPS port; do
not route Cloudflare directly to node pods.

## Two planes, two transports

| Plane | Transport | Where |
|-------|-----------|-------|
| client ↔ LB | **HTTP or HTTPS**; TLS can terminate here | this crate |
| LB ↔ node | plain HTTP to the shard leader or redirect target | this crate |
| node ↔ node (Raft replication) | direct peer RPC to `/raft/{shard}/{append,vote}` using `FIDUCIA_PEERS`; bypasses the LB | `fiducia-node`'s `Transport` — **not** here |

HTTP is first-class for clients precisely because a leader change becomes a
redirect on the next stateless request — nothing to migrate. (Note: the *edge*
cuts client↔LB RTT, but a strongly-consistent write still has to reach the shard
leader + a quorum; the brain placing leaders near demand is what helps the
commit.)

## Endpoints

| Route | Purpose |
|-------|---------|
| `/healthz`, `/readyz` | the LB's own liveness |
| `/_lb/routes` | dump the current `shard → leader` cache |
| `/_lb/resolve?path=/v1/kv/foo` | show the routing decision (no forwarding) |
| everything else | routed to the owning shard's leader |

## Layout

| File             | Responsibility                                                  |
|------------------|----------------------------------------------------------------|
| `src/main.rs`    | axum wiring, refresh task, debug endpoints                      |
| `src/routing.rs` | key-from-path extraction + shard hash (mirrors the node)        |
| `src/table.rs`   | `shard → leader` cache; `note_leader` on redirect; brain refresh|
| `src/proxy.rs`   | forward + `NotLeader` redirect/retry loop                       |

> `ShardId` + `shard_for` (the hash) come from the shared
> [`fiducia-routing`](https://github.com/fiducia-cloud/fiducia-routing.rs) crate,
> so the LB and the data plane can never disagree on where a key lives. Only the
> path-parsing (`routing_key_from_path`) is LB-specific.

## Run locally

```bash
FIDUCIA_NODES=http://localhost:8090 FIDUCIA_SHARD_COUNT=4 cargo run   # :8088 (override PORT)
curl 'localhost:8088/_lb/resolve?path=/v1/locks/checkout'
curl  localhost:8088/_lb/routes
```

Env: `PORT`, `FIDUCIA_SHARD_COUNT`, `FIDUCIA_NODES` (comma-separated node URLs),
`FIDUCIA_BRAIN_URL`, `FIDUCIA_TLS_CERT_PATH`, `FIDUCIA_TLS_KEY_PATH`, `TLS_PORT`.

## Related

- [`fiducia-node.rs`](https://github.com/fiducia-cloud/fiducia-node.rs) — data plane (sharded coordination engine).
- [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) — control plane (placement, scaling, failure handling).
- [`fiducia-backend.rs`](https://github.com/fiducia-cloud/fiducia-backend.rs) — the website webserver.
