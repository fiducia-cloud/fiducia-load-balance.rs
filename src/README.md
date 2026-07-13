# src

The edge, key-aware load balancer: clients speak HTTP/HTTPS to it, and it routes
each request to the leader of the shard that owns the request's key. It holds no
consensus state — just a self-correcting `shard → leader` cache — so it scales out
horizontally behind a plain L4 balancer.

- `main.rs` — binary entrypoint: Axum wiring, the control-plane refresh task, TLS
  termination, and the `/_lb/*` debug endpoints.
- `routing.rs` — extract the routing key from the request path and hash it to a
  shard via the shared `fiducia-routing` crate (so LB and data plane never disagree).
- `table.rs` — the `shard → leader` cache: allowed to be stale, seeded/refreshed
  from `fiducia-brain`, and corrected only by leader hints that match known
  healthy membership.
- `proxy.rs` — the bounded forwarding hop plus the `NotLeader` redirect loop;
  transport failover is read-only so ambiguous mutations are never replayed.
- `auth.rs` — the boundary auth gate: API-key introspection cache (`fiducia-auth`)
  and offline Fiducia JWT verification via JWKS.
