# fiducia-load-balance

The **edge, key-aware load balancer** for [fiducia.cloud](https://fiducia.cloud).
End clients speak **HTTP or HTTPS** to this service; it routes each request to the
**leader of the shard that owns the request's key**. It handles byte-level
forwarding, `NotLeader` redirects, and control-plane refresh from `fiducia-brain`.

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
  node replies `NotLeader` (HTTP `307` + leader hint); the LB follows it only
  when the target is present in brain's healthy membership, then updates the
  cache. An arbitrary redirect can never receive the trusted-hop secret.
- **No-hint fallback** — if a follower explicitly says `NotLeader` but cannot
  name the leader, the LB may try another known node. Transport failures are
  retried only for reads: a mutation with a lost response is ambiguous and is
  returned as `502 ambiguous_upstream_result`, never replayed automatically.
- **Retry diversity** — one request never spends its bounded retry budget on the
  same target twice. Stale hints and connection failures advance to an untried
  healthy member, so a dead leader cannot prevent the third replica being tried.

The cache is seeded/refreshed from the control plane (`fiducia-brain`'s
`/v1/placement`). Seed and brain node URLs are accepted only as credential-free
HTTP(S) origins—never a URL with userinfo, query, fragment, or a non-root path.
A brain refresh replaces the last-known-good table only when it contains one
valid leader for every configured shard; a partial or malformed snapshot is
logged and ignored instead of turning a transient control-plane read into a
data-plane outage. The LB holds **no consensus state**—it's just a cache—so run
as many instances as you want behind a plain L4 balancer / k8s Service.

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

Auth is still checked at the LB boundary. The public edge should reject most bad
traffic first, but the regional LB re-validates before proxying to nodes:

- Fiducia API keys (`fdc_live_<id>.<secret>`) are introspected through
  `fiducia-auth` and cached briefly by SHA-256 credential hash.
- Fiducia-issued JWTs are verified offline through the auth server's JWKS.
- Supabase sessions are not a data-plane credential here. Supabase belongs in
  `fiducia-auth` for dashboard/control-plane login and background sync.
- Raw `Authorization` / `x-api-key` headers are stripped before the node hop.
  Nodes only see LB-injected `x-fiducia-auth-kind`, `x-fiducia-org-id`,
  `x-fiducia-key-id`, and `x-fiducia-scopes`.

Customer-facing idempotency is enforced at this boundary too. Mutating requests
(`POST`, `PUT`, `PATCH`, `DELETE`) may include `Idempotency-Key: <key>`.
The LB hashes the customer key with the authenticated org, claims an internal
`/v1/idempotency` record, forwards the mutation once, then stores a replayable
status/body result for 24 hours. Exact retries replay the original response with
`Idempotent-Replayed: true`; the same key with a different method/path/body
returns `409 idempotency_key_conflict`; a retry while the first request is still
running returns `409 idempotency_key_in_progress` and `Retry-After: 1`. The raw
customer header is consumed at the LB and is not forwarded to nodes.

TLS termination can happen at this LB: set `FIDUCIA_TLS_CERT_PATH` and
`FIDUCIA_TLS_KEY_PATH` and it will listen on `TLS_PORT` (default `8443`) with
Rustls. When TLS is on, the plaintext `PORT` listener stays bound for k8s probes
but **stops proxying application traffic in cleartext**: it answers `/healthz` and
`/readyz`, and rejects every other path with `426 Upgrade Required`. It does not
construct redirects from an untrusted `Host` header, so a credential-bearing
mutation cannot be redirected to an attacker-controlled authority. If Cloudflare is later
enabled in front of it, use Cloudflare in "Full (strict)" mode and point the
origin at the LB HTTPS port; do not route Cloudflare directly to node pods.

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
| `/v1/kv?key=…&watch=true` and other SSE reads | routed to the owning shard and streamed without response buffering or a total request deadline; connect establishment remains bounded |
| everything else | routed to the owning shard's leader |

## Layout

| File             | Responsibility                                                  |
|------------------|----------------------------------------------------------------|
| `src/main.rs`    | axum wiring, refresh task, debug endpoints                      |
| `src/auth.rs`    | API-key introspection cache + Fiducia JWT offline verify         |
| `src/routing.rs` | key-from-path extraction + shard hash (mirrors the node)        |
| `src/table.rs`   | `shard → leader` cache; `note_leader` on redirect; brain refresh|
| `src/proxy.rs`   | forward + `NotLeader` redirect/retry loop                       |

> `ShardId` + `shard_for` (the hash) come from the shared
> [`fiducia-routing`](https://github.com/fiducia-cloud/fiducia-routing.rs) crate,
> so the LB and the data plane can never disagree on where a key lives. Only the
> path-parsing (`routing_key_from_path`) is LB-specific.

## Run locally

Single-node dev — no auth service, no cluster secret. Scoped routes still fail
closed (see the trust boundary below), so use a credential or hit the public
routes when exercising the proxy:

```bash
FIDUCIA_NODES=http://localhost:8090 FIDUCIA_SHARD_COUNT=4 cargo run --locked   # :8088 (override PORT)
curl 'localhost:8088/healthz'
curl 'localhost:8088/_lb/resolve?path=/v1/locks/checkout'   # operator route (admin scope if authed)
curl  localhost:8088/_lb/routes
```

On startup with no `FIDUCIA_INTERNAL_SECRET` and no TLS paths the LB logs loud
`WARN`s that it is running in plaintext, secret-less dev mode — expected locally,
never in production.

## Reproducible build inputs

CI and the container build use Rust 1.95.0, the committed `Cargo.lock`, and
immutable sibling revisions for the local path dependencies:

- `fiducia-interfaces` at
  `487e470c45ab5851e8f6f3b1dc048fe067fbf408`
- `fiducia-routing.rs` at
  `543b4ea3b3bba28b66c15a97a27514488d2ccce3`

When either shared contract changes, update the checkout refs in
`.github/workflows/ci.yml`, the build arguments in `.github/workflows/docker.yml`,
and the defaults in `Dockerfile` together. Cargo formatting, clippy, tests, and
release builds run with the lockfile enforced; dependency-audit failures block
CI. Docker build and runtime bases are pinned by multi-platform manifest digest,
and the final image runs as the distroless non-root uid/gid `65532:65532`.

## Configuration surface

All configuration is via environment variables (secrets are marked). Flags can be
mapped to these vars with `flags-2-env` (see below).

| Variable | Type | Default | Secret? | Meaning |
|----------|------|---------|:-------:|---------|
| `PORT` | integer | `8088` | no | Plain HTTP listen port (always bound). When TLS is on it serves only `/healthz` + `/readyz` and rejects everything else with `426` — no cleartext proxying or Host-derived redirect. |
| `TLS_PORT` | integer | `8443` | no | HTTPS listen port; only used when both TLS paths are set. |
| `FIDUCIA_SHARD_COUNT` | integer | `16` | no | Shard count; must match the data plane, or keys route to the wrong shard. |
| `FIDUCIA_NODES` | string | *(empty)* | no | Comma-separated seed node base URLs (provisional leaders until brain refresh). |
| `FIDUCIA_BRAIN_URL` | string | `http://localhost:8095` | no | Control-plane base URL for `shard→leader` placement refresh. |
| `FIDUCIA_BRAIN_REFRESH_TIMEOUT_SECS` | integer | `2` | no | HTTP timeout for brain refresh calls. |
| `FIDUCIA_INTERNAL_SECRET` | string | *(unset → off)* | **yes** | Shared trusted-hop secret. Proves an inbound request is a trusted edge hop and authenticates the LB→node/brain hop. Unset ⇒ edge-forwarded identities are **not** trusted. |
| `FIDUCIA_INTROSPECT_SECRET` | string | *(unset)* | **yes** | Optional `x-server-auth` secret sent to `fiducia-auth` on introspection. |
| `FIDUCIA_TLS_CERT_PATH` | string | *(unset → TLS off)* | no | PEM certificate chain served on `TLS_PORT`. Must be set together with the key. |
| `FIDUCIA_TLS_KEY_PATH` | string | *(unset → TLS off)* | no (points at a secret) | PEM private key served on `TLS_PORT`. Must be set together with the cert. |
| `FIDUCIA_AUTH_REQUIRED` | bool | `true` in release; `false` in debug | no | When `true`, a request with **no** raw credential or valid trusted-edge proof is rejected `401`. When `false`, credential-less requests are anonymous — but scoped routes still fail closed. |
| `FIDUCIA_AUTH_ALLOW_API_KEYS` | bool | `true` | no | Accept `fdc_…` API keys (introspected via `fiducia-auth`). |
| `FIDUCIA_AUTH_ALLOW_JWTS` | bool | `true` | no | Accept Fiducia JWTs (verified offline via JWKS). |
| `FIDUCIA_AUTH_URL` | string | `http://fiducia-auth.fiducia.svc.cluster.local:8097` | no | Base URL for the auth service. |
| `FIDUCIA_AUTH_INTROSPECT_URL` | string | `{auth_url}/v1/introspect` | no | Explicit introspection endpoint override. |
| `FIDUCIA_AUTH_JWKS_URL` | string | `{auth_url}/.well-known/jwks.json` | no | JWKS endpoint for offline JWT verification. |
| `FIDUCIA_AUTH_CACHE_TTL_SECS` | integer | `60` | no | Positive introspection cache TTL. |
| `FIDUCIA_AUTH_NEGATIVE_CACHE_TTL_SECS` | integer | `5` | no | Negative (rejected) auth cache TTL. |
| `FIDUCIA_AUTH_JWKS_TTL_SECS` | integer | `600` | no | JWKS cache TTL. |
| `FIDUCIA_AUTH_JWT_CACHE_TTL_SECS` | integer | `60` | no | Max verified-JWT cache TTL (capped by token `exp`). |
| `FIDUCIA_AUTH_HTTP_TIMEOUT_SECS` | integer | `2` | no | HTTP timeout for auth-service calls. |
| `FIDUCIA_JWT_ISSUER` | string | `fiducia-auth` | no | Required JWT `iss`. |
| `FIDUCIA_JWT_AUDIENCE` | string | `fiducia-api` | no | Required JWT `aud`. |

## Trust boundary and security posture

The LB authenticates at the boundary and **fails closed**:

- **Authentication and scopes fail closed.** With `FIDUCIA_AUTH_REQUIRED=true`
  (the release default), a request with no raw credential or valid trusted-edge
  proof is rejected `401`. With `AUTH_REQUIRED=false`, that request is anonymous;
  a scoped route (any `/v1/*` mutation or admin read) then rejects it `403`.
  Only genuinely public routes (`/healthz`, `/readyz`) serve anonymous callers,
  so an anonymous KV write never reaches a node in either mode.
- **Spoofable identity headers require the shared secret.** A trusted edge strips
  the raw credential and forwards the verified identity in `x-fiducia-*` headers
  plus `FIDUCIA_INTERNAL_SECRET` in `x-fiducia-edge-auth`. The LB trusts those
  headers **only** when the secret is present and **constant-time-equal**. With no
  secret configured (or a wrong one) the forwarded identity is dropped and the
  request is anonymous — closing the header-spoofing bypass.
- **Client-supplied trust headers are stripped.** `x-fiducia-*`, `authorization`,
  `x-api-key`, `cookie`, `x-fiducia-edge-auth`, and `x-fiducia-internal-auth` are
  never forwarded from a client to a node; the LB injects its own.
- **Body limits.** Inbound bodies are capped at 1 MiB; ordinary and
  idempotent-replay responses are bounded (8 MiB upstream/response ceiling,
  32 KiB stored, 255-byte idempotency keys). Successful `text/event-stream`
  reads are forwarded incrementally instead of buffered; an upstream stream
  error is logged and terminates that downstream stream.
- **Failover does not duplicate writes.** Explicit `NotLeader` responses are safe
  to retry against another known member because the node rejected the request.
  Network errors/timeouts on mutations are not retried: the result may have
  committed. Clients should retry with the same `Idempotency-Key`.
- **Leader hints are membership-bound.** Redirect targets must match the healthy
  node set learned from configuration/brain before the LB updates its cache or
  forwards the internal shared secret.
- **Path and query decoding stay distinct.** Query `+` is form-decoded as a
  space, while a literal `+` in a rate-limit, cron, or election path remains a
  plus, matching Axum's extractors so the LB and node hash identical keys.
- **Panics are contained.** A `CatchPanicLayer` turns any handler panic into a
  `500` instead of dropping the connection.

### TLS

- TLS terminates here when **both** `FIDUCIA_TLS_CERT_PATH` and
  `FIDUCIA_TLS_KEY_PATH` are set; setting only one is a hard startup error.
  It listens on `TLS_PORT` with Rustls (ring provider, safe TLS 1.2/1.3 defaults;
  no weakened cipher/version config).
- **The plaintext `PORT` listener never proxies application traffic in cleartext
  once TLS is on.** It stays bound (k8s liveness/readiness probes and the
  in-cluster ClusterIP target it) but only answers `/healthz` + `/readyz`; every
  other path gets `426 Upgrade Required`. The listener never trusts a caller's
  `Host` header to redirect a credential-bearing request. An attacker therefore
  cannot get a real request proxied over cleartext—or redirected to another
  authority—even on the internal port. The guard listener carries no
  auth/route-table state and never contacts a node. With no TLS paths set the LB
  serves the **full proxy in plaintext only**
  (dev) and logs a loud `WARN` at startup.
- Cert/key files are read from disk with no explicit permission check — mount them
  from a secret store with restrictive file modes.

## flags-2-env

Non-secret settings can be bridged to the `FIDUCIA_*` / `PORT` env vars above through the
pinned [`flags-2-env`](https://github.com/ORESoftware/flags-2-env) parser
(vendored as a git submodule under `vendor/flags-2-env`). The mapping lives in
[`.cli-flags.toml`](.cli-flags.toml) and is audited in CI (`cli-flags.yml`).

```bash
git submodule update --init vendor/flags-2-env
make -B -C vendor/flags-2-env all

# Run the binary with flags translated into env vars:
scripts/with-flags2env.sh --shards 4 --nodes http://localhost:8090 -- cargo run --locked

# Validate the schema:
vendor/flags-2-env/build/flags2env audit .cli-flags.toml
```

`FIDUCIA_INTERNAL_SECRET` and `FIDUCIA_INTROSPECT_SECRET` are deliberately
excluded from the CLI schema. Inject them through the environment or a secret
store so they cannot leak through shell history or process listings.

## Security

Hardening applied / verified in this crate:

- Boundary auth fails closed on scoped routes; edge-forwarded identity is trusted
  only behind a **constant-time**-verified shared secret (`src/auth.rs`).
- Loud startup `WARN`s when running without `FIDUCIA_INTERNAL_SECRET` or without
  TLS, so an insecure/opt-in mode is never silent (`src/main.rs`).
- Request-body and idempotency-capture size limits; handler panics caught → `500`.
- No `unsafe`; all `unwrap()` on the request path are over compile-time constants.

Accepted / known advisories (`cargo audit` is otherwise clean):

- **RUSTSEC-2025-0134 — `rustls-pemfile` unmaintained.** Pulled in transitively by
  `axum-server`'s Rustls PEM loading. It is an *unmaintained* warning, not a known
  vulnerability, and there is no in-semver replacement without a major upgrade of
  the TLS stack. We deliberately **do not** force-fix or major-bump it; TLS PEM
  parsing here only ever reads operator-provided cert/key files at startup (not
  attacker-controlled input). Revisit when `axum-server` moves off it.

## Related

- [`fiducia-node.rs`](https://github.com/fiducia-cloud/fiducia-node.rs) — data plane (sharded coordination engine).
- [`fiducia-brain.rs`](https://github.com/fiducia-cloud/fiducia-brain.rs) — control plane (placement, scaling, failure handling).
- [`fiducia-customer.rs`](https://github.com/fiducia-cloud/fiducia-customer.rs) — the website webserver.
