//! Fail-closed verifier-side JWT revocation gate for the regional load balancer.
//!
//! The load balancer verifies a raw Fiducia JWT offline first, then calls this
//! gate before returning an identity to route/scope authorization. Only a fresh
//! authoritative "not revoked" decision allows a request. Missing/stale state,
//! clock regression, authority failure, timeout, non-success status, oversized
//! response, or malformed response all deny.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

const READER_HEADER: &str = "x-revocation-reader-auth";
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub org_id: String,
    pub scopes: Vec<String>,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    Allowed,
    Revoked,
    Unavailable(Unavailable),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    ClockRegression,
    RefreshFailed,
    RefreshTimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lookup {
    Fresh(Decision),
    Stale,
    Miss,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    decision: Decision,
    observed_at: u64,
}

#[derive(Debug)]
struct RevocationCache {
    entries: HashMap<String, Entry>,
    high_water: u64,
    freshness_budget_secs: u64,
    capacity: usize,
}

impl RevocationCache {
    fn new(freshness_budget_secs: u64, capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            high_water: 0,
            freshness_budget_secs: freshness_budget_secs.max(1),
            capacity: capacity.max(1),
        }
    }

    fn lookup(&mut self, key: &str, now: u64) -> Result<Lookup, ()> {
        self.advance(now)?;
        Ok(match self.entries.get(key) {
            Some(entry) if now.saturating_sub(entry.observed_at) <= self.freshness_budget_secs => {
                Lookup::Fresh(entry.decision)
            }
            Some(_) => Lookup::Stale,
            None => Lookup::Miss,
        })
    }

    fn record_refresh_start(&mut self, now: u64) -> Result<(), ()> {
        self.advance(now)
    }

    fn apply(&mut self, key: &str, decision: Decision, now: u64) -> Result<(), ()> {
        self.advance(now)?;
        if !self.entries.contains_key(key) && self.entries.len() >= self.capacity {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.observed_at)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key.to_string(),
            Entry {
                decision,
                observed_at: now,
            },
        );
        Ok(())
    }

    fn advance(&mut self, now: u64) -> Result<(), ()> {
        if now < self.high_water {
            return Err(());
        }
        self.high_water = now;
        Ok(())
    }
}

#[derive(Debug)]
pub enum AuthorityError {
    Misconfigured,
    Transport,
    Status,
    Oversized,
    Malformed,
}

pub trait RevocationAuthority: Send + Sync {
    fn check_revocation(
        &self,
        claims: &Claims,
        now: u64,
    ) -> impl Future<Output = Result<bool, AuthorityError>> + Send;
}

#[derive(Clone)]
pub struct HttpRevocationAuthority {
    client: reqwest::Client,
    check_url: String,
    reader_secret: Option<String>,
}

impl HttpRevocationAuthority {
    pub fn new(client: reqwest::Client, check_url: String, reader_secret: Option<String>) -> Self {
        Self {
            client,
            check_url,
            reader_secret,
        }
    }
}

#[derive(Serialize)]
struct CheckRequest<'a> {
    claims: &'a Claims,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckEnvelope {
    decision: WireDecision,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDecision {
    revoked: bool,
    matched_target: Option<MatchedTarget>,
    generation: Option<u64>,
    expires_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatchedTarget {
    TokenId,
    Subject,
}

impl RevocationAuthority for HttpRevocationAuthority {
    fn check_revocation(
        &self,
        claims: &Claims,
        now: u64,
    ) -> impl Future<Output = Result<bool, AuthorityError>> + Send {
        let client = self.client.clone();
        let check_url = self.check_url.clone();
        let reader_secret = self.reader_secret.clone();
        let claims = claims.clone();
        async move {
            let secret = reader_secret
                .as_deref()
                .ok_or(AuthorityError::Misconfigured)?;
            let response = client
                .post(check_url)
                .header(READER_HEADER, secret)
                .header(CONTENT_TYPE, "application/json")
                .json(&CheckRequest { claims: &claims })
                .send()
                .await
                .map_err(|_| AuthorityError::Transport)?;
            if !response.status().is_success() {
                return Err(AuthorityError::Status);
            }
            let body = response
                .bytes()
                .await
                .map_err(|_| AuthorityError::Transport)?;
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(AuthorityError::Oversized);
            }
            let envelope: CheckEnvelope =
                serde_json::from_slice(&body).map_err(|_| AuthorityError::Malformed)?;
            validate_wire_decision(&envelope.decision, now)?;
            Ok(envelope.decision.revoked)
        }
    }
}

fn validate_wire_decision(decision: &WireDecision, now: u64) -> Result<(), AuthorityError> {
    if decision.revoked {
        if decision.matched_target.is_none()
            || decision.generation.is_none()
            || decision
                .expires_at
                .is_none_or(|expires_at| expires_at <= now)
        {
            return Err(AuthorityError::Malformed);
        }
    } else if decision.matched_target.is_some()
        || decision.generation.is_some()
        || decision.expires_at.is_some()
    {
        return Err(AuthorityError::Malformed);
    }
    Ok(())
}

pub struct RevocationGate<A: RevocationAuthority> {
    cache: Mutex<RevocationCache>,
    authority: A,
    refresh_timeout: Duration,
    key_locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl<A: RevocationAuthority> RevocationGate<A> {
    pub fn new(
        authority: A,
        freshness_budget_secs: u64,
        capacity: usize,
        refresh_timeout: Duration,
    ) -> Self {
        Self {
            cache: Mutex::new(RevocationCache::new(freshness_budget_secs, capacity)),
            authority,
            refresh_timeout,
            key_locks: Mutex::new(HashMap::new()),
        }
    }

    pub async fn authorize(&self, claims: &Claims, now: u64) -> Authorization {
        let key = revocation_cache_key(claims);
        match self.cache_lookup(&key, now) {
            Err(()) => return Authorization::Unavailable(Unavailable::ClockRegression),
            Ok(Lookup::Fresh(decision)) => return decision_to_authorization(decision),
            Ok(Lookup::Stale | Lookup::Miss) => {}
        }

        let lock = self.acquire_key(&key);
        let outcome = {
            let _guard = lock.lock().await;
            match self.cache_lookup(&key, now) {
                Err(()) => Authorization::Unavailable(Unavailable::ClockRegression),
                Ok(Lookup::Fresh(decision)) => decision_to_authorization(decision),
                Ok(Lookup::Stale | Lookup::Miss) => self.refresh(claims, &key, now).await,
            }
        };
        self.release_key(&key, lock);
        outcome
    }

    async fn refresh(&self, claims: &Claims, key: &str, now: u64) -> Authorization {
        if self
            .cache
            .lock()
            .expect("revocation cache mutex")
            .record_refresh_start(now)
            .is_err()
        {
            return Authorization::Unavailable(Unavailable::ClockRegression);
        }

        match tokio::time::timeout(
            self.refresh_timeout,
            self.authority.check_revocation(claims, now),
        )
        .await
        {
            Err(_) => Authorization::Unavailable(Unavailable::RefreshTimedOut),
            Ok(Err(_)) => Authorization::Unavailable(Unavailable::RefreshFailed),
            Ok(Ok(revoked)) => {
                let decision = if revoked {
                    Decision::Deny
                } else {
                    Decision::Allow
                };
                if self
                    .cache
                    .lock()
                    .expect("revocation cache mutex")
                    .apply(key, decision, now)
                    .is_err()
                {
                    Authorization::Unavailable(Unavailable::ClockRegression)
                } else {
                    decision_to_authorization(decision)
                }
            }
        }
    }

    fn cache_lookup(&self, key: &str, now: u64) -> Result<Lookup, ()> {
        self.cache
            .lock()
            .expect("revocation cache mutex")
            .lookup(key, now)
    }

    fn acquire_key(&self, key: &str) -> Arc<AsyncMutex<()>> {
        self.key_locks
            .lock()
            .expect("revocation key-lock mutex")
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    fn release_key(&self, key: &str, lock: Arc<AsyncMutex<()>>) {
        let mut locks = self.key_locks.lock().expect("revocation key-lock mutex");
        if Arc::strong_count(&lock) <= 2 {
            locks.remove(key);
        }
    }
}

fn decision_to_authorization(decision: Decision) -> Authorization {
    match decision {
        Decision::Allow => Authorization::Allowed,
        Decision::Deny => Authorization::Revoked,
    }
}

fn revocation_cache_key(claims: &Claims) -> String {
    let mut digest = Sha256::new();
    for field in [
        claims.iss.as_bytes(),
        claims.aud.as_bytes(),
        claims.org_id.as_bytes(),
        claims.sub.as_bytes(),
        claims.jti.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn claims(org: &str, subject: &str, jti: &str) -> Claims {
        Claims {
            sub: subject.to_string(),
            org_id: org.to_string(),
            scopes: vec!["kv:read".to_string()],
            iss: "fiducia-auth".to_string(),
            aud: "fiducia-api".to_string(),
            iat: 90,
            exp: 900,
            jti: jti.to_string(),
        }
    }

    #[derive(Clone)]
    struct PolicyAuthority {
        calls: Arc<AtomicUsize>,
        fail_after_first: bool,
        delay: Duration,
    }

    impl RevocationAuthority for PolicyAuthority {
        fn check_revocation(
            &self,
            claims: &Claims,
            _now: u64,
        ) -> impl Future<Output = Result<bool, AuthorityError>> + Send {
            let calls = self.calls.clone();
            let fail_after_first = self.fail_after_first;
            let delay = self.delay;
            let revoked = claims.jti == "revoked-token" || claims.sub == "revoked-subject";
            async move {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if fail_after_first && call > 0 {
                    Err(AuthorityError::Transport)
                } else {
                    Ok(revoked)
                }
            }
        }
    }

    fn gate(authority: PolicyAuthority, freshness: u64) -> Arc<RevocationGate<PolicyAuthority>> {
        Arc::new(RevocationGate::new(
            authority,
            freshness,
            64,
            Duration::from_millis(200),
        ))
    }

    #[tokio::test]
    async fn allows_only_after_authority_and_uses_fresh_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = gate(
            PolicyAuthority {
                calls: calls.clone(),
                fail_after_first: false,
                delay: Duration::ZERO,
            },
            30,
        );
        let token = claims("org-a", "subject-a", "token-a");
        assert_eq!(gate.authorize(&token, 100).await, Authorization::Allowed);
        assert_eq!(gate.authorize(&token, 110).await, Authorization::Allowed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_token_and_subject_revocations_deny() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = gate(
            PolicyAuthority {
                calls,
                fail_after_first: false,
                delay: Duration::ZERO,
            },
            30,
        );
        assert_eq!(
            gate.authorize(&claims("org-a", "subject-a", "revoked-token"), 100)
                .await,
            Authorization::Revoked
        );
        assert_eq!(
            gate.authorize(&claims("org-a", "revoked-subject", "token-b"), 100)
                .await,
            Authorization::Revoked
        );
    }

    #[tokio::test]
    async fn stale_allow_and_stale_deny_both_fail_closed_on_outage() {
        for token in [
            claims("org-a", "subject-a", "token-a"),
            claims("org-a", "subject-a", "revoked-token"),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let gate = gate(
                PolicyAuthority {
                    calls,
                    fail_after_first: true,
                    delay: Duration::ZERO,
                },
                1,
            );
            let first = gate.authorize(&token, 100).await;
            assert!(matches!(
                first,
                Authorization::Allowed | Authorization::Revoked
            ));
            assert_eq!(
                gate.authorize(&token, 102).await,
                Authorization::Unavailable(Unavailable::RefreshFailed)
            );
        }
    }

    #[tokio::test]
    async fn clock_regression_never_serves_cached_allow() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = gate(
            PolicyAuthority {
                calls,
                fail_after_first: false,
                delay: Duration::ZERO,
            },
            30,
        );
        let token = claims("org-a", "subject-a", "token-a");
        assert_eq!(gate.authorize(&token, 100).await, Authorization::Allowed);
        assert_eq!(
            gate.authorize(&token, 99).await,
            Authorization::Unavailable(Unavailable::ClockRegression)
        );
    }

    #[tokio::test]
    async fn equal_jti_in_different_tenants_is_independent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = gate(
            PolicyAuthority {
                calls: calls.clone(),
                fail_after_first: false,
                delay: Duration::ZERO,
            },
            30,
        );
        assert_eq!(
            gate.authorize(&claims("org-a", "subject", "shared-jti"), 100)
                .await,
            Authorization::Allowed
        );
        assert_eq!(
            gate.authorize(&claims("org-b", "subject", "shared-jti"), 100)
                .await,
            Authorization::Allowed
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_misses_coalesce_to_one_authority_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = gate(
            PolicyAuthority {
                calls: calls.clone(),
                fail_after_first: false,
                delay: Duration::from_millis(25),
            },
            30,
        );
        let token = claims("org-a", "subject-a", "token-a");
        let mut joins = Vec::new();
        for _ in 0..12 {
            let gate = gate.clone();
            let token = token.clone();
            joins.push(tokio::spawn(
                async move { gate.authorize(&token, 100).await },
            ));
        }
        for join in joins {
            assert_eq!(join.await.unwrap(), Authorization::Allowed);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_timeout_denies() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = RevocationGate::new(
            PolicyAuthority {
                calls,
                fail_after_first: false,
                delay: Duration::from_millis(50),
            },
            30,
            64,
            Duration::from_millis(5),
        );
        assert_eq!(
            gate.authorize(&claims("org-a", "subject-a", "token-a"), 100)
                .await,
            Authorization::Unavailable(Unavailable::RefreshTimedOut)
        );
    }

    #[derive(Clone)]
    struct HttpFixture {
        secret: String,
        body: Value,
        status: StatusCode,
    }

    async fn check_fixture(
        State(fixture): State<HttpFixture>,
        headers: HeaderMap,
        Json(_request): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        if headers
            .get(READER_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(fixture.secret.as_str())
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            );
        }
        (fixture.status, Json(fixture.body))
    }

    async fn fixture_authority(
        body: Value,
    ) -> (HttpRevocationAuthority, tokio::task::JoinHandle<()>) {
        let fixture = HttpFixture {
            secret: "reader-secret-reader-secret-reader-secret".to_string(),
            body,
            status: StatusCode::OK,
        };
        let app = Router::new()
            .route("/v1/revocations/check", post(check_fixture))
            .with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            HttpRevocationAuthority::new(
                reqwest::Client::new(),
                format!("http://{address}/v1/revocations/check"),
                Some(fixture.secret),
            ),
            task,
        )
    }

    #[tokio::test]
    async fn http_adapter_accepts_well_formed_reader_response() {
        let (authority, task) = fixture_authority(json!({
            "decision": {
                "revoked": false,
                "matched_target": null,
                "generation": null,
                "expires_at": null
            }
        }))
        .await;
        assert!(!authority
            .check_revocation(&claims("org-a", "subject-a", "token-a"), 100)
            .await
            .unwrap());
        task.abort();
    }

    #[tokio::test]
    async fn http_adapter_rejects_inconsistent_or_extra_fields() {
        let (authority, task) = fixture_authority(json!({
            "decision": {
                "revoked": false,
                "matched_target": "token_id",
                "generation": 1,
                "expires_at": 200,
                "unexpected": true
            }
        }))
        .await;
        assert!(matches!(
            authority
                .check_revocation(&claims("org-a", "subject-a", "token-a"), 100)
                .await,
            Err(AuthorityError::Malformed)
        ));
        task.abort();
    }
}
