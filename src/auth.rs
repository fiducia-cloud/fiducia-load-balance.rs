//! Hot-path auth gate for the regional load balancer.
//!
//! API keys are introspected through `fiducia-auth` and cached briefly. Raw
//! Fiducia JWTs are verified offline against JWKS, then checked through the
//! fail-closed revocation gate before any identity reaches route authorization.

#[path = "revocation.rs"]
mod revocation;

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fiducia_interfaces::Introspection;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use revocation::{Authorization, Claims, HttpRevocationAuthority, RevocationGate, Unavailable};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

const DEFAULT_AUTH_URL: &str = "http://fiducia-auth.fiducia.svc.cluster.local:8097";
const DEFAULT_REVOCATION_CHECK_URL: &str =
    "http://fiducia-revocation-admin.fiducia.svc.cluster.local:8098/v1/revocations/check";
const DEFAULT_CACHE_TTL_SECS: u64 = 60;
const DEFAULT_NEGATIVE_CACHE_TTL_SECS: u64 = 5;
const DEFAULT_JWKS_TTL_SECS: u64 = 10 * 60;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 2;
const DEFAULT_REVOCATION_FRESHNESS_SECS: u64 = 30;
const DEFAULT_REVOCATION_CAPACITY: usize = 65_536;
const DEFAULT_REVOCATION_TIMEOUT_MILLIS: u64 = 2_000;
const DEFAULT_JWT_ISSUER: &str = "fiducia-auth";
const DEFAULT_JWT_AUDIENCE: &str = "fiducia-api";
const MAX_ACCESS_TOKEN_TTL_SECS: u64 = 15 * 60;
const JWT_CLOCK_SKEW_SECS: u64 = 30;
const MAX_CACHED_DECISIONS: usize = 10_000;
const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_JWKS_RESPONSE_BYTES: usize = 256 * 1024;
const MIN_READER_SECRET_BYTES: usize = 32;

#[derive(Clone)]
pub struct AuthState {
    config: Arc<AuthConfig>,
    client: reqwest::Client,
    decisions: Arc<RwLock<HashMap<String, CachedDecision>>>,
    jwks: Arc<RwLock<Option<CachedJwks>>>,
    revocations: Arc<RevocationGate<HttpRevocationAuthority>>,
}

#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub kind: AuthKind,
    pub org_id: String,
    pub key_id: Option<String>,
    pub scopes: Vec<String>,
    pub require_idempotency: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    ApiKey,
    Jwt,
}

impl AuthState {
    pub fn from_env() -> Self {
        let config = AuthConfig::from_env();
        let client = reqwest::Client::builder()
            .timeout(config.http_timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let authority = HttpRevocationAuthority::new(
            client.clone(),
            config.revocation_check_url.clone(),
            config.revocation_reader_secret.clone(),
        );
        let revocations = Arc::new(RevocationGate::new(
            authority,
            config.revocation_freshness_secs,
            config.revocation_capacity,
            config.revocation_refresh_timeout,
        ));

        if config.allow_jwts && config.revocation_reader_secret.is_none() {
            tracing::error!(
                "FIDUCIA_REVOCATION_READER_SECRET is missing or invalid; raw JWT authentication will fail closed"
            );
        }

        Self {
            config: Arc::new(config),
            client,
            decisions: Arc::new(RwLock::new(HashMap::new())),
            jwks: Arc::new(RwLock::new(None)),
            revocations,
        }
    }

    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<VerifiedIdentity>, Response> {
        let Some(credential) = extract_credential(headers) else {
            return if self.config.required {
                Err(auth_response(
                    StatusCode::UNAUTHORIZED,
                    "missing_credentials",
                    "send Authorization: Bearer <api-key-or-token>",
                ))
            } else {
                Ok(None)
            };
        };

        if is_api_key(&credential) {
            if !self.config.allow_api_keys {
                return Err(auth_response(
                    StatusCode::UNAUTHORIZED,
                    "api_keys_disabled",
                    "api key authentication is disabled",
                ));
            }
            return self.authenticate_api_key(&credential).await.map(Some);
        }

        if looks_like_jwt(&credential) {
            if !self.config.allow_jwts {
                return Err(auth_response(
                    StatusCode::UNAUTHORIZED,
                    "jwt_disabled",
                    "jwt authentication is disabled",
                ));
            }
            return self.authenticate_jwt(&credential).await.map(Some);
        }

        Err(auth_response(
            StatusCode::UNAUTHORIZED,
            "unsupported_credentials",
            "credential must be a fiducia API key or fiducia JWT",
        ))
    }

    async fn authenticate_api_key(&self, api_key: &str) -> Result<VerifiedIdentity, Response> {
        let cache_key = credential_cache_key("api_key", api_key);
        if let Some(cached) = self.cached_decision(&cache_key).await {
            return cached.ok_or_else(|| {
                auth_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_api_key",
                    "invalid api key",
                )
            });
        }

        let intro = match self.fetch_introspection(api_key).await {
            Ok(intro) => intro,
            Err(error) => {
                tracing::warn!(error = %error, "auth introspection unavailable");
                return Err(auth_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "auth_unavailable",
                    "auth service is unavailable",
                ));
            }
        };

        let Some(identity) = identity_from_introspection(intro) else {
            self.cache_decision(cache_key, None, self.config.negative_cache_ttl)
                .await;
            return Err(auth_response(
                StatusCode::UNAUTHORIZED,
                "invalid_api_key",
                "invalid api key",
            ));
        };

        self.cache_decision(cache_key, Some(identity.clone()), self.config.cache_ttl)
            .await;
        Ok(identity)
    }

    async fn authenticate_jwt(&self, jwt: &str) -> Result<VerifiedIdentity, Response> {
        let cache_key = credential_cache_key("invalid_jwt", jwt);
        if matches!(self.cached_decision(&cache_key).await, Some(None)) {
            return Err(auth_response(
                StatusCode::UNAUTHORIZED,
                "invalid_jwt",
                "invalid or expired jwt",
            ));
        }

        let (identity, claims) = match self.verify_jwt(jwt).await {
            Ok(verified) => verified,
            Err(error) => {
                tracing::debug!(error = %error, "jwt rejected before revocation lookup");
                self.cache_decision(cache_key, None, self.config.negative_cache_ttl)
                    .await;
                return Err(auth_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_jwt",
                    "invalid or expired jwt",
                ));
            }
        };

        // Deliberately do not cache a positive JWT identity here. The previous
        // cache returned an identity for up to 60 seconds before consulting any
        // revocation state. Offline verification happens first on every request;
        // only the revocation gate's bounded, tenant-scoped fresh decision cache
        // may accelerate the authorization path.
        match self.revocations.authorize(&claims, unix_secs()).await {
            Authorization::Allowed => Ok(identity),
            Authorization::Revoked => Err(auth_response(
                StatusCode::UNAUTHORIZED,
                "revoked_jwt",
                "jwt has been revoked",
            )),
            Authorization::Unavailable(reason) => {
                let reason = match reason {
                    Unavailable::ClockRegression => "clock_regression",
                    Unavailable::RefreshFailed => "refresh_failed",
                    Unavailable::RefreshTimedOut => "refresh_timed_out",
                };
                tracing::warn!(reason, "jwt revocation state unavailable; denying request");
                Err(auth_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "revocation_unavailable",
                    "jwt revocation state is unavailable",
                ))
            }
        }
    }

    async fn fetch_introspection(&self, api_key: &str) -> Result<Introspection, AuthError> {
        #[derive(Serialize)]
        struct Body<'a> {
            api_key: &'a str,
        }

        let mut request = self
            .client
            .post(&self.config.introspect_url)
            .json(&Body { api_key });
        if let Some(secret) = self.config.introspect_secret.as_deref() {
            request = request.header("x-server-auth", secret);
        }
        let response = request
            .send()
            .await
            .map_err(AuthError::Http)?
            .error_for_status()
            .map_err(AuthError::Http)?;
        let body = response.bytes().await.map_err(AuthError::Http)?;
        if body.len() > MAX_INTROSPECTION_RESPONSE_BYTES {
            return Err(AuthError::OversizedResponse("introspection"));
        }
        serde_json::from_slice(&body).map_err(|_| AuthError::InvalidResponse("introspection"))
    }

    async fn verify_jwt(&self, jwt: &str) -> Result<(VerifiedIdentity, Claims), AuthError> {
        let header = decode_header(jwt).map_err(AuthError::Jwt)?;
        if !is_asymmetric_algorithm(header.alg) {
            return Err(AuthError::UnsupportedAlgorithm(header.alg));
        }
        let kid = header.kid.ok_or(AuthError::MissingKid)?;
        let jwk = self.jwk_for_kid(&kid).await?;
        reject_symmetric_jwk(&jwk)?;

        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(AuthError::Jwt)?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.config.jwt_issuer.as_str()]);
        validation.set_audience(&[self.config.jwt_audience.as_str()]);
        for claim in ["exp", "iss", "aud", "sub", "org_id", "iat", "jti"] {
            validation.required_spec_claims.insert(claim.to_string());
        }

        let token = decode::<Claims>(jwt, &decoding_key, &validation).map_err(AuthError::Jwt)?;
        validate_claim_contract(
            &token.claims,
            &self.config.jwt_issuer,
            &self.config.jwt_audience,
            unix_secs(),
        )?;
        let identity = identity_from_claims(&token.claims)?;
        Ok((identity, token.claims))
    }

    async fn jwk_for_kid(&self, kid: &str) -> Result<Jwk, AuthError> {
        let jwks = self.cached_jwks().await?;
        if let Some(jwk) = jwks.find(kid).cloned() {
            return Ok(jwk);
        }
        let jwks = self.refresh_jwks().await?;
        jwks.find(kid)
            .cloned()
            .ok_or_else(|| AuthError::MissingJwk(kid.to_string()))
    }

    async fn cached_jwks(&self) -> Result<JwkSet, AuthError> {
        {
            let guard = self.jwks.read().await;
            if let Some(cached) = guard.as_ref() {
                if cached.fetched_at.elapsed() < self.config.jwks_ttl {
                    return Ok(cached.jwks.clone());
                }
            }
        }
        self.refresh_jwks().await
    }

    async fn refresh_jwks(&self) -> Result<JwkSet, AuthError> {
        let response = self
            .client
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(AuthError::Http)?
            .error_for_status()
            .map_err(AuthError::Http)?;
        let body = response.bytes().await.map_err(AuthError::Http)?;
        if body.len() > MAX_JWKS_RESPONSE_BYTES {
            return Err(AuthError::OversizedResponse("jwks"));
        }
        let jwks: JwkSet =
            serde_json::from_slice(&body).map_err(|_| AuthError::InvalidResponse("jwks"))?;
        if jwks.keys.is_empty() {
            return Err(AuthError::EmptyJwks);
        }
        *self.jwks.write().await = Some(CachedJwks {
            fetched_at: Instant::now(),
            jwks: jwks.clone(),
        });
        Ok(jwks)
    }

    async fn cached_decision(&self, key: &str) -> Option<Option<VerifiedIdentity>> {
        let guard = self.decisions.read().await;
        let cached = guard.get(key)?;
        (cached.expires_at > Instant::now()).then(|| cached.identity.clone())
    }

    async fn cache_decision(&self, key: String, identity: Option<VerifiedIdentity>, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut decisions = self.decisions.write().await;
        prune_decisions(&mut decisions, now, MAX_CACHED_DECISIONS);
        decisions.insert(
            key,
            CachedDecision {
                expires_at: now + ttl,
                identity,
            },
        );
    }
}

fn prune_decisions(decisions: &mut HashMap<String, CachedDecision>, now: Instant, capacity: usize) {
    if decisions.len() < capacity {
        return;
    }
    decisions.retain(|_, cached| cached.expires_at > now);
    if decisions.len() < capacity {
        return;
    }
    if let Some(key) = decisions
        .iter()
        .min_by_key(|(_, cached)| cached.expires_at)
        .map(|(key, _)| key.clone())
    {
        decisions.remove(&key);
    }
}

impl VerifiedIdentity {
    pub fn kind_header(&self) -> &'static str {
        match self.kind {
            AuthKind::ApiKey => "api_key",
            AuthKind::Jwt => "jwt",
        }
    }

    pub fn scopes_header(&self) -> String {
        self.scopes.join(" ")
    }
}

pub fn should_strip_client_auth_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "x-api-key"
            | "cookie"
            | "x-fiducia-auth-kind"
            | "x-fiducia-org-id"
            | "x-fiducia-key-id"
            | "x-fiducia-scopes"
            | EDGE_AUTH_HEADER
            | "x-fiducia-internal-auth"
    )
}

pub const EDGE_AUTH_HEADER: &str = "x-fiducia-edge-auth";

pub fn trusted_edge_identity(
    headers: &HeaderMap,
    expected_secret: Option<&str>,
) -> Option<VerifiedIdentity> {
    let expected = expected_secret?;
    let provided = header_str(headers, EDGE_AUTH_HEADER)?;
    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return None;
    }

    let org_id = header_str(headers, "x-fiducia-org-id")?.trim().to_string();
    if !valid_identifier(&org_id) {
        return None;
    }
    let kind = match header_str(headers, "x-fiducia-auth-kind") {
        None | Some("api_key") => AuthKind::ApiKey,
        Some("jwt") => AuthKind::Jwt,
        Some(_) => return None,
    };
    let scopes = header_str(headers, "x-fiducia-scopes")
        .map(|value| value.split_whitespace().map(ToOwned::to_owned).collect())
        .unwrap_or_default();
    if !valid_scopes(&scopes) {
        return None;
    }
    let key_id = header_str(headers, "x-fiducia-key-id")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if key_id
        .as_deref()
        .is_some_and(|value| !valid_identifier(value))
    {
        return None;
    }

    Some(VerifiedIdentity {
        kind,
        org_id,
        key_id,
        scopes,
        require_idempotency: false,
    })
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[derive(Debug, Clone)]
struct AuthConfig {
    required: bool,
    allow_api_keys: bool,
    allow_jwts: bool,
    introspect_url: String,
    introspect_secret: Option<String>,
    jwks_url: String,
    jwt_issuer: String,
    jwt_audience: String,
    cache_ttl: Duration,
    negative_cache_ttl: Duration,
    jwks_ttl: Duration,
    http_timeout: Duration,
    revocation_check_url: String,
    revocation_reader_secret: Option<String>,
    revocation_freshness_secs: u64,
    revocation_capacity: usize,
    revocation_refresh_timeout: Duration,
}

fn auth_required_decision(explicit: Option<bool>, is_debug_build: bool) -> bool {
    explicit.unwrap_or(!is_debug_build)
}

impl AuthConfig {
    fn from_env() -> Self {
        let auth_url = normalize_url(
            &env_value("FIDUCIA_AUTH_URL").unwrap_or_else(|| DEFAULT_AUTH_URL.to_string()),
        );
        let explicit_required = env_bool_opt("FIDUCIA_AUTH_REQUIRED");
        let required = auth_required_decision(explicit_required, cfg!(debug_assertions));
        if !required {
            tracing::warn!(
                "load balancer accepts unauthenticated requests; set FIDUCIA_AUTH_REQUIRED=true before exposure"
            );
        }
        let revocation_reader_secret = env_value("FIDUCIA_REVOCATION_READER_SECRET")
            .filter(|secret| valid_reader_secret(secret));

        Self {
            required,
            allow_api_keys: env_bool("FIDUCIA_AUTH_ALLOW_API_KEYS", true),
            allow_jwts: env_bool("FIDUCIA_AUTH_ALLOW_JWTS", true),
            introspect_url: env_value("FIDUCIA_AUTH_INTROSPECT_URL")
                .unwrap_or_else(|| format!("{auth_url}/v1/introspect")),
            introspect_secret: env_value("FIDUCIA_INTROSPECT_SECRET"),
            jwks_url: env_value("FIDUCIA_AUTH_JWKS_URL")
                .unwrap_or_else(|| format!("{auth_url}/.well-known/jwks.json")),
            jwt_issuer: env_value("FIDUCIA_JWT_ISSUER")
                .unwrap_or_else(|| DEFAULT_JWT_ISSUER.to_string()),
            jwt_audience: env_value("FIDUCIA_JWT_AUDIENCE")
                .unwrap_or_else(|| DEFAULT_JWT_AUDIENCE.to_string()),
            cache_ttl: duration_env("FIDUCIA_AUTH_CACHE_TTL_SECS", DEFAULT_CACHE_TTL_SECS),
            negative_cache_ttl: duration_env(
                "FIDUCIA_AUTH_NEGATIVE_CACHE_TTL_SECS",
                DEFAULT_NEGATIVE_CACHE_TTL_SECS,
            ),
            jwks_ttl: duration_env("FIDUCIA_AUTH_JWKS_TTL_SECS", DEFAULT_JWKS_TTL_SECS),
            http_timeout: duration_env("FIDUCIA_AUTH_HTTP_TIMEOUT_SECS", DEFAULT_HTTP_TIMEOUT_SECS),
            revocation_check_url: env_value("FIDUCIA_REVOCATION_CHECK_URL")
                .unwrap_or_else(|| DEFAULT_REVOCATION_CHECK_URL.to_string()),
            revocation_reader_secret,
            revocation_freshness_secs: u64_env(
                "FIDUCIA_REVOCATION_CACHE_FRESHNESS_SECS",
                DEFAULT_REVOCATION_FRESHNESS_SECS,
            )
            .max(1),
            revocation_capacity: usize_env(
                "FIDUCIA_REVOCATION_CACHE_CAPACITY",
                DEFAULT_REVOCATION_CAPACITY,
            )
            .max(1),
            revocation_refresh_timeout: Duration::from_millis(
                u64_env(
                    "FIDUCIA_REVOCATION_TIMEOUT_MILLIS",
                    DEFAULT_REVOCATION_TIMEOUT_MILLIS,
                )
                .max(1),
            ),
        }
    }
}

#[derive(Clone)]
struct CachedDecision {
    expires_at: Instant,
    identity: Option<VerifiedIdentity>,
}

#[derive(Clone)]
struct CachedJwks {
    fetched_at: Instant,
    jwks: JwkSet,
}

#[derive(Debug)]
enum AuthError {
    EmptyJwks,
    Http(reqwest::Error),
    InvalidClaims(&'static str),
    InvalidResponse(&'static str),
    Jwt(jsonwebtoken::errors::Error),
    MissingJwk(String),
    MissingKid,
    OversizedResponse(&'static str),
    SymmetricJwk,
    UnsupportedAlgorithm(Algorithm),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyJwks => write!(formatter, "auth jwks endpoint returned no keys"),
            Self::Http(error) => write!(formatter, "auth http error: {error}"),
            Self::InvalidClaims(reason) => write!(formatter, "invalid jwt claims: {reason}"),
            Self::InvalidResponse(kind) => write!(formatter, "invalid {kind} response"),
            Self::Jwt(error) => write!(formatter, "jwt error: {error}"),
            Self::MissingJwk(kid) => write!(formatter, "jwks key not found for kid {kid}"),
            Self::MissingKid => write!(formatter, "jwt is missing kid"),
            Self::OversizedResponse(kind) => write!(formatter, "oversized {kind} response"),
            Self::SymmetricJwk => write!(formatter, "refusing symmetric jwk"),
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(formatter, "unsupported jwt signing algorithm {algorithm:?}")
            }
        }
    }
}

impl std::error::Error for AuthError {}

fn extract_credential(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
        .or_else(|| {
            headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn bearer_token(value: &str) -> Option<String> {
    let mut parts = value.trim().splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_string())
}

fn is_api_key(value: &str) -> bool {
    value.starts_with("fdc_") && value.contains('.')
}

fn looks_like_jwt(value: &str) -> bool {
    value.split('.').count() == 3
}

fn identity_from_introspection(introspection: Introspection) -> Option<VerifiedIdentity> {
    let org_id = introspection.org_id?;
    if !introspection.valid || !valid_identifier(&org_id) || !valid_scopes(&introspection.scopes) {
        return None;
    }
    Some(VerifiedIdentity {
        kind: AuthKind::ApiKey,
        org_id,
        key_id: introspection.key_id.filter(|value| valid_identifier(value)),
        scopes: introspection.scopes,
        require_idempotency: introspection.require_idempotency.unwrap_or(false),
    })
}

fn identity_from_claims(claims: &Claims) -> Result<VerifiedIdentity, AuthError> {
    Ok(VerifiedIdentity {
        kind: AuthKind::Jwt,
        org_id: claims.org_id.clone(),
        key_id: None,
        scopes: claims.scopes.clone(),
        require_idempotency: false,
    })
}

fn validate_claim_contract(
    claims: &Claims,
    expected_issuer: &str,
    expected_audience: &str,
    now: u64,
) -> Result<(), AuthError> {
    if claims.iss != expected_issuer || claims.aud != expected_audience {
        return Err(AuthError::InvalidClaims("issuer or audience"));
    }
    if !valid_identifier(&claims.sub)
        || !valid_identifier(&claims.org_id)
        || !valid_identifier(&claims.jti)
    {
        return Err(AuthError::InvalidClaims("identity"));
    }
    if claims.sub != claims.org_id {
        return Err(AuthError::InvalidClaims("subject/tenant mismatch"));
    }
    if claims.exp <= claims.iat || claims.exp - claims.iat > MAX_ACCESS_TOKEN_TTL_SECS {
        return Err(AuthError::InvalidClaims("lifetime"));
    }
    if claims.iat > now.saturating_add(JWT_CLOCK_SKEW_SECS) {
        return Err(AuthError::InvalidClaims("issued in the future"));
    }
    if !valid_scopes(&claims.scopes) {
        return Err(AuthError::InvalidClaims("scopes"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 256
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn valid_scopes(scopes: &[String]) -> bool {
    scopes.len() <= 64
        && scopes.iter().all(|scope| {
            !scope.is_empty()
                && scope.len() <= 128
                && !scope
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        })
}

fn reject_symmetric_jwk(jwk: &Jwk) -> Result<(), AuthError> {
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        return Err(AuthError::SymmetricJwk);
    }
    Ok(())
}

fn is_asymmetric_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::EdDSA
    )
}

fn auth_response(status: StatusCode, error: &str, detail: &str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({ "error": error, "detail": detail })),
    )
        .into_response()
}

fn credential_cache_key(kind: &str, credential: &str) -> String {
    let digest = Sha256::digest(credential.as_bytes());
    format!("{kind}:{}", to_hex(&digest))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_bool(name: &str, default: bool) -> bool {
    env_bool_opt(name).unwrap_or(default)
}

fn env_bool_opt(name: &str) -> Option<bool> {
    match env_value(name).as_deref() {
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON") => Some(true),
        Some("0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF") => Some(false),
        _ => None,
    }
}

fn duration_env(name: &str, default_secs: u64) -> Duration {
    Duration::from_secs(u64_env(name, default_secs))
}

fn u64_env(name: &str, default: u64) -> u64 {
    env_value(name)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn usize_env(name: &str, default: usize) -> usize {
    env_value(name)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn valid_reader_secret(secret: &str) -> bool {
    secret.len() >= MIN_READER_SECRET_BYTES
        && !secret
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_required_defaults_secure_in_release_but_open_in_debug() {
        assert!(auth_required_decision(Some(true), true));
        assert!(auth_required_decision(Some(true), false));
        assert!(!auth_required_decision(Some(false), true));
        assert!(!auth_required_decision(Some(false), false));
        assert!(auth_required_decision(None, false));
        assert!(!auth_required_decision(None, true));
    }

    #[test]
    fn extracts_bearer_or_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "bearer   header.payload.signature".parse().unwrap(),
        );
        assert_eq!(
            extract_credential(&headers).as_deref(),
            Some("header.payload.signature")
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "fdc_live_id.secret".parse().unwrap());
        assert_eq!(
            extract_credential(&headers).as_deref(),
            Some("fdc_live_id.secret")
        );
    }

    #[test]
    fn cache_keys_never_retain_credentials() {
        let key = credential_cache_key("api_key", "fdc_live_id.super-secret");
        assert_eq!(key.len(), "api_key:".len() + 64);
        assert!(!key.contains("super-secret"));
    }

    #[test]
    fn complete_internal_claim_contract_is_required() {
        let claims = Claims {
            sub: "org-a".to_string(),
            org_id: "org-a".to_string(),
            scopes: vec!["kv:read".to_string()],
            iss: DEFAULT_JWT_ISSUER.to_string(),
            aud: DEFAULT_JWT_AUDIENCE.to_string(),
            iat: 100,
            exp: 200,
            jti: "token-a".to_string(),
        };
        assert!(
            validate_claim_contract(&claims, DEFAULT_JWT_ISSUER, DEFAULT_JWT_AUDIENCE, 100).is_ok()
        );
        let mut mismatch = claims.clone();
        mismatch.org_id = "org-b".to_string();
        assert!(
            validate_claim_contract(&mismatch, DEFAULT_JWT_ISSUER, DEFAULT_JWT_AUDIENCE, 100)
                .is_err()
        );
        let mut long_lived = claims;
        long_lived.exp = long_lived.iat + MAX_ACCESS_TOKEN_TTL_SECS + 1;
        assert!(validate_claim_contract(
            &long_lived,
            DEFAULT_JWT_ISSUER,
            DEFAULT_JWT_AUDIENCE,
            100
        )
        .is_err());
    }

    #[test]
    fn reader_secret_contract_is_fail_closed() {
        assert!(valid_reader_secret(&"x".repeat(MIN_READER_SECRET_BYTES)));
        assert!(!valid_reader_secret("short"));
        assert!(!valid_reader_secret(
            &("x".repeat(MIN_READER_SECRET_BYTES) + " ")
        ));
    }

    #[test]
    fn strips_all_client_supplied_identity_and_secret_headers() {
        for name in [
            "authorization",
            "x-api-key",
            "cookie",
            "x-fiducia-auth-kind",
            "x-fiducia-org-id",
            "x-fiducia-key-id",
            "x-fiducia-scopes",
            "x-fiducia-edge-auth",
            "x-fiducia-internal-auth",
        ] {
            assert!(should_strip_client_auth_header(name));
        }
    }

    #[test]
    fn trusted_edge_identity_requires_exact_secret_and_valid_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(EDGE_AUTH_HEADER, "edge-secret".parse().unwrap());
        headers.insert("x-fiducia-auth-kind", "jwt".parse().unwrap());
        headers.insert("x-fiducia-org-id", "org-a".parse().unwrap());
        headers.insert("x-fiducia-scopes", "kv:read kv:write".parse().unwrap());
        let identity = trusted_edge_identity(&headers, Some("edge-secret")).unwrap();
        assert_eq!(identity.kind, AuthKind::Jwt);
        assert_eq!(identity.org_id, "org-a");
        assert!(trusted_edge_identity(&headers, Some("wrong-secret")).is_none());
        headers.insert("x-fiducia-auth-kind", "unknown".parse().unwrap());
        assert!(trusted_edge_identity(&headers, Some("edge-secret")).is_none());
    }

    #[test]
    fn decision_cache_is_bounded_and_sweeps_expired_entries() {
        let now = Instant::now();
        let live = |offset| CachedDecision {
            expires_at: now + Duration::from_secs(offset),
            identity: None,
        };
        let expired = CachedDecision {
            expires_at: now - Duration::from_secs(1),
            identity: None,
        };
        let mut decisions = HashMap::from([
            ("expired".to_string(), expired),
            ("b".to_string(), live(60)),
            ("c".to_string(), live(60)),
        ]);
        prune_decisions(&mut decisions, now, 3);
        assert_eq!(decisions.len(), 2);
        let mut decisions =
            HashMap::from([("soon".to_string(), live(1)), ("b".to_string(), live(60))]);
        prune_decisions(&mut decisions, now, 2);
        assert!(!decisions.contains_key("soon"));
    }

    #[test]
    fn auth_failures_are_not_cacheable() {
        let response = auth_response(StatusCode::UNAUTHORIZED, "invalid_jwt", "invalid jwt");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    }
}
