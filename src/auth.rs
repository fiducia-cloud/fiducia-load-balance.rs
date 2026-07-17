//! Hot-path auth gate for the regional LB.
//!
//! Supabase belongs behind `fiducia-auth`, not here. The LB accepts customer API
//! keys, caches `fiducia-auth` introspection responses by token hash, and
//! verifies Fiducia-issued short-lived JWTs offline via JWKS.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fiducia_interfaces::Introspection;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

const DEFAULT_AUTH_URL: &str = "http://fiducia-auth.fiducia.svc.cluster.local:8097";
const DEFAULT_CACHE_TTL_SECS: u64 = 60;
const DEFAULT_NEGATIVE_CACHE_TTL_SECS: u64 = 5;
const DEFAULT_JWKS_TTL_SECS: u64 = 10 * 60;
const DEFAULT_JWT_CACHE_TTL_SECS: u64 = 60;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 2;
const DEFAULT_JWT_ISSUER: &str = "fiducia-auth";
const DEFAULT_JWT_AUDIENCE: &str = "fiducia-api";

#[derive(Clone)]
pub struct AuthState {
    config: Arc<AuthConfig>,
    client: reqwest::Client,
    decisions: Arc<RwLock<HashMap<String, CachedDecision>>>,
    jwks: Arc<RwLock<Option<CachedJwks>>>,
}

#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub kind: AuthKind,
    pub org_id: String,
    pub key_id: Option<String>,
    pub scopes: Vec<String>,
    /// When true, the LB rejects mutating calls from this identity that omit an
    /// `Idempotency-Key`. Carried from key introspection; false for JWTs and for
    /// keys minted before the field existed (the control is opt-in).
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

        AuthState {
            config: Arc::new(config),
            client,
            decisions: Arc::new(RwLock::new(HashMap::new())),
            jwks: Arc::new(RwLock::new(None)),
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
            Err(err) => {
                tracing::warn!(error = %err, "auth introspection unavailable");
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
        let cache_key = credential_cache_key("jwt", jwt);
        if let Some(cached) = self.cached_decision(&cache_key).await {
            return cached.ok_or_else(|| {
                auth_response(StatusCode::UNAUTHORIZED, "invalid_jwt", "invalid jwt")
            });
        }

        match self.verify_jwt(jwt).await {
            Ok((identity, ttl)) => {
                self.cache_decision(cache_key, Some(identity.clone()), ttl)
                    .await;
                Ok(identity)
            }
            Err(err) => {
                tracing::debug!(error = %err, "jwt rejected");
                self.cache_decision(cache_key, None, self.config.negative_cache_ttl)
                    .await;
                Err(auth_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid_jwt",
                    "invalid or expired jwt",
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
        let response = request.send().await.map_err(AuthError::Http)?;

        if !response.status().is_success() {
            return Err(AuthError::AuthStatus(response.status()));
        }

        response
            .json::<Introspection>()
            .await
            .map_err(AuthError::Http)
    }

    async fn verify_jwt(&self, jwt: &str) -> Result<(VerifiedIdentity, Duration), AuthError> {
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
        validation.required_spec_claims.insert("exp".to_string());
        validation.required_spec_claims.insert("iss".to_string());
        validation.required_spec_claims.insert("sub".to_string());

        let token =
            decode::<FiduciaClaims>(jwt, &decoding_key, &validation).map_err(AuthError::Jwt)?;
        let identity = identity_from_claims(token.claims.clone())?;
        let ttl = jwt_cache_ttl(token.claims.exp, self.config.jwt_cache_ttl)?;
        Ok((identity, ttl))
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
        let jwks = self
            .client
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(AuthError::Http)?
            .error_for_status()
            .map_err(AuthError::Http)?
            .json::<JwkSet>()
            .await
            .map_err(AuthError::Http)?;

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
        self.decisions.write().await.insert(
            key,
            CachedDecision {
                expires_at: Instant::now() + ttl,
                identity,
            },
        );
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
            // The edge→LB trusted-hop proof. The LB consumes it inbound (to decide
            // whether to trust the forwarded `x-fiducia-*` identity) and must never
            // forward it to the node, nor let a direct client inject it.
            | EDGE_AUTH_HEADER
            // The trusted-hop secret to the node: only the LB may set it, never a
            // client. The LB re-attaches its own in `proxy::forward_once`.
            | "x-fiducia-internal-auth"
    )
}

/// Header the edge presents to prove an inbound request is a trusted edge hop.
/// Its value is the shared cluster secret (`FIDUCIA_INTERNAL_SECRET`); a direct
/// client cannot forge it, and `should_strip_client_auth_header` guarantees the
/// LB never forwards a client-supplied copy of it downstream.
pub const EDGE_AUTH_HEADER: &str = "x-fiducia-edge-auth";

/// Identity forwarded by a trusted edge hop.
///
/// The edge authenticates the caller, strips the raw client credential, and
/// forwards the verified identity in `x-fiducia-*` headers plus the shared secret
/// in [`EDGE_AUTH_HEADER`]. The LB trusts that identity **only** when the secret
/// is present and constant-time-equal to `expected_secret`. Without a valid
/// secret this returns `None`, so the request is treated as anonymous (and the
/// spoofable `x-fiducia-*` headers are stripped before forwarding), closing the
/// bypass where an edge-forwarded request would otherwise arrive with no identity
/// and skip the LB's per-route scope checks.
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
    if org_id.is_empty() {
        return None;
    }
    let kind = match header_str(headers, "x-fiducia-auth-kind") {
        Some("jwt") => AuthKind::Jwt,
        _ => AuthKind::ApiKey,
    };
    let scopes = header_str(headers, "x-fiducia-scopes")
        .map(|value| value.split_whitespace().map(ToOwned::to_owned).collect())
        .unwrap_or_default();
    let key_id = header_str(headers, "x-fiducia-key-id")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    Some(VerifiedIdentity {
        kind,
        org_id,
        key_id,
        scopes,
        // The per-key idempotency policy is not carried across the edge hop; it is
        // enforced when the LB authenticates a raw credential directly.
        require_idempotency: false,
    })
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Length-then-content compare that doesn't short-circuit on the first differing
/// byte, so the shared secret can't be recovered a byte at a time via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    jwt_cache_ttl: Duration,
    http_timeout: Duration,
}

/// Decide whether the LB requires authentication, given an explicit
/// `FIDUCIA_AUTH_REQUIRED` (if any) and whether this is a debug build.
///
/// Secure-by-default: an unset value means **required** in release binaries (the
/// posture any real deployment ships), while debug builds stay open so local/dev
/// keeps working without wiring up `fiducia-auth`. An explicit value always wins
/// in both directions — the documented escape hatch is `FIDUCIA_AUTH_REQUIRED=false`
/// (loosen prod) or `=true` (harden a debug run). Kept pure for unit testing.
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
        // Make the posture impossible to miss in logs at startup. `from_env` runs
        // once, right after telemetry init, so this is effectively a boot banner.
        if !required {
            tracing::warn!(
                "FIDUCIA_AUTH_REQUIRED is {} — the load balancer accepts UNAUTHENTICATED \
                 requests; scoped routes still fail closed, but set FIDUCIA_AUTH_REQUIRED=true \
                 before exposing this to untrusted traffic",
                match explicit_required {
                    Some(false) => "explicitly false",
                    _ => "unset (defaulting off in this debug build)",
                }
            );
        } else if explicit_required.is_none() {
            tracing::info!(
                "FIDUCIA_AUTH_REQUIRED is unset — defaulting to REQUIRED (secure) in this release build"
            );
        }
        AuthConfig {
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
            jwt_cache_ttl: duration_env(
                "FIDUCIA_AUTH_JWT_CACHE_TTL_SECS",
                DEFAULT_JWT_CACHE_TTL_SECS,
            ),
            http_timeout: duration_env("FIDUCIA_AUTH_HTTP_TIMEOUT_SECS", DEFAULT_HTTP_TIMEOUT_SECS),
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

#[derive(Debug, Clone, Deserialize)]
struct FiduciaClaims {
    sub: String,
    exp: u64,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug)]
enum AuthError {
    AuthStatus(reqwest::StatusCode),
    EmptyJwks,
    ExpiredJwt,
    Http(reqwest::Error),
    InvalidClaims(&'static str),
    Jwt(jsonwebtoken::errors::Error),
    MissingJwk(String),
    MissingKid,
    SymmetricJwk,
    UnsupportedAlgorithm(Algorithm),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::AuthStatus(status) => write!(f, "auth service returned {status}"),
            AuthError::EmptyJwks => write!(f, "auth jwks endpoint returned no keys"),
            AuthError::ExpiredJwt => write!(f, "jwt is expired"),
            AuthError::Http(err) => write!(f, "auth http error: {err}"),
            AuthError::InvalidClaims(reason) => write!(f, "invalid jwt claims: {reason}"),
            AuthError::Jwt(err) => write!(f, "jwt error: {err}"),
            AuthError::MissingJwk(kid) => write!(f, "jwks key not found for kid {kid}"),
            AuthError::MissingKid => write!(f, "jwt is missing kid"),
            AuthError::SymmetricJwk => write!(f, "refusing symmetric jwk"),
            AuthError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported jwt signing algorithm {alg:?}")
            }
        }
    }
}

impl std::error::Error for AuthError {}

fn extract_credential(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token)
        .or_else(|| {
            headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
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

fn identity_from_introspection(intro: Introspection) -> Option<VerifiedIdentity> {
    let org_id = intro.org_id?;
    intro.valid.then_some(VerifiedIdentity {
        kind: AuthKind::ApiKey,
        org_id,
        key_id: intro.key_id,
        scopes: intro.scopes,
        require_idempotency: intro.require_idempotency.unwrap_or(false),
    })
}

fn identity_from_claims(claims: FiduciaClaims) -> Result<VerifiedIdentity, AuthError> {
    let org_id = claims.org_id.unwrap_or(claims.sub);
    if org_id.trim().is_empty() {
        return Err(AuthError::InvalidClaims("missing org"));
    }
    Ok(VerifiedIdentity {
        kind: AuthKind::Jwt,
        org_id,
        key_id: claims.key_id,
        scopes: claims.scopes,
        // JWT claims don't carry the per-key idempotency requirement; the control
        // is an API-key policy, so JWT-authed callers are never gated on it.
        require_idempotency: false,
    })
}

fn jwt_cache_ttl(exp: u64, max_ttl: Duration) -> Result<Duration, AuthError> {
    let now = unix_secs();
    if exp <= now {
        return Err(AuthError::ExpiredJwt);
    }
    Ok(Duration::from_secs(exp - now).min(max_ttl))
}

fn reject_symmetric_jwk(jwk: &Jwk) -> Result<(), AuthError> {
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        return Err(AuthError::SymmetricJwk);
    }
    Ok(())
}

fn is_asymmetric_algorithm(alg: Algorithm) -> bool {
    matches!(
        alg,
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
    (status, Json(json!({ "error": error, "detail": detail }))).into_response()
}

fn credential_cache_key(kind: &str, credential: &str) -> String {
    let digest = Sha256::digest(credential.as_bytes());
    format!("{kind}:{}", to_hex(&digest))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
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

/// Parse a boolean env var, returning `None` when it is unset/blank or
/// unrecognized, so callers can distinguish "operator chose a value" from
/// "operator said nothing" (needed for secure-by-default resolution).
fn env_bool_opt(name: &str) -> Option<bool> {
    match env_value(name).as_deref() {
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON") => Some(true),
        Some("0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF") => Some(false),
        _ => None,
    }
}

fn duration_env(name: &str, default_secs: u64) -> Duration {
    Duration::from_secs(
        env_value(name)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default_secs),
    )
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
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
    fn extracts_bearer_or_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer fdc_live_id.secret".parse().unwrap(),
        );
        assert_eq!(
            extract_credential(&headers).as_deref(),
            Some("fdc_live_id.secret")
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "fdc_live_other.secret".parse().unwrap());
        assert_eq!(
            extract_credential(&headers).as_deref(),
            Some("fdc_live_other.secret")
        );
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_and_trims_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "bearer   header.payload.signature  ".parse().unwrap(),
        );
        assert_eq!(
            extract_credential(&headers).as_deref(),
            Some("header.payload.signature")
        );
    }

    #[test]
    fn extract_credential_ignores_empty_bearer_and_blank_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer    ".parse().unwrap());
        headers.insert("x-api-key", "   ".parse().unwrap());

        assert_eq!(extract_credential(&headers), None);
    }

    #[test]
    fn classifies_api_keys_and_jwts() {
        assert!(is_api_key("fdc_live_abc.def"));
        assert!(!is_api_key("not-a-key"));
        assert!(looks_like_jwt("header.payload.signature"));
        assert!(!looks_like_jwt("fdc_live_abc.def"));
    }

    #[test]
    fn credential_cache_key_hashes_the_secret() {
        let key = credential_cache_key("api_key", "fdc_live_id.super-secret");
        assert!(key.starts_with("api_key:"));
        assert!(!key.contains("super-secret"));
        assert_eq!(key.len(), "api_key:".len() + 64);
    }

    #[test]
    fn strips_client_supplied_identity_and_secret_headers() {
        for name in [
            "authorization",
            "x-api-key",
            "cookie",
            "x-fiducia-auth-kind",
            "x-fiducia-org-id",
            "x-fiducia-key-id",
            "x-fiducia-scopes",
            "x-fiducia-edge-auth",
            "X-Fiducia-Edge-Auth",
            "x-fiducia-internal-auth",
            "X-Fiducia-Internal-Auth",
        ] {
            assert!(should_strip_client_auth_header(name));
        }
        assert!(!should_strip_client_auth_header("x-fiducia-edge-region"));
    }

    #[test]
    fn trusted_edge_identity_requires_the_shared_secret() {
        let mut headers = HeaderMap::new();
        headers.insert(EDGE_AUTH_HEADER, "edge-secret".parse().unwrap());
        headers.insert("x-fiducia-auth-kind", "api_key".parse().unwrap());
        headers.insert("x-fiducia-org-id", "org_9".parse().unwrap());
        headers.insert("x-fiducia-scopes", "kv:read kv:write".parse().unwrap());
        headers.insert("x-fiducia-key-id", "key_9".parse().unwrap());

        // Valid secret → the forwarded identity is trusted.
        let identity = trusted_edge_identity(&headers, Some("edge-secret")).unwrap();
        assert_eq!(identity.kind, AuthKind::ApiKey);
        assert_eq!(identity.org_id, "org_9");
        assert_eq!(identity.key_id.as_deref(), Some("key_9"));
        assert_eq!(identity.scopes, vec!["kv:read", "kv:write"]);

        // Wrong secret, absent secret, or no secret configured → not trusted.
        assert!(trusted_edge_identity(&headers, Some("wrong-secret")).is_none());
        assert!(trusted_edge_identity(&headers, None).is_none());
    }

    #[test]
    fn trusted_edge_identity_rejects_spoofed_headers_without_the_secret() {
        // A direct client injects identity headers but cannot supply the secret.
        let mut headers = HeaderMap::new();
        headers.insert("x-fiducia-org-id", "org_evil".parse().unwrap());
        headers.insert("x-fiducia-scopes", "admin:write".parse().unwrap());
        assert!(trusted_edge_identity(&headers, Some("edge-secret")).is_none());
    }

    #[test]
    fn introspection_becomes_verified_api_key_identity() {
        let intro = Introspection {
            valid: true,
            org_id: Some("org_1".to_string()),
            key_id: Some("key_1".to_string()),
            scopes: vec!["kv:read".to_string()],
            require_idempotency: Some(true),
        };
        let identity = identity_from_introspection(intro).unwrap();
        assert_eq!(identity.kind, AuthKind::ApiKey);
        assert_eq!(identity.org_id, "org_1");
        assert_eq!(identity.key_id.as_deref(), Some("key_1"));
        assert_eq!(identity.scopes_header(), "kv:read");
        assert!(identity.require_idempotency);
    }
}
