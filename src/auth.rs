//! Edge authentication + caching at the LB.
//!
//! Two credential types, both kept off the auth-server hot path:
//!   * **fiducia JWT** (`Authorization: Bearer <jwt>`) — verified **offline**
//!     against the JWKS fiducia-auth publishes (fetched + cached ~10 min). No call
//!     to auth at all.
//!   * **API key** (`Authorization: Bearer fdc_<env>_<id>.<secret>`) — validated
//!     via auth `POST /v1/introspect`, with the result **cached** (short TTL), so
//!     steady state makes no auth call either.
//!
//! On success we inject trusted `x-fiducia-org` / `x-fiducia-scopes` headers for
//! the nodes and **strip any client-supplied ones** (anti-spoofing). Enforcement
//! is gated by `FIDUCIA_AUTH_MODE=enforce` (default: tag-if-present,
//! allow-if-absent) so it can roll out without breaking existing clients.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::json;

const JWKS_TTL: Duration = Duration::from_secs(600);
const INTROSPECT_TTL: Duration = Duration::from_secs(30);
const ISSUER: &str = "fiducia-auth";

#[derive(Clone, Debug)]
pub struct Identity {
    pub org: String,
    pub scopes: Vec<String>,
    pub via: &'static str, // "jwt" | "api_key"
}

#[derive(Deserialize)]
struct Claims {
    org_id: String,
    #[serde(default)]
    scopes: Vec<String>,
}

struct JwksCache {
    set: Option<JwkSet>,
    fetched: Instant,
}

pub struct Authenticator {
    auth_base: Option<String>,
    introspect_secret: Option<String>,
    enforce: bool,
    http: reqwest::Client,
    jwks: RwLock<JwksCache>,
    intro: RwLock<HashMap<String, (Identity, Instant)>>,
}

enum Outcome {
    Authenticated(Identity),
    Anonymous,
    Invalid(&'static str),
}

impl Authenticator {
    pub fn from_env() -> Self {
        let auth_base = std::env::var("FIDUCIA_AUTH_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .map(|u| u.trim_end_matches('/').to_string());
        let enforce = std::env::var("FIDUCIA_AUTH_MODE")
            .map(|m| m.eq_ignore_ascii_case("enforce"))
            .unwrap_or(false);
        if enforce {
            tracing::info!("auth ENFORCED on the data plane");
        } else {
            tracing::info!("auth permissive (tag-if-present); set FIDUCIA_AUTH_MODE=enforce to require");
        }
        Authenticator {
            auth_base,
            introspect_secret: std::env::var("FIDUCIA_INTROSPECT_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
            enforce,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap_or_default(),
            jwks: RwLock::new(JwksCache {
                set: None,
                fetched: Instant::now()
                    .checked_sub(JWKS_TTL * 2)
                    .unwrap_or_else(Instant::now),
            }),
            intro: RwLock::new(HashMap::new()),
        }
    }

    /// Strip spoofed identity headers, authenticate, and (on success) tag the
    /// request with trusted identity. Returns the headers to forward, or a 401.
    pub async fn authorize(&self, uri: &Uri, mut headers: HeaderMap) -> Result<HeaderMap, Response> {
        // Only the LB may set these — never trust an inbound copy.
        headers.remove("x-fiducia-org");
        headers.remove("x-fiducia-scopes");
        headers.remove("x-fiducia-via");

        if is_exempt(uri.path()) {
            return Ok(headers);
        }

        match self.identify(&headers).await {
            Outcome::Authenticated(id) => {
                if let Ok(v) = HeaderValue::from_str(&id.org) {
                    headers.insert("x-fiducia-org", v);
                }
                if let Ok(v) = HeaderValue::from_str(&id.scopes.join(" ")) {
                    headers.insert("x-fiducia-scopes", v);
                }
                headers.insert("x-fiducia-via", HeaderValue::from_static(id.via));
                Ok(headers)
            }
            Outcome::Invalid(why) => Err(unauthorized(why)),
            Outcome::Anonymous if self.enforce => Err(unauthorized("authentication required")),
            Outcome::Anonymous => Ok(headers), // permissive: allow, no identity
        }
    }

    async fn identify(&self, headers: &HeaderMap) -> Outcome {
        let Some(token) = bearer(headers) else {
            return Outcome::Anonymous;
        };
        if token.starts_with("fdc_") {
            match self.introspect_key(token).await {
                Some(id) => Outcome::Authenticated(id),
                None => Outcome::Invalid("invalid api key"),
            }
        } else {
            match self.verify_jwt(token).await {
                Some(id) => Outcome::Authenticated(id),
                None => Outcome::Invalid("invalid or expired token"),
            }
        }
    }

    async fn verify_jwt(&self, token: &str) -> Option<Identity> {
        let kid = decode_header(token).ok()?.kid?;
        let jwk = self.jwk_for_kid(&kid).await?;
        let dk = DecodingKey::from_jwk(&jwk).ok()?;
        let mut v = Validation::new(Algorithm::ES256);
        v.set_issuer(&[ISSUER]);
        let data = decode::<Claims>(token, &dk, &v).ok()?;
        Some(Identity {
            org: data.claims.org_id,
            scopes: data.claims.scopes,
            via: "jwt",
        })
    }

    async fn jwk_for_kid(&self, kid: &str) -> Option<Jwk> {
        {
            let c = self.jwks.read().unwrap();
            if c.fetched.elapsed() < JWKS_TTL {
                if let Some(j) = c.set.as_ref().and_then(|s| s.find(kid)) {
                    return Some(j.clone());
                }
            }
        }
        self.refresh_jwks().await;
        let c = self.jwks.read().unwrap();
        c.set.as_ref().and_then(|s| s.find(kid)).cloned()
    }

    async fn refresh_jwks(&self) {
        let Some(base) = &self.auth_base else {
            return;
        };
        let url = format!("{base}/.well-known/jwks.json");
        if let Ok(resp) = self.http.get(&url).send().await {
            if let Ok(set) = resp.json::<JwkSet>().await {
                let mut c = self.jwks.write().unwrap();
                c.set = Some(set);
                c.fetched = Instant::now();
            }
        }
    }

    async fn introspect_key(&self, key: &str) -> Option<Identity> {
        {
            let c = self.intro.read().unwrap();
            if let Some((id, exp)) = c.get(key) {
                if *exp > Instant::now() {
                    return Some(id.clone());
                }
            }
        }
        let base = self.auth_base.as_ref()?;
        let mut req = self
            .http
            .post(format!("{base}/v1/introspect"))
            .json(&json!({ "api_key": key }));
        if let Some(s) = &self.introspect_secret {
            req = req.header("x-internal-secret", s);
        }
        let intro: fiducia_interfaces::Introspection = req.send().await.ok()?.json().await.ok()?;
        if !intro.valid {
            return None;
        }
        let id = Identity {
            org: intro.org_id.unwrap_or_default(),
            scopes: intro.scopes,
            via: "api_key",
        };
        self.intro
            .write()
            .unwrap()
            .insert(key.to_string(), (id.clone(), Instant::now() + INTROSPECT_TTL));
        Some(id)
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Health / status / operator reads bypass auth.
fn is_exempt(path: &str) -> bool {
    path == "/healthz" || path == "/readyz" || path == "/v1/status" || path.starts_with("/_lb")
}

fn unauthorized(why: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized", "detail": why })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(enforce: bool) -> Authenticator {
        Authenticator {
            auth_base: None,
            introspect_secret: None,
            enforce,
            http: reqwest::Client::new(),
            jwks: RwLock::new(JwksCache {
                set: None,
                fetched: Instant::now(),
            }),
            intro: RwLock::new(HashMap::new()),
        }
    }

    fn uri(p: &str) -> Uri {
        p.parse().unwrap()
    }

    #[test]
    fn bearer_and_exempt_helpers() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer abc.def".parse().unwrap());
        assert_eq!(bearer(&h), Some("abc.def"));
        assert!(bearer(&HeaderMap::new()).is_none());

        assert!(is_exempt("/healthz"));
        assert!(is_exempt("/v1/status"));
        assert!(is_exempt("/_lb/routes"));
        assert!(!is_exempt("/v1/locks/acquire"));
    }

    #[tokio::test]
    async fn strips_client_supplied_identity_headers() {
        let mut h = HeaderMap::new();
        h.insert("x-fiducia-org", "evil-org".parse().unwrap());
        h.insert("x-fiducia-scopes", "admin".parse().unwrap());
        // Exempt path so we isolate the stripping behavior.
        let out = auth(false).authorize(&uri("/v1/status"), h).await.unwrap();
        assert!(out.get("x-fiducia-org").is_none(), "spoofed org must be stripped");
        assert!(out.get("x-fiducia-scopes").is_none());
    }

    #[tokio::test]
    async fn permissive_allows_anonymous_enforce_rejects() {
        // Default (permissive): anonymous data-plane request is allowed, untagged.
        let out = auth(false)
            .authorize(&uri("/v1/locks/acquire"), HeaderMap::new())
            .await
            .unwrap();
        assert!(out.get("x-fiducia-org").is_none());

        // Enforce: anonymous data-plane request is rejected.
        let rej = auth(true)
            .authorize(&uri("/v1/locks/acquire"), HeaderMap::new())
            .await;
        assert!(rej.is_err(), "enforce must reject anonymous");
    }

    #[tokio::test]
    async fn enforce_still_exempts_operational_reads() {
        let out = auth(true).authorize(&uri("/v1/status"), HeaderMap::new()).await;
        assert!(out.is_ok(), "status must not require auth even when enforcing");
    }
}
