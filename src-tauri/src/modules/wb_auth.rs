//! WorkBuddy plugin auth endpoints: OAuth-style login and token refresh.
//!
//! Flow (proven against both portals):
//!   POST {portal}/v2/plugin/auth/state?platform=CLI   -> data.authUrl + data.state
//!   GET  {portal}/v2/plugin/auth/token?state=...      -> data.accessToken / refreshToken
//!   POST {portal}/v2/plugin/auth/token/refresh        -> renewed token set
//!
//! The upstream does a UA-shaped fingerprint check: a browser-shaped agent is
//! rejected, the request must carry the CLI form `CLI/<ver> CodeBuddy/<ver>`.

use crate::error::{AppError, AppResult};
use crate::models::account::{site_from_domain, Site};
use base64::Engine;
use serde::Serialize;

/// UA version presented to the auth endpoints. Must contain both a product
/// and a version segment; the upstream parses it.
pub const AUTH_UA: &str = "CLI/2.63.2 CodeBuddy/2.63.2";
/// UA used by the refresh endpoint in the proven upstream implementation.
pub const REFRESH_UA: &str = "CLI/1.0.8 CodeBuddy/1.0.8";

/// How long a started auth session stays pollable (upstream allows 30 min).
pub const SESSION_TTL_SECS: i64 = 1800;

#[derive(Debug, Clone, Serialize)]
pub struct AuthSession {
    pub state: String,
    pub auth_url: String,
    pub site: Site,
    pub portal: String,
    pub expires_at: i64,
}

pub struct AuthClient {
    http: reqwest::Client,
}

/// The token set returned by the poll / refresh endpoints.
#[derive(Debug, Clone, Default)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_expires_in: i64,
    pub session_state: String,
    pub scope: String,
    pub domain: String,
}

impl AuthClient {
    pub fn new() -> AppResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Http(e.to_string()))?;
        Ok(Self { http })
    }

    // ── start ──────────────────────────────────────────────────────────────

    /// Create a new authorization session and return the URL to open.
    pub async fn start(&self, site: Site) -> AppResult<AuthSession> {
        let portal = site.portal();
        let nonce = hex_id(8);
        let url = format!("{}/v2/plugin/auth/state?platform=CLI", portal);

        let resp = self
            .http
            .post(&url)
            .header("User-Agent", AUTH_UA)
            .header("Accept", "application/json, text/plain, */*")
            .header("Content-Type", "application/json")
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Origin", portal)
            .header("Referer", format!("{}/", portal))
            .json(&serde_json::json!({ "nonce": nonce }))
            .send()
            .await
            .map_err(|e| AppError::Http(format!("auth state request failed: {}", e)))?;

        let status = resp.status();
        let payload: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Http(format!("auth state response not JSON ({}): {}", status, e)))?;

        if payload.get("code").and_then(|c| c.as_i64()) != Some(0) {
            let msg = payload
                .get("msg")
                .and_then(|m| m.as_str())
                .unwrap_or("auth failed");
            return Err(AppError::Oauth(format!(
                "auth state rejected ({}): {}",
                status, msg
            )));
        }

        let data = payload.get("data").cloned().unwrap_or_default();
        let state = data
            .get("state")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let auth_url = data
            .get("authUrl")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();

        if state.is_empty() || auth_url.is_empty() {
            return Err(AppError::Oauth("empty state or authUrl".to_string()));
        }

        Ok(AuthSession {
            state,
            auth_url,
            site,
            portal: portal.to_string(),
            expires_at: chrono::Utc::now().timestamp() + SESSION_TTL_SECS,
        })
    }

    // ── poll ───────────────────────────────────────────────────────────────

    /// Poll once for the login result. `Ok(None)` means "still waiting".
    pub async fn poll(&self, session: &AuthSession) -> AppResult<Option<TokenSet>> {
        let url = format!(
            "{}/v2/plugin/auth/token?state={}",
            session.portal, session.state
        );

        let resp = self
            .http
            .get(&url)
            .header("User-Agent", AUTH_UA)
            .header("Accept", "application/json, text/plain, */*")
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Origin", &session.portal)
            .header("Referer", format!("{}/", session.portal))
            .send()
            .await
            .map_err(|e| AppError::Http(format!("auth token poll failed: {}", e)))?;

        let status = resp.status();
        if status.as_u16() >= 400 {
            return Err(AppError::Http(format!("auth token poll: HTTP {}", status)));
        }

        let payload: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Http(format!("auth token response not JSON: {}", e)))?;

        if is_pending(&payload) {
            return Ok(None);
        }

        match extract_token_set(&payload) {
            Some(tokens) if !tokens.access_token.is_empty() => Ok(Some(tokens)),
            _ => {
                let msg = payload
                    .get("msg")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown status");
                Err(AppError::Oauth(format!("login not completed: {}", msg)))
            }
        }
    }

    // ── refresh ────────────────────────────────────────────────────────────

    /// Refresh an access token via the plugin refresh endpoint.
    ///
    /// The proven upstream implementation posts an empty JSON body and
    /// carries the refresh token in the `X-Refresh-Token` header.
    pub async fn refresh(
        &self,
        site: Site,
        access_token: &str,
        refresh_token: &str,
    ) -> AppResult<TokenSet> {
        let refresh_token = refresh_token.trim();
        if refresh_token.is_empty() {
            return Err(AppError::Validation(
                "该账号没有可用的 refresh token（可能已加密），无法刷新".to_string(),
            ));
        }

        let portal = site.portal();
        let url = format!("{}/v2/plugin/auth/token/refresh", portal);
        let host = portal.trim_start_matches("https://");
        let request_id = hex_id(16);
        let span_id = hex_id(4);

        let mut req = self
            .http
            .post(&url)
            .header("Accept", "application/json, text/plain, */*")
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
            .header("Connection", "close")
            .header("X-Requested-With", "XMLHttpRequest")
            .header("X-Request-Id", &request_id)
            .header("b3", format!("{}-{}-1-", request_id, span_id))
            .header("X-B3-Traceid", &request_id)
            .header("X-B3-Parentspanid", "")
            .header("X-B3-Spanid", &span_id)
            .header("X-B3-Sampled", "1")
            .header("X-Domain", host)
            .header("X-Refresh-Token", refresh_token)
            .header("X-Auth-Refresh-Source", "plugin")
            .header("User-Agent", REFRESH_UA)
            .header("X-Product", "SaaS");

        let access = access_token.trim();
        if !access.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", access));
        }

        let resp = req
            .body("{}")
            .send()
            .await
            .map_err(|e| AppError::Http(format!("token refresh failed: {}", e)))?;

        let status = resp.status();
        let payload: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Http(format!("token refresh response not JSON ({}): {}", status, e)))?;

        let tokens = extract_token_set(&payload);
        let ok = (200..300).contains(&status.as_u16());
        match tokens {
            Some(tokens) if ok && !tokens.access_token.is_empty() => Ok(tokens),
            _ => {
                let msg = first_str(
                    &[
                        payload.get("error_description"),
                        payload.get("error"),
                        payload.get("msg"),
                        payload.get("message"),
                    ],
                    &format!("HTTP {}", status),
                );
                Err(AppError::Oauth(format!(
                    "token refresh failed ({}): {}",
                    status, msg
                )))
            }
        }
    }
}

impl Default for AuthClient {
    fn default() -> Self {
        AuthClient::new().expect("failed to build HTTP client")
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

/// First `len` hex chars of a fresh UUIDv4.
fn hex_id(len: usize) -> String {
    uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(len)
        .collect()
}

fn first_str(values: &[Option<&serde_json::Value>], fallback: &str) -> String {
    for v in values.into_iter().flatten() {
        if let Some(s) = v.as_str() {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    fallback.to_string()
}

/// Pending-login detection, mirroring the proven upstream rules:
/// `code == 11217`, or a message containing `login`+`ing`, or `waiting`.
pub fn is_pending(payload: &serde_json::Value) -> bool {
    let code = payload.get("code").and_then(|c| c.as_i64());
    if code == Some(11217) {
        return true;
    }
    let msg = payload
        .get("msg")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_lowercase();
    (msg.contains("login") && msg.contains("ing")) || msg.contains("waiting")
}

/// Extract the token set from both known response shapes:
///   A) {"payload": {"tokenData": {...}}}
///   B) {"data": {"accessToken": ..., "refreshToken": ...}}
pub fn extract_token_set(payload: &serde_json::Value) -> Option<TokenSet> {
    let candidates = [
        payload.get("data").filter(|v| v.is_object()),
        payload
            .get("payload")
            .and_then(|p| p.get("tokenData"))
            .filter(|v| v.is_object()),
    ];

    for c in candidates.into_iter().flatten() {
        let Some(access) = string_of(c, &["accessToken", "bearerToken", "access_token", "token"])
        else {
            continue;
        };
        let refresh = string_of(c, &["refreshToken", "refresh_token"])
            .or_else(|| string_of(payload, &["refreshToken", "refresh_token"]))
            .unwrap_or_default();
        let token_type = string_of(c, &["tokenType", "token_type"])
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Bearer".to_string());
        return Some(TokenSet {
            access_token: access,
            refresh_token: refresh,
            token_type,
            expires_in: int_of(c, &["expiresIn", "expires_in"]),
            refresh_expires_in: int_of(c, &["refreshExpiresIn", "refresh_expires_in"]),
            session_state: string_of(c, &["sessionState", "session_state"]).unwrap_or_default(),
            scope: string_of(c, &["scope"]).unwrap_or_default(),
            domain: string_of(c, &["domain"]).unwrap_or_default(),
        });
    }
    None
}

fn string_of(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(k).and_then(|x| x.as_str()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn int_of(v: &serde_json::Value, keys: &[&str]) -> i64 {
    keys.iter()
        .find_map(|k| v.get(k).and_then(|x| x.as_i64()))
        .unwrap_or(0)
}

// ── JWT decoding (no signature verification — display only) ───────────────

/// A decoded JWT payload's display-relevant claims.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JwtClaims {
    pub email: Option<String>,
    pub preferred_username: Option<String>,
    pub phone: Option<String>,
    pub sub: Option<String>,
    /// Expiry in unix **milliseconds**.
    pub exp_ms: i64,
}

/// Decode a JWT's payload without verifying the signature.
/// Returns `None` for non-JWT values (encrypted envelopes, opaque tokens).
pub fn decode_jwt_claims(token: &str) -> Option<JwtClaims> {
    let token = token.trim();
    let mut parts = token.split('.');
    let (_h, p, _s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            (h, p, s)
        }
        _ => return None,
    };

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(p)
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE.decode(p).ok()
        })?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes).ok()?;

    let exp_s = payload.get("exp").and_then(|e| e.as_i64()).unwrap_or(0);
    Some(JwtClaims {
        email: payload
            .get("email")
            .and_then(|e| e.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        preferred_username: payload
            .get("preferred_username")
            .and_then(|e| e.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        phone: payload
            .get("phone_number")
            .and_then(|e| e.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        sub: payload
            .get("sub")
            .and_then(|e| e.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty()),
        // Some issuers use seconds, some milliseconds; treat >1e12 as ms.
        exp_ms: if exp_s > 1_000_000_000_000 {
            exp_s
        } else {
            exp_s * 1000
        },
    })
}

/// The auth `domain` recorded by the portal, mapped to a Site.
pub fn site_of_token_set(tokens: &TokenSet) -> Site {
    site_from_domain(&tokens.domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pending_detection() {
        assert!(is_pending(&json!({"code": 11217, "msg": "x"})));
        assert!(is_pending(&json!({"code": 1, "msg": "user is logging in"})));
        assert!(is_pending(&json!({"code": 1, "msg": "Waiting for login"})));
        assert!(!is_pending(&json!({"code": 0, "msg": "OK"})));
        assert!(!is_pending(&json!({"code": 10001, "msg": "state is empty"})));
    }

    #[test]
    fn extracts_data_shape() {
        let payload = json!({
            "code": 0,
            "data": {
                "accessToken": "acc",
                "refreshToken": "ref",
                "tokenType": "Bearer",
                "expiresIn": 3600,
                "sessionState": "sess",
                "scope": "openid",
                "domain": "www.workbuddy.ai"
            }
        });
        let t = extract_token_set(&payload).unwrap();
        assert_eq!(t.access_token, "acc");
        assert_eq!(t.refresh_token, "ref");
        assert_eq!(t.expires_in, 3600);
        assert_eq!(t.domain, "www.workbuddy.ai");
        assert_eq!(site_of_token_set(&t), Site::Global);
    }

    #[test]
    fn extracts_payload_shape() {
        let payload = json!({
            "code": 0,
            "payload": {"tokenData": {"bearerToken": "b", "refreshToken": "r"}}
        });
        let t = extract_token_set(&payload).unwrap();
        assert_eq!(t.access_token, "b");
        assert_eq!(t.token_type, "Bearer");
    }

    #[test]
    fn rejects_empty_token_data() {
        // an empty tokenData dict must not count as a valid token
        let payload = json!({"code": 0, "payload": {"tokenData": {}}});
        assert!(extract_token_set(&payload).is_none());
        assert!(extract_token_set(&json!({"code": 0})).is_none());
    }

    #[test]
    fn decodes_keycloak_jwt() {
        // header {"alg":"RS256","typ":"JWT"}, payload {"email":"a@b.c","exp":1823857525,"sub":"sub-1"}
        let payload = r#"{"email":"a@b.c","exp":1823857525,"sub":"sub-1","preferred_username":"user1"}"#;
        let p64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", p64);
        let claims = decode_jwt_claims(&token).unwrap();
        assert_eq!(claims.email.as_deref(), Some("a@b.c"));
        assert_eq!(claims.sub.as_deref(), Some("sub-1"));
        assert_eq!(claims.exp_ms, 1_823_857_525_000);
    }

    #[test]
    fn non_jwt_values_are_rejected() {
        assert!(decode_jwt_claims("").is_none());
        assert!(decode_jwt_claims("not-a-jwt").is_none());
        assert!(decode_jwt_claims("a.b").is_none());
        assert!(decode_jwt_claims("x.!!!.y").is_none()); // bad base64 payload
    }
}
