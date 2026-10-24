use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Which WorkBuddy portal an account belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Site {
    Domestic,
    #[default]
    Global,
}

impl Site {
    /// Portal used for the plugin auth endpoints (`/v2/plugin/auth/...`).
    pub fn portal(&self) -> &'static str {
        match self {
            Site::Domestic => "https://www.workbuddy.cn",
            Site::Global => "https://www.workbuddy.ai",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Site::Domestic => "国内版",
            Site::Global => "国际版",
        }
    }
}

/// Best-effort site detection from an auth `domain` value
/// (`www.codebuddy.cn` / `www.workbuddy.cn` → domestic, else global).
pub fn site_from_domain(domain: &str) -> Site {
    if domain.to_lowercase().contains(".cn") {
        Site::Domestic
    } else {
        Site::Global
    }
}

/// Where an account's credentials were captured from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Plugin OAuth login flow.
    OAuth,
    /// WorkBuddy desktop app (domestic variant) auth file.
    DesktopCn,
    /// WorkBuddy AI desktop app (global variant) auth file.
    DesktopAi,
    /// CodeBuddy CLI settings.json.
    Cli,
    /// Pasted refresh token / manual import.
    Manual,
    /// Imported from a JSON backup file.
    ImportFile,
}

impl Source {
    pub fn name(&self) -> &'static str {
        match self {
            Source::OAuth => "OAuth 登录",
            Source::DesktopCn => "WorkBuddy 桌面端",
            Source::DesktopAi => "WorkBuddy AI 桌面端",
            Source::Cli => "CodeBuddy CLI",
            Source::Manual => "手动导入",
            Source::ImportFile => "备份导入",
        }
    }
}

/// A credential value: a plaintext token string, or an encrypted
/// `$wbEncrypted` envelope object captured from a desktop auth file.
///
/// Envelopes cannot be decrypted by this app; they are passed through
/// verbatim when switching a desktop client, which works because the
/// envelope's key lives in that machine's credential store. Plaintext
/// values are required for the CLI (JWT) and for refresh flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialValue {
    Plain(String),
    Envelope(Value),
}

impl CredentialValue {
    pub fn plain(s: impl Into<String>) -> Self {
        CredentialValue::Plain(s.into())
    }

    /// The plaintext string, when this is one.
    pub fn plaintext(&self) -> Option<&str> {
        match self {
            CredentialValue::Plain(s) => Some(s.as_str()),
            CredentialValue::Envelope(_) => None,
        }
    }

    /// True when the value is an encrypted envelope.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, CredentialValue::Envelope(_))
    }

    pub fn is_empty(&self) -> bool {
        match self {
            CredentialValue::Plain(s) => s.is_empty(),
            CredentialValue::Envelope(_) => false,
        }
    }

    /// Masked single-line representation for the UI.
    pub fn masked(&self) -> String {
        match self {
            CredentialValue::Plain(s) => {
                let t = s.trim();
                if t.is_empty() {
                    "（空）".to_string()
                } else if t.len() <= 12 {
                    "****".to_string()
                } else {
                    format!("{}...{}", &t[..6], &t[t.len() - 4..])
                }
            }
            CredentialValue::Envelope(_) => "〔已加密信封〕".to_string(),
        }
    }
}

/// A full-fidelity snapshot of a desktop auth file's `account` and `auth`
/// blocks, captured verbatim. Switching writes these back as-is (merged
/// into the target file, preserving its other top-level keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopSnapshot {
    pub account: Value,
    pub auth: Value,
}

/// A snapshot of the CodeBuddy CLI settings.json fields that belong to a
/// login: the env credentials plus the endpoint and gateway (password
/// login) blocks. Restored verbatim on switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internet_environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// `gateway` object as captured (contains the password login).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Value>,
}

/// A managed WorkBuddy account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Stable unique identifier.
    pub id: String,
    /// Best-effort display name: email / phone / nickname / uid prefix.
    pub display: String,
    /// Account uid (Tencent OneID), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// Which portal family this account belongs to.
    pub site: Site,
    /// Where the credentials came from.
    pub source: Source,
    /// Bearer access token (plaintext or encrypted envelope).
    pub access_token: CredentialValue,
    /// Long-lived refresh token (plaintext or encrypted envelope).
    pub refresh_token: CredentialValue,
    /// Always "Bearer" when known.
    #[serde(default = "default_token_type")]
    pub token_type: String,
    /// Lifetime of the access token in seconds, when known.
    #[serde(default)]
    pub expires_in: i64,
    /// Unix **milliseconds** when the access token expires (desktop files use ms).
    #[serde(default)]
    pub expires_at_ms: i64,
    /// Keycloak session state, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
    /// OAuth scope, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Upstream auth domain recorded with the token (e.g. www.workbuddy.ai).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Verbatim desktop auth snapshot when captured from a desktop client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_snapshot: Option<DesktopSnapshot>,
    /// Verbatim CLI settings snapshot when captured from the CLI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_snapshot: Option<CliSnapshot>,
    /// Unix timestamp when the account was added.
    pub created_at: i64,
    /// Unix timestamp of the last time this account was activated.
    pub last_used: i64,
    /// User-defined label / remark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

impl Account {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        display: impl Into<String>,
        site: Site,
        source: Source,
        access_token: CredentialValue,
        refresh_token: CredentialValue,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            display: display.into(),
            uid: None,
            email: None,
            phone: None,
            site,
            source,
            access_token,
            refresh_token,
            token_type: default_token_type(),
            expires_in: 0,
            expires_at_ms: 0,
            session_state: None,
            scope: None,
            domain: None,
            desktop_snapshot: None,
            cli_snapshot: None,
            created_at: now,
            last_used: now,
            notes: None,
        }
    }

    pub fn update_last_used(&mut self) {
        self.last_used = chrono::Utc::now().timestamp();
    }

    /// Whether the access token is still valid (60-second buffer).
    /// Encrypted envelopes and unknown expiry count as valid — there is
    /// nothing to refresh from, and desktop envelopes outlive a year.
    pub fn is_access_token_valid(&self) -> bool {
        if self.expires_at_ms <= 0 {
            return true;
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        now_ms < self.expires_at_ms - 60_000
    }

    /// The dedupe key used to recognise the same login across sources.
    pub fn dedupe_key(&self) -> String {
        if let Some(uid) = &self.uid {
            return format!("uid:{}", uid);
        }
        if let Some(rt) = self.refresh_token.plaintext() {
            if !rt.is_empty() {
                return format!("rt:{}", rt);
            }
        }
        if let Some(at) = self.access_token.plaintext() {
            if !at.is_empty() {
                return format!("at:{}", at);
            }
        }
        format!("display:{}|{}", self.display, self.site_name_key())
    }

    fn site_name_key(&self) -> &'static str {
        match self.site {
            Site::Domestic => "cn",
            Site::Global => "global",
        }
    }
}

/// Index file: `accounts.json` at the root of the store.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountIndex {
    pub version: String,
    pub accounts: Vec<AccountSummary>,
    /// The account currently switched into the WorkBuddy (domestic) desktop app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_desktop_cn_account_id: Option<String>,
    /// The account currently switched into the WorkBuddy AI (global) desktop app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_desktop_ai_account_id: Option<String>,
    /// The account currently switched into CodeBuddy CLI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_cli_account_id: Option<String>,
}

impl AccountIndex {
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            accounts: Vec::new(),
            current_desktop_cn_account_id: None,
            current_desktop_ai_account_id: None,
            current_cli_account_id: None,
        }
    }
}

/// A summary view of an account, stored in the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub display: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default)]
    pub site: Site,
    pub source: Source,
    pub created_at: i64,
    pub last_used: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl From<&Account> for AccountSummary {
    fn from(acc: &Account) -> Self {
        Self {
            id: acc.id.clone(),
            display: acc.display.clone(),
            uid: acc.uid.clone(),
            site: acc.site,
            source: acc.source,
            created_at: acc.created_at,
            last_used: acc.last_used,
            notes: acc.notes.clone(),
        }
    }
}

/// Export item for backup / migration (own format, full fidelity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportItem {
    pub display: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    pub site: Site,
    pub source: Source,
    pub access_token: CredentialValue,
    pub refresh_token: CredentialValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: i64,
    #[serde(default)]
    pub expires_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_snapshot: Option<DesktopSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_snapshot: Option<CliSnapshot>,
}

/// Export response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExportResponse {
    pub exported_at: i64,
    pub accounts: Vec<AccountExportItem>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_account(site: Site, source: Source) -> Account {
        Account::new(
            "user@example.com",
            site,
            source,
            CredentialValue::plain("access-token-value"),
            CredentialValue::plain("refresh-token-value"),
        )
    }

    #[test]
    fn site_detection_by_domain() {
        assert_eq!(site_from_domain("www.codebuddy.cn"), Site::Domestic);
        assert_eq!(site_from_domain("www.workbuddy.cn"), Site::Domestic);
        assert_eq!(site_from_domain("www.workbuddy.ai"), Site::Global);
        assert_eq!(site_from_domain(""), Site::Global);
    }

    #[test]
    fn portals_match_product() {
        assert_eq!(Site::Domestic.portal(), "https://www.workbuddy.cn");
        assert_eq!(Site::Global.portal(), "https://www.workbuddy.ai");
    }

    #[test]
    fn masked_values() {
        assert_eq!(
            CredentialValue::plain("abcdefghijklmnop").masked(),
            "abcdef...mnop"
        );
        assert_eq!(CredentialValue::plain("short").masked(), "****");
        assert_eq!(CredentialValue::plain("").masked(), "（空）");
        let env = CredentialValue::Envelope(serde_json::json!({"$wbEncrypted": 1}));
        assert_eq!(env.masked(), "〔已加密信封〕");
        assert!(env.is_encrypted());
        assert!(env.plaintext().is_none());
    }

    #[test]
    fn validity_uses_millis_with_buffer() {
        let mut acc = plain_account(Site::Global, Source::OAuth);
        acc.expires_at_ms = chrono::Utc::now().timestamp_millis() + 3_600_000;
        assert!(acc.is_access_token_valid());
        acc.expires_at_ms = chrono::Utc::now().timestamp_millis() - 1_000;
        assert!(!acc.is_access_token_valid());
        // inside the 60s buffer counts as invalid
        acc.expires_at_ms = chrono::Utc::now().timestamp_millis() + 30_000;
        assert!(!acc.is_access_token_valid());
        // unknown expiry counts as valid (nothing to refresh from)
        acc.expires_at_ms = 0;
        assert!(acc.is_access_token_valid());
    }

    #[test]
    fn dedupe_prefers_uid_then_tokens() {
        let mut acc = plain_account(Site::Global, Source::OAuth);
        acc.uid = Some("uid-1".into());
        assert_eq!(acc.dedupe_key(), "uid:uid-1");

        acc.uid = None;
        assert_eq!(acc.dedupe_key(), "rt:refresh-token-value");

        acc.refresh_token = CredentialValue::Envelope(serde_json::json!({}));
        assert_eq!(acc.dedupe_key(), "at:access-token-value");
    }

    #[test]
    fn account_serde_roundtrip_keeps_envelope() {
        let mut acc = plain_account(Site::Domestic, Source::DesktopCn);
        acc.uid = Some("u".into());
        acc.refresh_token = CredentialValue::Envelope(serde_json::json!({
            "$wbEncrypted": 1, "envelope": "abc"
        }));
        acc.desktop_snapshot = Some(DesktopSnapshot {
            account: serde_json::json!({"uid": "u"}),
            auth: serde_json::json!({"accessToken": {"$wbEncrypted": 1}}),
        });
        let json = serde_json::to_string(&acc).unwrap();
        let back: Account = serde_json::from_str(&json).unwrap();
        assert!(back.refresh_token.is_encrypted());
        assert!(back.desktop_snapshot.is_some());
        assert_eq!(back.site, Site::Domestic);
        // optional fields are omitted when None
        assert!(!json.contains("notes"));
    }
}
