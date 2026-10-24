//! Sync credentials into the local WorkBuddy clients.
//!
//! Targets (all discovered in the wild on a real machine):
//! - WorkBuddy desktop (domestic): `%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info`
//! - WorkBuddy AI desktop (global): same folder, `workbuddy-desktop-ai.info`
//! - CodeBuddy CLI: `~/.codebuddy/settings.json` (`env.CODEBUDDY_AUTH_TOKEN`, …)
//!
//! The desktop auth files hold an `account` and an `auth` object. Credential
//! values may be plaintext strings or `{"$wbEncrypted":1,"envelope":…}`
//! objects whose key lives in this machine's credential store — envelopes are
//! passed through verbatim, so switching works for accounts captured on this
//! machine without ever decrypting anything.

use crate::error::{AppError, AppResult};
use crate::models::account::{site_from_domain, Account, Site};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    DesktopCn,
    DesktopAi,
    Cli,
}

impl ClientKind {
    pub fn name(&self) -> &'static str {
        match self {
            ClientKind::DesktopCn => "WorkBuddy 桌面端（国内）",
            ClientKind::DesktopAi => "WorkBuddy AI 桌面端（国际）",
            ClientKind::Cli => "CodeBuddy CLI",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            ClientKind::DesktopCn => "WB 桌面端",
            ClientKind::DesktopAi => "WB AI 桌面端",
            ClientKind::Cli => "CB CLI",
        }
    }
}

/// What the UI learns about one client's install and login state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientStatus {
    pub client: ClientKind,
    pub name: String,
    pub installed: bool,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<CurrentAccountInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CurrentAccountInfo {
    pub uid: String,
    pub display: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub site: Site,
    /// Access-token expiry in unix ms (0 = unknown).
    pub expires_at_ms: i64,
    /// True when the credentials are encrypted envelopes.
    pub encrypted: bool,
}

// ── paths ──────────────────────────────────────────────────────────────────

/// The folder holding the desktop clients' auth files.
pub fn desktop_auth_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| {
        d.join("CodeBuddyExtension")
            .join("Data")
            .join("Public")
            .join("auth")
    })
}

pub fn desktop_auth_file(kind: ClientKind) -> Option<PathBuf> {
    let name = match kind {
        ClientKind::DesktopCn => "workbuddy-desktop.info",
        ClientKind::DesktopAi => "workbuddy-desktop-ai.info",
        ClientKind::Cli => return None,
    };
    Some(desktop_auth_dir()?.join(name))
}

pub fn cli_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".codebuddy").join("settings.json"))
}

pub fn client_file_path(kind: ClientKind) -> Option<PathBuf> {
    match kind {
        ClientKind::Cli => cli_settings_path(),
        k => desktop_auth_file(k),
    }
}

// ── reading client state ───────────────────────────────────────────────────

/// Parsed pieces of a desktop auth `.info` file.
#[derive(Debug, Clone)]
pub struct DesktopAuthFile {
    pub account: Value,
    pub auth: Value,
    /// Everything else in the file, preserved verbatim on switch.
    pub extra: serde_json::Map<String, Value>,
}

pub fn parse_desktop_auth_file(doc: &Value) -> Option<DesktopAuthFile> {
    let obj = doc.as_object()?;
    let account = obj.get("account")?.clone();
    let auth = obj.get("auth")?.clone();
    if !account.is_object() || !auth.is_object() {
        return None;
    }
    let mut extra = obj.clone();
    extra.remove("account");
    extra.remove("auth");
    Some(DesktopAuthFile {
        account,
        auth,
        extra,
    })
}

fn json_str(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Best-effort display name for an `account` object: nickname (plaintext) /
/// phoneNumber / uin / uid prefix. Encrypted nicknames fall back to other
/// fields; the caller can enrich from JWT claims.
pub fn display_of_account(account: &Value) -> String {
    if let Some(n) = json_str(account, "nickname") {
        if !n.starts_with('{') {
            return n;
        }
    }
    for key in ["phoneNumber", "uin", "oneidAccountId"] {
        if let Some(v) = json_str(account, key) {
            return v;
        }
    }
    json_str(account, "uid")
        .map(|uid| format!("uid-{}", &uid[..uid.len().min(8)]))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Read one client's current login (None = signed out / file missing).
pub fn read_current(kind: ClientKind) -> Option<CurrentAccountInfo> {
    let path = client_file_path(kind)?;
    let raw = std::fs::read_to_string(path).ok()?;
    read_current_from_str(kind, &raw)
}

/// Same as [`read_current`], from raw content (testable).
pub fn read_current_from_str(kind: ClientKind, raw: &str) -> Option<CurrentAccountInfo> {
    match kind {
        ClientKind::Cli => read_current_cli(raw),
        k => read_current_desktop(k, raw),
    }
}

fn read_current_desktop(_kind: ClientKind, raw: &str) -> Option<CurrentAccountInfo> {
    let doc: Value = serde_json::from_str(raw).ok()?;
    let parsed = parse_desktop_auth_file(&doc)?;
    let account = &parsed.account;
    let auth = &parsed.auth;
    let uid = json_str(account, "uid").unwrap_or_default();
    if uid.is_empty() {
        return None;
    }

    let encrypted = is_encrypted_value(auth.get("accessToken"));
    let domain = json_str(auth, "domain");

    let mut display = display_of_account(account);
    let phone = json_str(account, "phoneNumber");
    if display.starts_with("uid-") || display.chars().all(|c| c.is_ascii_digit()) {
        // try to enrich from a plaintext JWT access token
        if let Some(token) = auth
            .get("accessToken")
            .and_then(|v| v.as_str())
            .and_then(crate::modules::wb_auth::decode_jwt_claims)
        {
            if let Some(email) = token.email.clone() {
                display = email;
            }
        }
    }

    Some(CurrentAccountInfo {
        uid,
        display,
        phone,
        domain,
        site: site_from_domain(domain.as_deref().unwrap_or("")),
        expires_at_ms: auth
            .get("expiresAt")
            .and_then(|e| e.as_i64())
            .unwrap_or(0),
        encrypted,
    })
}

fn read_current_cli(raw: &str) -> Option<CurrentAccountInfo> {
    let doc: Value = serde_json::from_str(raw).ok()?;
    let token = json_str(&doc, "CODEBUDDY_AUTH_TOKEN")
        .or_else(|| {
            doc.get("env")
                .and_then(|env| json_str(env, "CODEBUDDY_AUTH_TOKEN"))
        })
        .or_else(|| {
            doc.get("codebuddy")
                .and_then(|cb| json_str(cb, "CODEBUDDY_AUTH_TOKEN"))
        })?;
    if token.is_empty() {
        return None;
    }

    let claims = crate::modules::wb_auth::decode_jwt_claims(&token);
    let endpoint = json_str(&doc, "endpoint")
        .or_else(|| doc.get("env").and_then(|env| json_str(env, "CODEBUDDY_BASE_URL")));
    let display = claims
        .as_ref()
        .and_then(|c| c.email.clone())
        .or_else(|| claims.as_ref().and_then(|c| c.preferred_username.clone()))
        .unwrap_or_else(|| "CLI 登录账号".to_string());

    Some(CurrentAccountInfo {
        uid: claims.as_ref().and_then(|c| c.sub.clone()).unwrap_or_default(),
        display,
        phone: None,
        domain: endpoint.clone(),
        site: site_from_domain(endpoint.as_deref().unwrap_or("")),
        expires_at_ms: claims.as_ref().map(|c| c.exp_ms).unwrap_or(0),
        encrypted: false,
    })
}

fn is_encrypted_value(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Object(o)) if o.contains_key("$wbEncrypted"))
}

// ── switching ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct ClientSyncResult {
    pub client: ClientKind,
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Switch `account` into `kind`: back up, write, read back, verify.
pub fn switch(kind: ClientKind, account: &Account) -> ClientSyncResult {
    let name = kind.name().to_string();
    match switch_inner(kind, account) {
        Ok(detail) => ClientSyncResult {
            client: kind,
            name,
            ok: true,
            detail,
        },
        Err(e) => ClientSyncResult {
            client: kind,
            name,
            ok: false,
            detail: e.to_string(),
        },
    }
}

fn switch_inner(kind: ClientKind, account: &Account) -> AppResult<String> {
    let mut parts: Vec<String> = Vec::new();
    let result = match kind {
        ClientKind::Cli => switch_cli(account)?,
        k => switch_desktop(k, account)?,
    };
    parts.push(result);
    if client_process_running() {
        parts.push(
            "检测到 WorkBuddy 客户端正在运行：若界面未生效请先完全退出客户端再重试"
                .to_string(),
        );
    }
    Ok(parts.join("；"))
}

/// Build the desktop `account` + `auth` payload for an account.
pub fn desktop_payload(account: &Account, target: ClientKind) -> (Value, Value) {
    if let Some(snap) = &account.desktop_snapshot {
        let mut doc = snap.auth.clone();
        if let Some(o) = doc.as_object_mut() {
            o.insert("lastRefreshTime".into(), Value::from(now_ms()));
        }
        let mut acc = snap.account.clone();
        if let Some(o) = acc.as_object_mut() {
            o.insert("lastLogin".into(), Value::from(true));
            o.insert("isFirstLogin".into(), Value::from(false));
        }
        return (acc, doc);
    }

    // Synthesize from managed fields. Encrypted envelopes pass through as-is.
    let at = credential_to_json(&account.access_token);
    let rt = credential_to_json(&account.refresh_token);
    let now = now_ms();
    let expires_at = if account.expires_at_ms > 0 {
        account.expires_at_ms
    } else if account.expires_in > 0 {
        now + account.expires_in * 1000
    } else {
        0
    };
    let domain = account
        .domain
        .clone()
        .unwrap_or_else(|| match target {
            ClientKind::DesktopCn => "www.codebuddy.cn".to_string(),
            ClientKind::DesktopAi => "www.workbuddy.ai".to_string(),
            ClientKind::Cli => account.site.portal().trim_start_matches("https://").to_string(),
        });

    let mut acc = serde_json::json!({
        "uid": account.uid.clone().unwrap_or_default(),
        "nickname": account.display,
        "type": "personal",
        "lastLogin": true,
        "isFirstLogin": false,
        "isCreator": false,
        "isAdmin": false,
        "pluginEnabled": true,
        "accountType": "",
        "idp": "",
        "areaInfoComplete": true,
        "oneidAccountId": "",
        "isCurrentOneIdEnterprise": false,
        "isCurrentOneIdPersonal": false,
        "logOutEnable": false,
        "deployStatus": {"statusCode": 0, "statusMsg": "", "detailMsg": ""},
        "sso": {"domain": "", "domainModifiedTimes": 0},
    });
    if let Some(phone) = &account.phone {
        acc["phoneNumber"] = Value::from(phone.clone());
    }

    let mut auth = serde_json::json!({
        "accessToken": at,
        "refreshToken": rt,
        "tokenType": account.token_type,
        "expiresIn": account.expires_in,
        "refreshExpiresIn": account.expires_in,
        "scope": account.scope.clone().unwrap_or_else(|| "openid profile offline_access email".to_string()),
        "domain": domain,
        "lastRefreshTime": now,
        "expiresAt": expires_at,
        "refreshExpiresAt": expires_at,
    });
    if let Some(ss) = &account.session_state {
        auth["sessionState"] = Value::from(ss.clone());
    }
    (acc, auth)
}

fn credential_to_json(v: &crate::models::account::CredentialValue) -> Value {
    match v {
        crate::models::account::CredentialValue::Plain(s) => Value::from(s.clone()),
        crate::models::account::CredentialValue::Envelope(o) => o.clone(),
    }
}

fn switch_desktop(kind: ClientKind, account: &Account) -> AppResult<String> {
    let path = desktop_auth_file(kind).ok_or_else(|| AppError::Other("no path".into()))?;
    let dir = path
        .parent()
        .ok_or_else(|| AppError::Other("no parent dir".into()))?;

    // Read the current file to preserve its other top-level keys. A missing
    // file with an existing folder counts as "installed but signed out".
    let current_doc: Option<Value> = if path.exists() {
        Some(serde_json::from_str(&std::fs::read_to_string(&path)?)?)
    } else if dir.is_dir() {
        None
    } else {
        return Err(AppError::ClientNotInstalled(format!(
            "未找到 {} 的认证目录：{}",
            kind.name(),
            dir.display()
        )));
    };

    // Back up whatever is there now (only once per switch).
    if path.exists() {
        let backup = dir.join(format!(
            "{}.wcm-bak-{}.info",
            path.file_name().unwrap_or_default().to_string_lossy(),
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        ));
        std::fs::copy(&path, &backup)?;
    }

    let (acc_json, auth_json) = desktop_payload(account, kind);
    let mut doc = current_doc.unwrap_or_else(|| serde_json::json!({}));
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| AppError::Validation("auth 文件顶层不是 JSON 对象".into()))?;
    obj.insert("account".into(), acc_json.clone());
    obj.insert("auth".into(), auth_json.clone());

    write_atomic(&path, &doc)?;
    verify_desktop_write(&path, &acc_json, &auth_json)?;

    Ok(format!(
        "已写入 {}（写入前已备份，回读校验通过）",
        path.display()
    ))
}

/// Read back the written file and confirm the credentials actually landed —
/// a running client can overwrite the file between our write and its exit.
fn verify_desktop_write(path: &std::path::Path, acc: &Value, auth: &Value) -> AppResult<()> {
    let raw = std::fs::read_to_string(path)?;
    let doc: Value = serde_json::from_str(&raw)?;
    let parsed =
        parse_desktop_auth_file(&doc).ok_or_else(|| AppError::Other("回读校验失败：文件结构缺失".into()))?;
    if parsed.account != *acc {
        return Err(AppError::Other(
            "回读校验失败：account 内容与写入不一致（客户端可能正在运行并回写）".into(),
        ));
    }
    if parsed.auth != *auth {
        return Err(AppError::Other(
            "回读校验失败：auth 内容与写入不一致（客户端可能正在运行并回写）".into(),
        ));
    }
    Ok(())
}

/// CLI endpoints observed in the wild: the global CLI signs in at
/// workbuddy.ai but keeps its legacy plugin base URL on codebuddy.ai/v2.
fn cli_endpoints(site: Site) -> (String, String) {
    match site {
        Site::Global => (
            "https://www.workbuddy.ai".to_string(),
            "https://www.codebuddy.ai/v2".to_string(),
        ),
        Site::Domestic => (
            "https://www.workbuddy.cn".to_string(),
            "https://www.codebuddy.cn/v2".to_string(),
        ),
    }
}

fn switch_cli(account: &Account) -> AppResult<String> {
    let path = cli_settings_path().ok_or_else(|| AppError::Other("无法定位用户主目录".into()))?;
    if !path.is_file() {
        return Err(AppError::ClientNotInstalled(format!(
            "未找到 CodeBuddy CLI 配置：{}",
            path.display()
        )));
    }

    let raw = std::fs::read_to_string(&path)?;
    let mut doc: Value = serde_json::from_str(&raw)?;

    // Back up before touching anything.
    let parent = path.parent().ok_or_else(|| AppError::Other("no parent".into()))?;
    let backup = parent.join(format!(
        "settings.json.wcm-bak-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::copy(&path, &backup)?;

    apply_cli_snapshot(&mut doc, account);

    write_atomic(&path, &doc)?;

    // Read back and verify the token landed.
    let back: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let written = back
        .pointer("/env/CODEBUDDY_AUTH_TOKEN")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected = account
        .cli_snapshot
        .as_ref()
        .and_then(|s| s.auth_token.clone())
        .or_else(|| account.access_token.plaintext().map(|s| s.to_string()))
        .unwrap_or_default();
    if written != expected || written.is_empty() {
        return Err(AppError::Other(
            "回读校验失败：CLI 配置中的 token 与写入不一致".into(),
        ));
    }

    Ok(format!("已写入 {}（写入前已备份，回读校验通过）", path.display()))
}

/// Merge an account's CLI login fields into a settings.json document.
pub fn apply_cli_snapshot(doc: &mut Value, account: &Account) {
    let obj = match doc.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    let (endpoint, base_url) = cli_endpoints(account.site);
    let env = obj
        .entry("env")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(env_obj) = env.as_object_mut() {
        let token = account
            .cli_snapshot
            .as_ref()
            .and_then(|s| s.auth_token.clone())
            .or_else(|| account.access_token.plaintext().map(|s| s.to_string()));
        if let Some(t) = token {
            env_obj.insert("CODEBUDDY_AUTH_TOKEN".into(), Value::from(t));
        }
        let base = account
            .cli_snapshot
            .as_ref()
            .and_then(|s| s.base_url.clone())
            .unwrap_or(base_url);
        env_obj.insert("CODEBUDDY_BASE_URL".into(), Value::from(base));
        let ie = account
            .cli_snapshot
            .as_ref()
            .and_then(|s| s.internet_environment.clone())
            .unwrap_or_else(|| "public".to_string());
        env_obj.insert("CODEBUDDY_INTERNET_ENVIRONMENT".into(), Value::from(ie));
    }

    let endpoint = account
        .cli_snapshot
        .as_ref()
        .and_then(|s| s.endpoint.clone())
        .unwrap_or(endpoint);
    obj.insert("endpoint".into(), Value::from(endpoint));

    match account.cli_snapshot.as_ref().and_then(|s| s.gateway.clone()) {
        Some(gw) => {
            obj.insert("gateway".into(), gw);
        }
        // A login the CLI never performed itself must not keep the old
        // account's password around — the CLI would re-login and clobber
        // the switched-in token.
        None => {
            obj.remove("gateway");
        }
    }
}

// ── shared IO helpers ──────────────────────────────────────────────────────

/// Write JSON through a temp file + rename so a failed write never leaves a
/// truncated auth file behind. `std::fs::rename` replaces the destination on
/// Windows (MoveFileExW / MOVEFILE_REPLACE_EXISTING).
pub fn write_atomic(path: &std::path::Path, doc: &Value) -> AppResult<()> {
    let tmp = path.with_extension(format!(
        "wcm-tmp-{}",
        chrono::Utc::now().timestamp_millis()
    ));
    std::fs::write(&tmp, serde_json::to_string_pretty(doc)?)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e.into())
        }
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Whether a WorkBuddy desktop process is running (Windows only check).
pub fn client_process_running() -> bool {
    if !cfg!(target_os = "windows") {
        return false;
    }
    let out = std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output();
    let Ok(out) = out else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    text.contains("\"workbuddy.exe\"")
        || text.contains("\"workbuddyai.exe\"")
        || text.contains("workbuddy.exe")
        || text.contains("workbuddyai.exe")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::account::{Account, CredentialValue};
    use serde_json::json;

    fn account(source: crate::models::account::Source) -> Account {
        Account::new(
            "user@example.com",
            Site::Global,
            source,
            CredentialValue::plain("access.jwt.token"),
            CredentialValue::plain("refresh-token"),
        )
    }

    #[test]
    fn parse_and_preserve_extra_keys() {
        let doc = json!({
            "account": {"uid": "u1"},
            "auth": {"accessToken": "a"},
            "accounts": [{"uid": "u1"}],
            "allAccounts": []
        });
        let parsed = parse_desktop_auth_file(&doc).unwrap();
        assert_eq!(parsed.extra.len(), 2);
        assert!(parsed.extra.contains_key("accounts"));

        assert!(parse_desktop_auth_file(&json!({"account": {}})).is_none());
    }

    #[test]
    fn display_falls_back_through_fields() {
        assert_eq!(display_of_account(&json!({"nickname": "nick"})), "nick");
        assert_eq!(display_of_account(&json!({"phoneNumber": "138*"})), "138*");
        assert_eq!(display_of_account(&json!({"uin": "123", "uid": "abcd1234-xx"})), "123");
        assert_eq!(
            display_of_account(&json!({"uid": "abcd1234-5678"})),
            "uid-abcd1234"
        );
        // encrypted nickname (object) is skipped
        assert_eq!(
            display_of_account(&json!({"nickname": {"$wbEncrypted": 1}, "uin": "77"})),
            "77"
        );
    }

    #[test]
    fn read_current_desktop_parses_status() {
        let raw = serde_json::to_string(&json!({
            "account": {"uid": "u-12345678", "nickname": "nick", "phoneNumber": "13800000000"},
            "auth": {
                "accessToken": "x.y.z",
                "domain": "www.workbuddy.ai",
                "expiresAt": 1823857525844i64
            }
        }))
        .unwrap();
        let info = read_current_from_str(ClientKind::DesktopAi, &raw).unwrap();
        assert_eq!(info.uid, "u-12345678");
        assert_eq!(info.display, "nick");
        assert_eq!(info.phone.as_deref(), Some("13800000000"));
        assert_eq!(info.site, Site::Global);
        assert_eq!(info.expires_at_ms, 1823857525844);
        assert!(!info.encrypted);
    }

    #[test]
    fn desktop_payload_uses_snapshot_verbatim_and_marks_login() {
        let mut acc = account(crate::models::account::Source::DesktopAi);
        acc.desktop_snapshot = Some(crate::models::account::DesktopSnapshot {
            account: json!({"uid": "u1", "lastLogin": false}),
            auth: json!({"accessToken": {"$wbEncrypted": 1}}),
        });
        let (a, auth) = desktop_payload(&acc, ClientKind::DesktopAi);
        assert_eq!(a["uid"], "u1");
        assert_eq!(a["lastLogin"], true);
        assert_eq!(auth["accessToken"]["$wbEncrypted"], 1);
        assert!(auth.get("domain").is_none()); // untouched extras preserved
    }

    #[test]
    fn desktop_payload_synthesizes_minimal_blocks() {
        let mut acc = account(crate::models::account::Source::OAuth);
        acc.uid = Some("u9".into());
        acc.expires_in = 3600;
        let (a, auth) = desktop_payload(&acc, ClientKind::DesktopAi);
        assert_eq!(a["uid"], "u9");
        assert_eq!(a["nickname"], "user@example.com");
        assert_eq!(auth["accessToken"], "access.jwt.token");
        assert_eq!(auth["domain"], "www.workbuddy.ai");
        assert_eq!(auth["expiresIn"], 3600);
        assert!(auth["expiresAt"].as_i64().unwrap() > now_ms());
    }

    #[test]
    fn cli_merge_sets_token_and_drops_foreign_gateway() {
        let mut doc = json!({
            "codebuddy": {"version": "1"},
            "endpoint": "https://www.workbuddy.ai",
            "env": {"CODEBUDDY_AUTH_TOKEN": "old", "OTHER": "keep"},
            "gateway": {"auth": "password", "password": "secret"}
        });
        apply_cli_snapshot(&mut doc, &account(crate::models::account::Source::OAuth));

        assert_eq!(doc["env"]["CODEBUDDY_AUTH_TOKEN"], "access.jwt.token");
        assert_eq!(doc["env"]["OTHER"], "keep");
        assert_eq!(doc["endpoint"], "https://www.workbuddy.ai");
        assert_eq!(doc["env"]["CODEBUDDY_BASE_URL"], "https://www.codebuddy.ai/v2");
        assert_eq!(doc["env"]["CODEBUDDY_INTERNET_ENVIRONMENT"], "public");
        // OAuth account never logged the CLI in itself: password must go
        assert!(doc.get("gateway").is_none());
    }

    #[test]
    fn cli_merge_restores_snapshot_gateway() {
        let mut doc = json!({"env": {}});
        let mut acc = account(crate::models::account::Source::Cli);
        acc.cli_snapshot = Some(crate::models::account::CliSnapshot {
            auth_token: Some("snap-token".into()),
            base_url: Some("https://www.codebuddy.ai/v2".into()),
            internet_environment: Some("public".into()),
            endpoint: Some("https://www.workbuddy.ai".into()),
            gateway: Some(json!({"auth": "password", "password": "own"})),
        });
        apply_cli_snapshot(&mut doc, &acc);
        assert_eq!(doc["env"]["CODEBUDDY_AUTH_TOKEN"], "snap-token");
        assert_eq!(doc["gateway"]["password"], "own");
        assert_eq!(doc["endpoint"], "https://www.workbuddy.ai");
    }

    #[test]
    fn atomic_write_replaces_and_verifies() {
        let dir = std::env::temp_dir().join(format!("wcm-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("workbuddy-desktop.info");

        write_atomic(&path, &json!({"account": {"uid": "a"}})).unwrap();
        write_atomic(&path, &json!({"account": {"uid": "b"}})).unwrap();
        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["account"]["uid"], "b");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
