//! Tauri IPC command handlers exposed to the frontend.

use crate::error::{AppError, AppResult};
use crate::models::account::{Account, Site};
use crate::modules::account_store;
use crate::modules::client_sync::{self, ClientKind, ClientStatus, ClientSyncResult};
use crate::modules::local_import;
use crate::modules::logger;
use crate::modules::wb_auth::{self, AuthSession};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::OnceLock;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

// ── DTO types returned to the frontend ───────────────────────────────────

/// A safe (non-sensitive) view of an account for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    pub id: String,
    pub display: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    pub site: Site,
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: i64,
    pub last_used: i64,
    pub access_token_masked: String,
    pub refresh_token_masked: String,
    pub access_token_valid: bool,
    pub expires_at_ms: i64,
    /// Credentials are encrypted envelopes (limited switching + no refresh).
    pub encrypted: bool,
    pub can_refresh: bool,
    /// Every client this account is currently switched into.
    pub active_in: Vec<ClientKind>,
}

impl From<&Account> for AccountView {
    fn from(acc: &Account) -> Self {
        let active_in = account_store::load_index()
            .map(|idx| account_store::active_clients_for(&idx, &acc.id))
            .unwrap_or_default();
        Self {
            id: acc.id.clone(),
            display: acc.display.clone(),
            uid: acc.uid.clone(),
            email: acc.email.clone(),
            phone: acc.phone.clone(),
            site: acc.site,
            source: acc.source.name(),
            notes: acc.notes.clone(),
            created_at: acc.created_at,
            last_used: acc.last_used,
            access_token_masked: acc.access_token.masked(),
            refresh_token_masked: acc.refresh_token.masked(),
            access_token_valid: acc.is_access_token_valid(),
            expires_at_ms: acc.expires_at_ms,
            encrypted: acc.access_token.is_encrypted() || acc.refresh_token.is_encrypted(),
            can_refresh: acc.refresh_token.plaintext().is_some_and(|s| !s.is_empty()),
            active_in,
        }
    }
}

/// Status information returned by `get_status`.
#[derive(Debug, Clone, Serialize)]
pub struct AppStatus {
    pub data_dir: String,
    pub log_dir: String,
}

// ── account ops ────────────────────────────────────────────────────────────

/// List all managed accounts (non-sensitive view).
#[tauri::command]
pub fn list_accounts() -> AppResult<Vec<AccountView>> {
    let idx = account_store::load_index()?;
    let mut views: Vec<AccountView> = Vec::new();
    for summary in &idx.accounts {
        if let Ok(acc) = account_store::get_account(&summary.id) {
            views.push(AccountView::from(&acc));
        }
    }
    Ok(views)
}

/// Delete an account.
#[tauri::command]
pub fn delete_account(id: String) -> AppResult<()> {
    logger::log_info("cmd", &format!("Deleting account id={}", id));
    account_store::delete_account(&id)?;
    logger::log_info("cmd", &format!("Account {} deleted", id));
    Ok(())
}

/// Update an account's notes / label.
#[tauri::command]
pub fn update_account_notes(id: String, notes: String) -> AppResult<AccountView> {
    let mut acc = account_store::get_account(&id)?;
    let trimmed = notes.trim().to_string();
    acc.notes = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    };
    account_store::save_account(&acc)?;
    Ok(AccountView::from(&acc))
}

/// Refresh an account's access token right now (needs a plaintext refresh
/// token). Encrypted-envelope accounts cannot be refreshed here.
#[tauri::command]
pub async fn refresh_account(id: String) -> AppResult<AccountView> {
    logger::log_info("cmd", &format!("Refreshing account id={}", id));
    let acc = account_store::get_account(&id)?;
    let refresh = acc
        .refresh_token
        .plaintext()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            AppError::Validation("该账号的 refresh token 是加密信封，无法在本机刷新".to_string())
        })?
        .to_string();

    let client = wb_auth::AuthClient::new()?;
    let tokens = client
        .refresh(
            acc.site,
            acc.access_token.plaintext().unwrap_or(""),
            &refresh,
        )
        .await?;
    let expires_at_ms = if tokens.expires_in > 0 {
        chrono::Utc::now().timestamp_millis() + tokens.expires_in * 1000
    } else {
        acc.expires_at_ms
    };

    let mut acc = acc;
    account_store::apply_token_set(&mut acc, &tokens, expires_at_ms);
    account_store::save_account(&acc)?;
    logger::log_info("cmd", &format!("Account {} refreshed", acc.display));
    Ok(AccountView::from(&acc))
}

/// Switch an account into ONE selected client (`target`).
///
/// Each client holds its account independently — the other clients keep
/// whichever account they already have. The result reports that single
/// client's outcome.
#[tauri::command]
pub async fn activate_account(id: String, target: ClientKind) -> AppResult<ClientSyncResult> {
    logger::log_info(
        "cmd",
        &format!("Activating account id={} into client {}", id, target.name()),
    );
    let mut acc = account_store::get_account(&id)?;

    // Best-effort refresh first: a stale access token would otherwise be
    // written into the client. A failure here is not fatal — desktop
    // clients refresh on their own.
    if !acc.is_access_token_valid() {
        if let Some(refresh) = acc
            .refresh_token
            .plaintext()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            logger::log_info("cmd", "Access token expired, refreshing before switch");
            match wb_auth::AuthClient::new()?
                .refresh(
                    acc.site,
                    acc.access_token.plaintext().unwrap_or(""),
                    &refresh,
                )
                .await
            {
                Ok(tokens) => {
                    let expires_at_ms = if tokens.expires_in > 0 {
                        chrono::Utc::now().timestamp_millis() + tokens.expires_in * 1000
                    } else {
                        acc.expires_at_ms
                    };
                    account_store::apply_token_set(&mut acc, &tokens, expires_at_ms);
                    account_store::save_account(&acc)?;
                }
                Err(e) => logger::log_warn(
                    "cmd",
                    &format!(
                        "Pre-switch refresh failed ({}); continuing with stored token",
                        e
                    ),
                ),
            }
        }
    }

    let result = client_sync::switch(target, &acc);
    if result.ok {
        acc.update_last_used();
        account_store::save_account(&acc)?;
        account_store::set_client_account(&id, target)?;
    }
    logger::log_info(
        "cmd",
        &format!("client {}: ok={} {}", result.name, result.ok, result.detail),
    );
    Ok(result)
}

/// Detect installed clients and the account each one is signed in with.
#[tauri::command]
pub fn list_clients() -> AppResult<Vec<ClientStatus>> {
    let mut out = Vec::new();
    for kind in [
        ClientKind::DesktopCn,
        ClientKind::DesktopAi,
        ClientKind::Cli,
    ] {
        let path = client_sync::client_file_path(kind);
        let installed = match &path {
            Some(p) => match kind {
                ClientKind::Cli => p.is_file(),
                // the auth folder must exist; the live file may be absent
                // when the client is installed but signed out
                _ => p.parent().map(|d| d.is_dir()).unwrap_or(false),
            },
            None => false,
        };
        let current = path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|raw| client_sync::read_current_from_str(kind, &raw));
        out.push(ClientStatus {
            client: kind,
            name: kind.name().to_string(),
            installed,
            path: path
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            current,
        });
    }
    Ok(out)
}

// ── OAuth ──────────────────────────────────────────────────────────────────

fn sessions() -> &'static Mutex<std::collections::HashMap<String, AuthSession>> {
    static SESSIONS: OnceLock<Mutex<std::collections::HashMap<String, AuthSession>>> =
        OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Start an OAuth login: returns the URL to open in a browser.
/// The UI then polls `oauth_poll` until success.
#[tauri::command]
pub async fn oauth_start(site: Site) -> AppResult<AuthSession> {
    let session = wb_auth::AuthClient::new()?.start(site).await?;
    logger::log_info(
        "oauth",
        &format!(
            "OAuth session started for {} ({})",
            site.name(),
            session.state
        ),
    );
    sessions()
        .lock()
        .map_err(|_| AppError::Other("session lock poisoned".into()))?
        .insert(session.state.clone(), session.clone());
    Ok(session)
}

/// Poll the login result once. On success the account is created (or its
/// credentials updated) and returned.
#[tauri::command]
pub async fn oauth_poll(state: String) -> AppResult<OAuthPollResult> {
    let session = {
        let map = sessions()
            .lock()
            .map_err(|_| AppError::Other("session lock poisoned".into()))?;
        map.get(&state).cloned()
    }
    .ok_or_else(|| AppError::Oauth("授权会话不存在或已取消，请重新发起".to_string()))?;

    if chrono::Utc::now().timestamp() > session.expires_at {
        sessions()
            .lock()
            .map_err(|_| AppError::Other("session lock poisoned".into()))?
            .remove(&state);
        return Err(AppError::Oauth(
            "授权会话已过期（30 分钟），请重新发起登录".to_string(),
        ));
    }

    let client = wb_auth::AuthClient::new()?;
    match client.poll(&session).await? {
        None => Ok(OAuthPollResult {
            status: "pending".into(),
            message: "等待你在浏览器中完成登录…".into(),
            account: None,
        }),
        Some(tokens) => {
            let (acc, created) = account_store::upsert_from_token_set(session.site, &tokens)?;
            sessions()
                .lock()
                .map_err(|_| AppError::Other("session lock poisoned".into()))?
                .remove(&state);
            logger::log_info(
                "oauth",
                &format!(
                    "OAuth login finished: {} account {} ({})",
                    if created { "created" } else { "updated" },
                    acc.display,
                    session.site.name()
                ),
            );
            Ok(OAuthPollResult {
                status: "success".into(),
                message: if created {
                    format!("已添加账号 {}", acc.display)
                } else {
                    format!("已更新账号 {} 的凭证", acc.display)
                },
                account: Some(AccountView::from(&acc)),
            })
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OAuthPollResult {
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountView>,
}

/// Import an account by pasting a refresh token (plus optional access token).
#[tauri::command]
pub fn import_refresh_token(
    site: Site,
    refresh_token: String,
    access_token: Option<String>,
    label: Option<String>,
) -> AppResult<AccountView> {
    let acc = account_store::import_from_refresh_token(site, &refresh_token, access_token, label)?;
    Ok(AccountView::from(&acc))
}

// ── local import ───────────────────────────────────────────────────────────

/// Detect the accounts sitting on this machine without importing anything.
#[tauri::command]
pub fn import_local_preview() -> AppResult<Vec<local_import::ImportCandidate>> {
    logger::log_info("cmd", "Detecting accounts on local clients");
    local_import::preview_local_import()
}

/// Import the selected local accounts (empty selection = all).
#[tauri::command]
pub fn import_local_accounts(
    selected: Option<Vec<String>>,
) -> AppResult<local_import::LocalImportSummary> {
    logger::log_info(
        "cmd",
        &format!(
            "Importing accounts from local clients ({})",
            selected
                .as_ref()
                .map_or("all".to_string(), |s| format!("{} selected", s.len()))
        ),
    );
    Ok(local_import::import_local_accounts(selected))
}

// ── import / export ────────────────────────────────────────────────────────

/// Import accounts from this app's own export format.
#[tauri::command]
pub fn import_accounts_json(content: String) -> AppResult<account_store::ImportSummary> {
    logger::log_info("cmd", "Importing accounts from JSON file content");
    account_store::import_accounts(&content)
}

/// Export all accounts as JSON.
#[tauri::command]
pub fn export_accounts() -> AppResult<account_store::AccountExportResponse> {
    account_store::export_accounts()
}

/// Default export target: the downloads folder plus the dated file name.
#[tauri::command]
pub fn default_export_path() -> AppResult<String> {
    let dir = dirs::download_dir()
        .or_else(dirs::home_dir)
        .ok_or_else(|| AppError::Other("Could not determine a default export folder".into()))?;
    Ok(dir.join(export_file_name()).to_string_lossy().to_string())
}

fn export_file_name() -> String {
    format!(
        "workbuddy-credentials-{}.json",
        chrono::Utc::now().format("%Y-%m-%d")
    )
}

/// Open a native save dialog pre-filled with the current export target.
/// Returns the chosen path, or `None` when the user cancels the dialog.
#[tauri::command]
pub async fn choose_export_path(
    window: tauri::WebviewWindow,
    current_path: String,
) -> AppResult<Option<String>> {
    let current = PathBuf::from(&current_path);
    let file_name = current
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(export_file_name);
    let mut dialog = window
        .app_handle()
        .dialog()
        .file()
        .set_file_name(file_name)
        .add_filter("JSON", &["json"])
        .set_parent(&window);
    if let Some(dir) = current.parent().filter(|p| !p.as_os_str().is_empty()) {
        dialog = dialog.set_directory(dir);
    }
    let chosen = dialog.blocking_save_file();
    chosen
        .map(|path| {
            path.into_path()
                .map(|p| p.to_string_lossy().to_string())
                .map_err(|e| AppError::Other(e.to_string()))
        })
        .transpose()
}

/// Write the frontend-rendered export to the user-chosen path and return it.
/// The path comes from the native save dialog, so overwriting it is intended.
#[tauri::command]
pub fn save_export_file(content: String, path: String) -> AppResult<String> {
    let path = PathBuf::from(path);
    match std::fs::write(&path, content.as_bytes()) {
        Ok(()) => {
            logger::log_info("cmd", &format!("Export saved to {}", path.display()));
            Ok(path.to_string_lossy().to_string())
        }
        Err(e) => {
            logger::log_error("cmd", &format!("Export failed: {}", e));
            Err(e.into())
        }
    }
}

// ── status ─────────────────────────────────────────────────────────────────

/// Get app status.
#[tauri::command]
pub fn get_status() -> AppResult<AppStatus> {
    Ok(AppStatus {
        data_dir: account_store::data_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        log_dir: crate::modules::logger::log_dir_display(),
    })
}

/// Open the log directory in the system file manager.
#[tauri::command]
pub fn open_log_dir() -> AppResult<()> {
    logger::log_info("cmd", "Opening log directory");
    logger::open_log_dir().map_err(|e| {
        logger::log_error("cmd", &e);
        AppError::Other(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_writes_to_the_chosen_path_and_overwrites() {
        let dir = std::env::temp_dir().join(format!("wcm-export-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("picked-by-user.json");
        let path_str = path.to_string_lossy().to_string();

        save_export_file("{\"v\":1}".into(), path_str.clone()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"v\":1}");

        save_export_file("{\"v\":2}".into(), path_str).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"v\":2}");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
