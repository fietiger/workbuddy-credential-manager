mod commands;
mod error;
mod models;
mod modules;

use crate::modules::logger;
use commands::*;

pub fn run() {
    // Initialise logger (verbose if WB_LOG_DEBUG=1)
    let verbose = std::env::var("WB_LOG_DEBUG").is_ok();
    logger::init(verbose);
    logger::log_info(
        "app",
        &format!(
            "workbuddy-credential-manager {} starting",
            env!("CARGO_PKG_VERSION")
        ),
    );
    logger::log_info("app", &format!("log file: {}", logger::log_dir_display()));

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            // account ops
            list_accounts,
            delete_account,
            update_account_notes,
            activate_account,
            refresh_account,
            // oauth
            oauth_start,
            oauth_poll,
            import_refresh_token,
            // local import
            import_local_preview,
            import_local_accounts,
            // clients
            list_clients,
            // import/export
            import_accounts_json,
            export_accounts,
            default_export_path,
            choose_export_path,
            save_export_file,
            // status
            get_status,
            open_log_dir,
        ])
        .run(tauri::generate_context!());

    if let Err(e) = result {
        logger::log_error("app", &format!("Tauri runtime exited with error: {}", e));
    }
}
