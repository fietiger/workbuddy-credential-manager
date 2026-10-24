//! Structured file-based logger that writes to the app data directory.
//!
//! Logs are stored at:
//!   Windows: C:\Users\<user>\AppData\Roaming\workbuddy-credential-manager\logs\app.log
//!   Linux:   ~/.local/share/workbuddy-credential-manager/logs/app.log
//!   macOS:   ~/Library/Application Support/workbuddy-credential-manager/logs/app.log
//!
//! Each log line: `[2026-01-01T12:00:00Z] [INFO] [module] message`

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::SystemTime;

/// Log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// Global logger state (initialised lazily).
struct LoggerState {
    min_level: LogLevel,
}

static LOGGER: OnceLock<Mutex<LoggerState>> = OnceLock::new();

fn logger_state() -> &'static Mutex<LoggerState> {
    LOGGER.get_or_init(|| {
        Mutex::new(LoggerState {
            min_level: LogLevel::Info,
        })
    })
}

/// Initialise the logger. Call once at app startup.
///
/// If `verbose` is true, the minimum level is lowered to Debug.
pub fn init(verbose: bool) {
    let mut guard = logger_state().lock().expect("logger mutex poisoned");
    guard.min_level = if verbose {
        LogLevel::Debug
    } else {
        LogLevel::Info
    };
}

fn log_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("workbuddy-credential-manager")
        .join("logs")
}

fn log_file_path() -> Result<PathBuf, String> {
    let dir = log_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create log dir {:?}: {}", dir, e))?;
    Ok(dir.join("app.log"))
}

/// Return the log directory as a display-friendly string (for the status panel).
pub fn log_dir_display() -> String {
    log_dir().to_string_lossy().to_string()
}

/// Open the log directory in the system file manager.
pub fn open_log_dir() -> Result<(), String> {
    let dir = log_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create log dir: {}", e))?;

    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = std::process::Command::new("explorer");
        c.arg(&dir);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(&dir);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(&dir);
        c
    };

    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("failed to open {}: {}", dir.display(), e))
}

/// Append a single log line to the file and stderr.
fn append_line(level: LogLevel, module: &str, message: &str) {
    let guard = logger_state().lock().expect("logger mutex poisoned");
    if level < guard.min_level {
        return;
    }

    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = ts.as_secs();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days);
    let ts_str = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s);

    let line = format!(
        "[{}] [{}] [{}] {}\n",
        ts_str,
        level.as_str(),
        module,
        message
    );

    let path = match log_file_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[logger] could not open log file: {}", e);
            return;
        }
    };

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{}", line);
    } else {
        eprintln!("[logger] failed to open {}", path.display());
    }

    // Also print to stderr for immediate visibility in terminal runs
    eprint!("{}", line);
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u32, u32, u32) {
    let mut y: u32 = 1970;
    loop {
        let leap = is_leap(y);
        let days_in_year: u64 = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        y += 1;
    }
    let month_days: [u64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo: u32 = 1;
    let mut rem = days;
    for md in &month_days {
        if rem < *md {
            break;
        }
        rem -= *md;
        mo += 1;
    }
    (y, mo, rem as u32 + 1)
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── public API ─────────────────────────────────────────────────────────────

pub fn log_info(module: &str, message: &str) {
    append_line(LogLevel::Info, module, message);
}

pub fn log_warn(module: &str, message: &str) {
    append_line(LogLevel::Warn, module, message);
}

pub fn log_error(module: &str, message: &str) {
    append_line(LogLevel::Error, module, message);
}

pub fn log_debug(module: &str, message: &str) {
    append_line(LogLevel::Debug, module, message);
}
