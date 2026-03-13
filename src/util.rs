use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::types::ColorMode;

/// Run a command directly (no shell), returning trimmed stdout.
/// Returns empty string on failure.
pub fn run_cmd(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Run a command, returning (stdout, stderr, exit_code).
pub fn run_cmd_full(program: &str, args: &[&str]) -> (String, String, i32) {
    match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let code = output.status.code().unwrap_or(1);
            (stdout, stderr, code)
        }
        Err(_) => (String::new(), String::new(), 1),
    }
}

/// Run a command, returning stdout even on non-zero exit (useful for npm ls which exits 1 with peer dep issues).
pub fn run_cmd_stdout(program: &str, args: &[&str]) -> (String, String, i32) {
    match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let code = output.status.code().unwrap_or(1);
            (stdout, stderr, code)
        }
        Err(_) => (String::new(), String::new(), 127),
    }
}

/// Run a command in a specific working directory.
pub fn run_cmd_in_dir(program: &str, args: &[&str], dir: &str) -> (String, String, i32) {
    match Command::new(program)
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let code = output.status.code().unwrap_or(1);
            (stdout, stderr, code)
        }
        Err(_) => (String::new(), String::new(), 127),
    }
}

/// Search PATH for a binary and return its full path, or None.
pub fn which(binary: &str) -> Option<PathBuf> {
    // On Windows also check .exe, .cmd, .bat
    let extensions: Vec<String> = if cfg!(windows) {
        env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
            .split(';')
            .map(|s| s.to_string())
            .collect()
    } else {
        vec![String::new()]
    };

    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        for ext in &extensions {
            let candidate = dir.join(format!("{}{}", binary, ext));
            if candidate.is_file() {
                // On Unix, check if executable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&candidate) {
                        if meta.permissions().mode() & 0o111 == 0 {
                            continue;
                        }
                    }
                }
                return Some(candidate);
            }
        }
    }
    None
}

/// Get the first line of `binary --version` output.
pub fn get_version(binary_path: &str, flag: &str) -> String {
    let output = run_cmd(binary_path, &[flag]);
    output
        .lines()
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string()
}

/// Get current timestamp as epoch seconds.
pub fn timestamp_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Format timestamp as ISO 8601.
pub fn timestamp_to_iso(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// Format timestamp for display.
pub fn timestamp_to_display(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Escape HTML special characters.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Print progress message to stderr.
pub fn print_progress(verbose: bool, msg: &str) {
    if verbose {
        eprintln!("\x1b[2m[scanning]\x1b[0m {}", msg);
    }
}

/// Print error to stderr.
pub fn print_error(msg: &str) {
    eprintln!("\x1b[0;31m[error]\x1b[0m {}", msg);
}

/// Truncate a string with "..." suffix.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() > max && max > 3 {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

/// Check if colors should be used.
pub fn should_use_colors(color_mode: &ColorMode, is_tty: bool) -> bool {
    match color_mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => is_tty,
    }
}

/// Check if stdout is a TTY.
pub fn stdout_is_tty() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
    }
    #[cfg(windows)]
    {
        // On Windows, check using the windows API
        use std::os::windows::io::AsRawHandle;
        let handle = std::io::stdout().as_raw_handle();
        unsafe {
            let mut mode: u32 = 0;
            // GetConsoleMode returns non-zero if handle is a console
            windows_sys::Win32::System::Console::GetConsoleMode(
                handle as _,
                &mut mode,
            ) != 0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Get the user's home directory.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        env::var("USERPROFILE")
            .or_else(|_| env::var("HOMEDRIVE").and_then(|d| env::var("HOMEPATH").map(|p| format!("{}{}", d, p))))
            .ok()
            .map(PathBuf::from)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Get the current username.
pub fn current_username() -> String {
    #[cfg(unix)]
    {
        env::var("USER")
            .or_else(|_| env::var("LOGNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(windows)]
    {
        env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(any(unix, windows)))]
    {
        "unknown".to_string()
    }
}
