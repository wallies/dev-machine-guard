use std::env;
use std::fs;
#[cfg(target_os = "macos")]
use std::path::Path;

use crate::util::*;

// ─── Platform Detection ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Platform {
    MacOS,
    Linux,
    Windows,
    Unknown,
}

pub fn current_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Unknown
    }
}

pub fn platform_string() -> &'static str {
    match current_platform() {
        Platform::MacOS => "darwin",
        Platform::Linux => "linux",
        Platform::Windows => "windows",
        Platform::Unknown => "unknown",
    }
}

// ─── System Info ────────────────────────────────────────────────────────────

pub fn get_hostname() -> String {
    // Try the hostname command (cross-platform)
    let h = run_cmd("hostname", &[]);
    if !h.is_empty() {
        return h;
    }

    // Fallback: environment or gethostname
    #[cfg(unix)]
    {
        if let Ok(name) = fs::read_to_string("/etc/hostname") {
            let name = name.trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(name) = env::var("COMPUTERNAME") {
            return name;
        }
    }

    "unknown".to_string()
}

pub fn get_os_version() -> String {
    match current_platform() {
        Platform::MacOS => {
            let ver = run_cmd("sw_vers", &["-productVersion"]);
            if ver.is_empty() { "unknown".to_string() } else { ver }
        }
        Platform::Linux => {
            // Try /etc/os-release
            if let Ok(content) = fs::read_to_string("/etc/os-release") {
                for line in content.lines() {
                    if let Some(rest) = line.strip_prefix("VERSION_ID=") {
                        return rest.trim_matches('"').to_string();
                    }
                }
                for line in content.lines() {
                    if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                        return rest.trim_matches('"').to_string();
                    }
                }
            }
            // Fallback: uname -r
            let ver = run_cmd("uname", &["-r"]);
            if ver.is_empty() { "unknown".to_string() } else { ver }
        }
        Platform::Windows => {
            // Use ver command or read from registry
            let (stdout, _, _) = run_cmd_full("cmd", &["/C", "ver"]);
            let ver = stdout.trim().to_string();
            if ver.is_empty() { "unknown".to_string() } else { ver }
        }
        Platform::Unknown => "unknown".to_string(),
    }
}

pub fn get_serial_number() -> String {
    match current_platform() {
        Platform::MacOS => {
            // Read from IOKit via ioreg
            let output = run_cmd("ioreg", &["-l"]);
            for line in output.lines() {
                if line.contains("IOPlatformSerialNumber") {
                    if let Some(val) = extract_quoted_value(line) {
                        return val;
                    }
                }
            }
            // Fallback
            let output = run_cmd("system_profiler", &["SPHardwareDataType"]);
            for line in output.lines() {
                if line.contains("Serial") {
                    if let Some(serial) = line.split_whitespace().last() {
                        return serial.to_string();
                    }
                }
            }
            "unknown".to_string()
        }
        Platform::Linux => {
            // Try DMI data
            for path in &[
                "/sys/class/dmi/id/product_serial",
                "/sys/class/dmi/id/board_serial",
            ] {
                if let Ok(serial) = fs::read_to_string(path) {
                    let serial = serial.trim().to_string();
                    if !serial.is_empty() && serial != "None" {
                        return serial;
                    }
                }
            }
            // Fallback: machine-id
            if let Ok(id) = fs::read_to_string("/etc/machine-id") {
                let id = id.trim().to_string();
                if !id.is_empty() {
                    return id;
                }
            }
            "unknown".to_string()
        }
        Platform::Windows => {
            let output = run_cmd("wmic", &["bios", "get", "serialnumber"]);
            // Output is multi-line, skip header
            for line in output.lines().skip(1) {
                let line = line.trim();
                if !line.is_empty() {
                    return line.to_string();
                }
            }
            "unknown".to_string()
        }
        Platform::Unknown => "unknown".to_string(),
    }
}

pub fn get_developer_identity(username: &str) -> String {
    for var in &["USER_EMAIL", "DEVELOPER_EMAIL", "STEPSEC_DEVELOPER_EMAIL"] {
        if let Ok(val) = env::var(var) {
            if !val.is_empty() {
                return val;
            }
        }
    }
    username.to_string()
}

// ─── IDE Installation Paths ─────────────────────────────────────────────────

pub struct IdeLocation {
    pub app_name: &'static str,
    pub ide_type: &'static str,
    pub vendor: &'static str,
    pub paths: &'static [&'static str], // Platform-specific; ~ expands to home
    pub version_binary: &'static str,   // Relative to install path or absolute binary name
    pub version_flag: &'static str,
}

/// Get IDE definitions for the current platform.
/// Paths use ~ for home dir, and {app} for the detected install path.
pub fn ide_definitions() -> Vec<IdeLocation> {
    match current_platform() {
        Platform::MacOS => vec![
            IdeLocation {
                app_name: "Visual Studio Code",
                ide_type: "vscode",
                vendor: "Microsoft",
                paths: &["/Applications/Visual Studio Code.app"],
                version_binary: "code",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Cursor",
                ide_type: "cursor",
                vendor: "Cursor",
                paths: &["/Applications/Cursor.app"],
                version_binary: "cursor",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Windsurf",
                ide_type: "windsurf",
                vendor: "Codeium",
                paths: &["/Applications/Windsurf.app"],
                version_binary: "windsurf",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Antigravity",
                ide_type: "antigravity",
                vendor: "Google",
                paths: &["/Applications/Antigravity.app"],
                version_binary: "antigravity",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Zed",
                ide_type: "zed",
                vendor: "Zed",
                paths: &["/Applications/Zed.app"],
                version_binary: "",
                version_flag: "",
            },
            IdeLocation {
                app_name: "Claude",
                ide_type: "claude_desktop",
                vendor: "Anthropic",
                paths: &["/Applications/Claude.app"],
                version_binary: "",
                version_flag: "",
            },
            IdeLocation {
                app_name: "Microsoft Copilot",
                ide_type: "microsoft_copilot_desktop",
                vendor: "Microsoft",
                paths: &["/Applications/Copilot.app"],
                version_binary: "",
                version_flag: "",
            },
        ],
        Platform::Linux => vec![
            IdeLocation {
                app_name: "Visual Studio Code",
                ide_type: "vscode",
                vendor: "Microsoft",
                paths: &["/usr/share/code", "/snap/code/current", "/usr/bin/code"],
                version_binary: "code",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Cursor",
                ide_type: "cursor",
                vendor: "Cursor",
                paths: &["~/.local/share/cursor", "/opt/Cursor"],
                version_binary: "cursor",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Windsurf",
                ide_type: "windsurf",
                vendor: "Codeium",
                paths: &["~/.local/share/windsurf", "/opt/Windsurf"],
                version_binary: "windsurf",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Zed",
                ide_type: "zed",
                vendor: "Zed",
                paths: &["~/.local/bin/zed", "/usr/bin/zed"],
                version_binary: "zed",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Claude",
                ide_type: "claude_desktop",
                vendor: "Anthropic",
                paths: &["/opt/Claude", "~/.local/share/claude-desktop"],
                version_binary: "",
                version_flag: "",
            },
        ],
        Platform::Windows => vec![
            IdeLocation {
                app_name: "Visual Studio Code",
                ide_type: "vscode",
                vendor: "Microsoft",
                paths: &[
                    "C:\\Program Files\\Microsoft VS Code",
                    "~\\AppData\\Local\\Programs\\Microsoft VS Code",
                ],
                version_binary: "code",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Cursor",
                ide_type: "cursor",
                vendor: "Cursor",
                paths: &["~\\AppData\\Local\\Programs\\Cursor"],
                version_binary: "cursor",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Windsurf",
                ide_type: "windsurf",
                vendor: "Codeium",
                paths: &["~\\AppData\\Local\\Programs\\Windsurf"],
                version_binary: "windsurf",
                version_flag: "--version",
            },
            IdeLocation {
                app_name: "Claude",
                ide_type: "claude_desktop",
                vendor: "Anthropic",
                paths: &["~\\AppData\\Local\\Programs\\Claude"],
                version_binary: "",
                version_flag: "",
            },
        ],
        Platform::Unknown => vec![],
    }
}

// ─── MCP Config Paths ───────────────────────────────────────────────────────

pub struct McpConfigDef {
    pub source_name: &'static str,
    pub config_path: &'static str, // Relative to home
    pub vendor: &'static str,
}

pub fn mcp_config_definitions() -> Vec<McpConfigDef> {
    let mut configs = vec![
        McpConfigDef { source_name: "claude_code", config_path: ".claude/settings.json", vendor: "Anthropic" },
        McpConfigDef { source_name: "claude_code", config_path: ".claude.json", vendor: "Anthropic" },
        McpConfigDef { source_name: "cursor", config_path: ".cursor/mcp.json", vendor: "Cursor" },
    ];

    match current_platform() {
        Platform::MacOS => {
            configs.insert(0, McpConfigDef {
                source_name: "claude_desktop",
                config_path: "Library/Application Support/Claude/claude_desktop_config.json",
                vendor: "Anthropic",
            });
            configs.push(McpConfigDef { source_name: "windsurf", config_path: ".codeium/windsurf/mcp_config.json", vendor: "Codeium" });
            configs.push(McpConfigDef { source_name: "antigravity", config_path: ".gemini/antigravity/mcp_config.json", vendor: "Google" });
        }
        Platform::Linux => {
            configs.push(McpConfigDef {
                source_name: "claude_desktop",
                config_path: ".config/Claude/claude_desktop_config.json",
                vendor: "Anthropic",
            });
            configs.push(McpConfigDef { source_name: "windsurf", config_path: ".codeium/windsurf/mcp_config.json", vendor: "Codeium" });
        }
        Platform::Windows => {
            configs.push(McpConfigDef {
                source_name: "claude_desktop",
                config_path: "AppData/Roaming/Claude/claude_desktop_config.json",
                vendor: "Anthropic",
            });
            configs.push(McpConfigDef { source_name: "windsurf", config_path: ".codeium/windsurf/mcp_config.json", vendor: "Codeium" });
        }
        _ => {}
    }

    configs.push(McpConfigDef { source_name: "zed", config_path: ".config/zed/settings.json", vendor: "Zed" });
    configs.push(McpConfigDef { source_name: "open_interpreter", config_path: ".config/open-interpreter/config.yaml", vendor: "OpenSource" });
    configs.push(McpConfigDef { source_name: "codex", config_path: ".codex/config.toml", vendor: "OpenAI" });

    configs
}

// ─── IDE Extension Directories ──────────────────────────────────────────────

pub struct ExtensionDir {
    pub ide_name: &'static str,
    pub ide_type: &'static str,
    pub dir_suffix: &'static str, // Relative to home
}

pub fn extension_directories() -> Vec<ExtensionDir> {
    vec![
        ExtensionDir { ide_name: "VSCode", ide_type: "vscode", dir_suffix: ".vscode/extensions" },
        ExtensionDir { ide_name: "OpenVSX", ide_type: "openvsx", dir_suffix: ".cursor/extensions" },
    ]
}

// ─── Process Detection ──────────────────────────────────────────────────────

/// Check if a process with the given name is running.
pub fn is_process_running(name: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        let output = run_cmd("pgrep", &["-x", name]);
        !output.is_empty()
    }
    #[cfg(target_os = "linux")]
    {
        // Check /proc
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path().join("comm");
                if let Ok(comm) = fs::read_to_string(&path) {
                    if comm.trim() == name {
                        return true;
                    }
                }
            }
        }
        false
    }
    #[cfg(target_os = "windows")]
    {
        let output = run_cmd("tasklist", &["/FI", &format!("IMAGENAME eq {}.exe", name), "/NH"]);
        output.contains(name)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

// ─── macOS Plist Reading ────────────────────────────────────────────────────

/// Read a version string from a macOS Info.plist file.
#[cfg(target_os = "macos")]
pub fn read_plist_version(app_path: &str) -> Option<String> {
    let plist_path = format!("{}/Contents/Info.plist", app_path);
    let path = Path::new(&plist_path);
    if !path.exists() {
        return None;
    }
    let value = plist::Value::from_file(path).ok()?;
    let dict = value.as_dictionary()?;
    dict.get("CFBundleShortVersionString")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn read_plist_version(_app_path: &str) -> Option<String> {
    None
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Expand ~ to home directory in a path string.
pub fn expand_home(path: &str) -> String {
    if path.starts_with("~/") || path.starts_with("~\\") {
        if let Some(home) = home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    }
    path.to_string()
}

/// Extract a quoted value from a line like: "key" = "value"
fn extract_quoted_value(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split('"').collect();
    // The value is typically the 4th quoted segment: key "=" "value"
    if parts.len() >= 4 {
        let val = parts[parts.len() - 2].trim();
        if !val.is_empty() {
            return Some(val.to_string());
        }
    }
    None
}
