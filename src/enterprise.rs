use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::detect::*;
use crate::node_scan::*;
use crate::platform::*;
use crate::types::*;
use crate::util::*;

// ─── Enterprise Mode Detection ──────────────────────────────────────────────

pub fn is_enterprise_mode(config: &Config) -> bool {
    !config.api_key.is_empty() && !config.api_key.contains("{{")
}

// ─── Instance Locking ───────────────────────────────────────────────────────

fn get_lock_file_path() -> String {
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::getuid() } == 0;
        if is_root {
            return "/var/run/stepsecurity-agent.lock".to_string();
        }
    }

    let home = home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| {
            if cfg!(windows) { std::env::var("TEMP").unwrap_or_else(|_| "C:\\Temp".to_string()) }
            else { "/tmp".to_string() }
        });
    let lock_dir = format!("{}/.stepsecurity", home);
    let _ = fs::create_dir_all(&lock_dir);
    format!("{}/agent.lock", lock_dir)
}

pub fn acquire_lock() -> Result<(), String> {
    let lock_file = get_lock_file_path();
    let my_pid = std::process::id();

    if Path::new(&lock_file).exists() {
        if let Ok(contents) = fs::read_to_string(&lock_file) {
            if let Ok(existing_pid) = contents.trim().parse::<u32>() {
                // Check if process is still running
                let still_running = is_pid_running(existing_pid);
                if still_running {
                    return Err(format!(
                        "Another instance is already running (PID: {})",
                        existing_pid
                    ));
                }
                // Stale lock, remove it
                let _ = fs::remove_file(&lock_file);
            }
        }
    }

    // Write our PID
    if let Ok(mut f) = fs::File::create(&lock_file) {
        let _ = write!(f, "{}", my_pid);
    }

    Ok(())
}

fn is_pid_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let status = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output();
        if let Ok(output) = status {
            return output.status.success();
        }
        false
    }
    #[cfg(windows)]
    {
        let output = run_cmd("tasklist", &["/FI", &format!("PID eq {}", pid), "/NH"]);
        output.contains(&pid.to_string())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

pub fn release_lock() {
    let lock_file = get_lock_file_path();
    let my_pid = std::process::id();

    if let Ok(contents) = fs::read_to_string(&lock_file) {
        if let Ok(pid) = contents.trim().parse::<u32>() {
            if pid == my_pid {
                let _ = fs::remove_file(&lock_file);
            }
        }
    }
}

// ─── Scheduling Management ─────────────────────────────────────────────────

pub fn configure_scheduling(config: &Config) -> Result<(), String> {
    match current_platform() {
        Platform::MacOS => configure_launchd(config),
        Platform::Linux => configure_systemd(config),
        Platform::Windows => configure_task_scheduler(config),
        Platform::Unknown => Err("Unsupported platform for scheduling".to_string()),
    }
}

pub fn uninstall_scheduling() {
    match current_platform() {
        Platform::MacOS => uninstall_launchd(),
        Platform::Linux => uninstall_systemd(),
        Platform::Windows => uninstall_task_scheduler(),
        Platform::Unknown => eprintln!("Unsupported platform for scheduling"),
    }
}

pub fn is_scheduling_configured() -> bool {
    match current_platform() {
        Platform::MacOS => is_launchd_configured(),
        Platform::Linux => is_systemd_configured(),
        Platform::Windows => is_task_scheduler_configured(),
        Platform::Unknown => false,
    }
}

// ─── macOS LaunchD ──────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn configure_launchd(config: &Config) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("Failed to get executable path: {}", e))?;

    let is_root = unsafe { libc::getuid() } == 0;

    let scan_freq: u64 = config
        .scan_frequency_hours
        .parse::<u64>()
        .unwrap_or(6);
    let interval_seconds = scan_freq * 3600;

    eprintln!("Configuring launchd for periodic execution...");
    eprintln!("  Script: {}", exe_path);
    eprintln!("  Interval: Every {} hours ({} seconds)", scan_freq, interval_seconds);

    let (plist_path, log_dir) = if is_root {
        eprintln!("  Type: LaunchDaemon (system-wide)");
        let log_dir = "/var/log/stepsecurity";
        let _ = fs::create_dir_all(log_dir);
        (
            "/Library/LaunchDaemons/com.stepsecurity.agent.plist".to_string(),
            log_dir.to_string(),
        )
    } else {
        eprintln!("  Type: LaunchAgent (user-specific)");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let agents_dir = format!("{}/Library/LaunchAgents", home);
        let _ = fs::create_dir_all(&agents_dir);
        let log_dir = format!("{}/.stepsecurity", home);
        let _ = fs::create_dir_all(&log_dir);
        (
            format!("{}/com.stepsecurity.agent.plist", agents_dir),
            log_dir,
        )
    };

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.stepsecurity.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>send-telemetry</string>
    </array>
    <key>StartInterval</key>
    <integer>{}</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>{}/agent.error.log</string>
</dict>
</plist>"#,
        exe_path, interval_seconds, log_dir, log_dir
    );

    fs::write(&plist_path, plist_content)
        .map_err(|e| format!("Failed to write plist: {}", e))?;

    let status = Command::new("launchctl")
        .args(["load", &plist_path])
        .output();

    match status {
        Ok(output) if output.status.success() => {
            eprintln!("launchd configuration completed successfully");
            eprintln!("  Plist: {}", plist_path);
            eprintln!("  Logs: {}/agent.log", log_dir);
            Ok(())
        }
        _ => Err("Failed to load launchd configuration".to_string()),
    }
}

#[cfg(not(target_os = "macos"))]
fn configure_launchd(_config: &Config) -> Result<(), String> {
    Err("launchd is only available on macOS".to_string())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() {
    let is_root = unsafe { libc::getuid() } == 0;
    let plist_path = if is_root {
        eprintln!("Removing LaunchDaemon configuration...");
        "/Library/LaunchDaemons/com.stepsecurity.agent.plist".to_string()
    } else {
        eprintln!("Removing LaunchAgent configuration...");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/Library/LaunchAgents/com.stepsecurity.agent.plist", home)
    };

    let list_output = run_cmd("launchctl", &["list"]);
    if list_output.contains("com.stepsecurity.agent") {
        let _ = Command::new("launchctl")
            .args(["unload", &plist_path])
            .output();
        eprintln!("Unloaded launchd agent");
    }

    if Path::new(&plist_path).exists() {
        let _ = fs::remove_file(&plist_path);
        eprintln!("Removed plist file: {}", plist_path);
    } else {
        eprintln!("Plist file not found: {}", plist_path);
    }

    eprintln!("launchd configuration removed successfully");
}

#[cfg(not(target_os = "macos"))]
fn uninstall_launchd() {}

#[cfg(target_os = "macos")]
fn is_launchd_configured() -> bool {
    let list_output = run_cmd("launchctl", &["list"]);
    list_output.contains("com.stepsecurity.agent")
}

#[cfg(not(target_os = "macos"))]
fn is_launchd_configured() -> bool {
    false
}

// ─── Linux systemd ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn configure_systemd(config: &Config) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("Failed to get executable path: {}", e))?;

    let scan_freq: u64 = config
        .scan_frequency_hours
        .parse::<u64>()
        .unwrap_or(6);

    eprintln!("Configuring systemd for periodic execution...");
    eprintln!("  Binary: {}", exe_path);
    eprintln!("  Interval: Every {} hours", scan_freq);

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let systemd_dir = format!("{}/.config/systemd/user", home);
    let _ = fs::create_dir_all(&systemd_dir);

    let service_content = format!(
        r#"[Unit]
Description=StepSecurity Dev Machine Guard Agent

[Service]
Type=oneshot
ExecStart={} send-telemetry
"#,
        exe_path
    );

    let timer_content = format!(
        r#"[Unit]
Description=StepSecurity Dev Machine Guard Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec={}h
Persistent=true

[Install]
WantedBy=timers.target
"#,
        scan_freq
    );

    let service_path = format!("{}/stepsecurity-agent.service", systemd_dir);
    let timer_path = format!("{}/stepsecurity-agent.timer", systemd_dir);

    fs::write(&service_path, service_content)
        .map_err(|e| format!("Failed to write service file: {}", e))?;
    fs::write(&timer_path, timer_content)
        .map_err(|e| format!("Failed to write timer file: {}", e))?;

    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    let status = Command::new("systemctl")
        .args(["--user", "enable", "--now", "stepsecurity-agent.timer"])
        .output();

    match status {
        Ok(output) if output.status.success() => {
            eprintln!("systemd configuration completed successfully");
            Ok(())
        }
        _ => Err("Failed to enable systemd timer".to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_systemd(_config: &Config) -> Result<(), String> {
    Err("systemd is only available on Linux".to_string())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() {
    eprintln!("Removing systemd configuration...");
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", "stepsecurity-agent.timer"])
        .output();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let systemd_dir = format!("{}/.config/systemd/user", home);

    for file in &["stepsecurity-agent.service", "stepsecurity-agent.timer"] {
        let path = format!("{}/{}", systemd_dir, file);
        if Path::new(&path).exists() {
            let _ = fs::remove_file(&path);
            eprintln!("Removed: {}", path);
        }
    }

    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    eprintln!("systemd configuration removed successfully");
}

#[cfg(not(target_os = "linux"))]
fn uninstall_systemd() {}

#[cfg(target_os = "linux")]
fn is_systemd_configured() -> bool {
    let output = run_cmd("systemctl", &["--user", "is-enabled", "stepsecurity-agent.timer"]);
    output.trim() == "enabled"
}

#[cfg(not(target_os = "linux"))]
fn is_systemd_configured() -> bool {
    false
}

// ─── Windows Task Scheduler ────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn configure_task_scheduler(config: &Config) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("Failed to get executable path: {}", e))?;

    let scan_freq: u64 = config
        .scan_frequency_hours
        .parse::<u64>()
        .unwrap_or(6);

    eprintln!("Configuring Windows Task Scheduler...");
    eprintln!("  Binary: {}", exe_path);
    eprintln!("  Interval: Every {} hours", scan_freq);

    let interval_minutes = scan_freq * 60;
    let status = Command::new("schtasks")
        .args([
            "/Create", "/F",
            "/SC", "MINUTE",
            "/MO", &interval_minutes.to_string(),
            "/TN", "StepSecurity\\DevMachineGuard",
            "/TR", &format!("\"{}\" send-telemetry", exe_path),
            "/RL", "LIMITED",
        ])
        .output();

    match status {
        Ok(output) if output.status.success() => {
            eprintln!("Task Scheduler configuration completed successfully");
            Ok(())
        }
        _ => Err("Failed to create scheduled task".to_string()),
    }
}

#[cfg(not(target_os = "windows"))]
fn configure_task_scheduler(_config: &Config) -> Result<(), String> {
    Err("Task Scheduler is only available on Windows".to_string())
}

#[cfg(target_os = "windows")]
fn uninstall_task_scheduler() {
    eprintln!("Removing Windows Task Scheduler configuration...");
    let status = Command::new("schtasks")
        .args(["/Delete", "/F", "/TN", "StepSecurity\\DevMachineGuard"])
        .output();
    match status {
        Ok(output) if output.status.success() => {
            eprintln!("Task removed successfully");
        }
        _ => eprintln!("Failed to remove scheduled task (may not exist)"),
    }
}

#[cfg(not(target_os = "windows"))]
fn uninstall_task_scheduler() {}

#[cfg(target_os = "windows")]
fn is_task_scheduler_configured() -> bool {
    let output = run_cmd("schtasks", &["/Query", "/TN", "StepSecurity\\DevMachineGuard"]);
    !output.is_empty()
}

#[cfg(not(target_os = "windows"))]
fn is_task_scheduler_configured() -> bool {
    false
}

// ─── Telemetry Upload (using ureq) ──────────────────────────────────────────

fn upload_telemetry(
    device_id: &str,
    payload_json: &str,
    config: &Config,
) -> Result<(), String> {
    eprintln!("Requesting upload URL from backend...");

    let upload_url_endpoint = format!(
        "{}/v1/{}/developer-mdm-agent/telemetry/upload-url",
        config.api_endpoint, config.customer_id
    );

    let request_body = serde_json::json!({ "device_id": device_id });

    let response = ureq::post(&upload_url_endpoint)
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", config.api_key))
        .set("X-Agent-Version", AGENT_VERSION)
        .send_json(&request_body)
        .map_err(|e| format!("Failed to request upload URL: {}", e))?;

    let response_json: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("Failed to parse upload URL response: {}", e))?;

    let upload_url = response_json
        .get("upload_url")
        .and_then(|v| v.as_str())
        .ok_or("Missing upload_url in response")?
        .to_string();

    let s3_key = response_json
        .get("s3_key")
        .and_then(|v| v.as_str())
        .ok_or("Missing s3_key in response")?
        .to_string();

    eprintln!("Uploading telemetry to S3...");

    let upload_response = ureq::put(&upload_url)
        .set("Content-Type", "application/json")
        .send_string(payload_json)
        .map_err(|e| format!("Failed to upload to S3: {}", e))?;

    if upload_response.status() != 200 {
        return Err(format!("Failed to upload to S3 (HTTP {})", upload_response.status()));
    }

    eprintln!("Uploaded to S3");
    eprintln!("Notifying backend of upload...");

    let process_endpoint = format!(
        "{}/v1/{}/developer-mdm-agent/telemetry/process-uploaded",
        config.api_endpoint, config.customer_id
    );

    let notify_body = serde_json::json!({
        "s3_key": s3_key,
        "device_id": device_id,
    });

    let notify_response = ureq::post(&process_endpoint)
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", config.api_key))
        .set("X-Agent-Version", AGENT_VERSION)
        .send_json(&notify_body)
        .map_err(|e| format!("Failed to notify backend: {}", e))?;

    let status = notify_response.status();
    if status == 200 || status == 201 {
        eprintln!("Backend processing initiated (HTTP {})", status);
        Ok(())
    } else {
        Err(format!("Failed to notify backend (HTTP {})", status))
    }
}

// ─── Run Telemetry (Enterprise Mode) ────────────────────────────────────────

pub fn run_telemetry(config: &Config) {
    println!("==========================================");
    println!("StepSecurity Device Agent v{}", AGENT_VERSION);
    println!("==========================================");
    println!();

    // Acquire lock
    if let Err(e) = acquire_lock() {
        print_error(&e);
        std::process::exit(1);
    }

    // Validate config
    if config.customer_id.contains("{{") || config.api_key.contains("{{") || config.api_endpoint.contains("{{") {
        print_error("This binary needs to be customized with your customer details");
        release_lock();
        std::process::exit(1);
    }

    // Get device identity
    let serial_number = get_serial_number();
    let os_version = get_os_version();
    let device_id = serial_number.clone();
    let hostname = get_hostname();
    let platform = platform_string().to_string();

    // Get current user info
    let username = current_username();
    let user_home = home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let collected_at = timestamp_secs();

    if username.is_empty() || user_home.is_empty() {
        eprintln!("No user currently logged in - skipping data collection");

        let payload = TelemetryPayload {
            customer_id: config.customer_id.clone(),
            device_id: device_id.clone(),
            serial_number: serial_number.clone(),
            user_identity: "none".to_string(),
            hostname,
            platform,
            os_version,
            agent_version: AGENT_VERSION.to_string(),
            collected_at,
            no_user_logged_in: true,
            available_tools: None,
            ide_extensions: vec![],
            ide_installations: vec![],
            node_package_managers: vec![],
            node_global_packages: vec![],
            node_projects: vec![],
            ai_agents: vec![],
            mcp_configs: vec![],
            execution_logs: ExecutionLogs {
                output_base64: String::new(),
                start_time: collected_at,
                end_time: collected_at,
                exit_code: 0,
                agent_version: AGENT_VERSION.to_string(),
            },
            performance_metrics: PerformanceMetrics {
                extensions_count: 0,
                node_packages_scan_ms: 0,
                node_global_packages_count: 0,
                node_projects_count: 0,
            },
        };

        let payload_json = serde_json::to_string_pretty(&payload).unwrap_or_default();

        match upload_telemetry(&device_id, &payload_json, config) {
            Ok(()) => {
                eprintln!("Telemetry sent successfully (no user logged in)");
                release_lock();
                std::process::exit(0);
            }
            Err(e) => {
                print_error(&format!("Telemetry upload failed: {}", e));
                release_lock();
                std::process::exit(1);
            }
        }
    }

    let developer_identity = get_developer_identity(&username);

    eprintln!("Device ID (Serial): {}", device_id);
    eprintln!("OS Version: {}", os_version);
    eprintln!("Developer: {}", developer_identity);
    println!();

    // Run detections
    let ide_installations = detect_ide_installations(true);
    let ai_cli_tools = detect_ai_cli_tools(true);
    let general_ai_agents = detect_general_ai_agents(true);
    let ai_frameworks = detect_ai_frameworks(true);

    let mut ai_agents = Vec::new();
    ai_agents.extend(ai_cli_tools);
    ai_agents.extend(general_ai_agents);
    ai_agents.extend(ai_frameworks);

    let mcp_configs = collect_mcp_configs(true, true);

    let ide_extensions = collect_ide_extensions(true);

    // Node.js scanning
    let enable_npm = config.enable_npm_scan != NpmScanMode::Disabled;
    let mut node_package_managers = vec![];
    let mut node_global_scans = vec![];
    let mut node_project_scans = vec![];
    let mut node_projects_count = 0;

    if enable_npm {
        eprintln!("Node.js package scanning is ENABLED");
        node_package_managers = detect_package_managers(true);
        node_global_scans = scan_global_packages(true);
        let (scans, count) = scan_node_projects(&user_home, true);
        node_project_scans = scans;
        node_projects_count = count;
    } else {
        eprintln!("Node.js package scanning is DISABLED");
    }

    let payload = TelemetryPayload {
        customer_id: config.customer_id.clone(),
        device_id: device_id.clone(),
        serial_number: serial_number.clone(),
        user_identity: developer_identity,
        hostname,
        platform,
        os_version,
        agent_version: AGENT_VERSION.to_string(),
        collected_at,
        no_user_logged_in: false,
        available_tools: None,
        ide_extensions: ide_extensions.clone(),
        ide_installations,
        node_package_managers,
        node_global_packages: node_global_scans,
        node_projects: node_project_scans,
        ai_agents,
        mcp_configs,
        execution_logs: ExecutionLogs {
            output_base64: String::new(),
            start_time: collected_at,
            end_time: timestamp_secs(),
            exit_code: 0,
            agent_version: AGENT_VERSION.to_string(),
        },
        performance_metrics: PerformanceMetrics {
            extensions_count: ide_extensions.len(),
            node_packages_scan_ms: 0,
            node_global_packages_count: 0,
            node_projects_count,
        },
    };

    let payload_json = serde_json::to_string_pretty(&payload).unwrap_or_default();

    match upload_telemetry(&device_id, &payload_json, config) {
        Ok(()) => {
            println!();
            eprintln!("Telemetry collection completed successfully");
            release_lock();
            std::process::exit(0);
        }
        Err(e) => {
            println!();
            print_error(&format!("Telemetry upload failed: {}", e));
            release_lock();
            std::process::exit(1);
        }
    }
}
