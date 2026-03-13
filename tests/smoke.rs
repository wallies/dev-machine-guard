use std::process::Command;

fn binary_path() -> String {
    let debug = env!("CARGO_BIN_EXE_stepsecurity-dev-machine-guard");
    debug.to_string()
}

fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(binary_path())
        .args(args)
        .output()
        .expect("failed to execute binary");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(1);
    (stdout, stderr, code)
}

// ─── Script Basics ──────────────────────────────────────────────────────────

#[test]
fn test_help_exits_0() {
    let (_, stderr, code) = run(&["--help"]);
    assert_eq!(code, 0, "Expected exit 0 for --help");
    assert!(
        stderr.contains("Usage:"),
        "--help should show usage, got: {}",
        stderr
    );
}

#[test]
fn test_version_exits_0() {
    let (stdout, _, code) = run(&["--version"]);
    assert_eq!(code, 0, "Expected exit 0 for --version");
    assert!(
        stdout.contains("StepSecurity Dev Machine Guard v"),
        "--version should print version string, got: {}",
        stdout
    );
}

#[test]
fn test_invalid_flag_exits_nonzero() {
    let (_, stderr, code) = run(&["--bogus-flag"]);
    assert_ne!(code, 0, "Expected non-zero exit for invalid flag");
    assert!(
        stderr.contains("Unknown option"),
        "Should show error for invalid flag, got: {}",
        stderr
    );
}

// ─── Pretty Output ─────────────────────────────────────────────────────────

#[test]
fn test_pretty_output_contains_headers() {
    let (stdout, stderr, _) = run(&["--color=never"]);
    let combined = format!("{}{}", stdout, stderr);
    assert!(combined.contains("StepSecurity"), "Should contain StepSecurity");
    assert!(combined.contains("DEVICE"), "Should contain DEVICE header");
    assert!(
        combined.contains("AI AGENTS"),
        "Should contain AI AGENTS header"
    );
    assert!(combined.contains("SUMMARY"), "Should contain SUMMARY header");
}

// ─── JSON Output ────────────────────────────────────────────────────────────

#[test]
fn test_json_output_valid() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");
    assert!(value.is_object(), "JSON should be an object");
}

#[test]
fn test_json_top_level_keys() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let obj = value.as_object().unwrap();

    for key in &[
        "agent_version",
        "device",
        "ai_agents_and_tools",
        "ide_installations",
        "ide_extensions",
        "mcp_configs",
        "summary",
    ] {
        assert!(obj.contains_key(*key), "JSON missing top-level key: {}", key);
    }
}

#[test]
fn test_json_scan_metadata() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let obj = value.as_object().unwrap();

    for key in &["scan_timestamp", "scan_timestamp_iso", "agent_version"] {
        assert!(
            obj.contains_key(*key),
            "JSON missing scan metadata field: {}",
            key
        );
    }
}

#[test]
fn test_json_device_fields() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let device = value.get("device").expect("Missing device object");

    for key in &["hostname", "os_version"] {
        assert!(
            device.get(*key).is_some(),
            "device missing field: {}",
            key
        );
    }
}

#[test]
fn test_json_summary_counts() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let summary = value.get("summary").expect("Missing summary object");

    for key in &[
        "ai_agents_and_tools_count",
        "ide_installations_count",
        "ide_extensions_count",
        "mcp_configs_count",
        "node_projects_count",
    ] {
        let val = summary.get(*key).unwrap_or_else(|| panic!("summary missing field: {}", key));
        assert!(val.is_number(), "summary.{} should be a number", key);
    }
}

// ─── JSON Schema Validation ────────────────────────────────────────────────

#[test]
fn test_json_ai_tools_schema() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let items = value
        .get("ai_agents_and_tools")
        .and_then(|v| v.as_array())
        .unwrap();
    for (i, item) in items.iter().enumerate() {
        assert!(
            item.get("name").is_some(),
            "ai_agents_and_tools[{}] missing name",
            i
        );
        assert!(
            item.get("type").is_some(),
            "ai_agents_and_tools[{}] missing type",
            i
        );
    }
}

#[test]
fn test_json_ide_installations_schema() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let items = value
        .get("ide_installations")
        .and_then(|v| v.as_array())
        .unwrap();
    for (i, item) in items.iter().enumerate() {
        assert!(
            item.get("ide_type").is_some(),
            "ide_installations[{}] missing ide_type",
            i
        );
        assert!(
            item.get("version").is_some(),
            "ide_installations[{}] missing version",
            i
        );
    }
}

#[test]
fn test_json_ide_extensions_schema() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let items = value
        .get("ide_extensions")
        .and_then(|v| v.as_array())
        .unwrap();
    for (i, item) in items.iter().enumerate() {
        assert!(
            item.get("name").is_some(),
            "ide_extensions[{}] missing name",
            i
        );
        assert!(
            item.get("publisher").is_some(),
            "ide_extensions[{}] missing publisher",
            i
        );
        assert!(
            item.get("ide_type").is_some(),
            "ide_extensions[{}] missing ide_type",
            i
        );
    }
}

#[test]
fn test_json_mcp_configs_schema() {
    let (stdout, _, _) = run(&["--json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let items = value
        .get("mcp_configs")
        .and_then(|v| v.as_array())
        .unwrap();
    for (i, item) in items.iter().enumerate() {
        assert!(
            item.get("config_source").is_some(),
            "mcp_configs[{}] missing config_source",
            i
        );
        assert!(
            item.get("config_path").is_some(),
            "mcp_configs[{}] missing config_path",
            i
        );
        assert!(
            item.get("vendor").is_some(),
            "mcp_configs[{}] missing vendor",
            i
        );
    }
}

// ─── HTML Output ────────────────────────────────────────────────────────────

#[test]
fn test_html_output() {
    let tmp = std::env::temp_dir().join("test-dmg-smoke.html");
    let tmp_str = tmp.to_string_lossy().to_string();
    let _ = run(&["--html", &tmp_str]);

    assert!(tmp.exists(), "HTML file should exist");
    let content = std::fs::read_to_string(&tmp).expect("Should read HTML file");
    assert!(!content.is_empty(), "HTML file should not be empty");
    assert!(content.contains("<html"), "HTML should contain <html tag");
    assert!(content.contains("</html>"), "HTML should contain </html> tag");
    let _ = std::fs::remove_file(&tmp);
}

// ─── Flag Combinations ─────────────────────────────────────────────────────

#[test]
fn test_verbose_runs() {
    let (stdout, stderr, _) = run(&["--verbose", "--color=never"]);
    let combined = format!("{}{}", stdout, stderr);
    assert!(!combined.is_empty(), "--verbose should produce output");
}

#[test]
fn test_json_verbose_valid() {
    let (stdout, _, _) = run(&["--json", "--verbose"]);
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json --verbose should produce valid JSON");
}

#[test]
fn test_color_never_json_valid() {
    let (stdout, _, _) = run(&["--color=never", "--json"]);
    let _: serde_json::Value =
        serde_json::from_str(&stdout).expect("--color=never --json should produce valid JSON");
}
