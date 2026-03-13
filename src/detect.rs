use std::fs;
use std::path::Path;

use crate::platform::*;
use crate::types::*;
use crate::util::*;

// ─── IDE Detection ──────────────────────────────────────────────────────────

pub fn detect_ide_installations(verbose: bool) -> Vec<IdeInstallation> {
    print_progress(verbose, "Detecting IDE and AI desktop app installations...");
    let mut results = Vec::new();

    for ide in ide_definitions() {
        let mut found_path: Option<String> = None;

        // Check each candidate path
        for raw_path in ide.paths {
            let path_str = expand_home(raw_path);
            let path = Path::new(&path_str);

            // On macOS: check for .app directories
            // On Linux/Windows: check for directory or binary
            if path.exists() {
                found_path = Some(path_str);
                break;
            }
        }

        let install_path = match found_path {
            Some(p) => p,
            None => {
                // Also try finding the binary in PATH
                if !ide.version_binary.is_empty() {
                    if let Some(bin_path) = which(ide.version_binary) {
                        // Found in PATH but no install directory; use binary parent
                        bin_path
                            .parent()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default()
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
        };

        let mut version = String::from("unknown");

        // Try to get version from binary
        if !ide.version_binary.is_empty() && !ide.version_flag.is_empty() {
            if let Some(bin_path) = which(ide.version_binary) {
                let ver = get_version(&bin_path.to_string_lossy(), ide.version_flag);
                if !ver.is_empty() && ver != "unknown" {
                    version = ver;
                }
            }
        }

        // Fallback: macOS plist
        if version == "unknown" {
            if let Some(plist_ver) = read_plist_version(&install_path) {
                version = plist_ver;
            }
        }

        print_progress(
            verbose,
            &format!("  Found: {} ({}) v{} at {}", ide.app_name, ide.vendor, version, install_path),
        );

        results.push(IdeInstallation {
            ide_type: ide.ide_type.to_string(),
            version,
            install_path,
            vendor: ide.vendor.to_string(),
            is_installed: true,
        });
    }

    if results.is_empty() {
        print_progress(verbose, "  No IDEs or AI desktop apps found");
    }

    results
}

// ─── AI CLI Tools Detection ─────────────────────────────────────────────────

struct CliToolDef {
    tool_name: &'static str,
    vendor: &'static str,
    binary_names: &'static [&'static str],
    config_dirs: &'static [&'static str],
    version_flag: &'static str,
}

const CLI_TOOL_DEFS: &[CliToolDef] = &[
    CliToolDef {
        tool_name: "claude-code",
        vendor: "Anthropic",
        binary_names: &["claude"],
        config_dirs: &["~/.claude"],
        version_flag: "--version",
    },
    CliToolDef {
        tool_name: "codex",
        vendor: "OpenAI",
        binary_names: &["codex"],
        config_dirs: &["~/.codex"],
        version_flag: "--version",
    },
    CliToolDef {
        tool_name: "gemini-cli",
        vendor: "Google",
        binary_names: &["gemini"],
        config_dirs: &["~/.gemini"],
        version_flag: "--version",
    },
    CliToolDef {
        tool_name: "amazon-q-cli",
        vendor: "Amazon",
        binary_names: &["kiro-cli", "kiro", "q"],
        config_dirs: &["~/.q", "~/.kiro", "~/.aws/q"],
        version_flag: "--version",
    },
    CliToolDef {
        tool_name: "github-copilot-cli",
        vendor: "Microsoft",
        binary_names: &["copilot", "gh-copilot"],
        config_dirs: &["~/.config/github-copilot"],
        version_flag: "--version",
    },
    CliToolDef {
        tool_name: "microsoft-ai-shell",
        vendor: "Microsoft",
        binary_names: &["aish", "ai"],
        config_dirs: &["~/.aish"],
        version_flag: "--version",
    },
    CliToolDef {
        tool_name: "aider",
        vendor: "OpenSource",
        binary_names: &["aider"],
        config_dirs: &["~/.aider"],
        version_flag: "--version",
    },
    CliToolDef {
        tool_name: "opencode",
        vendor: "OpenSource",
        binary_names: &["opencode"],
        config_dirs: &["~/.config/opencode"],
        version_flag: "-v",
    },
];

pub fn detect_ai_cli_tools(verbose: bool) -> Vec<AiTool> {
    print_progress(verbose, "Detecting AI CLI tools...");
    let mut results = Vec::new();

    for tool in CLI_TOOL_DEFS {
        let mut found_binary: Option<String> = None;
        let mut version = String::from("unknown");

        // Search for the binary in PATH
        for binary_name in tool.binary_names {
            if let Some(bin_path) = which(binary_name) {
                let bin_str = bin_path.to_string_lossy().to_string();

                // Special: verify amazon-q-cli is actually Amazon Q
                if tool.tool_name == "amazon-q-cli" {
                    let ver_output = run_cmd(&bin_str, &["--version"]);
                    let lower = ver_output.to_lowercase();
                    if !lower.contains("amazon") && !lower.contains("kiro") && !lower.contains("q developer") {
                        continue;
                    }
                }

                // Get version
                let ver = get_version(&bin_str, tool.version_flag);
                if !ver.is_empty() && ver != "unknown" {
                    version = ver;
                }

                found_binary = Some(bin_str);
                break;
            }
        }

        // Also check home-relative paths
        if found_binary.is_none() {
            let extra_paths: Vec<String> = match tool.tool_name {
                "claude-code" => vec![
                    expand_home("~/.claude/local/claude"),
                    expand_home("~/.local/bin/claude"),
                ],
                "opencode" => vec![expand_home("~/.opencode/bin/opencode")],
                _ => vec![],
            };

            for extra in &extra_paths {
                let path = Path::new(extra);
                if path.is_file() {
                    let ver = get_version(extra, tool.version_flag);
                    if !ver.is_empty() && ver != "unknown" {
                        version = ver;
                    }
                    found_binary = Some(extra.clone());
                    break;
                }
            }
        }

        if let Some(binary_path) = found_binary {
            // Find config directory
            let config_dir = tool.config_dirs.iter().find_map(|dir| {
                let expanded = expand_home(dir);
                if Path::new(&expanded).is_dir() {
                    Some(expanded)
                } else {
                    None
                }
            });

            print_progress(
                verbose,
                &format!("  Found: {} ({}) v{} at {}", tool.tool_name, tool.vendor, version, binary_path),
            );

            results.push(AiTool {
                name: tool.tool_name.to_string(),
                vendor: tool.vendor.to_string(),
                tool_type: "cli_tool".to_string(),
                version,
                binary_path: Some(binary_path),
                config_dir,
                install_path: None,
                is_running: None,
            });
        }
    }

    if results.is_empty() {
        print_progress(verbose, "  No AI CLI tools found");
    } else {
        print_progress(verbose, &format!("  Found {} AI CLI tool(s)", results.len()));
    }

    results
}

// ─── General-Purpose AI Agents Detection ────────────────────────────────────

struct AgentDef {
    agent_name: &'static str,
    vendor: &'static str,
    detection_dir: &'static str,
    binary_name: &'static str,
}

const AGENT_DEFS: &[AgentDef] = &[
    AgentDef { agent_name: "openclaw", vendor: "OpenSource", detection_dir: ".openclaw", binary_name: "openclaw" },
    AgentDef { agent_name: "clawdbot", vendor: "OpenSource", detection_dir: ".clawdbot", binary_name: "clawdbot" },
    AgentDef { agent_name: "moltbot", vendor: "OpenSource", detection_dir: ".moltbot", binary_name: "moltbot" },
    AgentDef { agent_name: "moldbot", vendor: "OpenSource", detection_dir: ".moldbot", binary_name: "moldbot" },
    AgentDef { agent_name: "gpt-engineer", vendor: "OpenSource", detection_dir: ".gpt-engineer", binary_name: "gpt-engineer" },
];

pub fn detect_general_ai_agents(verbose: bool) -> Vec<AiTool> {
    print_progress(verbose, "Detecting general-purpose AI agents...");
    let mut results = Vec::new();

    let home = home_dir().unwrap_or_default();

    for agent in AGENT_DEFS {
        let detection_path = home.join(agent.detection_dir);
        let mut found = false;
        let mut install_path = String::new();
        let mut version = String::from("unknown");

        if detection_path.exists() {
            found = true;
            install_path = detection_path.to_string_lossy().to_string();
        }

        if !found {
            if let Some(bin_path) = which(agent.binary_name) {
                found = true;
                install_path = bin_path.to_string_lossy().to_string();
            }
        }

        if found {
            if let Some(bin_path) = which(agent.binary_name) {
                let ver = get_version(&bin_path.to_string_lossy(), "--version");
                if !ver.is_empty() && ver != "unknown" {
                    version = ver;
                }
            }

            print_progress(verbose, &format!("  Found: {} ({}) at {}", agent.agent_name, agent.vendor, install_path));

            results.push(AiTool {
                name: agent.agent_name.to_string(),
                vendor: agent.vendor.to_string(),
                tool_type: "general_agent".to_string(),
                version,
                binary_path: None,
                config_dir: None,
                install_path: Some(install_path),
                is_running: None,
            });
        }
    }

    // Claude Cowork (macOS-only: mode within Claude Desktop 0.7.0+)
    #[cfg(target_os = "macos")]
    {
        let claude_desktop_path = "/Applications/Claude.app";
        if Path::new(claude_desktop_path).is_dir() {
            if let Some(ver) = read_plist_version(claude_desktop_path) {
                let supports_cowork = ver.starts_with("0.7")
                    || ver.starts_with("0.8")
                    || ver.starts_with("0.9")
                    || ver.chars().next().map(|c| c.is_ascii_digit() && c != '0').unwrap_or(false);

                if supports_cowork {
                    print_progress(verbose, &format!("  Found: claude-cowork (Anthropic) v{}", ver));
                    results.push(AiTool {
                        name: "claude-cowork".to_string(),
                        vendor: "Anthropic".to_string(),
                        tool_type: "general_agent".to_string(),
                        version: ver,
                        binary_path: None,
                        config_dir: None,
                        install_path: Some(claude_desktop_path.to_string()),
                        is_running: None,
                    });
                }
            }
        }
    }

    if results.is_empty() {
        print_progress(verbose, "  No general-purpose AI agents found");
    } else {
        print_progress(verbose, &format!("  Found {} general-purpose AI agent(s)", results.len()));
    }

    results
}

// ─── AI Frameworks Detection ────────────────────────────────────────────────

struct FrameworkDef {
    name: &'static str,
    binary: &'static str,
    process: &'static str,
}

const FRAMEWORK_DEFS: &[FrameworkDef] = &[
    FrameworkDef { name: "ollama", binary: "ollama", process: "ollama" },
    FrameworkDef { name: "localai", binary: "local-ai", process: "local-ai" },
    FrameworkDef { name: "lm-studio", binary: "lm-studio", process: "lm-studio" },
    FrameworkDef { name: "text-generation-webui", binary: "textgen", process: "textgen" },
];

pub fn detect_ai_frameworks(verbose: bool) -> Vec<AiTool> {
    print_progress(verbose, "Detecting AI frameworks and runtimes...");
    let mut results = Vec::new();

    for fw in FRAMEWORK_DEFS {
        if let Some(bin_path) = which(fw.binary) {
            let bin_str = bin_path.to_string_lossy().to_string();
            let version = get_version(&bin_str, "--version");
            let is_running = is_process_running(fw.process);

            print_progress(
                verbose,
                &format!("  Found: {} v{} at {} (running: {})", fw.name, version, bin_str, is_running),
            );

            results.push(AiTool {
                name: fw.name.to_string(),
                vendor: "Unknown".to_string(),
                tool_type: "framework".to_string(),
                version,
                binary_path: Some(bin_str),
                config_dir: None,
                install_path: None,
                is_running: Some(is_running),
            });
        }
    }

    // LM Studio as an application (macOS)
    #[cfg(target_os = "macos")]
    {
        let lm_studio_app = "/Applications/LM Studio.app";
        if Path::new(lm_studio_app).is_dir() {
            let version = read_plist_version(lm_studio_app).unwrap_or_else(|| "unknown".to_string());
            let is_running = is_process_running("LM Studio");

            print_progress(verbose, &format!("  Found: lm-studio v{} (running: {})", version, is_running));

            results.push(AiTool {
                name: "lm-studio".to_string(),
                vendor: "LM Studio".to_string(),
                tool_type: "framework".to_string(),
                version,
                binary_path: Some(lm_studio_app.to_string()),
                config_dir: None,
                install_path: None,
                is_running: Some(is_running),
            });
        }
    }

    if results.is_empty() {
        print_progress(verbose, "  No AI frameworks found");
    } else {
        print_progress(verbose, &format!("  Found {} AI framework(s)", results.len()));
    }

    results
}

// ─── MCP Config Collection ──────────────────────────────────────────────────

pub fn collect_mcp_configs(is_enterprise: bool, verbose: bool) -> Vec<McpConfig> {
    print_progress(verbose, "Collecting MCP configuration files...");
    let mut results = Vec::new();

    let home = match home_dir() {
        Some(h) => h,
        None => return results,
    };

    for source in mcp_config_definitions() {
        let config_path = home.join(source.config_path);

        if !config_path.is_file() {
            continue;
        }

        // Cap file reads at 10MB to prevent memory exhaustion
        let metadata = match fs::metadata(&config_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if metadata.len() > 10 * 1024 * 1024 {
            print_progress(verbose, &format!("  Skipping {}: file too large ({}B)", source.source_name, metadata.len()));
            continue;
        }

        let content = match fs::read_to_string(&config_path) {
            Ok(c) if !c.is_empty() => c,
            _ => {
                print_progress(verbose, &format!("  Skipping {}: empty or unreadable", source.source_name));
                continue;
            }
        };

        // For JSON configs, filter to extract only MCP server info (no secrets)
        let filtered = if config_path.to_string_lossy().ends_with(".json") {
            filter_mcp_json(&content, source.source_name)
        } else {
            content.clone()
        };

        print_progress(verbose, &format!("  Found: {} config ({})", source.source_name, source.vendor));

        let config_content_base64 = if is_enterprise {
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                filtered.as_bytes(),
            ))
        } else {
            None
        };

        results.push(McpConfig {
            config_source: source.source_name.to_string(),
            config_path: config_path.to_string_lossy().to_string(),
            vendor: source.vendor.to_string(),
            config_content_base64,
        });
    }

    if results.is_empty() {
        print_progress(verbose, "  No MCP config files found");
    } else {
        print_progress(verbose, &format!("  Found {} MCP config file(s)", results.len()));
    }

    results
}

/// Filter MCP JSON to extract only server names, commands, and URLs (no secrets).
fn filter_mcp_json(content: &str, source_name: &str) -> String {
    // Strip JSONC comments for Zed configs
    let cleaned = if source_name == "zed" {
        strip_jsonc_comments(content)
    } else {
        content.to_string()
    };

    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&cleaned);
    let value = match parsed {
        Ok(v) => v,
        Err(_) => return content.to_string(), // Can't parse, return raw
    };

    // Extract mcpServers or context_servers
    let servers = value.get("mcpServers")
        .or_else(|| value.get("context_servers"));

    if let Some(servers) = servers {
        if let Some(obj) = servers.as_object() {
            let filtered: serde_json::Map<String, serde_json::Value> = obj
                .iter()
                .map(|(k, v)| {
                    let mut entry = serde_json::Map::new();
                    if let Some(cmd) = v.get("command") {
                        entry.insert("command".to_string(), cmd.clone());
                    }
                    if let Some(args) = v.get("args") {
                        entry.insert("args".to_string(), args.clone());
                    }
                    if let Some(url) = v.get("serverUrl").or_else(|| v.get("url")) {
                        entry.insert("url".to_string(), url.clone());
                    }
                    (k.clone(), serde_json::Value::Object(entry))
                })
                .collect();
            let mut result = serde_json::Map::new();
            result.insert("mcpServers".to_string(), serde_json::Value::Object(filtered));
            return serde_json::to_string(&serde_json::Value::Object(result)).unwrap_or_default();
        }
    }

    content.to_string()
}

/// Strip // and /* */ comments from JSONC.
fn strip_jsonc_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_string = false;

    while i < len {
        if in_string {
            result.push(chars[i]);
            if chars[i] == '\\' && i + 1 < len {
                i += 1;
                result.push(chars[i]);
            } else if chars[i] == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if chars[i] == '"' {
            in_string = true;
            result.push(chars[i]);
            i += 1;
            continue;
        }

        if chars[i] == '/' && i + 1 < len {
            if chars[i + 1] == '/' {
                // Line comment - skip to end of line
                i += 2;
                while i < len && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            } else if chars[i + 1] == '*' {
                // Block comment - skip to */
                i += 2;
                while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2; // skip */
                continue;
            }
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}

// ─── IDE Extension Collection ───────────────────────────────────────────────

pub fn collect_ide_extensions(verbose: bool) -> Vec<IdeExtension> {
    print_progress(verbose, "Scanning IDE extensions...");
    let mut all_extensions = Vec::new();

    let home = match home_dir() {
        Some(h) => h,
        None => return all_extensions,
    };

    for ext_dir_def in extension_directories() {
        let ext_dir = home.join(ext_dir_def.dir_suffix);
        if !ext_dir.is_dir() {
            continue;
        }

        let exts = scan_extension_dir(&ext_dir.to_string_lossy(), ext_dir_def.ide_type);
        print_progress(verbose, &format!("  Found {} {} extensions", exts.len(), ext_dir_def.ide_name));
        all_extensions.extend(exts);
    }

    if all_extensions.is_empty() {
        print_progress(verbose, "  No IDE extensions found");
    } else {
        print_progress(verbose, &format!("Found total of {} IDE extensions", all_extensions.len()));
    }

    all_extensions
}

fn scan_extension_dir(ext_dir: &str, ide_type: &str) -> Vec<IdeExtension> {
    let mut extensions = Vec::new();

    let obsolete_path = format!("{}/.obsolete", ext_dir);
    let obsolete_content = fs::read_to_string(&obsolete_path).unwrap_or_else(|_| "{}".to_string());

    let entries = match fs::read_dir(ext_dir) {
        Ok(entries) => entries,
        Err(_) => return extensions,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let dirname = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };

        if dirname == "extensions.json" || dirname == ".obsolete" {
            continue;
        }

        if obsolete_content.contains(&format!("\"{}\":true", dirname)) {
            continue;
        }

        // Parse: publisher.name-version[-platform]
        let (publisher, rest) = match dirname.split_once('.') {
            Some((p, r)) => (p.to_string(), r.to_string()),
            None => continue,
        };

        // Remove platform suffix
        let rest = if let Some(idx) = rest.find("-darwin-") {
            rest[..idx].to_string()
        } else if let Some(idx) = rest.find("-linux-") {
            rest[..idx].to_string()
        } else if let Some(idx) = rest.find("-win32-") {
            rest[..idx].to_string()
        } else {
            rest.strip_suffix("-universal").unwrap_or(&rest).to_string()
        };

        let (name, version) = match rest.rfind('-') {
            Some(idx) => (rest[..idx].to_string(), rest[idx + 1..].to_string()),
            None => continue,
        };

        if publisher.is_empty() || name.is_empty() || version.is_empty() {
            continue;
        }

        let install_date = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        extensions.push(IdeExtension {
            id: format!("{}.{}", publisher, name),
            name,
            version,
            publisher,
            install_date,
            ide_type: ide_type.to_string(),
        });
    }

    extensions
}
