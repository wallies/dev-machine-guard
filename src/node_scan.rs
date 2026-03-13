use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use base64::Engine;
use walkdir::WalkDir;

use crate::types::*;
use crate::util::*;

// ─── Package Manager Detection ──────────────────────────────────────────────

pub fn detect_package_managers(verbose: bool) -> Vec<PackageManager> {
    print_progress(verbose, "Detecting Node.js package managers...");
    let mut managers = Vec::new();

    let checks: &[(&str, &str)] = &[
        ("npm", "--version"),
        ("yarn", "--version"),
        ("pnpm", "--version"),
        ("bun", "--version"),
    ];

    for (name, flag) in checks {
        if let Some(path) = which(name) {
            let version = run_cmd(&path.to_string_lossy(), &[flag]);
            let version = if version.is_empty() { "unknown".to_string() } else { version };
            let path_str = path.to_string_lossy().to_string();

            print_progress(verbose, &format!("  Found: {} v{} at {}", name, version, path_str));

            managers.push(PackageManager {
                name: name.to_string(),
                version,
                is_global: true,
                binary_path: path_str,
            });
        }
    }

    if managers.is_empty() {
        print_progress(verbose, "  No Node.js package managers found");
    }

    managers
}

// ─── Global Package Scanning ────────────────────────────────────────────────

pub fn scan_global_packages(verbose: bool) -> Vec<NodeProjectScan> {
    print_progress(verbose, "Scanning globally installed packages...");
    let mut scans = Vec::new();

    scan_npm_global(verbose, &mut scans);
    scan_yarn_global(verbose, &mut scans);
    scan_pnpm_global(verbose, &mut scans);

    if scans.is_empty() {
        print_progress(verbose, "  No globally installed packages found");
    } else {
        print_progress(verbose, &format!("  Found {} global package location(s)", scans.len()));
    }

    scans
}

fn scan_npm_global(verbose: bool, scans: &mut Vec<NodeProjectScan>) {
    print_progress(verbose, "  Checking npm global packages...");

    if which("npm").is_none() {
        return;
    }

    let npm_version = run_cmd("npm", &["--version"]);
    let npm_prefix = run_cmd("npm", &["config", "get", "prefix"]);

    if npm_prefix.is_empty() {
        return;
    }

    let start = Instant::now();
    let (stdout, stderr, exit_code) = run_cmd_stdout("npm", &["list", "-g", "--json", "--depth=3"]);

    let duration = start.elapsed().as_millis() as u64;
    let error = if exit_code != 0 {
        format!("npm list -g command failed with exit code {}", exit_code)
    } else {
        String::new()
    };

    scans.push(NodeProjectScan {
        project_path: npm_prefix.clone(),
        package_manager: "npm".to_string(),
        package_manager_version: Some(npm_version),
        working_directory: npm_prefix,
        raw_stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        raw_stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr.as_bytes()),
        error,
        exit_code,
        scan_duration_ms: duration,
    });
}

fn scan_yarn_global(verbose: bool, scans: &mut Vec<NodeProjectScan>) {
    print_progress(verbose, "  Checking yarn global packages...");

    if which("yarn").is_none() {
        return;
    }

    let yarn_version = run_cmd("yarn", &["--version"]);
    let yarn_global_dir = run_cmd("yarn", &["global", "dir"]);

    if yarn_global_dir.is_empty() {
        return;
    }

    let start = Instant::now();
    let (stdout, stderr, exit_code) = run_cmd_in_dir(
        "yarn",
        &["list", "--json", "--depth=0"],
        &yarn_global_dir,
    );

    let duration = start.elapsed().as_millis() as u64;
    let error = if exit_code != 0 {
        format!("yarn global list command failed with exit code {}", exit_code)
    } else {
        String::new()
    };

    scans.push(NodeProjectScan {
        project_path: yarn_global_dir.clone(),
        package_manager: "yarn".to_string(),
        package_manager_version: Some(yarn_version),
        working_directory: yarn_global_dir,
        raw_stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        raw_stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr.as_bytes()),
        error,
        exit_code,
        scan_duration_ms: duration,
    });
}

fn scan_pnpm_global(verbose: bool, scans: &mut Vec<NodeProjectScan>) {
    print_progress(verbose, "  Checking pnpm global packages...");

    if which("pnpm").is_none() {
        return;
    }

    let pnpm_version = run_cmd("pnpm", &["--version"]);
    let pnpm_global_dir = run_cmd("pnpm", &["root", "-g"]);

    if pnpm_global_dir.is_empty() {
        return;
    }

    // pnpm root -g returns node_modules path, get parent
    let pnpm_dir = Path::new(&pnpm_global_dir)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or(pnpm_global_dir.clone());

    let start = Instant::now();
    let (stdout, stderr, exit_code) = run_cmd_stdout("pnpm", &["list", "-g", "--json", "--depth=3"]);

    let duration = start.elapsed().as_millis() as u64;
    let error = if exit_code != 0 {
        format!("pnpm list -g command failed with exit code {}", exit_code)
    } else {
        String::new()
    };

    scans.push(NodeProjectScan {
        project_path: pnpm_dir.clone(),
        package_manager: "pnpm".to_string(),
        package_manager_version: Some(pnpm_version),
        working_directory: pnpm_dir,
        raw_stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        raw_stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr.as_bytes()),
        error,
        exit_code,
        scan_duration_ms: duration,
    });
}

// ─── Node.js Project Scanning ───────────────────────────────────────────────

fn detect_project_package_manager(project_dir: &str) -> &'static str {
    if project_dir.contains("/.bun/install/") || project_dir.contains("\\.bun\\install\\") {
        return "bun";
    }

    let dir = Path::new(project_dir);
    if dir.join("bun.lock").exists() || dir.join("bun.lockb").exists() {
        "bun"
    } else if dir.join("pnpm-lock.yaml").exists() {
        "pnpm"
    } else if dir.join("yarn.lock").exists() {
        if dir.join(".yarnrc.yml").exists() || dir.join(".yarn/releases").is_dir() {
            "yarn-berry"
        } else {
            "yarn"
        }
    } else if dir.join("package-lock.json").exists() {
        "npm"
    } else {
        "npm"
    }
}

fn get_pm_version(pm: &str) -> String {
    let binary = match pm {
        "npm" => "npm",
        "yarn" | "yarn-berry" => "yarn",
        "pnpm" => "pnpm",
        "bun" => "bun",
        _ => return "unknown".to_string(),
    };
    if which(binary).is_none() {
        return "unknown".to_string();
    }
    let ver = run_cmd(binary, &["--version"]);
    if ver.is_empty() { "unknown".to_string() } else { ver }
}

fn list_project_packages(
    project_dir: &str,
    package_manager: &str,
) -> Option<NodeProjectScan> {
    // Check node_modules for most package managers
    match package_manager {
        "npm" | "yarn" | "pnpm" | "bun" => {
            let nm = Path::new(project_dir).join("node_modules");
            if !nm.is_dir() {
                return None;
            }
        }
        _ => {}
    }

    let start = Instant::now();

    let (binary, args): (&str, Vec<&str>) = match package_manager {
        "npm" => ("npm", vec!["ls", "--json", "--depth=3"]),
        "yarn" => ("yarn", vec!["list", "--json"]),
        "yarn-berry" => ("yarn", vec!["info", "--all", "--json"]),
        "pnpm" => ("pnpm", vec!["ls", "--json", "--depth=3"]),
        "bun" => ("bun", vec!["pm", "ls", "--all"]),
        _ => return None,
    };

    if which(binary).is_none() {
        return None;
    }

    let (stdout, stderr, exit_code) = run_cmd_in_dir(binary, &args, project_dir);
    let duration = start.elapsed().as_millis() as u64;

    let error = if exit_code != 0 {
        format!("{} command failed with exit code {}", package_manager, exit_code)
    } else {
        String::new()
    };

    Some(NodeProjectScan {
        project_path: project_dir.to_string(),
        package_manager: package_manager.to_string(),
        package_manager_version: None,
        working_directory: project_dir.to_string(),
        raw_stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout.as_bytes()),
        raw_stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr.as_bytes()),
        error,
        exit_code,
        scan_duration_ms: duration,
    })
}

/// Check if a path is a global package directory
fn is_global_package_directory(check_path: &str) -> bool {
    // Check npm prefix
    if which("npm").is_some() {
        let npm_prefix = run_cmd("npm", &["config", "get", "prefix"]);
        if !npm_prefix.is_empty() && check_path.starts_with(&npm_prefix) {
            return true;
        }
    }

    // Check yarn global dir
    if which("yarn").is_some() {
        let yarn_dir = run_cmd("yarn", &["global", "dir"]);
        if !yarn_dir.is_empty() && check_path.starts_with(&yarn_dir) {
            return true;
        }
    }

    // Check pnpm global dir
    if which("pnpm").is_some() {
        let pnpm_root = run_cmd("pnpm", &["root", "-g"]);
        if !pnpm_root.is_empty() {
            let pnpm_dir = Path::new(&pnpm_root)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or(pnpm_root);
            if check_path.starts_with(&pnpm_dir) {
                return true;
            }
        }
    }

    false
}

pub fn scan_node_projects(
    search_dir: &str,
    verbose: bool,
) -> (Vec<NodeProjectScan>, usize) {
    print_progress(verbose, "Searching for Node.js projects...");

    if search_dir.is_empty() {
        return (Vec::new(), 0);
    }

    let start = Instant::now();
    let mut scans = Vec::new();
    let mut project_count = 0;
    let mut cumulative_size: u64 = 0;
    let mut processed_paths: HashSet<String> = HashSet::new();

    print_progress(verbose, &format!("  Searching in: {}", search_dir));

    // Use walkdir to find package.json files, collect with mtimes for sorting
    let mut package_jsons: Vec<(std::time::SystemTime, String)> = Vec::new();

    for entry in WalkDir::new(search_dir)
        .follow_links(false)
        .max_depth(20)
        .into_iter()
        .filter_entry(|e| {
            // Skip node_modules directories during traversal
            let name = e.file_name().to_string_lossy();
            name != "node_modules" && name != ".git" && name != ".cache"
        })
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if entry.file_type().is_file() && entry.file_name() == "package.json" {
            let mtime = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            package_jsons.push((mtime, entry.path().to_string_lossy().to_string()));
        }
    }

    // Sort by mtime descending (most recent first)
    package_jsons.sort_by(|a, b| b.0.cmp(&a.0));

    for (_mtime, package_json) in &package_jsons {
        let project_dir = match Path::new(package_json).parent() {
            Some(p) => p.to_string_lossy().to_string(),
            None => continue,
        };

        // Skip if inside node_modules of a processed project
        let skip = processed_paths.iter().any(|p| {
            let nm = format!("{}/node_modules", p);
            project_dir.starts_with(&nm)
        });
        if skip {
            continue;
        }

        // Skip already processed
        if processed_paths.contains(&project_dir) {
            continue;
        }

        // Skip global package directories
        if is_global_package_directory(&project_dir) {
            print_progress(verbose, &format!("    Skipping global package directory: {}", project_dir));
            continue;
        }

        processed_paths.insert(project_dir.clone());

        print_progress(verbose, &format!("    Found project: {}", project_dir));

        let pm = detect_project_package_manager(&project_dir);
        print_progress(verbose, &format!("      Package manager: {}", pm));

        let pm_version = get_pm_version(pm);

        let scan_result = match list_project_packages(&project_dir, pm) {
            Some(mut scan) => {
                scan.package_manager_version = Some(pm_version);
                scan
            }
            None => {
                print_progress(verbose, "      Skipping (no node_modules directory)");
                continue;
            }
        };

        // Check cumulative size
        let result_size = serde_json::to_string(&scan_result).unwrap_or_default().len() as u64;
        if cumulative_size + result_size > MAX_NODE_PROJECTS_SIZE_BYTES {
            print_progress(verbose, &format!("    Reached data size limit ({} bytes collected)", cumulative_size));
            break;
        }
        cumulative_size += result_size;

        scans.push(scan_result);
        project_count += 1;

        if project_count >= MAX_NODE_PROJECTS {
            print_progress(verbose, "    Reached maximum of 1000 projects, stopping search");
            break;
        }
    }

    let duration = start.elapsed().as_millis();
    print_progress(verbose, &format!("Found {} Node.js projects", project_count));
    print_progress(verbose, &format!("  Scan duration: {}ms", duration));

    (scans, project_count)
}

// ─── Package Extraction (for pretty/HTML/JSON output) ───────────────────────

pub fn extract_packages_from_scans(scans: &[NodeProjectScan]) -> Vec<NodePackageFolder> {
    let mut folders = Vec::new();

    for scan in scans {
        if scan.raw_stdout_base64.is_empty() {
            continue;
        }

        let decoded = match base64::engine::general_purpose::STANDARD.decode(&scan.raw_stdout_base64) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => continue,
        };

        if decoded.is_empty() {
            continue;
        }

        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        // Try to parse as JSON for npm/pnpm
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&decoded) {
            extract_npm_packages(&value, &mut packages, &mut seen, 0);
        }

        // If no packages found, try yarn JSON format
        if packages.is_empty() {
            for line in decoded.lines() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(name) = value.get("name").and_then(|n| n.as_str()) {
                        if name.contains('@') {
                            let parts: Vec<&str> = name.rsplitn(2, '@').collect();
                            if parts.len() == 2 {
                                let key = format!("{}@{}", parts[1], parts[0]);
                                if seen.insert(key) {
                                    packages.push(NodePackageEntry {
                                        name: parts[1].to_string(),
                                        version: parts[0].to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try bun text format
        if packages.is_empty() {
            for line in decoded.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("├── ").or_else(|| line.strip_prefix("└── ")) {
                    if let Some(at_pos) = rest.rfind('@') {
                        let name = &rest[..at_pos];
                        let version = &rest[at_pos + 1..];
                        let key = format!("{}@{}", name, version);
                        if seen.insert(key) {
                            packages.push(NodePackageEntry {
                                name: name.to_string(),
                                version: version.to_string(),
                            });
                        }
                    }
                }
            }
        }

        if !packages.is_empty() {
            packages.sort_by(|a, b| a.name.cmp(&b.name));
            folders.push(NodePackageFolder {
                folder: scan.project_path.clone(),
                package_manager: scan.package_manager.clone(),
                packages,
            });
        }
    }

    folders
}

const MAX_NPM_RECURSION_DEPTH: usize = 16;

fn extract_npm_packages(
    value: &serde_json::Value,
    packages: &mut Vec<NodePackageEntry>,
    seen: &mut HashSet<String>,
    depth: usize,
) {
    if depth > MAX_NPM_RECURSION_DEPTH {
        return;
    }
    if let Some(deps) = value.get("dependencies").and_then(|d| d.as_object()) {
        for (name, info) in deps {
            if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                let key = format!("{}@{}", name, version);
                if seen.insert(key) {
                    packages.push(NodePackageEntry {
                        name: name.clone(),
                        version: version.to_string(),
                    });
                }
            }
            // Recurse into nested dependencies
            extract_npm_packages(info, packages, seen, depth + 1);
        }
    }
}
