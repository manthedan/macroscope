use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use owo_colors::OwoColorize;
use plist::Value;
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(name = "macroscope")]
#[command(about = "Audit your macOS developer environment", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan this Mac and print a pretty developer-environment audit.
    Scan {
        /// Write a Markdown report to this path.
        #[arg(long)]
        markdown: Option<PathBuf>,

        /// Emit JSON instead of the pretty text summary.
        #[arg(long)]
        json: bool,
    },

    /// Generate a read-only cleanup/migration action plan.
    Plan {
        /// Write a Markdown action plan to this path.
        #[arg(long)]
        markdown: Option<PathBuf>,

        /// Emit JSON instead of the pretty text plan.
        #[arg(long)]
        json: bool,
    },

    /// Explain a path, action ID, bundle ID, or finding text.
    Explain {
        /// Path, action ID, bundle ID, or text to explain.
        target: String,
    },

    /// Apply or dry-run an action plan.
    Apply {
        /// Read an action plan JSON file. If omitted, generate a fresh plan.
        plan: Option<PathBuf>,

        /// Print what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,

        /// Required for real mutations. Without this, apply refuses to change the system.
        #[arg(long)]
        yes: bool,
    },

    /// Open an interactive terminal dashboard.
    Tui {
        /// Enable guarded apply controls in the TUI. Plain `tui` remains read-only.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Debug, Serialize)]
struct Report {
    system: SystemReport,
    homebrew: HomebrewReport,
    apps: AppsReport,
    local_bins: Vec<BinEntry>,
    path: PathReport,
    dev_tools: DevToolsReport,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct SystemReport {
    arch: String,
    macos: String,
    shell: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct HomebrewReport {
    brew_path: Option<String>,
    prefix: Option<String>,
    formulae: Vec<String>,
    casks: Vec<String>,
    leaves: Vec<String>,
    outdated_formulae: Vec<String>,
    outdated_casks: Vec<String>,
    services: Vec<HomebrewService>,
    autoremove_preview: Vec<String>,
    cleanup_preview: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct HomebrewService {
    name: String,
    status: Option<String>,
    user: Option<String>,
    file: Option<String>,
}

#[derive(Debug, Serialize)]
struct AppsReport {
    scanned_roots: Vec<PathBuf>,
    apps: Vec<AppEntry>,
    duplicate_bundle_ids: BTreeMap<String, Vec<PathBuf>>,
}

#[derive(Debug, Serialize)]
struct AppEntry {
    path: PathBuf,
    name: Option<String>,
    bundle_id: Option<String>,
    version: Option<String>,
    executable: Option<PathBuf>,
    executable_arch: Option<String>,
}

#[derive(Debug, Serialize)]
struct BinEntry {
    path: PathBuf,
    kind: String,
    arch: Option<String>,
    target: Option<PathBuf>,
    owner: Option<String>,
}

#[derive(Debug, Serialize)]
struct PathReport {
    entries: Vec<String>,
    duplicates: BTreeMap<String, usize>,
    opt_homebrew_before_usr_local: Option<bool>,
}

#[derive(Debug, Serialize, Default)]
struct DevToolsReport {
    node: ToolVersion,
    npm: NpmReport,
    cargo: CargoReport,
    python: ToolVersion,
    uv: ToolVersion,
    conda: CondaReport,
    go: GoReport,
}

#[derive(Debug, Serialize, Default)]
struct ToolVersion {
    path: Option<String>,
    version: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct NpmReport {
    npm: ToolVersion,
    prefix: Option<String>,
    root: Option<String>,
    global_packages: Vec<PackageEntry>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct CargoReport {
    cargo: ToolVersion,
    installed: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct CondaReport {
    conda: ToolVersion,
    platform: Option<String>,
    root_prefix: Option<String>,
    active_prefix: Option<String>,
    envs: Vec<String>,
    envs_dirs: Vec<String>,
    package_caches: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct GoReport {
    go: ToolVersion,
    gopath: Option<String>,
    gobin: Option<String>,
    goroot: Option<String>,
    goos: Option<String>,
    goarch: Option<String>,
    bin_dir: Option<PathBuf>,
    binaries: Vec<GoBinary>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct GoBinary {
    path: PathBuf,
    arch: Option<String>,
}

#[derive(Debug, Serialize)]
struct PackageEntry {
    name: String,
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct Finding {
    severity: Severity,
    title: String,
    detail: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info,
    Warn,
    Risk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiTab {
    Findings,
    Plan,
}

#[derive(Debug, Serialize, Deserialize)]
struct ActionPlan {
    summary: ActionPlanSummary,
    actions: Vec<PlannedAction>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ActionPlanSummary {
    total: usize,
    destructive: usize,
    low_risk: usize,
    medium_risk: usize,
    high_risk: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlannedAction {
    id: String,
    title: String,
    rationale: String,
    confidence: Confidence,
    risk: ActionRisk,
    destructive: bool,
    kind: ActionKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ActionRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum ActionKind {
    MoveToTrash { path: PathBuf },
    BrewInstall { package: String },
    Manual { instructions: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { markdown, json } => {
            let report = scan();

            if let Some(path) = markdown {
                let rendered = render_markdown(&report);
                fs::write(&path, rendered).with_context(|| {
                    format!("failed to write Markdown report to {}", path.display())
                })?;
                eprintln!("Wrote {}", path.display());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_summary(&report);
            }
        }
        Commands::Plan { markdown, json } => {
            let report = scan();
            let plan = generate_action_plan(&report);

            if let Some(path) = markdown {
                let rendered = render_action_plan_markdown(&plan);
                fs::write(&path, rendered).with_context(|| {
                    format!("failed to write Markdown action plan to {}", path.display())
                })?;
                eprintln!("Wrote {}", path.display());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print_action_plan(&plan);
            }
        }
        Commands::Explain { target } => {
            let report = scan();
            let plan = generate_action_plan(&report);
            print_explanation(&target, &report, &plan);
        }
        Commands::Apply { plan, dry_run, yes } => {
            let plan = load_or_generate_plan(plan.as_deref())?;
            if dry_run {
                dry_run_action_plan(&plan);
            } else {
                apply_action_plan(&plan, yes)?;
            }
        }
        Commands::Tui { apply } => {
            let report = scan();
            let plan = generate_action_plan(&report);
            run_tui(report, plan, apply)?;
        }
    }

    Ok(())
}

fn scan() -> Report {
    let system = scan_system();
    let homebrew = scan_homebrew();
    let apps = scan_apps();
    let local_bins = scan_local_bins(Path::new("/usr/local/bin"));
    let path = scan_path();
    let dev_tools = scan_dev_tools();

    let findings = build_findings(&system, &homebrew, &apps, &local_bins, &path, &dev_tools);

    Report {
        system,
        homebrew,
        apps,
        local_bins,
        path,
        dev_tools,
        findings,
    }
}

fn scan_system() -> SystemReport {
    SystemReport {
        arch: command_stdout("uname", &["-m"]).unwrap_or_else(|_| env::consts::ARCH.to_string()),
        macos: command_stdout("sw_vers", &["-productVersion"]).unwrap_or_else(|_| "unknown".into()),
        shell: env::var("SHELL").ok(),
    }
}

fn scan_homebrew() -> HomebrewReport {
    let Some(brew_path) = which("brew").or_else(find_homebrew) else {
        return HomebrewReport {
            error: Some("brew not found in PATH or standard Homebrew locations".into()),
            ..Default::default()
        };
    };

    let mut report = HomebrewReport {
        brew_path: Some(brew_path.display().to_string()),
        ..Default::default()
    };

    report.prefix = command_stdout_path(&brew_path, &["--prefix"]).ok();
    report.formulae = command_lines_path(&brew_path, &["list", "--formula", "--versions"])
        .unwrap_or_default()
        .into_iter()
        .map(|line| first_field(&line).to_string())
        .collect();
    report.casks = command_lines_path(&brew_path, &["list", "--cask"]).unwrap_or_default();
    report.leaves = command_lines_path(&brew_path, &["leaves"]).unwrap_or_default();
    report.outdated_formulae = command_lines_path(&brew_path, &["outdated", "--formula"])
        .unwrap_or_default()
        .into_iter()
        .map(|line| first_field(&line).to_string())
        .collect();
    report.outdated_casks = command_lines_path(&brew_path, &["outdated", "--cask"])
        .unwrap_or_default()
        .into_iter()
        .map(|line| first_field(&line).to_string())
        .collect();
    report.services = command_stdout_path(&brew_path, &["services", "list", "--json"])
        .ok()
        .and_then(|json| parse_homebrew_services(&json).ok())
        .unwrap_or_default();
    report.autoremove_preview = command_lines_path(&brew_path, &["autoremove", "--dry-run"])
        .unwrap_or_default()
        .into_iter()
        .filter(|line| !line.starts_with("Warning:"))
        .collect();
    report.cleanup_preview =
        command_lines_path(&brew_path, &["cleanup", "--dry-run"]).unwrap_or_default();

    report
}

fn parse_homebrew_services(json: &str) -> Result<Vec<HomebrewService>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let Some(items) = value.as_array() else {
        return Ok(Vec::new());
    };

    let mut services = Vec::new();
    for item in items {
        services.push(HomebrewService {
            name: json_string(item, "name").unwrap_or_else(|| "unknown".into()),
            status: json_string(item, "status"),
            user: json_string(item, "user"),
            file: json_string(item, "file"),
        });
    }
    services.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(services)
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(String::from)
}

fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn scan_apps() -> AppsReport {
    let mut roots = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join("Applications"));
    }

    let mut apps = Vec::new();

    for root in &roots {
        if !root.exists() {
            continue;
        }

        for entry in WalkDir::new(root)
            .max_depth(2)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if path.extension() == Some(OsStr::new("app")) && path.is_dir() {
                apps.push(read_app(path));
            }
        }
    }

    apps.sort_by(|a, b| a.path.cmp(&b.path));

    let mut bundle_map: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for app in &apps {
        if let Some(bundle_id) = &app.bundle_id {
            bundle_map
                .entry(bundle_id.clone())
                .or_default()
                .push(app.path.clone());
        }
    }
    bundle_map.retain(|_, paths| paths.len() > 1);

    AppsReport {
        scanned_roots: roots,
        apps,
        duplicate_bundle_ids: bundle_map,
    }
}

fn read_app(path: &Path) -> AppEntry {
    let info_plist = path.join("Contents/Info.plist");
    let plist = Value::from_file(&info_plist).ok();

    let name = plist_string(&plist, "CFBundleDisplayName")
        .or_else(|| plist_string(&plist, "CFBundleName"))
        .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()));
    let bundle_id = plist_string(&plist, "CFBundleIdentifier");
    let version = plist_string(&plist, "CFBundleShortVersionString")
        .or_else(|| plist_string(&plist, "CFBundleVersion"));
    let executable =
        plist_string(&plist, "CFBundleExecutable").map(|exe| path.join("Contents/MacOS").join(exe));
    let executable_arch = executable.as_ref().and_then(|exe| file_arch(exe).ok());

    AppEntry {
        path: path.to_path_buf(),
        name,
        bundle_id,
        version,
        executable,
        executable_arch,
    }
}

fn scan_local_bins(root: &Path) -> Vec<BinEntry> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };

    let mut bins = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };

        if metadata.is_dir() {
            continue;
        }

        let target = if metadata.file_type().is_symlink() {
            fs::read_link(&path).ok()
        } else {
            None
        };
        let kind = if metadata.file_type().is_symlink() {
            "symlink"
        } else {
            "file"
        }
        .to_string();
        let arch = file_arch(&path).ok();
        let owner = infer_bin_owner(&path, target.as_ref());

        bins.push(BinEntry {
            path,
            kind,
            arch,
            target,
            owner,
        });
    }

    bins.sort_by(|a, b| a.path.cmp(&b.path));
    bins
}

fn infer_bin_owner(path: &Path, target: Option<&PathBuf>) -> Option<String> {
    let resolved_target = target.map(|target| {
        if target.is_absolute() {
            target.clone()
        } else {
            path.parent().unwrap_or_else(|| Path::new("/")).join(target)
        }
    });
    let subject = resolved_target
        .clone()
        .unwrap_or_else(|| path.to_path_buf());
    let text = subject.display().to_string();

    if target.is_some() && fs::symlink_metadata(&subject).is_err() {
        return Some("broken symlink".into());
    }

    if text.starts_with("/Applications/") {
        return Some(format!("app bundle ({})", app_name_from_path(&subject)));
    }
    if text.starts_with("/opt/homebrew/") {
        return Some("Homebrew (/opt/homebrew)".into());
    }
    if text.starts_with("/usr/local/Cellar/") || text.starts_with("/usr/local/Homebrew/") {
        return Some("legacy Homebrew (/usr/local)".into());
    }
    if text.starts_with("/usr/local/Caskroom/") {
        return Some("legacy Homebrew cask (/usr/local/Caskroom)".into());
    }
    if text.starts_with("/usr/local/aws-cli/") {
        return Some("AWS CLI manual installer".into());
    }
    if text.contains("/.cargo/bin") {
        return Some("Cargo".into());
    }
    if text.contains("/.nvm/") {
        return Some("nvm/npm".into());
    }
    if text.contains("/node_modules/") || text.starts_with("/usr/local/lib/node_modules/") {
        return Some("Node/npm (/usr/local)".into());
    }
    if path.starts_with("/usr/local/bin") {
        return Some("standalone/manual /usr/local/bin".into());
    }

    None
}

fn app_name_from_path(path: &Path) -> String {
    for ancestor in path.ancestors() {
        if ancestor.extension() == Some(OsStr::new("app")) {
            return ancestor
                .file_stem()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| ancestor.display().to_string());
        }
    }
    "unknown app".into()
}

fn scan_path() -> PathReport {
    let entries: Vec<String> = env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for entry in &entries {
        *counts.entry(entry.clone()).or_default() += 1;
    }
    counts.retain(|_, count| *count > 1);

    let opt = entries.iter().position(|p| p == "/opt/homebrew/bin");
    let usr = entries.iter().position(|p| p == "/usr/local/bin");
    let opt_homebrew_before_usr_local = match (opt, usr) {
        (Some(o), Some(u)) => Some(o < u),
        _ => None,
    };

    PathReport {
        entries,
        duplicates: counts,
        opt_homebrew_before_usr_local,
    }
}

fn scan_dev_tools() -> DevToolsReport {
    DevToolsReport {
        node: tool_version("node", &["--version"]),
        npm: scan_npm(),
        cargo: scan_cargo(),
        python: tool_version("python3", &["--version"]),
        uv: tool_version("uv", &["--version"]),
        conda: scan_conda(),
        go: scan_go(),
    }
}

fn scan_npm() -> NpmReport {
    let npm = tool_version("npm", &["--version"]);
    if npm.path.is_none() {
        return NpmReport {
            npm,
            error: Some("npm not found in PATH".into()),
            ..Default::default()
        };
    }

    let prefix = command_stdout("npm", &["prefix", "-g"]).ok();
    let root = command_stdout("npm", &["root", "-g"]).ok();
    let global_packages = command_stdout("npm", &["list", "-g", "--depth=0", "--json"])
        .ok()
        .and_then(|json| parse_npm_packages(&json).ok())
        .unwrap_or_default();

    NpmReport {
        npm,
        prefix,
        root,
        global_packages,
        error: None,
    }
}

fn scan_cargo() -> CargoReport {
    let cargo = tool_version("cargo", &["--version"]);
    if cargo.path.is_none() {
        return CargoReport {
            cargo,
            error: Some("cargo not found in PATH".into()),
            ..Default::default()
        };
    }

    let installed = command_stdout("cargo", &["install", "--list"])
        .ok()
        .map(|out| {
            out.lines()
                .filter(|line| !line.starts_with(' ') && line.contains(' '))
                .map(|line| line.trim_end_matches(':').to_string())
                .collect()
        })
        .unwrap_or_default();

    CargoReport {
        cargo,
        installed,
        error: None,
    }
}

fn scan_conda() -> CondaReport {
    let Some(conda_path) = which("conda").or_else(find_conda) else {
        return CondaReport {
            conda: ToolVersion {
                error: Some("conda not found in PATH or standard locations".into()),
                ..Default::default()
            },
            error: Some("conda not found".into()),
            ..Default::default()
        };
    };

    let conda = tool_version_path(&conda_path, &["--version"]);
    let info = command_stdout_path(&conda_path, &["info", "--json"])
        .ok()
        .and_then(|json| parse_conda_info(&conda, &json).ok());

    info.unwrap_or_else(|| CondaReport {
        conda,
        error: Some("failed to parse `conda info --json`".into()),
        ..Default::default()
    })
}

fn parse_conda_info(conda: &ToolVersion, json: &str) -> Result<CondaReport> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    Ok(CondaReport {
        conda: ToolVersion {
            path: conda.path.clone(),
            version: conda.version.clone(),
            error: conda.error.clone(),
        },
        platform: json_string(&value, "platform"),
        root_prefix: json_string(&value, "root_prefix")
            .or_else(|| json_string(&value, "base_prefix"))
            .or_else(|| json_string(&value, "conda_prefix")),
        active_prefix: json_string(&value, "active_prefix"),
        envs: json_string_array(&value, "envs"),
        envs_dirs: json_string_array(&value, "envs_dirs"),
        package_caches: json_string_array(&value, "pkgs_dirs"),
        error: None,
    })
}

fn scan_go() -> GoReport {
    let go_path = which("go").or_else(find_go);
    let go = go_path
        .as_ref()
        .map(|path| tool_version_path(path, &["version"]))
        .unwrap_or_else(|| ToolVersion {
            error: Some("go not found in PATH or Homebrew fallback".into()),
            ..Default::default()
        });

    let gopath = go_path
        .as_ref()
        .and_then(|path| command_stdout_path(path, &["env", "GOPATH"]).ok())
        .or_else(|| dirs::home_dir().map(|home| home.join("go").display().to_string()));
    let gobin = go_path
        .as_ref()
        .and_then(|path| command_stdout_path(path, &["env", "GOBIN"]).ok())
        .filter(|value| !value.is_empty());
    let goroot = go_path
        .as_ref()
        .and_then(|path| command_stdout_path(path, &["env", "GOROOT"]).ok());
    let goos = go_path
        .as_ref()
        .and_then(|path| command_stdout_path(path, &["env", "GOOS"]).ok());
    let goarch = go_path
        .as_ref()
        .and_then(|path| command_stdout_path(path, &["env", "GOARCH"]).ok());

    let bin_dir = gobin
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| gopath.as_ref().map(|path| PathBuf::from(path).join("bin")));
    let binaries = bin_dir
        .as_ref()
        .map(|dir| scan_go_binaries(dir))
        .unwrap_or_default();

    GoReport {
        go,
        gopath,
        gobin,
        goroot,
        goos,
        goarch,
        bin_dir,
        binaries,
        error: None,
    }
}

fn scan_go_binaries(dir: &Path) -> Vec<GoBinary> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut binaries = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            continue;
        }
        binaries.push(GoBinary {
            arch: file_arch(&path).ok(),
            path,
        });
    }
    binaries.sort_by(|a, b| a.path.cmp(&b.path));
    binaries
}

fn parse_npm_packages(json: &str) -> Result<Vec<PackageEntry>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let mut packages = Vec::new();

    if let Some(deps) = value.get("dependencies").and_then(|d| d.as_object()) {
        for (name, meta) in deps {
            packages.push(PackageEntry {
                name: name.clone(),
                version: meta
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            });
        }
    }

    packages.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(packages)
}

fn tool_version(cmd: &str, args: &[&str]) -> ToolVersion {
    let Some(path) = which(cmd) else {
        return ToolVersion {
            error: Some(format!("{cmd} not found in PATH")),
            ..Default::default()
        };
    };
    tool_version_path(&path, args)
}

fn tool_version_path(path: &Path, args: &[&str]) -> ToolVersion {
    ToolVersion {
        path: Some(path.display().to_string()),
        version: command_stdout_path(path, args).ok(),
        error: None,
    }
}

fn build_findings(
    system: &SystemReport,
    homebrew: &HomebrewReport,
    apps: &AppsReport,
    local_bins: &[BinEntry],
    path: &PathReport,
    dev_tools: &DevToolsReport,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if system.arch == "arm64" {
        for bin in local_bins {
            if bin
                .arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
            {
                findings.push(Finding {
                    severity: Severity::Risk,
                    title: "Intel-only binary in /usr/local/bin".into(),
                    detail: format!(
                        "{} appears to be {} (owner: {})",
                        bin.path.display(),
                        bin.arch.as_deref().unwrap_or("unknown"),
                        bin.owner.as_deref().unwrap_or("unknown/manual")
                    ),
                });
            }
        }

        for app in &apps.apps {
            if app
                .executable_arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
            {
                findings.push(Finding {
                    severity: Severity::Warn,
                    title: "Intel-only app executable".into(),
                    detail: format!(
                        "{} appears to be {}",
                        app.path.display(),
                        app.executable_arch.as_deref().unwrap_or("unknown")
                    ),
                });
            }
        }
    }

    if !apps.duplicate_bundle_ids.is_empty() {
        for (bundle_id, paths) in &apps.duplicate_bundle_ids {
            findings.push(Finding {
                severity: Severity::Warn,
                title: "Duplicate app bundle identifier".into(),
                detail: format!(
                    "{bundle_id}: {}",
                    paths
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }

    if !path.duplicates.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            title: "Duplicate PATH entries".into(),
            detail: path
                .duplicates
                .iter()
                .map(|(entry, count)| format!("{entry} ({count}x)"))
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    if path.opt_homebrew_before_usr_local == Some(false) {
        findings.push(Finding {
            severity: Severity::Warn,
            title: "/usr/local/bin precedes /opt/homebrew/bin".into(),
            detail:
                "On Apple Silicon, ARM Homebrew should usually come before legacy /usr/local/bin."
                    .into(),
        });
    }

    if homebrew.prefix.as_deref() == Some("/usr/local") && system.arch == "arm64" {
        findings.push(Finding {
            severity: Severity::Risk,
            title: "Intel Homebrew appears active on Apple Silicon".into(),
            detail: "brew --prefix returned /usr/local".into(),
        });
    }

    let outdated_count = homebrew.outdated_formulae.len() + homebrew.outdated_casks.len();
    if outdated_count > 0 {
        findings.push(Finding {
            severity: Severity::Info,
            title: "Outdated Homebrew packages".into(),
            detail: format!(
                "{} formulae and {} casks are outdated.",
                homebrew.outdated_formulae.len(),
                homebrew.outdated_casks.len()
            ),
        });
    }

    if !homebrew.cleanup_preview.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            title: "Homebrew cleanup can reclaim space".into(),
            detail: homebrew
                .cleanup_preview
                .last()
                .cloned()
                .unwrap_or_else(|| "brew cleanup --dry-run returned removable files.".into()),
        });
    }

    if dev_tools.npm.global_packages.len() > 20 {
        findings.push(Finding {
            severity: Severity::Info,
            title: "Many global npm packages".into(),
            detail: format!(
                "{} packages installed globally; consider whether any are stale.",
                dev_tools.npm.global_packages.len()
            ),
        });
    }

    if dev_tools.conda.conda.path.is_some() {
        findings.push(Finding {
            severity: Severity::Info,
            title: "Conda installation detected".into(),
            detail: format!(
                "conda {} at {}; platform {}; {} env(s).",
                dev_tools
                    .conda
                    .conda
                    .version
                    .as_deref()
                    .unwrap_or("unknown version"),
                dev_tools
                    .conda
                    .root_prefix
                    .as_deref()
                    .unwrap_or("unknown prefix"),
                dev_tools.conda.platform.as_deref().unwrap_or("unknown"),
                dev_tools.conda.envs.len()
            ),
        });
    }

    let conda_roots = conda_rootish_envs(&dev_tools.conda.envs);
    if conda_roots.len() > 1 {
        findings.push(Finding {
            severity: Severity::Warn,
            title: "Multiple Conda roots detected".into(),
            detail: format!(
                "Conda sees multiple root-like prefixes: {}",
                conda_roots.join(", ")
            ),
        });
    }

    let intel_go_binaries = intel_go_binaries(&dev_tools.go);
    if system.arch == "arm64" && !intel_go_binaries.is_empty() {
        findings.push(Finding {
            severity: Severity::Warn,
            title: "Intel-only Go-installed binaries".into(),
            detail: format!(
                "{} GOPATH/bin binaries appear Intel-only: {}{}",
                intel_go_binaries.len(),
                intel_go_binaries
                    .iter()
                    .take(8)
                    .map(|binary| binary.path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                if intel_go_binaries.len() > 8 {
                    ", ..."
                } else {
                    ""
                }
            ),
        });
    }

    if let Some(bin_dir) = &dev_tools.go.bin_dir {
        let bin_dir = bin_dir.display().to_string();
        if !dev_tools.go.binaries.is_empty() && !path.entries.iter().any(|entry| entry == &bin_dir)
        {
            findings.push(Finding {
                severity: Severity::Info,
                title: "Go bin directory is not on PATH".into(),
                detail: format!(
                    "{} contains {} binaries but is not present in PATH.",
                    bin_dir,
                    dev_tools.go.binaries.len()
                ),
            });
        }
    }

    findings
}

fn generate_action_plan(report: &Report) -> ActionPlan {
    let mut actions = Vec::new();
    let mut suggested_brew_packages = BTreeSet::new();

    for bin in &report.local_bins {
        let Some(arch) = &bin.arch else {
            continue;
        };
        if !(arch.contains("x86_64") && !arch.contains("arm64")) {
            continue;
        }

        let name = bin
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        if let Some(package) = known_brew_replacement(&name) {
            if suggested_brew_packages.insert(package.to_string()) {
                actions.push(PlannedAction {
                id: format!("brew-install-{}", slugify(package)),
                title: format!("Install native ARM Homebrew replacement for `{name}`"),
                rationale: format!(
                    "`{}` is Intel-only on an ARM Mac. `{package}` is a likely Homebrew replacement. Install and verify the replacement before removing the old binary.",
                    bin.path.display()
                ),
                confidence: Confidence::Medium,
                risk: ActionRisk::Medium,
                destructive: false,
                    kind: ActionKind::BrewInstall {
                        package: package.to_string(),
                    },
                });
            }
        }

        let owner = bin.owner.as_deref().unwrap_or("unknown/manual");
        if requires_owner_aware_manual_removal(owner) {
            actions.push(PlannedAction {
                id: format!("review-owner-{}", slugify(&bin.path.display().to_string())),
                title: format!("Review owner-managed Intel binary `{name}`"),
                rationale: format!(
                    "`{}` is Intel-only, but appears to be owned by {owner}. Prefer updating/removing it through that owner instead of deleting the file directly.",
                    bin.path.display()
                ),
                confidence: Confidence::Medium,
                risk: ActionRisk::Medium,
                destructive: false,
                kind: ActionKind::Manual {
                    instructions: format!(
                        "Inspect `{}` and its owner ({owner}). Update, reinstall, unlink, or uninstall through the owning app/package manager before removing any file.",
                        bin.path.display()
                    ),
                },
            });
        } else {
            actions.push(PlannedAction {
                id: format!("trash-{}", slugify(&bin.path.display().to_string())),
                title: format!("Move stale Intel binary `{name}` to Trash"),
                rationale: format!(
                    "`{}` is an Intel-only binary in `/usr/local/bin` and appears to be owned by {owner}. Move to Trash only after confirming it is unused or replaced.",
                    bin.path.display()
                ),
                confidence: if known_brew_replacement(&name).is_some() {
                    Confidence::Medium
                } else {
                    Confidence::Low
                },
                risk: ActionRisk::Medium,
                destructive: true,
                kind: ActionKind::MoveToTrash {
                    path: bin.path.clone(),
                },
            });
        }
    }

    for (bundle_id, paths) in &report.apps.duplicate_bundle_ids {
        actions.push(PlannedAction {
            id: format!("review-duplicate-app-{}", slugify(bundle_id)),
            title: format!("Review duplicate app bundle ID `{bundle_id}`"),
            rationale: format!(
                "Multiple app bundles share the same identifier, which can confuse macOS permissions, updates, and automation: {}",
                paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            confidence: Confidence::High,
            risk: ActionRisk::Low,
            destructive: false,
            kind: ActionKind::Manual {
                instructions: "Open both app bundles, identify the one you actually use, then remove only the obsolete duplicate after backing up anything important.".into(),
            },
        });
    }

    if !report.path.duplicates.is_empty() {
        actions.push(PlannedAction {
            id: "review-duplicate-path-entries".into(),
            title: "Review duplicate PATH entries".into(),
            rationale: format!(
                "The current shell PATH contains duplicate entries: {}",
                report
                    .path
                    .duplicates
                    .iter()
                    .map(|(entry, count)| format!("{entry} ({count}x)"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            confidence: Confidence::High,
            risk: ActionRisk::Low,
            destructive: false,
            kind: ActionKind::Manual {
                instructions: "Inspect shell startup files such as ~/.zprofile, ~/.zshrc, ~/.profile, and package-manager init blocks. Remove only redundant PATH exports.".into(),
            },
        });
    }

    if report.homebrew.prefix.as_deref() == Some("/usr/local") && report.system.arch == "arm64" {
        actions.push(PlannedAction {
            id: "migrate-intel-homebrew-to-arm".into(),
            title: "Migrate Intel Homebrew to native ARM Homebrew".into(),
            rationale: "This ARM Mac appears to be using `/usr/local` Homebrew. Native Apple Silicon Homebrew should usually live at `/opt/homebrew`.".into(),
            confidence: Confidence::High,
            risk: ActionRisk::High,
            destructive: false,
            kind: ActionKind::Manual {
                instructions: "Install ARM Homebrew in /opt/homebrew, export an inventory from the Intel prefix, reinstall formulae/casks natively, verify command resolution, then retire the Intel prefix only after confirmation.".into(),
            },
        });
    }

    let outdated_count =
        report.homebrew.outdated_formulae.len() + report.homebrew.outdated_casks.len();
    if outdated_count > 0 {
        actions.push(PlannedAction {
            id: "review-homebrew-outdated".into(),
            title: format!("Review {outdated_count} outdated Homebrew package(s)"),
            rationale: format!(
                "Homebrew reports {} outdated formulae and {} outdated casks. Updates can affect developer tooling, so review before upgrading everything at once.",
                report.homebrew.outdated_formulae.len(),
                report.homebrew.outdated_casks.len()
            ),
            confidence: Confidence::High,
            risk: ActionRisk::Low,
            destructive: false,
            kind: ActionKind::Manual {
                instructions: "Run `brew outdated`, review release notes for critical tools, then upgrade selectively with `brew upgrade <name>` or all at once with `brew upgrade`.".into(),
            },
        });
    }

    if !report.homebrew.cleanup_preview.is_empty() {
        actions.push(PlannedAction {
            id: "review-homebrew-cleanup".into(),
            title: "Review Homebrew cleanup dry-run".into(),
            rationale: report
                .homebrew
                .cleanup_preview
                .last()
                .cloned()
                .unwrap_or_else(|| "Homebrew reports cleanup candidates.".into()),
            confidence: Confidence::High,
            risk: ActionRisk::Low,
            destructive: false,
            kind: ActionKind::Manual {
                instructions: "Run `brew cleanup --dry-run` to review removable cache/old-version files, then `brew cleanup` when comfortable.".into(),
            },
        });
    }

    let conda_roots = conda_rootish_envs(&report.dev_tools.conda.envs);
    if conda_roots.len() > 1 {
        actions.push(PlannedAction {
            id: "review-multiple-conda-roots".into(),
            title: "Review multiple Conda roots".into(),
            rationale: format!(
                "Conda reports multiple root-like prefixes: {}. This can create PATH confusion and duplicate Python/package caches.",
                conda_roots.join(", ")
            ),
            confidence: Confidence::High,
            risk: ActionRisk::Low,
            destructive: false,
            kind: ActionKind::Manual {
                instructions: "Run `conda info --envs`, identify the active/root install you use, export any important envs, then remove obsolete Conda roots only after backup/export.".into(),
            },
        });
    }

    let intel_go_binaries = intel_go_binaries(&report.dev_tools.go);
    if !intel_go_binaries.is_empty() {
        actions.push(PlannedAction {
            id: "review-intel-go-binaries".into(),
            title: format!(
                "Review {} Intel-only Go-installed binaries",
                intel_go_binaries.len()
            ),
            rationale: format!(
                "{} binaries in GOPATH/bin appear Intel-only. Go-installed CLIs are often rebuilt with `go install <module>@latest`, but module provenance should be confirmed first. Examples: {}{}",
                intel_go_binaries.len(),
                intel_go_binaries
                    .iter()
                    .take(8)
                    .map(|binary| binary.path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                if intel_go_binaries.len() > 8 { ", ..." } else { "" }
            ),
            confidence: Confidence::Medium,
            risk: ActionRisk::Low,
            destructive: false,
            kind: ActionKind::Manual {
                instructions: "For each Go binary you still need, identify its module, rebuild it with native Go using `go install <module>@latest`, verify the new binary is arm64, then remove stale binaries only after replacement.".into(),
            },
        });
    }

    let summary = summarize_actions(&actions);
    ActionPlan { summary, actions }
}

fn summarize_actions(actions: &[PlannedAction]) -> ActionPlanSummary {
    let mut summary = ActionPlanSummary {
        total: actions.len(),
        destructive: 0,
        low_risk: 0,
        medium_risk: 0,
        high_risk: 0,
    };

    for action in actions {
        if action.destructive {
            summary.destructive += 1;
        }
        match action.risk {
            ActionRisk::Low => summary.low_risk += 1,
            ActionRisk::Medium => summary.medium_risk += 1,
            ActionRisk::High => summary.high_risk += 1,
        }
    }

    summary
}

fn intel_go_binaries(go: &GoReport) -> Vec<&GoBinary> {
    go.binaries
        .iter()
        .filter(|binary| {
            binary
                .arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
        })
        .collect()
}

fn conda_rootish_envs(envs: &[String]) -> Vec<String> {
    envs.iter()
        .filter(|env| env.ends_with("/miniconda3") || env.ends_with("/anaconda3"))
        .cloned()
        .collect()
}

fn requires_owner_aware_manual_removal(owner: &str) -> bool {
    owner.starts_with("Homebrew")
        || owner.starts_with("legacy Homebrew")
        || owner.starts_with("Node/npm")
        || owner.starts_with("nvm/npm")
        || owner.starts_with("Cargo")
        || owner.starts_with("app bundle")
}

fn known_brew_replacement(binary_name: &str) -> Option<&'static str> {
    match binary_name {
        "aws" | "aws_completer" => Some("awscli"),
        _ => None,
    }
}

fn render_action_plan_markdown(plan: &ActionPlan) -> String {
    let mut out = String::new();
    out.push_str("# Macroscope Action Plan\n\n");
    out.push_str("> Read-only generated plan. Review carefully before taking any action.\n\n");
    out.push_str("## Summary\n\n");
    out.push_str(&format!("- Total actions: {}\n", plan.summary.total));
    out.push_str(&format!(
        "- Destructive actions: {}\n",
        plan.summary.destructive
    ));
    out.push_str(&format!("- Low risk: {}\n", plan.summary.low_risk));
    out.push_str(&format!("- Medium risk: {}\n", plan.summary.medium_risk));
    out.push_str(&format!("- High risk: {}\n\n", plan.summary.high_risk));

    if plan.actions.is_empty() {
        out.push_str("No actions proposed.\n");
        return out;
    }

    out.push_str("## Actions\n\n");
    for action in &plan.actions {
        out.push_str(&format!("### `{}` — {}\n\n", action.id, action.title));
        out.push_str(&format!("- Confidence: `{:?}`\n", action.confidence));
        out.push_str(&format!("- Risk: `{:?}`\n", action.risk));
        out.push_str(&format!("- Destructive: `{}`\n", action.destructive));
        out.push_str(&format!("- Kind: `{}`\n", action_kind_label(&action.kind)));
        out.push_str(&format!("\n{}\n\n", action.rationale));
        out.push_str("Suggested command/instruction:\n\n");
        out.push_str(&format!("```text\n{}\n```\n\n", action_instruction(action)));
    }

    out
}

fn print_action_plan(plan: &ActionPlan) {
    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Action Plan".bright_cyan().bold()
    );
    println!(
        "{}",
        "Read-only suggestions. Nothing has been changed.".dimmed()
    );
    println!();

    let mut summary = Table::new();
    summary.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Total"),
        Cell::new("Destructive"),
        Cell::new("Low risk"),
        Cell::new("Medium risk"),
        Cell::new("High risk"),
    ]);
    summary.add_row(vec![
        Cell::new(plan.summary.total),
        Cell::new(plan.summary.destructive),
        Cell::new(plan.summary.low_risk),
        Cell::new(plan.summary.medium_risk),
        Cell::new(plan.summary.high_risk),
    ]);
    println!("{summary}");

    if plan.actions.is_empty() {
        println!("{}", "No actions proposed. Nice.".green());
        return;
    }

    for action in &plan.actions {
        println!(
            "{} {} {}",
            risk_badge(action.risk),
            confidence_badge(action.confidence),
            action.title.bold()
        );
        println!("  {}", action.rationale.dimmed());
        println!("  {} {}", "Action:".bold(), action_instruction(action));
        if action.destructive {
            println!(
                "  {}",
                "Destructive: review and prefer Trash/dry-run before applying."
                    .red()
                    .bold()
            );
        }
        println!();
    }

    println!(
        "{}",
        "Tip: `macroscope plan --markdown cleanup-plan.md` writes this as a reviewable document."
            .dimmed()
    );
}

fn action_kind_label(kind: &ActionKind) -> &'static str {
    match kind {
        ActionKind::MoveToTrash { .. } => "move-to-trash",
        ActionKind::BrewInstall { .. } => "brew-install",
        ActionKind::Manual { .. } => "manual",
    }
}

fn action_instruction(action: &PlannedAction) -> String {
    match &action.kind {
        ActionKind::MoveToTrash { path } => format!(
            "Move `{}` to Trash after confirming it is unused or replaced.",
            path.display()
        ),
        ActionKind::BrewInstall { package } => format!("brew install {package}"),
        ActionKind::Manual { instructions } => instructions.clone(),
    }
}

fn risk_badge(risk: ActionRisk) -> String {
    match risk {
        ActionRisk::Low => "LOW".green().bold().to_string(),
        ActionRisk::Medium => "MED".yellow().bold().to_string(),
        ActionRisk::High => "HIGH".red().bold().to_string(),
    }
}

fn confidence_badge(confidence: Confidence) -> String {
    match confidence {
        Confidence::Low => "low-confidence".dimmed().to_string(),
        Confidence::Medium => "medium-confidence".blue().to_string(),
        Confidence::High => "high-confidence".green().to_string(),
    }
}

fn slugify(input: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }

    slug.trim_matches('-').to_string()
}

fn render_markdown(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Macroscope Report\n\n");

    out.push_str("## System\n\n");
    out.push_str(&format!("- Architecture: `{}`\n", report.system.arch));
    out.push_str(&format!("- macOS: `{}`\n", report.system.macos));
    if let Some(shell) = &report.system.shell {
        out.push_str(&format!("- Shell: `{shell}`\n"));
    }
    out.push('\n');

    out.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("No notable findings.\n\n");
    } else {
        for finding in &report.findings {
            out.push_str(&format!(
                "- **{:?}**: {} — {}\n",
                finding.severity, finding.title, finding.detail
            ));
        }
        out.push('\n');
    }

    out.push_str("## Homebrew\n\n");
    out.push_str(&format!("- brew: `{}`\n", opt(&report.homebrew.brew_path)));
    out.push_str(&format!("- prefix: `{}`\n", opt(&report.homebrew.prefix)));
    out.push_str(&format!("- formulae: {}\n", report.homebrew.formulae.len()));
    out.push_str(&format!("- casks: {}\n", report.homebrew.casks.len()));
    out.push_str(&format!("- leaves: {}\n", report.homebrew.leaves.len()));
    out.push_str(&format!(
        "- outdated formulae: {}\n",
        report.homebrew.outdated_formulae.len()
    ));
    out.push_str(&format!(
        "- outdated casks: {}\n",
        report.homebrew.outdated_casks.len()
    ));
    out.push_str(&format!(
        "- services: {}\n\n",
        report.homebrew.services.len()
    ));

    out.push_str("### Homebrew Outdated Formulae\n\n");
    push_bullets(&mut out, &report.homebrew.outdated_formulae);

    out.push_str("### Homebrew Outdated Casks\n\n");
    push_bullets(&mut out, &report.homebrew.outdated_casks);

    out.push_str("### Homebrew Services\n\n");
    push_homebrew_services_md(&mut out, &report.homebrew.services);

    out.push_str("### Homebrew Autoremove Preview\n\n");
    push_bullets(&mut out, &report.homebrew.autoremove_preview);

    out.push_str("### Homebrew Cleanup Preview\n\n");
    push_bullets(&mut out, &report.homebrew.cleanup_preview);

    out.push_str("### Homebrew Leaves\n\n");
    push_bullets(&mut out, &report.homebrew.leaves);

    out.push_str("## Applications\n\n");
    out.push_str(&format!("Scanned {} apps.\n\n", report.apps.apps.len()));
    push_app_table_md(&mut out, &report.apps.apps);
    if !report.apps.duplicate_bundle_ids.is_empty() {
        out.push_str("### Duplicate Bundle IDs\n\n");
        for (bundle_id, paths) in &report.apps.duplicate_bundle_ids {
            out.push_str(&format!("- `{bundle_id}`\n"));
            for path in paths {
                out.push_str(&format!("  - `{}`\n", path.display()));
            }
        }
        out.push('\n');
    }

    out.push_str("## /usr/local/bin\n\n");
    if report.local_bins.is_empty() {
        out.push_str("No entries found or directory missing.\n\n");
    } else {
        for bin in &report.local_bins {
            out.push_str(&format!("- `{}` — {}", bin.path.display(), bin.kind));
            if let Some(arch) = &bin.arch {
                out.push_str(&format!(", `{arch}`"));
            }
            if let Some(target) = &bin.target {
                out.push_str(&format!(", -> `{}`", target.display()));
            }
            if let Some(owner) = &bin.owner {
                out.push_str(&format!(", owner: `{}`", md_escape(owner)));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str("## Developer Tools\n\n");
    push_tool_md(&mut out, "node", &report.dev_tools.node);
    push_tool_md(&mut out, "npm", &report.dev_tools.npm.npm);
    push_tool_md(&mut out, "python3", &report.dev_tools.python);
    push_tool_md(&mut out, "uv", &report.dev_tools.uv);
    push_tool_md(&mut out, "conda", &report.dev_tools.conda.conda);
    push_tool_md(&mut out, "go", &report.dev_tools.go.go);
    push_tool_md(&mut out, "cargo", &report.dev_tools.cargo.cargo);
    out.push_str(&format!(
        "\n### Global npm Packages ({})\n\n",
        report.dev_tools.npm.global_packages.len()
    ));
    for package in &report.dev_tools.npm.global_packages {
        out.push_str(&format!(
            "- `{}` `{}`\n",
            package.name,
            package.version.as_deref().unwrap_or("unknown")
        ));
    }
    out.push_str(&format!(
        "\n### Cargo-installed Crates ({})\n\n",
        report.dev_tools.cargo.installed.len()
    ));
    push_bullets(&mut out, &report.dev_tools.cargo.installed);

    out.push_str("\n### Conda\n\n");
    push_conda_md(&mut out, &report.dev_tools.conda);

    out.push_str("\n### Go\n\n");
    push_go_md(&mut out, &report.dev_tools.go);

    out.push_str("## PATH\n\n");
    for (idx, entry) in report.path.entries.iter().enumerate() {
        out.push_str(&format!("{}. `{entry}`\n", idx + 1));
    }

    out
}

fn print_summary(report: &Report) {
    let (risks, warns, infos) = finding_counts(report);
    let intel_bins = intel_bin_count(report);
    let intel_apps = intel_app_count(report);

    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope".bright_cyan().bold()
    );
    println!(
        "{}",
        "A local-first audit of this Mac developer environment".dimmed()
    );
    println!();

    let mut overview = Table::new();
    overview.load_preset(UTF8_FULL).set_header(vec![
        Cell::new("Area"),
        Cell::new("Signal"),
        Cell::new("Value"),
    ]);
    overview.add_row(vec![
        Cell::new("System"),
        Cell::new("macOS / arch"),
        Cell::new(format!("{} / {}", report.system.macos, report.system.arch)),
    ]);
    overview.add_row(vec![
        Cell::new("Homebrew"),
        Cell::new("prefix"),
        Cell::new(opt(&report.homebrew.prefix)),
    ]);
    overview.add_row(vec![
        Cell::new("Homebrew"),
        Cell::new("formulae / casks / leaves"),
        Cell::new(format!(
            "{} / {} / {}",
            report.homebrew.formulae.len(),
            report.homebrew.casks.len(),
            report.homebrew.leaves.len()
        )),
    ]);
    overview.add_row(vec![
        Cell::new("Homebrew"),
        Cell::new("outdated / services / cleanup lines"),
        Cell::new(format!(
            "{} / {} / {}",
            report.homebrew.outdated_formulae.len() + report.homebrew.outdated_casks.len(),
            report.homebrew.services.len(),
            report.homebrew.cleanup_preview.len()
        )),
    ]);
    overview.add_row(vec![
        Cell::new("Applications"),
        Cell::new("scanned / Intel-only / duplicate IDs"),
        Cell::new(format!(
            "{} / {} / {}",
            report.apps.apps.len(),
            intel_apps,
            report.apps.duplicate_bundle_ids.len()
        )),
    ]);
    overview.add_row(vec![
        Cell::new("/usr/local/bin"),
        Cell::new("entries / Intel-only"),
        Cell::new(format!("{} / {}", report.local_bins.len(), intel_bins)),
    ]);
    overview.add_row(vec![
        Cell::new("PATH"),
        Cell::new("entries / duplicates"),
        Cell::new(format!(
            "{} / {}",
            report.path.entries.len(),
            report.path.duplicates.len()
        )),
    ]);
    println!("{overview}");

    print_homebrew_report(report);
    print_app_report(report);

    println!("{}", "Developer tools".bold());
    let mut tools = Table::new();
    tools
        .load_preset(UTF8_FULL)
        .set_header(vec![Cell::new("Tool"), Cell::new("Version / location")]);
    tools.add_row(vec![
        Cell::new("node"),
        Cell::new(tool_line(&report.dev_tools.node)),
    ]);
    tools.add_row(vec![
        Cell::new("npm"),
        Cell::new(tool_line(&report.dev_tools.npm.npm)),
    ]);
    tools.add_row(vec![
        Cell::new("npm globals"),
        Cell::new(report.dev_tools.npm.global_packages.len()),
    ]);
    tools.add_row(vec![
        Cell::new("cargo installs"),
        Cell::new(report.dev_tools.cargo.installed.len()),
    ]);
    tools.add_row(vec![
        Cell::new("python3"),
        Cell::new(tool_line(&report.dev_tools.python)),
    ]);
    tools.add_row(vec![
        Cell::new("uv"),
        Cell::new(tool_line(&report.dev_tools.uv)),
    ]);
    tools.add_row(vec![
        Cell::new("conda"),
        Cell::new(format!(
            "{}; {} envs",
            tool_line(&report.dev_tools.conda.conda),
            report.dev_tools.conda.envs.len()
        )),
    ]);
    tools.add_row(vec![
        Cell::new("go"),
        Cell::new(format!(
            "{}; {} GOPATH/bin binaries",
            tool_line(&report.dev_tools.go.go),
            report.dev_tools.go.binaries.len()
        )),
    ]);
    println!("{tools}");

    println!(
        "{} {} {} {} {} {}",
        "Findings".bold(),
        format!("{risks} risk").red().bold(),
        "·".dimmed(),
        format!("{warns} warn").yellow().bold(),
        "·".dimmed(),
        format!("{infos} info").blue().bold()
    );

    if report.findings.is_empty() {
        println!("  {}", "No notable findings. Nice.".green());
    } else {
        for finding in &report.findings {
            println!(
                "  {} {}",
                severity_badge(&finding.severity),
                finding.title.bold()
            );
            println!("      {}", finding.detail.dimmed());
        }
    }

    println!();
    println!(
        "{}",
        "Tip: run `macroscope tui` for the interactive dashboard, or `macroscope scan --markdown report.md` for a shareable report."
            .dimmed()
    );
}

fn print_homebrew_report(report: &Report) {
    if report.homebrew.outdated_formulae.is_empty()
        && report.homebrew.outdated_casks.is_empty()
        && report.homebrew.services.is_empty()
        && report.homebrew.cleanup_preview.is_empty()
    {
        return;
    }

    println!("{}", "Homebrew intelligence".bold());
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![Cell::new("Signal"), Cell::new("Details")]);
    if !report.homebrew.outdated_formulae.is_empty() {
        table.add_row(vec![
            Cell::new("Outdated formulae"),
            Cell::new(report.homebrew.outdated_formulae.join(", ")),
        ]);
    }
    if !report.homebrew.outdated_casks.is_empty() {
        table.add_row(vec![
            Cell::new("Outdated casks"),
            Cell::new(report.homebrew.outdated_casks.join(", ")),
        ]);
    }
    if !report.homebrew.services.is_empty() {
        table.add_row(vec![
            Cell::new("Services"),
            Cell::new(
                report
                    .homebrew
                    .services
                    .iter()
                    .map(|svc| {
                        format!(
                            "{} ({})",
                            svc.name,
                            svc.status.as_deref().unwrap_or("unknown")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        ]);
    }
    if !report.homebrew.cleanup_preview.is_empty() {
        table.add_row(vec![
            Cell::new("Cleanup preview"),
            Cell::new(
                report
                    .homebrew
                    .cleanup_preview
                    .last()
                    .cloned()
                    .unwrap_or_else(|| "cleanup candidates found".into()),
            ),
        ]);
    }
    println!("{table}");
}

fn print_app_report(report: &Report) {
    let intel_apps: Vec<&AppEntry> = report
        .apps
        .apps
        .iter()
        .filter(|app| {
            app.executable_arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
        })
        .collect();

    if intel_apps.is_empty() && report.apps.duplicate_bundle_ids.is_empty() {
        return;
    }

    println!("{}", "Applications".bold());

    if !intel_apps.is_empty() {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).set_header(vec![
            Cell::new("App"),
            Cell::new("Version"),
            Cell::new("Arch"),
            Cell::new("Bundle ID"),
            Cell::new("Path"),
        ]);
        for app in intel_apps.into_iter().take(12) {
            table.add_row(vec![
                Cell::new(app.name.as_deref().unwrap_or("unknown")),
                Cell::new(app.version.as_deref().unwrap_or("unknown")),
                Cell::new(app.executable_arch.as_deref().unwrap_or("unknown")),
                Cell::new(app.bundle_id.as_deref().unwrap_or("unknown")),
                Cell::new(app.path.display()),
            ]);
        }
        println!("{}", "Intel-only app executables".yellow().bold());
        println!("{table}");
    }

    if !report.apps.duplicate_bundle_ids.is_empty() {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_header(vec![Cell::new("Bundle ID"), Cell::new("Paths")]);
        for (bundle_id, paths) in &report.apps.duplicate_bundle_ids {
            table.add_row(vec![
                Cell::new(bundle_id),
                Cell::new(
                    paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ]);
        }
        println!("{}", "Duplicate bundle identifiers".yellow().bold());
        println!("{table}");
    }
}

fn print_explanation(target: &str, report: &Report, plan: &ActionPlan) {
    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Explain".bright_cyan().bold()
    );
    println!("{} {}", "Target:".bold(), target);
    println!();

    if let Some(action) = plan.actions.iter().find(|action| action.id == target) {
        println!("{}", "Matched action".bold());
        print_action_detail(action);
        return;
    }

    let target_path = Path::new(target);
    if target_path.is_absolute() {
        explain_path_target(target_path, report, plan);
        return;
    }

    if let Some(paths) = report.apps.duplicate_bundle_ids.get(target) {
        println!("{}", "Matched duplicate bundle identifier".bold());
        println!("  Bundle ID: `{target}`");
        for path in paths {
            println!("  - {}", path.display());
        }
        print_related_actions(target, plan);
        return;
    }

    let matched_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| {
            finding
                .title
                .to_lowercase()
                .contains(&target.to_lowercase())
                || finding
                    .detail
                    .to_lowercase()
                    .contains(&target.to_lowercase())
        })
        .collect();

    if !matched_findings.is_empty() {
        println!("{}", "Matched findings".bold());
        for finding in matched_findings {
            println!(
                "  {} {}",
                severity_badge(&finding.severity),
                finding.title.bold()
            );
            println!("      {}", finding.detail.dimmed());
        }
        println!();
        print_related_actions(target, plan);
        return;
    }

    println!("{}", "No exact match found.".yellow().bold());
    println!(
        "{}",
        "Try a full path, action ID from `macroscope plan`, app bundle ID, or text from a finding."
            .dimmed()
    );
}

fn explain_path_target(path: &Path, report: &Report, plan: &ActionPlan) {
    if let Some(bin) = report.local_bins.iter().find(|bin| bin.path == path) {
        println!("{}", "Matched /usr/local/bin entry".bold());
        println!("  Path: {}", bin.path.display());
        println!("  Kind: {}", bin.kind);
        println!(
            "  Owner: {}",
            bin.owner.as_deref().unwrap_or("unknown/manual")
        );
        println!(
            "  Architecture: {}",
            bin.arch.as_deref().unwrap_or("unknown")
        );
        if let Some(target) = &bin.target {
            println!("  Symlink target: {}", target.display());
        }
        println!();
        print_related_actions(&path.display().to_string(), plan);
        return;
    }

    if let Some(app) = report.apps.apps.iter().find(|app| app.path == path) {
        println!("{}", "Matched application".bold());
        println!("  Path: {}", app.path.display());
        println!("  Name: {}", app.name.as_deref().unwrap_or("unknown"));
        println!(
            "  Bundle ID: {}",
            app.bundle_id.as_deref().unwrap_or("unknown")
        );
        println!("  Version: {}", app.version.as_deref().unwrap_or("unknown"));
        println!(
            "  Executable arch: {}",
            app.executable_arch.as_deref().unwrap_or("unknown")
        );
        println!();
        print_related_actions(&path.display().to_string(), plan);
        return;
    }

    println!(
        "{}",
        "Path was not part of the current scan.".yellow().bold()
    );
    println!("  {}", path.display());
    print_related_actions(&path.display().to_string(), plan);
}

fn print_related_actions(target: &str, plan: &ActionPlan) {
    let actions = related_actions(target, plan);
    if actions.is_empty() {
        println!("{}", "No related planned actions.".dimmed());
        return;
    }

    println!("{}", "Related planned actions".bold());
    for action in actions {
        print_action_detail(action);
    }
}

fn related_actions<'a>(target: &str, plan: &'a ActionPlan) -> Vec<&'a PlannedAction> {
    if target.starts_with('/') {
        let target_path = Path::new(target);
        let quoted = format!("`{target}`").to_lowercase();
        return plan
            .actions
            .iter()
            .filter(|action| match &action.kind {
                ActionKind::MoveToTrash { path } => path == target_path,
                _ => {
                    action.rationale.to_lowercase().contains(&quoted)
                        || action_instruction(action).to_lowercase().contains(&quoted)
                }
            })
            .collect();
    }

    let target = target.to_lowercase();
    plan.actions
        .iter()
        .filter(|action| {
            action.id.to_lowercase().contains(&target)
                || action.title.to_lowercase().contains(&target)
                || action.rationale.to_lowercase().contains(&target)
                || action_instruction(action).to_lowercase().contains(&target)
        })
        .collect()
}

fn related_actions_for_finding<'a>(
    finding: &Finding,
    plan: &'a ActionPlan,
) -> Vec<&'a PlannedAction> {
    plan.actions
        .iter()
        .filter(|action| {
            finding.detail.contains(&action_subject(action))
                || action.rationale.contains(&finding.detail)
                || action.title.contains(&finding.title)
        })
        .collect()
}

fn action_subject(action: &PlannedAction) -> String {
    match &action.kind {
        ActionKind::MoveToTrash { path } => path.display().to_string(),
        ActionKind::BrewInstall { package } => package.clone(),
        ActionKind::Manual { instructions } => instructions.clone(),
    }
}

fn print_action_detail(action: &PlannedAction) {
    println!(
        "  {} {} {}",
        risk_badge(action.risk),
        confidence_badge(action.confidence),
        action.title.bold()
    );
    println!("      ID: {}", action.id.dimmed());
    println!("      {}", action.rationale.dimmed());
    println!("      {} {}", "Action:".bold(), action_instruction(action));
    if action.destructive {
        println!(
            "      {}",
            "Destructive action: dry-run/review first.".red().bold()
        );
    }
    println!();
}

fn load_or_generate_plan(path: Option<&Path>) -> Result<ActionPlan> {
    if let Some(path) = path {
        let json = fs::read_to_string(path)
            .with_context(|| format!("failed to read action plan {}", path.display()))?;
        let plan = serde_json::from_str(&json)
            .with_context(|| format!("failed to parse action plan JSON {}", path.display()))?;
        Ok(plan)
    } else {
        let report = scan();
        Ok(generate_action_plan(&report))
    }
}

fn dry_run_action_plan(plan: &ActionPlan) {
    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Apply Dry Run".bright_cyan().bold()
    );
    println!("{}", "No changes will be made.".dimmed());
    println!();

    if plan.actions.is_empty() {
        println!("{}", "No actions to dry-run.".green());
        return;
    }

    for action in &plan.actions {
        print_apply_preview(action, true);
    }
}

fn apply_action_plan(plan: &ActionPlan, yes: bool) -> Result<()> {
    if !yes {
        anyhow::bail!(
            "refusing to mutate without --yes; run `macroscope apply --dry-run` first, then `macroscope apply --yes [plan.json]`"
        );
    }

    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Apply".bright_cyan().bold()
    );
    println!(
        "{}",
        "Mutating mode: only move-to-trash actions are executed; package installs and manual actions are printed."
            .yellow()
            .bold()
    );
    println!();

    if plan.actions.is_empty() {
        println!("{}", "No actions to apply.".green());
        return Ok(());
    }

    for action in &plan.actions {
        match &action.kind {
            ActionKind::MoveToTrash { path } => {
                println!("{} {}", "Applying:".bold(), action.title.bold());
                println!("  ID: {}", action.id);
                move_to_trash(path)?;
                println!("  {} {}", "Moved to Trash:".green().bold(), path.display());
                println!();
            }
            ActionKind::BrewInstall { .. } | ActionKind::Manual { .. } => {
                print_apply_preview(action, false);
            }
        }
    }

    Ok(())
}

fn print_apply_preview(action: &PlannedAction, dry_run: bool) {
    let prefix = if dry_run { "Would run:" } else { "Skipped:" };
    println!("{} {}", prefix.bold(), action.title.bold());
    println!("  ID: {}", action.id);
    println!(
        "  Risk: {:?} | Confidence: {:?} | Destructive: {}",
        action.risk, action.confidence, action.destructive
    );
    match &action.kind {
        ActionKind::MoveToTrash { path } => {
            if dry_run {
                println!("  Would move to Trash: {}", path.display());
            } else {
                println!("  Not moved in this pass: {}", path.display());
            }
        }
        ActionKind::BrewInstall { package } => {
            if dry_run {
                println!("  Would execute: brew install {package}");
            } else {
                println!("  Manual/package-manager action not executed: brew install {package}");
            }
        }
        ActionKind::Manual { instructions } => {
            println!("  Manual instruction: {instructions}");
        }
    }
    println!();
}

fn move_to_trash(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot move missing path to Trash: {}", path.display()))?;

    if !metadata.is_dir() {
        return move_to_user_trash(path).or_else(|trash_error| {
            move_to_trash_with_finder(path).with_context(|| {
                format!(
                    "direct ~/.Trash move failed ({trash_error}); Finder trash also failed for {}",
                    path.display()
                )
            })
        });
    }

    match move_to_trash_with_finder(path) {
        Ok(()) => Ok(()),
        Err(finder_error) => move_to_user_trash(path).with_context(|| {
            format!(
                "Finder trash failed ({finder_error}); fallback ~/.Trash move also failed for {}",
                path.display()
            )
        }),
    }
}

fn move_to_trash_with_finder(path: &Path) -> Result<()> {
    let script = format!(
        "tell application \"Finder\" to delete POSIX file \"{}\"",
        escape_applescript_string(&path.display().to_string())
    );
    let output = Command::new("osascript").arg("-e").arg(script).output()?;
    if !output.status.success() {
        anyhow::bail!(
            "osascript failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn move_to_user_trash(path: &Path) -> Result<()> {
    let home = dirs::home_dir().context("cannot locate home directory for ~/.Trash fallback")?;
    let trash = home.join(".Trash");
    fs::create_dir_all(&trash).with_context(|| format!("failed to create {}", trash.display()))?;

    let file_name = path
        .file_name()
        .context("cannot move path without a file name to Trash")?;
    let mut destination = trash.join(file_name);
    if destination.exists() || fs::symlink_metadata(&destination).is_ok() {
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "item".into());
        let extension = path.extension().map(|s| s.to_string_lossy().into_owned());
        for idx in 1..1000 {
            let candidate_name = if let Some(extension) = &extension {
                format!("{stem} {idx}.{extension}")
            } else {
                format!("{stem} {idx}")
            };
            let candidate = trash.join(candidate_name);
            if !candidate.exists() && fs::symlink_metadata(&candidate).is_err() {
                destination = candidate;
                break;
            }
        }
    }

    fs::rename(path, &destination).or_else(|err| {
        if err.kind() == ErrorKind::CrossesDevices {
            if path.is_dir() {
                anyhow::bail!(
                    "cannot fallback-trash directory across filesystems: {}",
                    path.display()
                );
            }
            fs::copy(path, &destination)?;
            fs::remove_file(path)?;
            Ok(())
        } else {
            Err(err.into())
        }
    })?;
    Ok(())
}

fn escape_applescript_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Debug)]
enum TuiOverlay {
    Help,
    Message {
        title: String,
        lines: Vec<String>,
    },
    Confirm {
        target: ConfirmTarget,
        title: String,
        prompt: String,
        required: String,
        buffer: String,
    },
}

#[derive(Debug, Clone, Copy)]
enum ConfirmTarget {
    SelectedAction(usize),
    WholeExecutablePlan,
}

fn run_tui(report: Report, plan: ActionPlan, apply_enabled: bool) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = tui_loop(&mut terminal, report, plan, apply_enabled);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn tui_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    mut report: Report,
    mut plan: ActionPlan,
    apply_enabled: bool,
) -> Result<()> {
    let mut active_tab = TuiTab::Findings;
    let mut selected_finding = if report.findings.is_empty() {
        None
    } else {
        Some(0)
    };
    let mut selected_action = if plan.actions.is_empty() {
        None
    } else {
        Some(0)
    };
    let mut overlay: Option<TuiOverlay> = None;
    let mut dry_run_actions = BTreeSet::new();
    let mut plan_dry_run_done = false;
    let mut status = if apply_enabled {
        "Apply mode enabled. Move-to-Trash actions still require dry-run and typed confirmation."
            .to_string()
    } else {
        "Read-only TUI. Restart with `macroscope tui --apply` to enable guarded apply controls."
            .to_string()
    };

    loop {
        terminal.draw(|frame| {
            let root = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(11),
                    Constraint::Min(8),
                    Constraint::Length(4),
                ])
                .split(frame.area());

            let title = Paragraph::new(Line::from(vec![
                Span::styled(
                    "◉ ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "Macroscope",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                tab_span("Findings", active_tab == TuiTab::Findings),
                Span::raw("  "),
                tab_span("Plan", active_tab == TuiTab::Plan),
                Span::raw("  "),
                Span::styled(
                    if apply_enabled {
                        "apply-capable audit"
                    } else {
                        "read-only audit"
                    },
                    Style::default().fg(if apply_enabled {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }),
                ),
            ]))
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(title, root[0]);

            let overview_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(root[1]);

            let intel_bins = intel_bin_count(&report);
            let intel_apps = intel_app_count(&report);
            let (risks, warns, infos) = finding_counts(&report);

            let overview = Paragraph::new(vec![
                Line::from(vec![Span::styled(
                    format!("macOS {} ({})", report.system.macos, report.system.arch),
                    Style::default().add_modifier(Modifier::BOLD),
                )]),
                Line::from(format!("Homebrew: {}", opt(&report.homebrew.prefix))),
                Line::from(format!(
                    "Packages: {} formulae · {} casks · {} leaves",
                    report.homebrew.formulae.len(),
                    report.homebrew.casks.len(),
                    report.homebrew.leaves.len()
                )),
                Line::from(format!(
                    "Homebrew: {} outdated · {} services",
                    report.homebrew.outdated_formulae.len() + report.homebrew.outdated_casks.len(),
                    report.homebrew.services.len()
                )),
                Line::from(format!(
                    "Apps: {} scanned · {} Intel-only · {} duplicate IDs",
                    report.apps.apps.len(),
                    intel_apps,
                    report.apps.duplicate_bundle_ids.len()
                )),
                Line::from(format!(
                    "/usr/local/bin: {} entries · {} Intel-only",
                    report.local_bins.len(),
                    intel_bins
                )),
                Line::from(format!(
                    "Plan: {} actions · {} executable · {} destructive",
                    plan.summary.total,
                    executable_action_count(&plan),
                    plan.summary.destructive
                )),
            ])
            .block(Block::default().title("Overview").borders(Borders::ALL));
            frame.render_widget(overview, overview_chunks[0]);

            let tools = Paragraph::new(vec![
                Line::from(format!("node: {}", tool_line(&report.dev_tools.node))),
                Line::from(format!("npm: {}", tool_line(&report.dev_tools.npm.npm))),
                Line::from(format!(
                    "npm globals: {}",
                    report.dev_tools.npm.global_packages.len()
                )),
                Line::from(format!(
                    "cargo installs: {}",
                    report.dev_tools.cargo.installed.len()
                )),
                Line::from(format!("python3: {}", tool_line(&report.dev_tools.python))),
                Line::from(format!(
                    "conda: {} envs · {}",
                    report.dev_tools.conda.envs.len(),
                    report
                        .dev_tools
                        .conda
                        .platform
                        .as_deref()
                        .unwrap_or("unknown")
                )),
                Line::from(format!(
                    "go: {} GOPATH/bin binaries",
                    report.dev_tools.go.binaries.len()
                )),
            ])
            .block(
                Block::default()
                    .title("Developer tools")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });
            frame.render_widget(tools, overview_chunks[1]);

            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                .split(root[2]);

            match active_tab {
                TuiTab::Findings => render_findings_tab(
                    frame,
                    body_chunks[0],
                    body_chunks[1],
                    &report,
                    &plan,
                    selected_finding,
                    risks,
                    warns,
                    infos,
                ),
                TuiTab::Plan => render_plan_tab(
                    frame,
                    body_chunks[0],
                    body_chunks[1],
                    &plan,
                    selected_action,
                ),
            }

            let mode = if apply_enabled {
                Span::styled(
                    "APPLY MODE",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    "READ ONLY",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            };
            let footer = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("Tab", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" switch · "),
                    Span::styled("j/k", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" move · "),
                    Span::styled("e", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" explain · "),
                    Span::styled("d/D", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" dry-run · "),
                    Span::styled("x/m", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" export · "),
                    Span::styled("a/A", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" apply · "),
                    Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" rescan · "),
                    Span::styled("?", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" help · "),
                    Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" quit"),
                ]),
                Line::from(vec![mode, Span::raw(format!("  {status}"))]),
            ])
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(footer, root[3]);

            if let Some(overlay) = &overlay {
                render_tui_overlay(frame, overlay);
            }
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if let Some(current_overlay) = overlay.as_mut() {
                    match current_overlay {
                        TuiOverlay::Help | TuiOverlay::Message { .. } => match key.code {
                            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter => overlay = None,
                            _ => {}
                        },
                        TuiOverlay::Confirm {
                            target,
                            required,
                            buffer,
                            ..
                        } => match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                status = "Apply confirmation cancelled.".into();
                                overlay = None;
                            }
                            KeyCode::Backspace => {
                                buffer.pop();
                            }
                            KeyCode::Enter => {
                                if buffer == required {
                                    let lines = match *target {
                                        ConfirmTarget::SelectedAction(idx) => plan
                                            .actions
                                            .get(idx)
                                            .map(apply_tui_action)
                                            .unwrap_or_else(|| {
                                                vec!["Selected action no longer exists.".into()]
                                            }),
                                        ConfirmTarget::WholeExecutablePlan => {
                                            apply_tui_executable_plan(&plan)
                                        }
                                    };
                                    status = "Apply command finished; review result modal.".into();
                                    overlay = Some(TuiOverlay::Message {
                                        title: "Apply result".into(),
                                        lines,
                                    });
                                } else {
                                    status = format!(
                                        "Confirmation did not match. Type exactly `{required}` or Esc to cancel."
                                    );
                                    buffer.clear();
                                }
                            }
                            KeyCode::Char(ch) => buffer.push(ch),
                            _ => {}
                        },
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => active_tab = toggle_tab(active_tab),
                    KeyCode::Char('f') => active_tab = TuiTab::Findings,
                    KeyCode::Char('p') => active_tab = TuiTab::Plan,
                    KeyCode::Down | KeyCode::Char('j') => match active_tab {
                        TuiTab::Findings => {
                            selected_finding = next_finding(selected_finding, report.findings.len())
                        }
                        TuiTab::Plan => {
                            selected_action = next_finding(selected_action, plan.actions.len())
                        }
                    },
                    KeyCode::Up | KeyCode::Char('k') => match active_tab {
                        TuiTab::Findings => {
                            selected_finding =
                                previous_finding(selected_finding, report.findings.len())
                        }
                        TuiTab::Plan => {
                            selected_action = previous_finding(selected_action, plan.actions.len())
                        }
                    },
                    KeyCode::Char('?') => overlay = Some(TuiOverlay::Help),
                    KeyCode::Char('e') => {
                        overlay = Some(TuiOverlay::Message {
                            title: "Explain".into(),
                            lines: tui_explain_lines(
                                active_tab,
                                selected_finding,
                                selected_action,
                                &report,
                                &plan,
                            ),
                        });
                    }
                    KeyCode::Char('d') => match active_tab {
                        TuiTab::Findings => {
                            let Some(finding) =
                                selected_finding.and_then(|idx| report.findings.get(idx))
                            else {
                                status = "No finding selected to dry-run.".into();
                                continue;
                            };
                            let related = related_actions_for_finding(finding, &plan);
                            if related.is_empty() {
                                status = "Selected finding has no related plan actions to dry-run."
                                    .into();
                                continue;
                            }
                            for action in &related {
                                dry_run_actions.insert(action.id.clone());
                            }
                            let count = related.len();
                            overlay = Some(TuiOverlay::Message {
                                title: "Related action dry run".into(),
                                lines: dry_run_related_actions_lines(finding, &related),
                            });
                            status = format!(
                                "Dry-run recorded for {count} action(s) related to the selected finding."
                            );
                        }
                        TuiTab::Plan => {
                            if let Some(action) =
                                selected_action.and_then(|idx| plan.actions.get(idx))
                            {
                                dry_run_actions.insert(action.id.clone());
                                overlay = Some(TuiOverlay::Message {
                                    title: "Selected action dry run".into(),
                                    lines: dry_run_action_lines(action),
                                });
                                status = format!("Dry-run recorded for `{}`.", action.id);
                            } else {
                                status = "No plan action selected to dry-run.".into();
                            }
                        }
                    },
                    KeyCode::Char('D') => {
                        plan_dry_run_done = true;
                        overlay = Some(TuiOverlay::Message {
                            title: "Whole-plan dry run".into(),
                            lines: dry_run_plan_lines(&plan),
                        });
                        status = "Whole-plan dry-run recorded for this TUI session.".into();
                    }
                    KeyCode::Char('x') => match export_plan_json(&plan) {
                        Ok(path) => status = format!("Exported JSON plan to {}", path.display()),
                        Err(err) => status = format!("Failed to export JSON plan: {err}"),
                    },
                    KeyCode::Char('m') => match export_plan_markdown(&plan) {
                        Ok(path) => {
                            status = format!("Exported Markdown plan to {}", path.display())
                        }
                        Err(err) => status = format!("Failed to export Markdown plan: {err}"),
                    },
                    KeyCode::Char('r') => {
                        report = scan();
                        plan = generate_action_plan(&report);
                        selected_finding = if report.findings.is_empty() {
                            None
                        } else {
                            Some(0)
                        };
                        selected_action = if plan.actions.is_empty() {
                            None
                        } else {
                            Some(0)
                        };
                        dry_run_actions.clear();
                        plan_dry_run_done = false;
                        status = "Rescanned and regenerated the action plan.".into();
                    }
                    KeyCode::Char('a') => {
                        if !apply_enabled {
                            status = "Apply is disabled in read-only TUI mode. Restart with `macroscope tui --apply`.".into();
                            continue;
                        }
                        let Some(idx) = selected_action else {
                            status = "No selected plan action to apply.".into();
                            continue;
                        };
                        let Some(action) = plan.actions.get(idx) else {
                            status = "Selected plan action no longer exists.".into();
                            continue;
                        };
                        if !is_executable_action(action) {
                            overlay = Some(TuiOverlay::Message {
                                title: "Review-only action".into(),
                                lines: vec![
                                    format!("`{}` is not executable by Macroscope yet.", action.id),
                                    format!("Kind: {}", action_kind_label(&action.kind)),
                                    "".into(),
                                    format!(
                                        "Suggested instruction: {}",
                                        action_instruction(action)
                                    ),
                                ],
                            });
                            status = "Review-only action was not executed.".into();
                            continue;
                        }
                        if !dry_run_actions.contains(&action.id) {
                            dry_run_actions.insert(action.id.clone());
                            overlay = Some(TuiOverlay::Message {
                                title: "Dry-run required first".into(),
                                lines: dry_run_action_lines(action),
                            });
                            status =
                                "Dry-run recorded. Press `a` again to request confirmation.".into();
                            continue;
                        }
                        overlay = Some(confirm_selected_action_overlay(idx, action));
                    }
                    KeyCode::Char('A') => {
                        if !apply_enabled {
                            status = "Apply is disabled in read-only TUI mode. Restart with `macroscope tui --apply`.".into();
                            continue;
                        }
                        let count = executable_action_count(&plan);
                        if count == 0 {
                            status =
                                "No executable Move-to-Trash actions in the current plan.".into();
                            continue;
                        }
                        if !plan_dry_run_done {
                            plan_dry_run_done = true;
                            overlay = Some(TuiOverlay::Message {
                                title: "Whole-plan dry run required first".into(),
                                lines: dry_run_plan_lines(&plan),
                            });
                            status = "Whole-plan dry-run recorded. Press `A` again to request confirmation.".into();
                            continue;
                        }
                        overlay = Some(confirm_whole_plan_overlay(count));
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn render_tui_overlay(frame: &mut ratatui::Frame<'_>, overlay: &TuiOverlay) {
    let area = centered_rect(74, 72, frame.area());
    frame.render_widget(Clear, area);

    let (title, lines) = match overlay {
        TuiOverlay::Help => (
            "TUI help".to_string(),
            vec![
                "Tab / f / p: switch between Findings and Plan".into(),
                "j/k or arrows: move selection".into(),
                "e: explain selected finding or action".into(),
                "d: dry-run selected plan action, or related actions for a selected finding".into(),
                "D: dry-run the whole generated plan".into(),
                "x: export plan JSON to ./macroscope-plan.json".into(),
                "m: export plan Markdown to ./macroscope-plan.md".into(),
                "r: rescan and regenerate plan".into(),
                "a: apply selected executable action; requires --apply, dry-run, and typed confirmation".into(),
                "A: apply all executable actions; requires --apply, dry-run, and typed confirmation".into(),
                "q / Esc: close modal or quit".into(),
            ],
        ),
        TuiOverlay::Message { title, lines } => (title.clone(), lines.clone()),
        TuiOverlay::Confirm {
            title,
            prompt,
            required,
            buffer,
            ..
        } => (
            title.clone(),
            vec![
                prompt.clone(),
                "".into(),
                format!("Type exactly `{required}` and press Enter."),
                "Esc cancels.".into(),
                "".into(),
                format!("Confirmation: {buffer}"),
            ],
        ),
    };

    let paragraph = Paragraph::new(
        lines
            .into_iter()
            .map(Line::from)
            .collect::<Vec<Line<'static>>>(),
    )
    .block(Block::default().title(title).borders(Borders::ALL))
    .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    area: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn tui_explain_lines(
    active_tab: TuiTab,
    selected_finding: Option<usize>,
    selected_action: Option<usize>,
    report: &Report,
    plan: &ActionPlan,
) -> Vec<String> {
    match active_tab {
        TuiTab::Findings => selected_finding
            .and_then(|idx| report.findings.get(idx))
            .map(|finding| {
                let mut lines = vec![
                    format!("{} — {}", severity_label(&finding.severity), finding.title),
                    "".into(),
                    finding.detail.clone(),
                ];
                let related = related_actions_for_finding(finding, plan);
                if !related.is_empty() {
                    lines.push("".into());
                    lines.push("Related actions:".into());
                    for action in related {
                        lines.push(format!("- {} ({})", action.title, action.id));
                    }
                }
                lines
            })
            .unwrap_or_else(|| vec!["No finding selected.".into()]),
        TuiTab::Plan => selected_action
            .and_then(|idx| plan.actions.get(idx))
            .map(action_explain_lines)
            .unwrap_or_else(|| vec!["No action selected.".into()]),
    }
}

fn action_explain_lines(action: &PlannedAction) -> Vec<String> {
    vec![
        action.title.clone(),
        "".into(),
        format!("ID: {}", action.id),
        format!("Kind: {}", action_kind_label(&action.kind)),
        format!("Risk: {:?}", action.risk),
        format!("Confidence: {:?}", action.confidence),
        format!("Destructive: {}", action.destructive),
        "".into(),
        action.rationale.clone(),
        "".into(),
        format!("Suggested instruction: {}", action_instruction(action)),
    ]
}

fn dry_run_action_lines(action: &PlannedAction) -> Vec<String> {
    let mut lines = vec![
        format!("Would evaluate action `{}`.", action.id),
        format!("Title: {}", action.title),
        format!("Risk: {:?}", action.risk),
        format!("Confidence: {:?}", action.confidence),
        format!("Destructive: {}", action.destructive),
        "".into(),
    ];
    match &action.kind {
        ActionKind::MoveToTrash { path } => {
            lines.push(format!("Would move to Trash: {}", path.display()));
            lines.push("Real apply requires `macroscope tui --apply`, this dry-run, then typed TRASH confirmation.".into());
        }
        ActionKind::BrewInstall { package } => {
            lines.push(format!(
                "Would suggest, but not execute: brew install {package}"
            ));
            lines.push("Package-manager actions are review-only in the TUI for now.".into());
        }
        ActionKind::Manual { instructions } => {
            lines.push(format!("Manual instruction: {instructions}"));
            lines.push("Manual actions are never auto-executed.".into());
        }
    }
    lines
}

fn dry_run_related_actions_lines(finding: &Finding, actions: &[&PlannedAction]) -> Vec<String> {
    let mut lines = vec![
        format!("Finding: {}", finding.title),
        finding.detail.clone(),
        "".into(),
        format!("Related actions to dry-run: {}", actions.len()),
        "".into(),
    ];

    for action in actions {
        let prefix = if is_executable_action(action) {
            "Would run"
        } else {
            "Would skip/review"
        };
        lines.push(format!("{prefix}: {} ({})", action.title, action.id));
        lines.push(format!("  {}", action_instruction(action)));
    }

    lines
}

fn dry_run_plan_lines(plan: &ActionPlan) -> Vec<String> {
    let mut lines = vec![
        format!("Plan actions: {}", plan.summary.total),
        format!(
            "Executable Move-to-Trash actions: {}",
            executable_action_count(plan)
        ),
        format!("Destructive actions: {}", plan.summary.destructive),
        "".into(),
    ];

    for action in &plan.actions {
        let prefix = if is_executable_action(action) {
            "Would run"
        } else {
            "Would skip/review"
        };
        lines.push(format!("{prefix}: {} ({})", action.title, action.id));
    }

    if plan.actions.is_empty() {
        lines.push("No actions proposed.".into());
    }
    lines
}

fn export_plan_json(plan: &ActionPlan) -> Result<PathBuf> {
    let path = PathBuf::from("macroscope-plan.json");
    fs::write(&path, serde_json::to_string_pretty(plan)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn export_plan_markdown(plan: &ActionPlan) -> Result<PathBuf> {
    let path = PathBuf::from("macroscope-plan.md");
    fs::write(&path, render_action_plan_markdown(plan))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn is_executable_action(action: &PlannedAction) -> bool {
    matches!(action.kind, ActionKind::MoveToTrash { .. })
}

fn executable_action_count(plan: &ActionPlan) -> usize {
    plan.actions
        .iter()
        .filter(|action| is_executable_action(action))
        .count()
}

fn confirm_selected_action_overlay(idx: usize, action: &PlannedAction) -> TuiOverlay {
    let path = match &action.kind {
        ActionKind::MoveToTrash { path } => path.display().to_string(),
        _ => "non-executable action".into(),
    };
    TuiOverlay::Confirm {
        target: ConfirmTarget::SelectedAction(idx),
        title: "Confirm selected apply".into(),
        prompt: format!(
            "Move this path to Trash?\n\n{path}\n\nAction: {}\nRisk: {:?}",
            action.id, action.risk
        ),
        required: "TRASH".into(),
        buffer: String::new(),
    }
}

fn confirm_whole_plan_overlay(count: usize) -> TuiOverlay {
    TuiOverlay::Confirm {
        target: ConfirmTarget::WholeExecutablePlan,
        title: "Confirm plan apply".into(),
        prompt: format!(
            "Move {count} executable plan item(s) to Trash? Review-only actions will be skipped."
        ),
        required: format!("APPLY {count}"),
        buffer: String::new(),
    }
}

fn apply_tui_action(action: &PlannedAction) -> Vec<String> {
    match &action.kind {
        ActionKind::MoveToTrash { path } => match move_to_trash(path) {
            Ok(()) => vec![
                format!("Applied: {}", action.title),
                format!("Moved to Trash: {}", path.display()),
            ],
            Err(err) => vec![format!("Failed: {}", action.title), format!("Error: {err}")],
        },
        ActionKind::BrewInstall { .. } | ActionKind::Manual { .. } => vec![
            format!("Skipped review-only action: {}", action.title),
            format!("Instruction: {}", action_instruction(action)),
        ],
    }
}

fn apply_tui_executable_plan(plan: &ActionPlan) -> Vec<String> {
    let mut lines = Vec::new();
    for action in &plan.actions {
        if is_executable_action(action) {
            lines.extend(apply_tui_action(action));
            lines.push("".into());
        }
    }
    if lines.is_empty() {
        lines.push("No executable actions were applied.".into());
    }
    lines
}

fn render_findings_tab(
    frame: &mut ratatui::Frame<'_>,
    list_area: ratatui::layout::Rect,
    detail_area: ratatui::layout::Rect,
    report: &Report,
    plan: &ActionPlan,
    selected: Option<usize>,
    risks: usize,
    warns: usize,
    infos: usize,
) {
    let items: Vec<ListItem> = if report.findings.is_empty() {
        vec![ListItem::new(Line::from(vec![Span::styled(
            "No notable findings. Nice.",
            Style::default().fg(Color::Green),
        )]))]
    } else {
        report
            .findings
            .iter()
            .map(|finding| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:<4} ", severity_label(&finding.severity)),
                        tui_severity_style(&finding.severity),
                    ),
                    Span::raw(finding.title.clone()),
                ]))
            })
            .collect()
    };

    let mut state = ListState::default();
    state.select(selected);
    let findings = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "Findings  {risks} risk · {warns} warn · {infos} info"
                ))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("➜ ");
    frame.render_stateful_widget(findings, list_area, &mut state);

    let detail_lines =
        if let Some(idx) = selected.and_then(|idx| report.findings.get(idx).map(|_| idx)) {
            let finding = &report.findings[idx];
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(
                        severity_label(&finding.severity),
                        tui_severity_style(&finding.severity),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        finding.title.clone(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(finding.detail.clone()),
                Line::from(""),
            ];

            let related = related_actions_for_finding(finding, plan);
            if !related.is_empty() {
                lines.push(Line::from(Span::styled(
                    "Related actions:",
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                for action in related.into_iter().take(3) {
                    lines.push(Line::from(format!("- {}", action.title)));
                }
                lines.push(Line::from(""));
            }

            lines.push(Line::from(Span::styled(
                format!("Finding {} of {}", idx + 1, report.findings.len()),
                Style::default().fg(Color::DarkGray),
            )));
            lines
        } else {
            vec![Line::from("No finding selected.")]
        };

    let detail = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title("Finding detail")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, detail_area);
}

fn render_plan_tab(
    frame: &mut ratatui::Frame<'_>,
    list_area: ratatui::layout::Rect,
    detail_area: ratatui::layout::Rect,
    plan: &ActionPlan,
    selected: Option<usize>,
) {
    let items: Vec<ListItem> = if plan.actions.is_empty() {
        vec![ListItem::new(Line::from(vec![Span::styled(
            "No actions proposed. Nice.",
            Style::default().fg(Color::Green),
        )]))]
    } else {
        plan.actions
            .iter()
            .map(|action| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:<4} ", risk_label(action.risk)),
                        tui_risk_style(action.risk),
                    ),
                    Span::raw(action.title.clone()),
                ]))
            })
            .collect()
    };

    let mut state = ListState::default();
    state.select(selected);
    let actions = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "Plan  {} actions · {} destructive",
                    plan.summary.total, plan.summary.destructive
                ))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("➜ ");
    frame.render_stateful_widget(actions, list_area, &mut state);

    let detail_lines =
        if let Some(idx) = selected.and_then(|idx| plan.actions.get(idx).map(|_| idx)) {
            let action = &plan.actions[idx];
            vec![
                Line::from(vec![
                    Span::styled(risk_label(action.risk), tui_risk_style(action.risk)),
                    Span::raw("  "),
                    Span::styled(
                        confidence_label(action.confidence),
                        Style::default().fg(Color::Blue),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    action.title.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(format!("ID: {}", action.id)),
                Line::from(format!("Kind: {}", action_kind_label(&action.kind))),
                Line::from(format!("Destructive: {}", action.destructive)),
                Line::from(""),
                Line::from(action.rationale.clone()),
                Line::from(""),
                Line::from(format!("Action: {}", action_instruction(action))),
                Line::from(""),
                Line::from(Span::styled(
                    format!("Action {} of {}", idx + 1, plan.actions.len()),
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        } else {
            vec![Line::from("No action selected.")]
        };

    let detail = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title("Action detail")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, detail_area);
}

fn tab_span(label: &'static str, active: bool) -> Span<'static> {
    if active {
        Span::styled(
            format!("[{label}]"),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(format!(" {label} "), Style::default().fg(Color::DarkGray))
    }
}

fn toggle_tab(tab: TuiTab) -> TuiTab {
    match tab {
        TuiTab::Findings => TuiTab::Plan,
        TuiTab::Plan => TuiTab::Findings,
    }
}

fn risk_label(risk: ActionRisk) -> &'static str {
    match risk {
        ActionRisk::Low => "LOW",
        ActionRisk::Medium => "MED",
        ActionRisk::High => "HIGH",
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low-confidence",
        Confidence::Medium => "medium-confidence",
        Confidence::High => "high-confidence",
    }
}

fn tui_risk_style(risk: ActionRisk) -> Style {
    match risk {
        ActionRisk::Low => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        ActionRisk::Medium => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        ActionRisk::High => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn next_finding(selected: Option<usize>, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(selected.map_or(0, |idx| (idx + 1).min(len - 1)))
    }
}

fn previous_finding(selected: Option<usize>, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(selected.map_or(0, |idx| idx.saturating_sub(1)))
    }
}

fn intel_bin_count(report: &Report) -> usize {
    report
        .local_bins
        .iter()
        .filter(|bin| {
            bin.arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
        })
        .count()
}

fn intel_app_count(report: &Report) -> usize {
    report
        .apps
        .apps
        .iter()
        .filter(|app| {
            app.executable_arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
        })
        .count()
}

fn finding_counts(report: &Report) -> (usize, usize, usize) {
    let mut risks = 0;
    let mut warns = 0;
    let mut infos = 0;

    for finding in &report.findings {
        match finding.severity {
            Severity::Risk => risks += 1,
            Severity::Warn => warns += 1,
            Severity::Info => infos += 1,
        }
    }

    (risks, warns, infos)
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Risk => "RISK",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

fn severity_badge(severity: &Severity) -> String {
    match severity {
        Severity::Risk => "RISK".red().bold().to_string(),
        Severity::Warn => "WARN".yellow().bold().to_string(),
        Severity::Info => "INFO".blue().bold().to_string(),
    }
}

fn tui_severity_style(severity: &Severity) -> Style {
    match severity {
        Severity::Risk => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::Warn => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        Severity::Info => Style::default()
            .fg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    }
}

fn plist_string(plist: &Option<Value>, key: &str) -> Option<String> {
    plist
        .as_ref()?
        .as_dictionary()?
        .get(key)?
        .as_string()
        .map(String::from)
}

fn command_stdout(cmd: &str, args: &[&str]) -> Result<String> {
    command_stdout_path(Path::new(cmd), args)
}

fn command_stdout_path(cmd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd).args(args).output()?;
    if !output.status.success() {
        anyhow::bail!("command failed: {} {}", cmd.display(), args.join(" "));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn command_lines_path(cmd: &Path, args: &[&str]) -> Result<Vec<String>> {
    Ok(command_stdout_path(cmd, args)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect())
}

fn file_arch(path: &Path) -> Result<String> {
    let output = Command::new("file").arg("-b").arg(path).output()?;
    if !output.status.success() {
        anyhow::bail!("file failed for {}", path.display());
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(simplify_file_arch(&text))
}

fn simplify_file_arch(file_output: &str) -> String {
    let mut parts = Vec::new();
    if file_output.contains("arm64") {
        parts.push("arm64");
    }
    if file_output.contains("x86_64") {
        parts.push("x86_64");
    }
    if file_output.contains("Mach-O") {
        parts.push("Mach-O");
    } else if file_output.contains("script") || file_output.starts_with("#!") {
        parts.push("script");
    } else if file_output.contains("ASCII text") || file_output.contains("Unicode text") {
        parts.push("text");
    }

    if parts.is_empty() {
        file_output.to_string()
    } else {
        parts.join(" ")
    }
}

fn find_homebrew() -> Option<PathBuf> {
    ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

fn find_conda() -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("/opt/anaconda3/bin/conda")];
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join("miniconda3/bin/conda"));
        candidates.push(home.join("anaconda3/bin/conda"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn find_go() -> Option<PathBuf> {
    [
        "/opt/homebrew/bin/go",
        "/usr/local/go/bin/go",
        "/usr/local/bin/go",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

fn which(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('/') {
        let path = PathBuf::from(cmd);
        return path.exists().then_some(path);
    }

    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn first_field(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or(line)
}

fn opt(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("not found")
}

fn tool_line(tool: &ToolVersion) -> String {
    match (&tool.path, &tool.version) {
        (Some(path), Some(version)) => format!("{version} ({path})"),
        (Some(path), None) => format!("found ({path})"),
        _ => "not found".into(),
    }
}

fn push_conda_md(out: &mut String, conda: &CondaReport) {
    out.push_str(&format!("- conda: {}\n", tool_line(&conda.conda)));
    out.push_str(&format!(
        "- platform: `{}`\n",
        conda.platform.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "- root prefix: `{}`\n",
        conda.root_prefix.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "- active prefix: `{}`\n",
        conda.active_prefix.as_deref().unwrap_or("unknown")
    ));
    out.push_str("\n#### Conda envs\n\n");
    push_bullets(out, &conda.envs);
    out.push_str("#### Conda env directories\n\n");
    push_bullets(out, &conda.envs_dirs);
    out.push_str("#### Conda package caches\n\n");
    push_bullets(out, &conda.package_caches);
}

fn push_go_md(out: &mut String, go: &GoReport) {
    out.push_str(&format!("- go: {}\n", tool_line(&go.go)));
    out.push_str(&format!(
        "- GOOS/GOARCH: `{}/{}`\n",
        go.goos.as_deref().unwrap_or("unknown"),
        go.goarch.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "- GOPATH: `{}`\n",
        go.gopath.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "- GOBIN: `{}`\n",
        go.gobin.as_deref().unwrap_or("not set")
    ));
    out.push_str(&format!(
        "- GOROOT: `{}`\n",
        go.goroot.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "- bin dir: `{}`\n\n",
        go.bin_dir
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "unknown".into())
    ));

    if go.binaries.is_empty() {
        out.push_str("No GOPATH/bin binaries found.\n\n");
    } else {
        out.push_str("| Binary | Architecture |\n");
        out.push_str("| --- | --- |\n");
        for binary in &go.binaries {
            out.push_str(&format!(
                "| `{}` | {} |\n",
                md_escape(&binary.path.display().to_string()),
                md_escape(binary.arch.as_deref().unwrap_or("unknown"))
            ));
        }
        out.push('\n');
    }
}

fn push_homebrew_services_md(out: &mut String, services: &[HomebrewService]) {
    if services.is_empty() {
        out.push_str("None.\n\n");
        return;
    }

    out.push_str("| Service | Status | User | Plist |\n");
    out.push_str("| --- | --- | --- | --- |\n");
    for service in services {
        out.push_str(&format!(
            "| {} | {} | {} | `{}` |\n",
            md_escape(&service.name),
            md_escape(service.status.as_deref().unwrap_or("unknown")),
            md_escape(service.user.as_deref().unwrap_or("none")),
            md_escape(service.file.as_deref().unwrap_or("none"))
        ));
    }
    out.push('\n');
}

fn push_app_table_md(out: &mut String, apps: &[AppEntry]) {
    if apps.is_empty() {
        out.push_str("No apps found.\n\n");
        return;
    }

    out.push_str("| App | Version | Architecture | Bundle ID | Path |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for app in apps {
        out.push_str(&format!(
            "| {} | {} | {} | {} | `{}` |\n",
            md_escape(app.name.as_deref().unwrap_or("unknown")),
            md_escape(app.version.as_deref().unwrap_or("unknown")),
            md_escape(app.executable_arch.as_deref().unwrap_or("unknown")),
            md_escape(app.bundle_id.as_deref().unwrap_or("unknown")),
            md_escape(&app.path.display().to_string())
        ));
    }
    out.push('\n');
}

fn md_escape(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn push_bullets(out: &mut String, values: &[String]) {
    if values.is_empty() {
        out.push_str("None.\n\n");
    } else {
        for value in values {
            out.push_str(&format!("- `{value}`\n"));
        }
        out.push('\n');
    }
}

fn push_tool_md(out: &mut String, name: &str, tool: &ToolVersion) {
    out.push_str(&format!("- `{name}`: {}\n", tool_line(tool)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planned_action(
        id: &str,
        destructive: bool,
        risk: ActionRisk,
        kind: ActionKind,
    ) -> PlannedAction {
        PlannedAction {
            id: id.into(),
            title: format!("Action {id}"),
            rationale: "test rationale".into(),
            confidence: Confidence::High,
            risk,
            destructive,
            kind,
        }
    }

    #[test]
    fn slugify_normalizes_paths_and_symbols() {
        assert_eq!(
            slugify("/usr/local/bin/aws_completer"),
            "usr-local-bin-aws-completer"
        );
        assert_eq!(slugify("  Review: Go/Binary v2!! "), "review-go-binary-v2");
        assert_eq!(slugify("Already-Clean"), "already-clean");
    }

    #[test]
    fn simplify_file_arch_extracts_useful_arch_labels() {
        assert_eq!(
            simplify_file_arch("Mach-O universal binary with 2 architectures: [x86_64] [arm64]"),
            "arm64 x86_64 Mach-O"
        );
        assert_eq!(
            simplify_file_arch("Mach-O 64-bit executable x86_64"),
            "x86_64 Mach-O"
        );
        assert_eq!(
            simplify_file_arch("POSIX shell script text executable"),
            "script"
        );
        assert_eq!(simplify_file_arch("ASCII text"), "text");
    }

    #[test]
    fn parse_npm_packages_sorts_dependencies_and_keeps_versions() {
        let packages = parse_npm_packages(
            r#"{
                "dependencies": {
                    "zeta": { "version": "2.0.0" },
                    "alpha": { "version": "1.0.0" },
                    "noversion": {}
                }
            }"#,
        )
        .expect("npm package JSON should parse");

        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "alpha");
        assert_eq!(packages[0].version.as_deref(), Some("1.0.0"));
        assert_eq!(packages[1].name, "noversion");
        assert_eq!(packages[1].version, None);
        assert_eq!(packages[2].name, "zeta");
    }

    #[test]
    fn parse_conda_info_extracts_prefixes_and_arrays() {
        let tool = ToolVersion {
            path: Some("/opt/anaconda3/bin/conda".into()),
            version: Some("conda 24.7.1".into()),
            error: None,
        };
        let report = parse_conda_info(
            &tool,
            r#"{
                "platform": "osx-arm64",
                "base_prefix": "/opt/anaconda3",
                "active_prefix": "/opt/anaconda3/envs/demo",
                "envs": ["/opt/anaconda3", "/Users/example/miniconda3"],
                "envs_dirs": ["/opt/anaconda3/envs"],
                "pkgs_dirs": ["/opt/anaconda3/pkgs", "/Users/example/.conda/pkgs"]
            }"#,
        )
        .expect("conda info JSON should parse");

        assert_eq!(
            report.conda.path.as_deref(),
            Some("/opt/anaconda3/bin/conda")
        );
        assert_eq!(report.platform.as_deref(), Some("osx-arm64"));
        assert_eq!(report.root_prefix.as_deref(), Some("/opt/anaconda3"));
        assert_eq!(
            report.active_prefix.as_deref(),
            Some("/opt/anaconda3/envs/demo")
        );
        assert_eq!(report.envs.len(), 2);
        assert_eq!(report.envs_dirs, vec!["/opt/anaconda3/envs"]);
        assert_eq!(report.package_caches.len(), 2);
    }

    #[test]
    fn summarizes_actions_and_counts_executable_trash_actions() {
        let actions = vec![
            planned_action(
                "trash-old-tool",
                true,
                ActionRisk::Medium,
                ActionKind::MoveToTrash {
                    path: PathBuf::from("/usr/local/bin/old-tool"),
                },
            ),
            planned_action(
                "review-cleanup",
                false,
                ActionRisk::Low,
                ActionKind::Manual {
                    instructions: "Review cleanup".into(),
                },
            ),
            planned_action(
                "manual-risky",
                false,
                ActionRisk::High,
                ActionKind::Manual {
                    instructions: "Review risky action".into(),
                },
            ),
        ];

        let summary = summarize_actions(&actions);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.destructive, 1);
        assert_eq!(summary.low_risk, 1);
        assert_eq!(summary.medium_risk, 1);
        assert_eq!(summary.high_risk, 1);

        let plan = ActionPlan { summary, actions };
        assert_eq!(executable_action_count(&plan), 1);
    }
}
