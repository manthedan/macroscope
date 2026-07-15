use crate::findings::build_findings;
use crate::model::*;
use crate::util::*;
use anyhow::Result;
use plist::Value;
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

pub fn scan() -> Report {
    scan_with_observer(|_, _, _| {})
}

pub fn scan_with_cli_progress(title: &'static str) -> Report {
    let progress = CliProgress::start(title);
    let report = scan_with_observer(|phase, index, total| {
        progress.set(format!("[{index}/{total}] {phase}"));
    });
    progress.finish("Scan complete");
    report
}

pub fn scan_with_observer<F>(mut progress: F) -> Report
where
    F: FnMut(&'static str, usize, usize),
{
    const TOTAL: usize = 9;

    progress("System", 1, TOTAL);
    let system = scan_system();
    progress("Homebrew", 2, TOTAL);
    let homebrew = scan_homebrew();
    progress("Applications", 3, TOTAL);
    let apps = scan_apps();
    progress("Persistence", 4, TOTAL);
    let persistence = crate::hygiene::scan_persistence(&apps);
    progress("Runtime", 5, TOTAL);
    let runtime = crate::hygiene::scan_runtime();
    progress("/usr/local/bin", 6, TOTAL);
    let (local_bins, local_bin_errors) = scan_local_bins_with_errors(Path::new("/usr/local/bin"));
    progress("PATH", 7, TOTAL);
    let path = scan_path();
    progress("Developer tools", 8, TOTAL);
    let dev_tools = scan_dev_tools();

    progress("Findings", 9, TOTAL);
    let mut findings = build_findings(&system, &homebrew, &apps, &local_bins, &path, &dev_tools);
    findings.extend(crate::hygiene::detect_hygiene_findings(
        &persistence,
        &runtime,
    ));
    let correlations =
        crate::correlation::build_correlation_graph(&apps, &persistence, &runtime, &local_bins);
    let (findings, suppressed_findings, decision_errors) = match crate::decisions::load_decisions()
    {
        Ok(decisions) => {
            let (active, suppressed) = crate::decisions::apply_decisions(findings, &decisions);
            (active, suppressed, Vec::new())
        }
        Err(error) => (findings, Vec::new(), vec![error.to_string()]),
    };

    Report {
        schema_version: 4,
        collected_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        system,
        homebrew,
        apps,
        persistence,
        runtime,
        correlations,
        local_bins,
        local_bin_errors,
        path,
        dev_tools,
        findings,
        suppressed_findings,
        decision_errors,
    }
}

struct CliProgress {
    done: Arc<AtomicBool>,
    message: Arc<Mutex<String>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl CliProgress {
    fn start(title: &'static str) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let message = Arc::new(Mutex::new(title.to_string()));
        let thread_done = Arc::clone(&done);
        let thread_message = Arc::clone(&message);
        let handle = thread::spawn(move || {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut idx = 0;
            while !thread_done.load(Ordering::Relaxed) {
                let current = thread_message
                    .lock()
                    .map(|message| message.clone())
                    .unwrap_or_else(|_| title.to_string());
                eprint!("\r\x1b[2K{} {}", frames[idx % frames.len()], current);
                let _ = io::stderr().flush();
                idx += 1;
                thread::sleep(Duration::from_millis(90));
            }
        });

        Self {
            done,
            message,
            handle: Some(handle),
        }
    }

    fn set(&self, message: String) {
        if let Ok(mut current) = self.message.lock() {
            *current = message;
        }
    }

    fn finish(mut self, message: &'static str) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        eprintln!("\r\x1b[2K✓ {message}");
    }
}

pub fn scan_system() -> SystemReport {
    SystemReport {
        arch: command_stdout("uname", &["-m"]).unwrap_or_else(|_| env::consts::ARCH.to_string()),
        macos: command_stdout("sw_vers", &["-productVersion"]).unwrap_or_else(|_| "unknown".into()),
        shell: env::var("SHELL").ok(),
    }
}

pub fn scan_homebrew() -> HomebrewReport {
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

pub fn parse_homebrew_services(json: &str) -> Result<Vec<HomebrewService>> {
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

pub fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(String::from)
}

pub fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
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

pub fn scan_apps() -> AppsReport {
    let mut roots = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join("Applications"));
    }

    let mut apps = Vec::new();
    let mut errors = Vec::new();
    let mut root_errors = Vec::new();

    for root in &roots {
        match root.try_exists() {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) => {
                let error = format!("{}: failed to inspect root: {error}", root.display());
                root_errors.push(error.clone());
                errors.push(error);
                continue;
            }
        }

        for entry in WalkDir::new(root).max_depth(2).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    let error = format!("{}: {error}", root.display());
                    root_errors.push(error.clone());
                    errors.push(error);
                    continue;
                }
            };
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

    errors.extend(apps.iter().filter_map(|app| app.scan_error.clone()));
    AppsReport {
        scanned_roots: roots,
        apps,
        duplicate_bundle_ids: bundle_map,
        errors,
        root_errors,
    }
}

pub fn read_app(path: &Path) -> AppEntry {
    let info_plist = path.join("Contents/Info.plist");
    let (plist, mut scan_error) = match Value::from_file(&info_plist) {
        Ok(value) => (Some(value), None),
        Err(error) => (
            None,
            Some(format!(
                "{}: failed to read metadata: {error}",
                path.display()
            )),
        ),
    };

    let name = plist_string(&plist, "CFBundleDisplayName")
        .or_else(|| plist_string(&plist, "CFBundleName"))
        .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()));
    let bundle_id = plist_string(&plist, "CFBundleIdentifier");
    let version = plist_string(&plist, "CFBundleShortVersionString")
        .or_else(|| plist_string(&plist, "CFBundleVersion"));
    let executable =
        plist_string(&plist, "CFBundleExecutable").map(|exe| path.join("Contents/MacOS").join(exe));
    let executable_arch = executable.as_ref().and_then(|exe| match file_arch(exe) {
        Ok(arch) => Some(arch),
        Err(error) => {
            scan_error = Some(format!(
                "{}: failed to inspect executable architecture: {error}",
                path.display()
            ));
            None
        }
    });

    AppEntry {
        path: path.to_path_buf(),
        name,
        bundle_id,
        version,
        executable,
        executable_arch,
        scan_error,
    }
}

pub fn scan_local_bins(root: &Path) -> Vec<BinEntry> {
    scan_local_bins_with_errors(root).0
}

fn scan_local_bins_with_errors(root: &Path) -> (Vec<BinEntry>, Vec<String>) {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (Vec::new(), Vec::new());
        }
        Err(error) => {
            return (
                Vec::new(),
                vec![format!("{}: failed to enumerate: {error}", root.display())],
            );
        }
    };

    let mut bins = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("{}: failed to read entry: {error}", root.display()));
                continue;
            }
        };
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                errors.push(format!(
                    "{}: failed to read metadata: {error}",
                    path.display()
                ));
                continue;
            }
        };

        if metadata.is_dir() {
            continue;
        }

        let target = if metadata.file_type().is_symlink() {
            match fs::read_link(&path) {
                Ok(target) => Some(target),
                Err(error) => {
                    errors.push(format!(
                        "{}: failed to read symlink: {error}",
                        path.display()
                    ));
                    None
                }
            }
        } else {
            None
        };
        let kind = if metadata.file_type().is_symlink() {
            "symlink"
        } else {
            "file"
        }
        .to_string();
        let arch = match file_arch(&path) {
            Ok(arch) => Some(arch),
            Err(error) => {
                errors.push(format!(
                    "{}: failed to inspect architecture: {error}",
                    path.display()
                ));
                None
            }
        };
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
    (bins, errors)
}

pub fn infer_bin_owner(path: &Path, target: Option<&PathBuf>) -> Option<String> {
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

pub fn app_name_from_path(path: &Path) -> String {
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

pub fn scan_path() -> PathReport {
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

pub fn scan_dev_tools() -> DevToolsReport {
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

pub fn scan_npm() -> NpmReport {
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

pub fn scan_cargo() -> CargoReport {
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

pub fn scan_conda() -> CondaReport {
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

pub fn parse_conda_info(conda: &ToolVersion, json: &str) -> Result<CondaReport> {
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

pub fn scan_go() -> GoReport {
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

pub fn scan_go_binaries(dir: &Path) -> Vec<GoBinary> {
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

pub fn parse_npm_packages(json: &str) -> Result<Vec<PackageEntry>> {
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

pub fn tool_version(cmd: &str, args: &[&str]) -> ToolVersion {
    let Some(path) = which(cmd) else {
        return ToolVersion {
            error: Some(format!("{cmd} not found in PATH")),
            ..Default::default()
        };
    };
    tool_version_path(&path, args)
}

pub fn tool_version_path(path: &Path, args: &[&str]) -> ToolVersion {
    ToolVersion {
        path: Some(path.display().to_string()),
        version: command_stdout_path(path, args).ok(),
        error: None,
    }
}
