use crate::model::{AppEntry, CondaReport, GoReport, HomebrewService, ToolVersion};
use anyhow::{Context, Result};
use plist::Value;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let file_name = path
        .file_name()
        .context("cannot atomically write a path without a file name")?
        .to_string_lossy();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..100_u32 {
        let temporary = parent.join(format!(
            ".{file_name}.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary);
        let mut file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create temporary file {}", temporary.display())
                });
            }
        };
        if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| format!("failed to write {}", temporary.display()));
        }
        drop(file);
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| format!("failed to replace {}", path.display()));
        }
        return Ok(());
    }
    anyhow::bail!(
        "failed to allocate a unique temporary file for {}",
        path.display()
    )
}

pub fn plist_string(plist: &Option<Value>, key: &str) -> Option<String> {
    plist
        .as_ref()?
        .as_dictionary()?
        .get(key)?
        .as_string()
        .map(String::from)
}

pub fn command_stdout(cmd: &str, args: &[&str]) -> Result<String> {
    command_stdout_path(Path::new(cmd), args)
}

pub fn command_stdout_path(cmd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd).args(args).output()?;
    if !output.status.success() {
        anyhow::bail!("command failed: {} {}", cmd.display(), args.join(" "));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn command_lines_path(cmd: &Path, args: &[&str]) -> Result<Vec<String>> {
    Ok(command_stdout_path(cmd, args)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect())
}

pub fn file_arch(path: &Path) -> Result<String> {
    let output = Command::new("file").arg("-b").arg(path).output()?;
    if !output.status.success() {
        anyhow::bail!("file failed for {}", path.display());
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(simplify_file_arch(&text))
}

pub fn simplify_file_arch(file_output: &str) -> String {
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

pub fn find_homebrew() -> Option<PathBuf> {
    ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

pub fn find_conda() -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("/opt/anaconda3/bin/conda")];
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join("miniconda3/bin/conda"));
        candidates.push(home.join("anaconda3/bin/conda"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

pub fn find_go() -> Option<PathBuf> {
    [
        "/opt/homebrew/bin/go",
        "/usr/local/go/bin/go",
        "/usr/local/bin/go",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

pub fn which(cmd: &str) -> Option<PathBuf> {
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

pub fn first_field(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or(line)
}

pub fn opt(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("not found")
}

pub fn tool_line(tool: &ToolVersion) -> String {
    match (&tool.path, &tool.version) {
        (Some(path), Some(version)) => format!("{version} ({path})"),
        (Some(path), None) => format!("found ({path})"),
        _ => "not found".into(),
    }
}

pub fn push_conda_md(out: &mut String, conda: &CondaReport) {
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

pub fn push_go_md(out: &mut String, go: &GoReport) {
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

pub fn push_homebrew_services_md(out: &mut String, services: &[HomebrewService]) {
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

pub fn push_app_table_md(out: &mut String, apps: &[AppEntry]) {
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

pub fn md_escape(value: &str) -> String {
    value
        .replace('`', "ʼ")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

pub fn push_bullets(out: &mut String, values: &[String]) {
    if values.is_empty() {
        out.push_str("None.\n\n");
    } else {
        for value in values {
            out.push_str(&format!("- `{}`\n", md_escape(value)));
        }
        out.push('\n');
    }
}

pub fn push_tool_md(out: &mut String, name: &str, tool: &ToolVersion) {
    out.push_str(&format!("- `{name}`: {}\n", tool_line(tool)));
}
