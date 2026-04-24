use crate::model::*;

pub fn build_findings(
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

pub fn intel_go_binaries(go: &GoReport) -> Vec<&GoBinary> {
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

pub fn conda_rootish_envs(envs: &[String]) -> Vec<String> {
    envs.iter()
        .filter(|env| env.ends_with("/miniconda3") || env.ends_with("/anaconda3"))
        .cloned()
        .collect()
}
