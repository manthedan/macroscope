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
                findings.push(finding(
                    format!("intel-local-bin:{}", bin.path.display()),
                    FindingCategory::Architecture,
                    Severity::Risk,
                    Confidence::High,
                    "Intel-only binary in /usr/local/bin",
                    format!(
                        "{} appears to be {} (owner: {})",
                        bin.path.display(),
                        bin.arch.as_deref().unwrap_or("unknown"),
                        bin.owner.as_deref().unwrap_or("unknown/manual")
                    ),
                    vec![bin.path.display().to_string()],
                ));
            }
        }

        for app in &apps.apps {
            if app
                .executable_arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
            {
                findings.push(finding(
                    format!("intel-app:{}", app.path.display()),
                    FindingCategory::Architecture,
                    Severity::Warn,
                    Confidence::High,
                    "Intel-only app executable",
                    format!(
                        "{} appears to be {}",
                        app.path.display(),
                        app.executable_arch.as_deref().unwrap_or("unknown")
                    ),
                    vec![app.path.display().to_string()],
                ));
            }
        }
    }

    for (bundle_id, paths) in &apps.duplicate_bundle_ids {
        findings.push(finding(
            format!("duplicate-app:{bundle_id}"),
            FindingCategory::Environment,
            Severity::Warn,
            Confidence::High,
            "Duplicate app bundle identifier",
            format!(
                "{bundle_id}: {}",
                paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        ));
    }

    if !path.duplicates.is_empty() {
        findings.push(finding(
            "duplicate-path-entries",
            FindingCategory::Environment,
            Severity::Info,
            Confidence::High,
            "Duplicate PATH entries",
            path.duplicates
                .iter()
                .map(|(entry, count)| format!("{entry} ({count}x)"))
                .collect::<Vec<_>>()
                .join(", "),
            path.duplicates.keys().cloned().collect(),
        ));
    }

    if path.opt_homebrew_before_usr_local == Some(false) {
        findings.push(finding(
            "legacy-path-before-arm-homebrew",
            FindingCategory::Environment,
            Severity::Warn,
            Confidence::High,
            "/usr/local/bin precedes /opt/homebrew/bin",
            "On Apple Silicon, ARM Homebrew should usually come before legacy /usr/local/bin.",
            vec!["PATH ordering".into()],
        ));
    }

    if homebrew.prefix.as_deref() == Some("/usr/local") && system.arch == "arm64" {
        findings.push(finding(
            "intel-homebrew-on-arm",
            FindingCategory::PackageManager,
            Severity::Risk,
            Confidence::High,
            "Intel Homebrew appears active on Apple Silicon",
            "brew --prefix returned /usr/local",
            vec!["brew --prefix=/usr/local".into()],
        ));
    }

    let outdated_count = homebrew.outdated_formulae.len() + homebrew.outdated_casks.len();
    if outdated_count > 0 {
        findings.push(finding(
            "homebrew-outdated",
            FindingCategory::PackageManager,
            Severity::Info,
            Confidence::High,
            "Outdated Homebrew packages",
            format!(
                "{} formulae and {} casks are outdated.",
                homebrew.outdated_formulae.len(),
                homebrew.outdated_casks.len()
            ),
            vec![format!("{outdated_count} outdated package(s)")],
        ));
    }

    if !homebrew.cleanup_preview.is_empty() {
        let detail = homebrew
            .cleanup_preview
            .last()
            .cloned()
            .unwrap_or_else(|| "brew cleanup --dry-run returned removable files.".into());
        findings.push(finding(
            "homebrew-cleanup",
            FindingCategory::PackageManager,
            Severity::Info,
            Confidence::High,
            "Homebrew cleanup can reclaim space",
            detail.clone(),
            vec![detail],
        ));
    }

    if dev_tools.npm.global_packages.len() > 20 {
        findings.push(finding(
            "many-global-npm-packages",
            FindingCategory::PackageManager,
            Severity::Info,
            Confidence::Medium,
            "Many global npm packages",
            format!(
                "{} packages installed globally; consider whether any are stale.",
                dev_tools.npm.global_packages.len()
            ),
            vec![format!("count={}", dev_tools.npm.global_packages.len())],
        ));
    }

    if dev_tools.conda.conda.path.is_some() {
        findings.push(finding(
            "conda-installation",
            FindingCategory::PackageManager,
            Severity::Info,
            Confidence::High,
            "Conda installation detected",
            format!(
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
            vec![
                dev_tools
                    .conda
                    .root_prefix
                    .clone()
                    .unwrap_or_else(|| "unknown prefix".into()),
            ],
        ));
    }

    let conda_roots = conda_rootish_envs(&dev_tools.conda.envs);
    if conda_roots.len() > 1 {
        findings.push(finding(
            "multiple-conda-roots",
            FindingCategory::PackageManager,
            Severity::Warn,
            Confidence::High,
            "Multiple Conda roots detected",
            format!(
                "Conda sees multiple root-like prefixes: {}",
                conda_roots.join(", ")
            ),
            conda_roots,
        ));
    }

    let intel_go_binaries = intel_go_binaries(&dev_tools.go);
    if system.arch == "arm64" && !intel_go_binaries.is_empty() {
        findings.push(finding(
            "intel-go-binaries",
            FindingCategory::Architecture,
            Severity::Warn,
            Confidence::High,
            "Intel-only Go-installed binaries",
            format!(
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
            intel_go_binaries
                .iter()
                .map(|binary| binary.path.display().to_string())
                .collect(),
        ));
    }

    if let Some(bin_dir) = &dev_tools.go.bin_dir {
        let bin_dir = bin_dir.display().to_string();
        if !dev_tools.go.binaries.is_empty() && !path.entries.iter().any(|entry| entry == &bin_dir)
        {
            findings.push(finding(
                "go-bin-not-on-path",
                FindingCategory::Environment,
                Severity::Info,
                Confidence::High,
                "Go bin directory is not on PATH",
                format!(
                    "{} contains {} binaries but is not present in PATH.",
                    bin_dir,
                    dev_tools.go.binaries.len()
                ),
                vec![bin_dir],
            ));
        }
    }

    findings
}

fn finding(
    id: impl Into<String>,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence,
    title: impl Into<String>,
    detail: impl Into<String>,
    evidence: Vec<String>,
) -> Finding {
    Finding {
        id: id.into(),
        category,
        severity,
        confidence,
        title: title.into(),
        detail: detail.into(),
        evidence,
    }
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
