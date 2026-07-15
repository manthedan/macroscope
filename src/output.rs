use crate::model::*;
use crate::plan::{print_action_detail, print_related_actions};
use crate::util::*;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use owo_colors::OwoColorize;
use std::path::Path;

pub fn print_summary(report: &Report) {
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
        Cell::new("Persistence"),
        Cell::new("launch items / scan errors"),
        Cell::new(format!(
            "{} / {}",
            report.persistence.launch_items.len(),
            report.persistence.errors.len()
        )),
    ]);
    overview.add_row(vec![
        Cell::new("Runtime"),
        Cell::new("processes / listeners / scan errors"),
        Cell::new(format!(
            "{} / {} / {}",
            report.runtime.processes.len(),
            report.runtime.listeners.len(),
            report.runtime.errors.len()
        )),
    ]);
    overview.add_row(vec![
        Cell::new("Correlations"),
        Cell::new("nodes / edges / suppressed findings"),
        Cell::new(format!(
            "{} / {} / {}",
            report.correlations.nodes.len(),
            report.correlations.edges.len(),
            report.suppressed_findings.len()
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

    if !report.suppressed_findings.is_empty() {
        println!(
            "  {} finding(s) suppressed by keep/ignore/snooze decisions",
            report.suppressed_findings.len()
        );
    }

    if report.findings.is_empty() {
        println!("  {}", "No notable findings. Nice.".green());
    } else {
        let intel_app_findings = report
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("intel-app:"))
            .count();
        if intel_app_findings > 0 {
            println!(
                "  {} {} {}",
                severity_badge(&Severity::Info),
                "Architecture".dimmed(),
                format!("{intel_app_findings} Intel-only app executables (collapsed; use Markdown/JSON for details)").bold()
            );
        }
        for finding in report
            .findings
            .iter()
            .filter(|finding| !finding.id.starts_with("intel-app:"))
        {
            println!(
                "  {} {} {}",
                severity_badge(&finding.severity),
                format!("{:?}", finding.category).dimmed(),
                finding.title.bold()
            );
            println!("      {}", finding.detail.dimmed());
            println!("      ID: {}", finding.id.dimmed());
        }
    }

    println!();
    println!(
        "{}",
        "Tip: run `macroscope guide` for a guided workflow, or `macroscope scan --markdown report.md` for a shareable report."
            .dimmed()
    );
}

pub fn print_homebrew_report(report: &Report) {
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

pub fn print_app_report(report: &Report) {
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
        println!(
            "{} {} (details available in Markdown/JSON or with `explain`)",
            "Intel-only app executables:".yellow().bold(),
            intel_apps.len()
        );
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

pub fn print_explanation(target: &str, report: &Report, plan: &ActionPlan) {
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
        .chain(report.suppressed_findings.iter().map(|item| &item.finding))
        .filter(|finding| {
            finding.id.eq_ignore_ascii_case(target)
                || finding
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
                "  {} {} {}",
                severity_badge(&finding.severity),
                format!("{:?}", finding.category).dimmed(),
                finding.title.bold()
            );
            println!("      {}", finding.detail.dimmed());
            println!("      ID: {}", finding.id.dimmed());
            if let Some(suppressed) = report
                .suppressed_findings
                .iter()
                .find(|item| item.finding.id == finding.id)
            {
                println!(
                    "      Decision: {:?}{}",
                    suppressed.decision.decision,
                    suppressed
                        .decision
                        .reason
                        .as_deref()
                        .map(|reason| format!(" — {reason}"))
                        .unwrap_or_default()
                );
            }
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

pub fn print_port_explanation(port: u16, report: &Report, plan: &ActionPlan) {
    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Explain".bright_cyan().bold()
    );
    println!("{} {}", "Port:".bold(), port);
    let listeners: Vec<&ListenerEntry> = report
        .runtime
        .listeners
        .iter()
        .filter(|listener| listener.port == Some(port))
        .collect();
    let listener_errors: Vec<&String> = report
        .runtime
        .errors
        .iter()
        .filter(|error| error.to_ascii_lowercase().contains("lsof"))
        .collect();
    if !listener_errors.is_empty() {
        println!(
            "{}",
            "Listener results may be partial because collection failed:".red()
        );
        for error in &listener_errors {
            println!("  - {error}");
        }
    }
    if listeners.is_empty() {
        if listener_errors.is_empty() {
            println!("{}", "No current TCP listener found.".yellow());
        } else {
            println!("{}", "No conclusive listener result is available.".yellow());
        }
        return;
    }
    let missing_process_evidence = listeners.iter().any(|listener| {
        !report
            .runtime
            .processes
            .iter()
            .any(|process| process.pid == listener.pid)
    });
    if missing_process_evidence {
        let process_errors: Vec<&String> = report
            .runtime
            .errors
            .iter()
            .filter(|error| {
                let lower = error.to_ascii_lowercase();
                lower.starts_with("ps failed") || lower.starts_with("failed to run ps")
            })
            .collect();
        if process_errors.is_empty() {
            println!(
                "{}",
                "Some listener PIDs are absent from the process snapshot; process details are incomplete."
                    .yellow()
            );
        } else {
            println!(
                "{}",
                "Process details are inconclusive because collection failed:".red()
            );
            for error in process_errors {
                println!("  - {error}");
            }
        }
    }
    for listener in listeners {
        println!(
            "\nListener {} ({:?}) — PID {}",
            listener.endpoint, listener.exposure, listener.pid
        );
        if let Some(process) = report
            .runtime
            .processes
            .iter()
            .find(|process| process.pid == listener.pid)
        {
            print_process_evidence(process, report);
        }
    }
    print_related_runtime_findings(report, plan, Some(port), None);
}

pub fn print_pid_explanation(pid: u32, report: &Report, plan: &ActionPlan) {
    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Explain".bright_cyan().bold()
    );
    println!("{} {}", "PID:".bold(), pid);
    let Some(process) = report
        .runtime
        .processes
        .iter()
        .find(|process| process.pid == pid)
    else {
        let process_errors: Vec<&String> = report
            .runtime
            .errors
            .iter()
            .filter(|error| {
                let lower = error.to_ascii_lowercase();
                lower.starts_with("ps failed") || lower.starts_with("failed to run ps")
            })
            .collect();
        if process_errors.is_empty() {
            println!("{}", "PID is not present in the process snapshot.".yellow());
        } else {
            println!(
                "{}",
                "PID status is inconclusive because process collection failed:".red()
            );
            for error in process_errors {
                println!("  - {error}");
            }
        }
        let listener_errors: Vec<&String> = report
            .runtime
            .errors
            .iter()
            .filter(|error| error.to_ascii_lowercase().contains("lsof"))
            .collect();
        for error in &listener_errors {
            println!("  Listener evidence may be partial: {error}");
        }
        for listener in report
            .runtime
            .listeners
            .iter()
            .filter(|listener| listener.pid == pid)
        {
            println!(
                "  lsof listener evidence: {} ({:?})",
                listener.endpoint, listener.exposure
            );
        }
        return;
    };
    print_process_evidence(process, report);
    let listener_errors: Vec<&String> = report
        .runtime
        .errors
        .iter()
        .filter(|error| error.to_ascii_lowercase().contains("lsof"))
        .collect();
    if !listener_errors.is_empty() {
        println!(
            "{}",
            "Listener results may be partial because collection failed:".red()
        );
        for error in listener_errors {
            println!("  - {error}");
        }
    }
    for listener in report
        .runtime
        .listeners
        .iter()
        .filter(|item| item.pid == pid)
    {
        println!(
            "  Listener: {} ({:?})",
            listener.endpoint, listener.exposure
        );
    }
    print_related_runtime_findings(report, plan, None, Some(pid));
}

fn print_process_evidence(process: &ProcessEntry, report: &Report) {
    println!("  Command: {}", process.command);
    println!(
        "  PPID / PGID / UID / age: {} / {} / {} / {}s",
        process.ppid, process.pgid, process.uid, process.elapsed_seconds
    );
    if let Some(parent) = report
        .runtime
        .processes
        .iter()
        .find(|parent| parent.pid == process.ppid)
    {
        println!("  Parent: PID {} — {}", parent.pid, parent.command);
    }
    for item in report.persistence.launch_items.iter().filter(|item| {
        crate::hygiene::process_matches_launch_item(
            item,
            &process.command,
            process.executable.as_deref(),
        )
    }) {
        println!(
            "  launchd owner: {} ({:?}) — {}",
            item.label,
            item.scope,
            item.path.display()
        );
    }
}

fn trusted_evidence_marker(evidence: &str, markers: &[String]) -> bool {
    if !evidence
        .split_whitespace()
        .any(|field| field.starts_with("command="))
    {
        return markers.iter().any(|marker| evidence == marker);
    }
    evidence
        .split_whitespace()
        .take_while(|field| !field.starts_with("command=") && !field.starts_with("parent_command="))
        .any(|field| markers.iter().any(|marker| field == marker))
}

fn print_related_runtime_findings(
    report: &Report,
    plan: &ActionPlan,
    port: Option<u16>,
    pid: Option<u32>,
) {
    let port_marker = port.map(|port| format!("port={port}"));
    let pid_markers = pid.map(|pid| {
        [
            format!("pid={pid}"),
            format!("ppid={pid}"),
            format!("recommended_target_pid={pid}"),
        ]
    });
    let findings: Vec<&Finding> = report
        .findings
        .iter()
        .chain(report.suppressed_findings.iter().map(|item| &item.finding))
        .filter(|finding| {
            finding.evidence.iter().any(|evidence| {
                port_marker.as_ref().is_some_and(|marker| {
                    trusted_evidence_marker(evidence, std::slice::from_ref(marker))
                }) || pid_markers
                    .as_ref()
                    .is_some_and(|markers| trusted_evidence_marker(evidence, markers))
            }) || pid.is_some_and(|pid| plan_finding_targets_pid(plan, &finding.id, pid))
        })
        .collect();
    if findings.is_empty() {
        return;
    }
    println!("\n{}", "Related findings".bold());
    for finding in findings {
        println!(
            "  {:?}: {} ({})",
            finding.severity, finding.title, finding.id
        );
        print_related_actions(&finding.id, plan);
    }
}

fn plan_finding_targets_pid(plan: &ActionPlan, finding_id: &str, pid: u32) -> bool {
    plan.actions.iter().any(|action| {
        action.controls.source_finding_id.as_deref() == Some(finding_id)
            && (action
                .controls
                .preconditions
                .iter()
                .any(|check| match &check.kind {
                    ActionCheckKind::ProcessMatches { pid: target, .. }
                    | ActionCheckKind::ListenerPresent { pid: target, .. } => *target == pid,
                    ActionCheckKind::ZombieParent { parent_pid, .. } => *parent_pid == pid,
                    _ => false,
                })
                || action.controls.recommended_steps.iter().any(|step| {
                    step.command.as_ref().is_some_and(|command| {
                        command.program == "/bin/kill"
                            && command
                                .args
                                .last()
                                .is_some_and(|target| target == &pid.to_string())
                    })
                }))
    })
}

pub fn explain_path_target(path: &Path, report: &Report, plan: &ActionPlan) {
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

pub fn intel_bin_count(report: &Report) -> usize {
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

pub fn intel_app_count(report: &Report) -> usize {
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

pub fn finding_counts(report: &Report) -> (usize, usize, usize) {
    report
        .findings
        .iter()
        .fold((0, 0, 0), |mut counts, finding| {
            match finding.severity {
                Severity::Risk => counts.0 += 1,
                Severity::Warn => counts.1 += 1,
                Severity::Info => counts.2 += 1,
            }
            counts
        })
}

pub fn severity_badge(severity: &Severity) -> String {
    match severity {
        Severity::Risk => "RISK".red().bold().to_string(),
        Severity::Warn => "WARN".yellow().bold().to_string(),
        Severity::Info => "INFO".blue().bold().to_string(),
    }
}
