use crate::model::{FindingCategory, Report, Severity};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct ReportDiff {
    pub before_collected_at_unix: u64,
    pub after_collected_at_unix: u64,
    pub added_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
    pub inconclusive_findings: Vec<String>,
    pub inconclusive_added_findings: Vec<String>,
    pub added_launch_items: Vec<String>,
    pub inconclusive_added_launch_items: Vec<String>,
    pub removed_launch_items: Vec<String>,
    pub changed_launch_items: Vec<String>,
    pub added_listeners: Vec<String>,
    pub inconclusive_added_listeners: Vec<String>,
    pub removed_listeners: Vec<String>,
    pub correlation_nodes_before: usize,
    pub correlation_nodes_after: usize,
    pub correlation_edges_before: usize,
    pub correlation_edges_after: usize,
    pub inconclusive_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotHistoryEntry {
    pub name: String,
    pub path: PathBuf,
    pub collected_at_unix: Option<u64>,
    pub findings: Option<usize>,
    pub risks: Option<usize>,
    pub warnings: Option<usize>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub passed: bool,
    pub baseline_collected_at_unix: u64,
    pub verified_at_unix: u64,
    pub targets: Vec<String>,
    pub unknown_targets: Vec<String>,
    pub inconclusive_targets: Vec<String>,
    pub resolved: Vec<String>,
    pub remaining: Vec<String>,
    pub new_priority_findings: Vec<String>,
    pub inconclusive_errors: Vec<String>,
}

pub fn managed_snapshot_dir() -> Result<PathBuf> {
    if let Some(root) = std::env::var_os("XDG_STATE_HOME") {
        let root = PathBuf::from(root);
        if root.is_absolute() {
            return Ok(root.join("macroscope/snapshots"));
        }
    }
    let home = dirs::home_dir().context("cannot locate home directory for snapshot storage")?;
    Ok(home.join(".local/state/macroscope/snapshots"))
}

pub fn managed_snapshot_path(name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        anyhow::bail!("snapshot name must use only letters, numbers, '.', '_', or '-'");
    }
    Ok(managed_snapshot_dir()?.join(format!("{name}.json")))
}

pub fn save_managed_snapshot(name: Option<&str>, report: &Report) -> Result<PathBuf> {
    let generated;
    let name = if let Some(name) = name {
        name
    } else {
        generated = format!("snapshot-{}", report.collected_at_unix);
        &generated
    };
    let path = managed_snapshot_path(name)?;
    if path
        .try_exists()
        .with_context(|| format!("failed to inspect {}", path.display()))?
    {
        anyhow::bail!("managed snapshot `{name}` already exists; choose another name");
    }
    crate::util::atomic_write_private_new(&path, &serde_json::to_vec_pretty(report)?)
        .with_context(|| format!("failed to create immutable managed snapshot `{name}`"))?;
    Ok(path)
}

pub fn list_managed_snapshots() -> Result<Vec<SnapshotHistoryEntry>> {
    let root = managed_snapshot_dir()?;
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", root.display()));
        }
    };
    let mut history = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read entry in {}", root.display()))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_stem()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        match load_snapshot(&path) {
            Ok(report) => history.push(SnapshotHistoryEntry {
                name,
                path,
                collected_at_unix: Some(report.collected_at_unix),
                findings: Some(report.findings.len()),
                risks: Some(
                    report
                        .findings
                        .iter()
                        .filter(|finding| finding.severity == Severity::Risk)
                        .count(),
                ),
                warnings: Some(
                    report
                        .findings
                        .iter()
                        .filter(|finding| finding.severity == Severity::Warn)
                        .count(),
                ),
                error: None,
            }),
            Err(error) => history.push(SnapshotHistoryEntry {
                name,
                path,
                collected_at_unix: None,
                findings: None,
                risks: None,
                warnings: None,
                error: Some(error.to_string()),
            }),
        }
    }
    history.sort_by(|a, b| {
        b.collected_at_unix
            .cmp(&a.collected_at_unix)
            .then(a.name.cmp(&b.name))
    });
    Ok(history)
}

pub fn save_snapshot(path: &Path, report: &Report) -> Result<()> {
    crate::util::atomic_write_private(path, &serde_json::to_vec_pretty(report)?)
        .with_context(|| format!("failed to save snapshot {}", path.display()))
}

pub fn load_snapshot(path: &Path) -> Result<Report> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read snapshot {}", path.display()))?;
    let report: Report = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse snapshot {}", path.display()))?;
    if report.schema_version > 4 {
        anyhow::bail!(
            "snapshot schema {} is newer than this binary supports",
            report.schema_version
        );
    }
    Ok(report)
}

pub fn diff_reports(before: &Report, after: &Report) -> ReportDiff {
    let before_findings: BTreeSet<_> = observed_findings(before)
        .map(|item| item.id.clone())
        .collect();
    let after_findings: BTreeSet<_> = observed_findings(after)
        .map(|item| item.id.clone())
        .collect();
    let before_launch = launch_signatures(before);
    let after_launch = launch_signatures(after);
    let before_listeners = listener_keys(before);
    let after_listeners = listener_keys(after);
    let runtime_failed = !after.runtime.errors.is_empty();
    let mut resolved_findings = Vec::new();
    let mut inconclusive_findings = Vec::new();
    for id in before_findings.difference(&after_findings) {
        let affected = observed_findings(before)
            .find(|finding| finding.id == id.as_str())
            .is_some_and(|finding| collector_failed_for(finding, after));
        if affected {
            inconclusive_findings.push(id.clone());
        } else {
            resolved_findings.push(id.clone());
        }
    }
    let mut added_findings = Vec::new();
    let mut inconclusive_added_findings = Vec::new();
    for id in after_findings.difference(&before_findings) {
        let affected = observed_findings(after)
            .find(|finding| finding.id == id.as_str())
            .is_some_and(|finding| collector_failed_for(finding, before));
        if affected {
            inconclusive_added_findings.push(id.clone());
        } else {
            added_findings.push(id.clone());
        }
    }
    let mut added_launch_items = Vec::new();
    let mut inconclusive_added_launch_items = Vec::new();
    for label in after_launch
        .keys()
        .filter(|label| !before_launch.contains_key(*label))
    {
        let affected = after
            .persistence
            .launch_items
            .iter()
            .find(|item| crate::hygiene::launch_item_identity(item) == label.as_str())
            .is_some_and(|item| {
                path_errors_affect(&item.path.display().to_string(), &before.persistence.errors)
            });
        if affected {
            inconclusive_added_launch_items.push(label.clone());
        } else {
            added_launch_items.push(label.clone());
        }
    }
    let (added_listeners, inconclusive_added_listeners) = if before.runtime.errors.is_empty() {
        (
            after_listeners
                .difference(&before_listeners)
                .cloned()
                .collect(),
            Vec::new(),
        )
    } else {
        (
            Vec::new(),
            after_listeners
                .difference(&before_listeners)
                .cloned()
                .collect(),
        )
    };
    let inconclusive_errors = collector_errors(before)
        .into_iter()
        .map(|error| format!("baseline: {error}"))
        .chain(
            collector_errors(after)
                .into_iter()
                .map(|error| format!("current: {error}")),
        )
        .collect();

    ReportDiff {
        before_collected_at_unix: before.collected_at_unix,
        after_collected_at_unix: after.collected_at_unix,
        added_findings,
        resolved_findings,
        inconclusive_findings,
        inconclusive_added_findings,
        added_launch_items,
        inconclusive_added_launch_items,
        removed_launch_items: before_launch
            .keys()
            .filter(|label| {
                !after_launch.contains_key(*label)
                    && before
                        .persistence
                        .launch_items
                        .iter()
                        .find(|item| crate::hygiene::launch_item_identity(item) == label.as_str())
                        .is_some_and(|item| {
                            !path_errors_affect(
                                &item.path.display().to_string(),
                                &after.persistence.errors,
                            )
                        })
            })
            .cloned()
            .collect(),
        changed_launch_items: before_launch
            .iter()
            .filter(|(label, signature)| {
                after_launch
                    .get(*label)
                    .is_some_and(|next| next != *signature)
                    && before
                        .persistence
                        .launch_items
                        .iter()
                        .find(|item| crate::hygiene::launch_item_identity(item) == label.as_str())
                        .is_some_and(|item| {
                            !path_errors_affect(
                                &item.path.display().to_string(),
                                &after.persistence.errors,
                            )
                        })
            })
            .map(|(label, _)| label.clone())
            .collect(),
        added_listeners,
        inconclusive_added_listeners,
        removed_listeners: if runtime_failed {
            Vec::new()
        } else {
            before_listeners
                .difference(&after_listeners)
                .cloned()
                .collect()
        },
        correlation_nodes_before: before.correlations.nodes.len(),
        correlation_nodes_after: after.correlations.nodes.len(),
        correlation_edges_before: before.correlations.edges.len(),
        correlation_edges_after: after.correlations.edges.len(),
        inconclusive_errors,
    }
}

pub fn verify_reports(before: &Report, after: &Report, requested: &[String]) -> VerificationReport {
    let baseline_priority: BTreeSet<String> = observed_findings(before)
        .filter(|finding| {
            matches!(
                finding.category,
                FindingCategory::Persistence | FindingCategory::Runtime
            ) && matches!(finding.severity, Severity::Warn | Severity::Risk)
        })
        .map(|finding| finding.id.clone())
        .collect();
    let observed_before: BTreeSet<String> = observed_findings(before)
        .map(|finding| finding.id.clone())
        .collect();
    let requested: BTreeSet<String> = requested.iter().cloned().collect();
    let unknown_targets: Vec<String> = requested.difference(&observed_before).cloned().collect();
    let targets: BTreeSet<String> = if requested.is_empty() {
        baseline_priority
    } else {
        requested.intersection(&observed_before).cloned().collect()
    };
    let after_findings: BTreeSet<String> = observed_findings(after)
        .map(|item| item.id.clone())
        .collect();
    let inconclusive_targets: Vec<String> = targets
        .iter()
        .filter(|target| {
            observed_findings(before)
                .find(|finding| finding.id == target.as_str())
                .is_some_and(|finding| collector_failed_for(finding, after))
        })
        .cloned()
        .collect();
    let inconclusive_set: BTreeSet<&String> = inconclusive_targets.iter().collect();
    let mut resolved = Vec::new();
    let mut remaining = Vec::new();
    for target in &targets {
        if inconclusive_set.contains(target) {
            continue;
        }
        let baseline = observed_findings(before).find(|finding| finding.id == *target);
        let present = after_findings.contains(target)
            || baseline.is_some_and(|finding| runtime_evidence_still_present(finding, after));
        if present {
            remaining.push(target.clone());
        } else {
            resolved.push(target.clone());
        }
    }
    let new_priority_findings = observed_findings(after)
        .filter(|finding| {
            matches!(
                finding.category,
                FindingCategory::Persistence | FindingCategory::Runtime
            ) && matches!(finding.severity, Severity::Warn | Severity::Risk)
                && !observed_findings(before).any(|old| old.id == finding.id)
        })
        .map(|finding| finding.id.clone())
        .collect();

    let inconclusive_errors = collector_errors(after);
    VerificationReport {
        passed: remaining.is_empty()
            && unknown_targets.is_empty()
            && inconclusive_targets.is_empty(),
        baseline_collected_at_unix: before.collected_at_unix,
        verified_at_unix: after.collected_at_unix,
        targets: targets.into_iter().collect(),
        unknown_targets,
        inconclusive_targets,
        resolved,
        remaining,
        new_priority_findings,
        inconclusive_errors,
    }
}

pub fn print_diff(diff: &ReportDiff) {
    println!("Macroscope snapshot diff");
    print_list("Resolved findings", &diff.resolved_findings);
    print_list("Inconclusive findings", &diff.inconclusive_findings);
    print_list("Added findings", &diff.added_findings);
    print_list(
        "Possibly added findings (baseline incomplete)",
        &diff.inconclusive_added_findings,
    );
    print_list("Removed launch items", &diff.removed_launch_items);
    print_list("Added launch items", &diff.added_launch_items);
    print_list(
        "Possibly added launch items (baseline incomplete)",
        &diff.inconclusive_added_launch_items,
    );
    print_list("Changed launch items", &diff.changed_launch_items);
    print_list("Closed listeners", &diff.removed_listeners);
    print_list("New listeners", &diff.added_listeners);
    print_list(
        "Possibly new listeners (baseline incomplete)",
        &diff.inconclusive_added_listeners,
    );
    print_list(
        "Collector errors (diff inconclusive)",
        &diff.inconclusive_errors,
    );
    println!(
        "Correlation graph: {}→{} nodes, {}→{} edges",
        diff.correlation_nodes_before,
        diff.correlation_nodes_after,
        diff.correlation_edges_before,
        diff.correlation_edges_after
    );
}

pub fn print_verification(report: &VerificationReport) {
    println!(
        "Macroscope verification: {}",
        if report.passed { "PASS" } else { "INCOMPLETE" }
    );
    print_list("Resolved targets", &report.resolved);
    print_list("Remaining targets", &report.remaining);
    print_list("Unknown requested targets", &report.unknown_targets);
    print_list("Inconclusive targets", &report.inconclusive_targets);
    print_list("New priority findings", &report.new_priority_findings);
    print_list(
        "Collector errors (verification inconclusive)",
        &report.inconclusive_errors,
    );
}

fn collector_errors(report: &Report) -> Vec<String> {
    report
        .persistence
        .errors
        .iter()
        .map(|error| format!("persistence: {error}"))
        .chain(
            report
                .runtime
                .errors
                .iter()
                .map(|error| format!("runtime: {error}")),
        )
        .chain(
            report
                .apps
                .root_errors
                .iter()
                .map(|error| format!("applications: {error}")),
        )
        .chain(
            report
                .persistence
                .launch_items
                .iter()
                .filter(|item| {
                    item.parent_app_present.is_none()
                        && item.program.as_ref().is_some_and(|program| {
                            program.starts_with("/Library/PrivilegedHelperTools")
                        })
                })
                .map(|item| {
                    format!(
                        "parent-product correlation incomplete: {}",
                        item.path.display()
                    )
                }),
        )
        .collect()
}

fn collector_failed_for(finding: &crate::model::Finding, report: &Report) -> bool {
    match finding.category {
        FindingCategory::Persistence => {
            finding
                .evidence
                .first()
                .is_some_and(|path| path_errors_affect(path, &report.persistence.errors))
                || (finding.id.starts_with("orphaned-privileged-helper:")
                    && (finding.evidence.first().is_some_and(|path| {
                        report.persistence.launch_items.iter().any(|item| {
                            item.path.display().to_string() == *path
                                && item.parent_app_present.is_none()
                        })
                    }) || !report.apps.root_errors.is_empty()))
        }
        FindingCategory::Runtime => runtime_collector_failed_for(finding, report),
        FindingCategory::PackageManager => {
            if finding.id.contains("homebrew") {
                report.homebrew.error.is_some()
            } else if finding.id.contains("conda") {
                report.dev_tools.conda.error.is_some()
            } else if finding.id.contains("npm") {
                report.dev_tools.npm.error.is_some()
            } else {
                false
            }
        }
        FindingCategory::Architecture => {
            if let Some(path) = finding.id.strip_prefix("intel-app:") {
                path_errors_affect(path, &report.apps.errors)
            } else if let Some(path) = finding.id.strip_prefix("intel-local-bin:") {
                path_errors_affect(path, &report.local_bin_errors)
            } else {
                finding.id.contains("go") && report.dev_tools.go.error.is_some()
            }
        }
        FindingCategory::Environment => {
            (finding.id.starts_with("go-") && report.dev_tools.go.error.is_some())
                || (finding.id.starts_with("duplicate-app:")
                    && (!report.apps.root_errors.is_empty()
                        || finding
                            .evidence
                            .iter()
                            .any(|path| path_errors_affect(path, &report.apps.errors))))
        }
    }
}

fn runtime_collector_failed_for(finding: &crate::model::Finding, report: &Report) -> bool {
    report.runtime.errors.iter().any(|error| {
        let lower = error.to_ascii_lowercase();
        if finding.id.starts_with("old-detached-listener:") {
            lower.starts_with("lsof failed") || lower.starts_with("failed to run lsof")
        } else if matches!(
            finding.id.as_str(),
            "detached-agent-browser-processes" | "zombie-processes"
        ) {
            lower.starts_with("ps failed") || lower.starts_with("failed to run ps")
        } else {
            true
        }
    })
}

fn path_errors_affect(path: &str, errors: &[String]) -> bool {
    errors.iter().any(|error| {
        let source = error.split(": ").next().unwrap_or(error);
        source == path
            || ((error.contains("failed to enumerate")
                || error.contains("failed to read directory entry")
                || error.contains("failed to inspect root"))
                && path.starts_with(source))
    })
}

fn runtime_evidence_still_present(finding: &crate::model::Finding, after: &Report) -> bool {
    if finding.id == "detached-agent-browser-processes" {
        return after.runtime.processes.iter().any(|process| {
            process.ppid == 1
                && process.elapsed_seconds >= 6 * 60 * 60
                && (process.command.contains("/.agent-browser/browsers/")
                    || process.command.contains("agent-browser-darwin"))
        });
    }
    if !finding.id.starts_with("old-detached-listener:") {
        return false;
    }
    let endpoint = finding.evidence.last();
    let Some(port) = endpoint.and_then(|value| value.rsplit_once(':')?.1.parse::<u16>().ok())
    else {
        return false;
    };
    after
        .runtime
        .listeners
        .iter()
        .any(|listener| listener.port == Some(port))
}

fn observed_findings(report: &Report) -> impl Iterator<Item = &crate::model::Finding> {
    report
        .findings
        .iter()
        .chain(report.suppressed_findings.iter().map(|item| &item.finding))
}

fn launch_signatures(report: &Report) -> BTreeMap<String, String> {
    report
        .persistence
        .launch_items
        .iter()
        .map(|item| {
            let mut associated_bundle_ids = item.associated_bundle_ids.clone();
            associated_bundle_ids.sort();
            (
                crate::hygiene::launch_item_identity(item),
                format!(
                    "{:?}|{}|{}|{:?}|{:?}|{}|{}|{:?}",
                    item.scope,
                    item.program
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default(),
                    item.program_from_arguments,
                    item.program_arguments,
                    item.translocation_target,
                    item.keep_alive,
                    item.run_at_load,
                    associated_bundle_ids
                ),
            )
        })
        .collect()
}

fn listener_keys(report: &Report) -> BTreeSet<String> {
    report
        .runtime
        .listeners
        .iter()
        .map(|listener| {
            format!(
                "{} {}",
                listener.command.as_deref().unwrap_or("unknown"),
                listener.endpoint
            )
        })
        .collect()
}

fn print_list(label: &str, values: &[String]) {
    println!("{label}: {}", values.len());
    for value in values {
        println!("  - {value}");
    }
}
