use crate::findings::{conda_rootish_envs, intel_go_binaries};
use crate::model::*;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use owo_colors::OwoColorize;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn controls_for_finding(finding_id: impl Into<String>) -> ActionControls {
    ActionControls {
        source_finding_id: Some(finding_id.into()),
        ..ActionControls::default()
    }
}

fn stable_action_id(prefix: &str, subject: &str) -> String {
    format!(
        "{prefix}-{}-{:016x}",
        slugify(subject),
        stable_hash(subject)
    )
}

fn stable_hash(value: &str) -> u64 {
    value
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}

pub fn generate_action_plan(report: &Report) -> ActionPlan {
    let mut actions = Vec::new();
    let mut suggested_brew_packages = BTreeSet::new();

    for bin in &report.local_bins {
        let Some(arch) = &bin.arch else {
            continue;
        };
        if !arch.contains("x86_64") || arch.contains("arm64") {
            continue;
        }
        let source_finding_id = format!("intel-local-bin:{}", bin.path.display());
        if !report
            .findings
            .iter()
            .any(|finding| finding.id == source_finding_id)
        {
            continue;
        }

        let name = bin
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        if let Some(package) = known_brew_replacement(&name)
            && suggested_brew_packages.insert(package.to_string())
        {
            actions.push(PlannedAction {
                id: stable_action_id("brew-install", package),
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
                controls: controls_for_finding(format!(
                    "intel-local-bin:{}",
                    bin.path.display()
                )),
            });
        }

        let owner = bin.owner.as_deref().unwrap_or("unknown/manual");
        if requires_owner_aware_manual_removal(owner) {
            actions.push(PlannedAction {
                id: stable_action_id("review-owner", &bin.path.display().to_string()),
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
                controls: controls_for_finding(format!(
                    "intel-local-bin:{}",
                    bin.path.display()
                )),
            });
        } else {
            actions.push(PlannedAction {
                id: stable_action_id("trash", &bin.path.display().to_string()),
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
                controls: controls_for_finding(format!(
                    "intel-local-bin:{}",
                    bin.path.display()
                )),
            });
        }
    }

    for (bundle_id, paths) in &report.apps.duplicate_bundle_ids {
        actions.push(PlannedAction {
            id: stable_action_id("review-duplicate-app", bundle_id),
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
            controls: controls_for_finding(format!("duplicate-app:{bundle_id}")),
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
            controls: controls_for_finding("duplicate-path-entries"),
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
            controls: controls_for_finding("intel-homebrew-on-arm"),
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
            controls: controls_for_finding("homebrew-outdated"),
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
            controls: controls_for_finding("homebrew-cleanup"),
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
            controls: controls_for_finding("multiple-conda-roots"),
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
            controls: controls_for_finding("intel-go-binaries"),
        });
    }

    for finding in report.findings.iter().filter(|finding| {
        matches!(
            finding.category,
            FindingCategory::Persistence | FindingCategory::Runtime
        )
    }) {
        if let Some(action) = hygiene_action(finding) {
            actions.push(action);
        }
    }

    actions.retain(|action| {
        action
            .controls
            .source_finding_id
            .as_ref()
            .is_none_or(|id| report.findings.iter().any(|finding| finding.id == *id))
    });
    for action in &mut actions {
        populate_action_controls(action, report);
    }
    let summary = summarize_actions(&actions);
    ActionPlan {
        schema_version: 3,
        summary,
        actions,
    }
}

fn populate_action_controls(action: &mut PlannedAction, report: &Report) {
    action.controls.provenance.push(action.rationale.clone());
    match &action.kind {
        ActionKind::MoveToTrash { path } => {
            action.controls.expected_file = file_identity(path);
            action.controls.provenance.extend(
                report
                    .local_bins
                    .iter()
                    .filter(|entry| entry.path == *path)
                    .flat_map(|entry| {
                        [
                            format!("kind={}", entry.kind),
                            format!("arch={}", entry.arch.as_deref().unwrap_or("unknown")),
                            format!("owner={}", entry.owner.as_deref().unwrap_or("unknown")),
                        ]
                    }),
            );
            action.controls.preconditions.extend([
                ActionCheck {
                    description: "The planned path still exists".into(),
                    kind: ActionCheckKind::PathExists { path: path.clone() },
                },
                ActionCheck {
                    description: "The user confirmed this exact path is unused or replaced".into(),
                    kind: ActionCheckKind::ManualConfirmation,
                },
            ]);
            action.controls.undo.push(ActionStep {
                description: format!(
                    "Restore `{}` from ~/.Trash before emptying Trash",
                    path.display()
                ),
                command: None,
            });
            action.controls.verification.push(ActionCheck {
                description: "The original path is absent".into(),
                kind: ActionCheckKind::PathAbsent { path: path.clone() },
            });
        }
        ActionKind::BrewInstall { package } => {
            action.controls.preconditions.push(ActionCheck {
                description: "Homebrew is available".into(),
                kind: ActionCheckKind::CommandSucceeds {
                    command: CommandSpec {
                        program: "brew".into(),
                        args: vec!["--version".into()],
                        requires_root: false,
                    },
                },
            });
            action.controls.undo.push(ActionStep {
                description: format!(
                    "Uninstall {package} with Homebrew if the replacement is rejected"
                ),
                command: Some(CommandSpec {
                    program: "brew".into(),
                    args: vec!["uninstall".into(), package.clone()],
                    requires_root: false,
                }),
            });
            action.controls.verification.push(ActionCheck {
                description: format!("Homebrew reports {package} installed"),
                kind: ActionCheckKind::CommandSucceeds {
                    command: CommandSpec {
                        program: "brew".into(),
                        args: vec!["list".into(), "--versions".into(), package.clone()],
                        requires_root: false,
                    },
                },
            });
        }
        ActionKind::Manual { .. } => {
            action.controls.preconditions.push(ActionCheck {
                description: "A human approved the exact manual procedure".into(),
                kind: ActionCheckKind::ManualConfirmation,
            });
            action.controls.undo.push(ActionStep {
                description: "Use the owning app/package rollback or restore from the backup created before manual changes".into(),
                command: None,
            });
            action.controls.verification.push(ActionCheck {
                description: "Run a fresh Macroscope scan and confirm the intended state without unrelated regressions".into(),
                kind: ActionCheckKind::ManualConfirmation,
            });
        }
    }

    if let Some(finding) = action
        .controls
        .source_finding_id
        .as_ref()
        .and_then(|id| report.findings.iter().find(|finding| finding.id == *id))
    {
        action.controls.provenance.extend(finding.evidence.clone());
        action.controls.provenance.sort();
        action.controls.provenance.dedup();
        action.controls.preconditions.push(ActionCheck {
            description: format!("Finding {} is still present", finding.id),
            kind: ActionCheckKind::FindingPresent {
                finding_id: finding.id.clone(),
            },
        });
        action.controls.verification.push(ActionCheck {
            description: format!("Finding {} no longer appears in a fresh scan", finding.id),
            kind: ActionCheckKind::FindingAbsent {
                finding_id: finding.id.clone(),
            },
        });
        if finding.id.starts_with("orphaned-privileged-helper:") {
            action.controls.requires_root = true;
            action.controls.undo.push(ActionStep {
                description: "Reinstall the signed owning product to restore its privileged helper"
                    .into(),
                command: None,
            });
        }
        if let Some(label) = finding
            .id
            .strip_prefix("persistent-launch-item:")
            .or_else(|| finding.id.strip_prefix("translocated-launch-item:"))
            .or_else(|| finding.id.strip_prefix("orphaned-privileged-helper:"))
            && let Some(item) = report
                .persistence
                .launch_items
                .iter()
                .find(|item| crate::hygiene::launch_item_identity(item) == label)
        {
            if item.path.starts_with("/Library") {
                action.controls.requires_root = true;
            }
            let launch_targets: Vec<(String, String, bool)> = match item.scope {
                LaunchItemScope::SystemDaemon => {
                    action.controls.requires_root = true;
                    vec![("system".into(), format!("system/{}", item.label), true)]
                }
                LaunchItemScope::UserAgent | LaunchItemScope::SystemAgent => {
                    let invoking_uid = current_uid().and_then(|uid| uid.parse::<u32>().ok());
                    launch_gui_uids(item, report)
                        .into_iter()
                        .map(|uid| {
                            let domain = format!("gui/{uid}");
                            let requires_root = item.scope == LaunchItemScope::SystemAgent
                                || invoking_uid != Some(uid);
                            (
                                domain.clone(),
                                format!("{domain}/{}", item.label),
                                requires_root,
                            )
                        })
                        .collect()
                }
            };
            if launch_targets.is_empty() {
                action.controls.recommended_steps.push(ActionStep {
                    description: format!(
                        "No unambiguous loaded GUI domain was found for `{}`; inspect launchctl domains and do not remove the plist until every loaded instance is stopped",
                        item.label
                    ),
                    command: None,
                });
            }
            for (domain, target, command_requires_root) in launch_targets {
                action.controls.requires_root |= command_requires_root;
                action.controls.preconditions.push(ActionCheck {
                    description: format!("launchd currently knows `{target}`"),
                    kind: ActionCheckKind::CommandSucceeds {
                        command: CommandSpec {
                            program: "/bin/launchctl".into(),
                            args: vec!["print".into(), target.clone()],
                            requires_root: command_requires_root,
                        },
                    },
                });
                action.controls.recommended_steps.push(ActionStep {
                    description: format!("Boot out the exact launchd service `{target}`"),
                    command: Some(CommandSpec {
                        program: "/bin/launchctl".into(),
                        args: vec!["bootout".into(), target],
                        requires_root: command_requires_root,
                    }),
                });
                action.controls.undo.push(ActionStep {
                    description: format!(
                        "Bootstrap the retained plist at `{}` in `{domain}` again",
                        item.path.display()
                    ),
                    command: Some(CommandSpec {
                        program: "/bin/launchctl".into(),
                        args: vec!["bootstrap".into(), domain, item.path.display().to_string()],
                        requires_root: command_requires_root,
                    }),
                });
            }
        }
        populate_runtime_steps(action, finding, report);
    }
}

fn launch_gui_uids(item: &LaunchItem, report: &Report) -> BTreeSet<u32> {
    let process_uids: BTreeSet<u32> = report
        .runtime
        .processes
        .iter()
        .filter(|process| {
            crate::hygiene::process_matches_launch_item(
                item,
                &process.command,
                process.executable.as_deref(),
            )
        })
        .map(|process| process.uid)
        .filter(|uid| *uid > 0)
        .collect();
    if item.scope == LaunchItemScope::SystemAgent {
        return process_uids;
    }
    let owner_uid = std::fs::symlink_metadata(&item.path)
        .ok()
        .map(|metadata| metadata.uid())
        .filter(|uid| *uid > 0);
    match (owner_uid, process_uids.len()) {
        (Some(owner), 0) => BTreeSet::from([owner]),
        (Some(owner), 1) if process_uids.contains(&owner) => process_uids,
        (None, 1) => process_uids,
        _ => BTreeSet::new(),
    }
}

fn populate_runtime_steps(action: &mut PlannedAction, finding: &Finding, report: &Report) {
    if finding.id.starts_with("old-detached-listener:") {
        let Some(port) =
            evidence_number(finding, "port").and_then(|value| u16::try_from(value).ok())
        else {
            return;
        };
        let Some(service_signature) = evidence_value(finding, "service_signature") else {
            return;
        };
        let Some(exposure) = evidence_value(finding, "exposure") else {
            return;
        };
        let mut seen = BTreeSet::new();
        for listener in report.runtime.listeners.iter().filter(|listener| {
            listener.port == Some(port) && format!("{:?}", listener.exposure) == exposure
        }) {
            let Some(process) = report
                .runtime
                .processes
                .iter()
                .find(|process| process.pid == listener.pid)
            else {
                continue;
            };
            let launch_managed = report.persistence.launch_items.iter().any(|item| {
                crate::hygiene::process_matches_launch_item(
                    item,
                    &process.command,
                    process.executable.as_deref(),
                )
            });
            if process.ppid != 1
                || process.elapsed_seconds < 24 * 60 * 60
                || launch_managed
                || crate::hygiene::stable_service_signature(process) != service_signature
                || !seen.insert(process.pid)
            {
                continue;
            }
            let pid = process.pid;
            action.controls.preconditions.extend([
                ActionCheck {
                    description: format!("PID {pid} still has the reviewed command"),
                    kind: ActionCheckKind::ProcessMatches {
                        pid,
                        command_contains: process.command.clone(),
                    },
                },
                ActionCheck {
                    description: format!("PID {pid} still listens on TCP port {port}"),
                    kind: ActionCheckKind::ListenerPresent { pid, port },
                },
            ]);
            let requires_root = process_requires_root(process);
            action.controls.requires_root |= requires_root;
            action.controls.recommended_steps.push(ActionStep {
                description: format!("Request graceful termination of exact PID {pid}"),
                command: Some(CommandSpec {
                    program: "/bin/kill".into(),
                    args: vec!["-TERM".into(), pid.to_string()],
                    requires_root,
                }),
            });
        }
        action.controls.verification.push(ActionCheck {
            description: format!("TCP port {port} is closed"),
            kind: ActionCheckKind::PortClosed { port },
        });
    } else if finding.id == "detached-agent-browser-processes" {
        let processes = report
            .runtime
            .processes
            .iter()
            .filter(|process| {
                process.ppid == 1
                    && process.elapsed_seconds >= 6 * 60 * 60
                    && (process.command.contains("/.agent-browser/browsers/")
                        || process.command.contains("agent-browser-darwin"))
            })
            .collect();
        add_exact_process_steps(action, processes, "agent-browser/Chrome");
    } else if finding.id == "zombie-processes" {
        let parent_pids: BTreeSet<u32> = report
            .runtime
            .processes
            .iter()
            .filter(|process| process.state.contains('Z'))
            .map(|process| process.ppid)
            .collect();
        for pid in parent_pids {
            let Some(parent) = report
                .runtime
                .processes
                .iter()
                .find(|process| process.pid == pid)
            else {
                continue;
            };
            if protected_process_parent(parent) {
                action.controls.recommended_steps.push(ActionStep {
                    description: format!(
                        "Do not signal protected/system zombie parent PID {pid}; inspect or reboot through normal macOS controls"
                    ),
                    command: None,
                });
                continue;
            }
            for zombie in report
                .runtime
                .processes
                .iter()
                .filter(|process| process.state.contains('Z') && process.ppid == pid)
            {
                action.controls.preconditions.push(ActionCheck {
                    description: format!(
                        "Zombie PID {} is still a zombie child of parent PID {pid}",
                        zombie.pid
                    ),
                    kind: ActionCheckKind::ZombieParent {
                        zombie_pid: zombie.pid,
                        parent_pid: pid,
                    },
                });
            }
            action.controls.preconditions.push(ActionCheck {
                description: format!("Zombie parent PID {pid} still has the reviewed command"),
                kind: ActionCheckKind::ProcessMatches {
                    pid,
                    command_contains: parent.command.clone(),
                },
            });
            let requires_root = process_requires_root(parent);
            action.controls.requires_root |= requires_root;
            action.controls.recommended_steps.push(ActionStep {
                description: format!(
                    "After confirming it is not active work, request termination of zombie parent PID {pid}"
                ),
                command: Some(CommandSpec {
                    program: "/bin/kill".into(),
                    args: vec!["-TERM".into(), pid.to_string()],
                    requires_root,
                }),
            });
        }
    }
}

fn protected_process_parent(process: &ProcessEntry) -> bool {
    process.pid <= 1
        || process_requires_root(process)
        || process.command.starts_with("/System/")
        || process.command.starts_with("/usr/libexec/")
        || process.command.starts_with("/sbin/launchd")
        || process.command.starts_with("/usr/sbin/")
}

fn add_exact_process_steps(action: &mut PlannedAction, processes: Vec<&ProcessEntry>, label: &str) {
    let mut seen = BTreeSet::new();
    for process in processes {
        if !seen.insert(process.pid) {
            continue;
        }
        let pid = process.pid;
        action.controls.preconditions.push(ActionCheck {
            description: format!("{label} PID {pid} still has the reviewed command"),
            kind: ActionCheckKind::ProcessMatches {
                pid,
                command_contains: process.command.clone(),
            },
        });
        let requires_root = process_requires_root(process);
        action.controls.requires_root |= requires_root;
        action.controls.recommended_steps.push(ActionStep {
            description: format!("Request graceful termination of exact {label} PID {pid}"),
            command: Some(CommandSpec {
                program: "/bin/kill".into(),
                args: vec!["-TERM".into(), pid.to_string()],
                requires_root,
            }),
        });
    }
}

fn process_requires_root(process: &ProcessEntry) -> bool {
    current_uid()
        .and_then(|uid| uid.parse::<u32>().ok())
        .is_none_or(|uid| uid != process.uid)
}

fn evidence_value<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    finding
        .evidence
        .iter()
        .find_map(|evidence| evidence.strip_prefix(&prefix))
}

fn evidence_number(finding: &Finding, key: &str) -> Option<u32> {
    let prefix = format!("{key}=");
    finding
        .evidence
        .iter()
        .find_map(|evidence| evidence.strip_prefix(&prefix))?
        .parse()
        .ok()
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

fn current_uid() -> Option<String> {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn hygiene_action(finding: &Finding) -> Option<PlannedAction> {
    let (risk, instructions) = if finding.id.starts_with("persistent-launch-item:") {
        (
            ActionRisk::Medium,
            "Identify the owning app/package, inspect the plist and current launchctl state, ask whether the service is still needed, then stop and disable it before removing persistence. Verify it does not restart.".to_string(),
        )
    } else if finding.id.starts_with("translocated-launch-item:") {
        (
            ActionRisk::Medium,
            "Confirm the referenced app is no longer intentionally installed, boot out and disable the launch item, move the stale plist to Trash, then verify the label and process do not return.".to_string(),
        )
    } else if finding.id.starts_with("orphaned-privileged-helper:") {
        (
            ActionRisk::High,
            "Confirm the parent app is absent/unused, prefer its signed vendor uninstaller, then remove the root launch daemon/helper with explicit administrator approval. Verify the launchd label, plist, helper, and processes are gone.".to_string(),
        )
    } else if finding.id.starts_with("old-detached-listener:") {
        (
            ActionRisk::Medium,
            "Inspect the process command, cwd, open files, connections, and owning project before terminating it. After approval, stop the process and verify its listening port is closed.".to_string(),
        )
    } else if finding.id == "detached-agent-browser-processes" {
        (
            ActionRisk::Medium,
            "Check whether any agent/browser session is still active. After approval, terminate detached agent-browser and Chrome-for-Testing process groups, remove only their abandoned temporary profiles, and verify no matching processes remain.".to_string(),
        )
    } else if finding.id == "zombie-processes" {
        (
            ActionRisk::Medium,
            "Inspect each zombie's parent process. Restart or terminate the parent only after confirming it is not active work, then verify the zombie has been reaped.".to_string(),
        )
    } else {
        return None;
    };

    Some(PlannedAction {
        id: stable_action_id("review", &finding.id),
        title: format!("Review {}", finding.title.to_lowercase()),
        rationale: finding.detail.clone(),
        confidence: finding.confidence,
        risk,
        destructive: false,
        kind: ActionKind::Manual { instructions },
        controls: ActionControls {
            source_finding_id: Some(finding.id.clone()),
            ..ActionControls::default()
        },
    })
}

pub fn summarize_actions(actions: &[PlannedAction]) -> ActionPlanSummary {
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

pub fn requires_owner_aware_manual_removal(owner: &str) -> bool {
    owner.starts_with("Homebrew")
        || owner.starts_with("legacy Homebrew")
        || owner.starts_with("Node/npm")
        || owner.starts_with("nvm/npm")
        || owner.starts_with("Cargo")
        || owner.starts_with("app bundle")
}

pub fn known_brew_replacement(binary_name: &str) -> Option<&'static str> {
    match binary_name {
        "aws" | "aws_completer" => Some("awscli"),
        _ => None,
    }
}

pub fn render_action_plan_markdown(plan: &ActionPlan) -> String {
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
        out.push_str(&format!(
            "- Requires root: `{}`\n",
            action.controls.requires_root
        ));
        out.push_str(&format!("- Kind: `{}`\n", action_kind_label(&action.kind)));
        out.push_str(&format!("\n{}\n\n", action.rationale));
        out.push_str("Suggested command/instruction:\n\n");
        out.push_str(&format!("```text\n{}\n```\n\n", action_instruction(action)));
        if !action.controls.preconditions.is_empty() {
            out.push_str("Preconditions:\n\n");
            for check in &action.controls.preconditions {
                out.push_str(&format!("- {}\n", check.description));
            }
            out.push('\n');
        }
        if !action.controls.recommended_steps.is_empty() {
            out.push_str(
                "Recommended reviewed steps (structured argv; do not paste as shell text):\n\n",
            );
            for step in &action.controls.recommended_steps {
                out.push_str(&format!("- {}\n", step.description));
                if let Some(command) = &step.command {
                    out.push_str(&format!(
                        "  - structured argv: `{}`\n",
                        display_command(command)
                    ));
                }
            }
            out.push('\n');
        }
        if !action.controls.undo.is_empty() {
            out.push_str("Undo:\n\n");
            for step in &action.controls.undo {
                out.push_str(&format!("- {}\n", step.description));
            }
            out.push('\n');
        }
        if !action.controls.verification.is_empty() {
            out.push_str("Verification:\n\n");
            for check in &action.controls.verification {
                out.push_str(&format!("- {}\n", check.description));
            }
            out.push('\n');
        }
    }

    out
}

pub fn print_action_plan(plan: &ActionPlan) {
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
        println!(
            "  {} {}",
            "Requires root:".bold(),
            action.controls.requires_root
        );
        for step in &action.controls.recommended_steps {
            println!("  {} {}", "Reviewed step:".bold(), step.description);
            if let Some(command) = &step.command {
                println!("    argv={}", display_command(command));
            }
        }
        for check in &action.controls.verification {
            println!("  {} {}", "Verify:".bold(), check.description);
        }
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

pub fn display_command(command: &CommandSpec) -> String {
    let argv: Vec<&str> = std::iter::once(command.program.as_str())
        .chain(command.args.iter().map(String::as_str))
        .collect();
    serde_json::to_string(&argv)
        .unwrap_or_else(|_| "[\"<unserializable argv>\"]".into())
        .replace('`', "\\u0060")
}

pub fn action_kind_label(kind: &ActionKind) -> &'static str {
    match kind {
        ActionKind::MoveToTrash { .. } => "move-to-trash",
        ActionKind::BrewInstall { .. } => "brew-install",
        ActionKind::Manual { .. } => "manual",
    }
}

pub fn action_instruction(action: &PlannedAction) -> String {
    match &action.kind {
        ActionKind::MoveToTrash { path } => format!(
            "Move `{}` to Trash after confirming it is unused or replaced.",
            path.display()
        ),
        ActionKind::BrewInstall { package } => format!("brew install {package}"),
        ActionKind::Manual { instructions } => instructions.clone(),
    }
}

pub fn action_disposition(action: &PlannedAction) -> ActionDisposition {
    match action.kind {
        ActionKind::MoveToTrash { .. } => ActionDisposition::ApplyNow,
        ActionKind::BrewInstall { .. } => ActionDisposition::Manual,
        ActionKind::Manual { .. } => match (action.confidence, action.risk) {
            (Confidence::Low, _) | (_, ActionRisk::High) => ActionDisposition::NeedsMoreEvidence,
            (Confidence::Medium, _) | (_, ActionRisk::Medium) => ActionDisposition::Handoff,
            (Confidence::High, ActionRisk::Low) => ActionDisposition::Manual,
        },
    }
}

pub fn action_disposition_label(disposition: ActionDisposition) -> &'static str {
    match disposition {
        ActionDisposition::ApplyNow => "apply now",
        ActionDisposition::Manual => "manual",
        ActionDisposition::Handoff => "handoff",
        ActionDisposition::NeedsMoreEvidence => "needs more evidence",
    }
}

pub fn risk_badge(risk: ActionRisk) -> String {
    match risk {
        ActionRisk::Low => "LOW".green().bold().to_string(),
        ActionRisk::Medium => "MED".yellow().bold().to_string(),
        ActionRisk::High => "HIGH".red().bold().to_string(),
    }
}

pub fn confidence_badge(confidence: Confidence) -> String {
    match confidence {
        Confidence::Low => "low-confidence".dimmed().to_string(),
        Confidence::Medium => "medium-confidence".blue().to_string(),
        Confidence::High => "high-confidence".green().to_string(),
    }
}

pub fn slugify(input: &str) -> String {
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

pub fn print_related_actions(target: &str, plan: &ActionPlan) {
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

pub fn related_actions<'a>(target: &str, plan: &'a ActionPlan) -> Vec<&'a PlannedAction> {
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
            action
                .controls
                .source_finding_id
                .as_ref()
                .is_some_and(|finding_id| finding_id.to_lowercase() == target)
                || action.id.to_lowercase().contains(&target)
                || action.title.to_lowercase().contains(&target)
                || action.rationale.to_lowercase().contains(&target)
                || action_instruction(action).to_lowercase().contains(&target)
        })
        .collect()
}

pub fn related_actions_for_finding<'a>(
    finding: &Finding,
    plan: &'a ActionPlan,
) -> Vec<&'a PlannedAction> {
    plan.actions
        .iter()
        .filter(|action| {
            action.controls.source_finding_id.as_deref() == Some(finding.id.as_str())
                || finding.detail.contains(&action_subject(action))
                || action.rationale.contains(&finding.detail)
                || action.title.contains(&finding.title)
        })
        .collect()
}

pub fn action_subject(action: &PlannedAction) -> String {
    match &action.kind {
        ActionKind::MoveToTrash { path } => path.display().to_string(),
        ActionKind::BrewInstall { package } => package.clone(),
        ActionKind::Manual { instructions } => instructions.clone(),
    }
}

pub fn print_action_detail(action: &PlannedAction) {
    println!(
        "  {} {} {}",
        risk_badge(action.risk),
        confidence_badge(action.confidence),
        action.title.bold()
    );
    println!("      ID: {}", action.id.dimmed());
    println!("      {}", action.rationale.dimmed());
    println!("      {} {}", "Action:".bold(), action_instruction(action));
    for step in &action.controls.recommended_steps {
        println!("      {} {}", "Reviewed step:".bold(), step.description);
        if let Some(command) = &step.command {
            println!("        argv={}", display_command(command));
        }
    }
    if action.destructive {
        println!(
            "      {}",
            "Destructive action: dry-run/review first.".red().bold()
        );
    }
    println!();
}
