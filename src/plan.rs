use crate::findings::{conda_rootish_envs, intel_go_binaries};
use crate::model::*;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use owo_colors::OwoColorize;
use std::collections::BTreeSet;
use std::path::Path;

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

        let name = bin
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        if let Some(package) = known_brew_replacement(&name)
            && suggested_brew_packages.insert(package.to_string())
        {
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
        out.push_str(&format!("- Kind: `{}`\n", action_kind_label(&action.kind)));
        out.push_str(&format!("\n{}\n\n", action.rationale));
        out.push_str("Suggested command/instruction:\n\n");
        out.push_str(&format!("```text\n{}\n```\n\n", action_instruction(action)));
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
            action.id.to_lowercase().contains(&target)
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
            finding.detail.contains(&action_subject(action))
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
    if action.destructive {
        println!(
            "      {}",
            "Destructive action: dry-run/review first.".red().bold()
        );
    }
    println!();
}
