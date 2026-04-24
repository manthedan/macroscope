use crate::model::*;
use crate::plan::{action_instruction, action_kind_label};

pub fn render_brief(report: &Report, plan: &ActionPlan, for_llm: bool) -> String {
    let mut out = String::new();
    out.push_str("# Macroscope Handoff Brief\n\n");

    if for_llm {
        out.push_str(
            "> You are helping review a macOS developer environment. Treat this brief as evidence, not permission to mutate the system. Ask before destructive changes, prefer package-manager operations when ownership is known, and keep cleanup reversible where possible.\n\n",
        );
    } else {
        out.push_str(
            "> Local evidence and suggested next steps for a human reviewer or AI coding agent.\n\n",
        );
    }

    push_machine_context(&mut out, report);
    push_findings_summary(&mut out, report);
    push_action_summary(&mut out, plan);
    push_high_confidence_findings(&mut out, report);
    push_ambiguous_findings(&mut out, report, plan);
    push_suggested_next_commands(&mut out, plan);
    push_do_not_automate(&mut out);
    push_questions(&mut out, report, plan);
    push_raw_evidence(&mut out, report);

    out
}

fn push_machine_context(out: &mut String, report: &Report) {
    out.push_str("## Machine context\n\n");
    out.push_str(&format!("- macOS: `{}`\n", report.system.macos));
    out.push_str(&format!("- Architecture: `{}`\n", report.system.arch));
    if let Some(shell) = &report.system.shell {
        out.push_str(&format!("- Shell: `{shell}`\n"));
    }
    out.push_str(&format!(
        "- Homebrew: `{}`\n",
        report.homebrew.brew_path.as_deref().unwrap_or("not found")
    ));
    out.push_str(&format!(
        "- Homebrew prefix: `{}`\n",
        report.homebrew.prefix.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "- PATH entries: {} total, {} duplicate entr{}\n\n",
        report.path.entries.len(),
        report.path.duplicates.len(),
        if report.path.duplicates.len() == 1 {
            "y"
        } else {
            "ies"
        }
    ));
}

fn push_findings_summary(out: &mut String, report: &Report) {
    let (risks, warns, infos) = finding_counts(report);
    out.push_str("## Findings summary\n\n");
    out.push_str(&format!("- Risk: {risks}\n"));
    out.push_str(&format!("- Warning: {warns}\n"));
    out.push_str(&format!("- Info: {infos}\n\n"));
}

fn push_action_summary(out: &mut String, plan: &ActionPlan) {
    out.push_str("## Plan summary\n\n");
    out.push_str(&format!("- Total actions: {}\n", plan.summary.total));
    out.push_str(&format!(
        "- Executable now by Macroscope: {}\n",
        executable_action_count(plan)
    ));
    out.push_str(&format!(
        "- Destructive actions: {}\n",
        plan.summary.destructive
    ));
    out.push_str(&format!("- Low risk: {}\n", plan.summary.low_risk));
    out.push_str(&format!("- Medium risk: {}\n", plan.summary.medium_risk));
    out.push_str(&format!("- High risk: {}\n\n", plan.summary.high_risk));
}

fn push_high_confidence_findings(out: &mut String, report: &Report) {
    out.push_str("## High-confidence findings\n\n");
    let notable: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| matches!(finding.severity, Severity::Risk | Severity::Warn))
        .collect();

    if notable.is_empty() {
        out.push_str("No risk/warning findings were reported.\n\n");
        return;
    }

    for finding in notable {
        out.push_str(&format!(
            "- **{:?}**: {} — {}\n",
            finding.severity, finding.title, finding.detail
        ));
    }
    out.push('\n');
}

fn push_ambiguous_findings(out: &mut String, report: &Report, plan: &ActionPlan) {
    out.push_str("## Needs human judgment\n\n");

    let mut wrote = false;
    for action in &plan.actions {
        let ambiguous = matches!(action.confidence, Confidence::Low | Confidence::Medium)
            || matches!(
                action.kind,
                ActionKind::Manual { .. } | ActionKind::BrewInstall { .. }
            );
        if ambiguous {
            wrote = true;
            out.push_str(&format!("- `{}` — {}\n", action.id, action.title));
            out.push_str(&format!("  - Why: {}\n", action.rationale));
            out.push_str(&format!(
                "  - Suggested next step: {}\n",
                action_instruction(action)
            ));
        }
    }

    if report.dev_tools.conda.conda.path.is_some() {
        wrote = true;
        out.push_str("- Conda is installed. Treat Conda root/env deletion as manual review only; export important envs first.\n");
    }

    if !report.dev_tools.go.binaries.is_empty() {
        wrote = true;
        out.push_str("- GOPATH/bin contains Go-installed binaries. Rebuild known tools natively before removing stale binaries.\n");
    }

    if !wrote {
        out.push_str("No ambiguous actions were generated.\n");
    }
    out.push('\n');
}

fn push_suggested_next_commands(out: &mut String, plan: &ActionPlan) {
    out.push_str("## Suggested next commands\n\n");
    out.push_str("Review without mutating:\n\n");
    out.push_str("```bash\n");
    out.push_str("macroscope scan --markdown macroscope-report.md\n");
    out.push_str("macroscope plan --markdown macroscope-plan.md\n");
    out.push_str("macroscope apply --dry-run\n");
    out.push_str("```\n\n");

    let executable = executable_action_count(plan);
    if executable > 0 {
        out.push_str(&format!(
            "Macroscope can execute {executable} currently supported action(s), all `move-to-trash`, but only after explicit confirmation:\n\n"
        ));
        out.push_str(
            "```bash\nmacroscope apply --dry-run\nmacroscope apply --yes plan.json\n```\n\n",
        );
    }

    let manual_actions: Vec<&PlannedAction> = plan
        .actions
        .iter()
        .filter(|action| !matches!(action.kind, ActionKind::MoveToTrash { .. }))
        .collect();
    if !manual_actions.is_empty() {
        out.push_str("Manual/package-manager review items:\n\n");
        for action in manual_actions {
            out.push_str(&format!(
                "- `{}` (`{}`): {}\n",
                action.id,
                action_kind_label(&action.kind),
                action_instruction(action)
            ));
        }
        out.push('\n');
    }
}

fn push_do_not_automate(out: &mut String) {
    out.push_str("## Do not automate without explicit user approval\n\n");
    out.push_str("- Removing Conda roots, Python envs, or package caches.\n");
    out.push_str("- Deleting app bundles or app support data.\n");
    out.push_str("- Editing shell startup files.\n");
    out.push_str("- Running broad package-manager upgrades or cleanup.\n");
    out.push_str(
        "- Removing owner-managed binaries without using the owning package manager/app.\n",
    );
    out.push_str(
        "- Removing Go/npm/Cargo/Python tools before confirming replacement/provenance.\n\n",
    );
}

fn push_questions(out: &mut String, report: &Report, plan: &ActionPlan) {
    out.push_str("## Questions to ask before cleanup\n\n");
    out.push_str("- Which stale tools/apps are still actively used?\n");
    out.push_str("- Are any findings tied to current work projects?\n");
    if plan.actions.iter().any(|action| action.destructive) {
        out.push_str("- Has each destructive action been dry-run and verified as reversible?\n");
    }
    if report.dev_tools.conda.conda.path.is_some() {
        out.push_str(
            "- Which Conda root/envs are still needed, and have important envs been exported?\n",
        );
    }
    if !report.dev_tools.go.binaries.is_empty() {
        out.push_str("- Which Go-installed binaries should be rebuilt from known module paths?\n");
    }
    if !report.apps.duplicate_bundle_ids.is_empty() {
        out.push_str("- For duplicate app bundle IDs, which app copy is the canonical one?\n");
    }
    out.push('\n');
}

fn push_raw_evidence(out: &mut String, report: &Report) {
    out.push_str("## Raw evidence summary\n\n");
    out.push_str(&format!(
        "- Homebrew formulae: {}\n",
        report.homebrew.formulae.len()
    ));
    out.push_str(&format!(
        "- Homebrew casks: {}\n",
        report.homebrew.casks.len()
    ));
    out.push_str(&format!(
        "- Outdated Homebrew items: {}\n",
        report.homebrew.outdated_formulae.len() + report.homebrew.outdated_casks.len()
    ));
    out.push_str(&format!(
        "- Applications scanned: {}\n",
        report.apps.apps.len()
    ));
    out.push_str(&format!(
        "- Duplicate bundle IDs: {}\n",
        report.apps.duplicate_bundle_ids.len()
    ));
    out.push_str(&format!(
        "- /usr/local/bin entries: {}\n",
        report.local_bins.len()
    ));
    out.push_str(&format!(
        "- npm globals: {}\n",
        report.dev_tools.npm.global_packages.len()
    ));
    out.push_str(&format!(
        "- Cargo installs: {}\n",
        report.dev_tools.cargo.installed.len()
    ));
    out.push_str(&format!(
        "- Conda envs: {}\n",
        report.dev_tools.conda.envs.len()
    ));
    out.push_str(&format!(
        "- GOPATH/bin binaries: {}\n",
        report.dev_tools.go.binaries.len()
    ));
}

fn finding_counts(report: &Report) -> (usize, usize, usize) {
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

pub fn executable_action_count(plan: &ActionPlan) -> usize {
    plan.actions
        .iter()
        .filter(|action| matches!(action.kind, ActionKind::MoveToTrash { .. }))
        .count()
}
