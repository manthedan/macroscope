use crate::model::*;
use crate::plan::{action_disposition, action_instruction, action_kind_label};

const COMPACT_FINDING_LIMIT: usize = 12;
const COMPACT_ACTION_LIMIT: usize = 8;

pub fn render_brief(report: &Report, plan: &ActionPlan, for_llm: bool, full: bool) -> String {
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
    if for_llm {
        push_agent_prompt(&mut out);
    }
    push_high_confidence_findings(&mut out, report, full);
    push_decision_buckets(&mut out, plan, full);
    push_ecosystem_notes(&mut out, report);
    push_follow_up_commands(&mut out, plan);
    push_do_not_automate(&mut out);
    push_questions(&mut out, report, plan);
    push_raw_evidence(&mut out, report, full);

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

fn push_agent_prompt(out: &mut String) {
    out.push_str("## Suggested agent prompt\n\n");
    out.push_str(
        "> Help me clean up this Mac developer environment. Use the evidence below to propose a safe sequence. Do not mutate anything without asking. Prefer package-manager operations for owner-managed files, use Trash-backed cleanup for standalone files, and move ambiguous ecosystem-specific work into manual review. Start by asking which flagged apps/tools are still used.\n\n",
    );
}

fn push_high_confidence_findings(out: &mut String, report: &Report, full: bool) {
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

    let limit = if full {
        notable.len()
    } else {
        COMPACT_FINDING_LIMIT
    };
    for finding in notable.iter().take(limit) {
        out.push_str(&format!(
            "- **{:?}**: {} — {}\n",
            finding.severity, finding.title, finding.detail
        ));
    }
    if notable.len() > limit {
        out.push_str(&format!(
            "- … and {} more risk/warning finding(s). Use `macroscope scan --markdown macroscope-report.md` for the full list.\n",
            notable.len() - limit
        ));
    }
    out.push('\n');
}

fn push_decision_buckets(out: &mut String, plan: &ActionPlan, full: bool) {
    out.push_str("## Recommended decision buckets\n\n");

    let buckets = [
        (
            ActionDisposition::ApplyNow,
            "Apply now candidates",
            "Only execute after dry-run and explicit confirmation.",
        ),
        (
            ActionDisposition::Manual,
            "Manual/package-manager review",
            "Use the owning package manager or app-specific process where possible.",
        ),
        (
            ActionDisposition::Handoff,
            "Handoff to human/AI agent",
            "Good candidates for contextual reasoning before any mutation.",
        ),
        (
            ActionDisposition::NeedsMoreEvidence,
            "Needs more evidence",
            "Do not act until provenance, ownership, or current use is clearer.",
        ),
    ];

    for (disposition, heading, note) in buckets {
        let actions: Vec<&PlannedAction> = plan
            .actions
            .iter()
            .filter(|action| action_disposition(action) == disposition)
            .collect();

        out.push_str(&format!("### {heading}\n\n"));
        out.push_str(&format!("{note}\n\n"));
        if actions.is_empty() {
            out.push_str("- None.\n\n");
            continue;
        }

        let limit = if full {
            actions.len()
        } else {
            COMPACT_ACTION_LIMIT
        };
        for action in actions.iter().take(limit) {
            out.push_str(&format!(
                "- `{}` — {} (`{}`, {:?} risk, {:?} confidence)\n",
                action.id,
                action.title,
                action_kind_label(&action.kind),
                action.risk,
                action.confidence
            ));
            out.push_str(&format!("  - Next: {}\n", action_instruction(action)));
        }
        if actions.len() > limit {
            out.push_str(&format!(
                "- … and {} more action(s) in this bucket. Use `macroscope plan --markdown macroscope-plan.md` for the full plan.\n",
                actions.len() - limit
            ));
        }
        out.push('\n');
    }
}

fn push_ecosystem_notes(out: &mut String, report: &Report) {
    out.push_str("## Ecosystem notes needing judgment\n\n");

    let mut wrote = false;
    if report.dev_tools.conda.conda.path.is_some() {
        wrote = true;
        out.push_str("- Conda is installed. Treat Conda root/env deletion as manual review only; export important envs first.\n");
    }

    if !report.dev_tools.go.binaries.is_empty() {
        wrote = true;
        out.push_str("- GOPATH/bin contains Go-installed binaries. Rebuild known tools natively before removing stale binaries.\n");
    }

    if !wrote {
        out.push_str("No ecosystem-specific judgment notes were generated.\n");
    }
    out.push('\n');
}

fn push_follow_up_commands(out: &mut String, plan: &ActionPlan) {
    out.push_str("## Follow-up commands\n\n");
    out.push_str("These commands are for verification or for regenerating artifacts after manual changes. They are not required just to read this brief.\n\n");
    out.push_str("After taking manual/package-manager actions, rescan and regenerate the review artifacts:\n\n");
    out.push_str("```bash\n");
    out.push_str("macroscope scan --markdown macroscope-report.md\n");
    out.push_str("macroscope plan --markdown macroscope-plan.md\n");
    out.push_str("macroscope brief --markdown macroscope-brief.md --for-llm\n");
    out.push_str("```\n\n");
    out.push_str("Before any Macroscope-managed cleanup, preview the current plan again:\n\n");
    out.push_str("```bash\nmacroscope apply --dry-run\n```\n\n");

    let executable = executable_action_count(plan);
    if executable > 0 {
        out.push_str(&format!(
            "Macroscope can execute {executable} currently supported action(s), all `move-to-trash`, but only from an explicit reviewed plan and after confirmation:\n\n"
        ));
        out.push_str(
            "```bash\nmacroscope plan --json > plan.json\nmacroscope apply --dry-run plan.json\nmacroscope apply --yes plan.json\n```\n\n",
        );
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

fn push_raw_evidence(out: &mut String, report: &Report, full: bool) {
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

    if full {
        out.push_str("\n### PATH\n\n");
        for (idx, entry) in report.path.entries.iter().enumerate() {
            out.push_str(&format!("{}. `{entry}`\n", idx + 1));
        }
    }
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
