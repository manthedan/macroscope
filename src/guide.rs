use crate::apply::{apply_action_plan, dry_run_action_plan};
use crate::brief::{executable_action_count, render_brief};
use crate::markdown::render_markdown;
use crate::model::*;
use crate::plan::{generate_action_plan, render_action_plan_markdown};
use crate::scan::scan_with_cli_progress;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct GuideOptions {
    pub apply: bool,
    pub brief_path: PathBuf,
    pub no_prompt: bool,
}

pub fn run_guide(options: GuideOptions) -> Result<()> {
    print_header();

    let report = scan_with_cli_progress("Guide step 1/4: scanning this Mac");
    let plan = generate_action_plan(&report);

    print_session_summary(&report, &plan);

    let report_path = PathBuf::from("macroscope-report.md");
    let plan_path = PathBuf::from("macroscope-plan.md");

    if options.no_prompt || prompt_yes("Write scan report and action plan Markdown files?", true)? {
        write_file(&report_path, &render_markdown(&report))?;
        write_file(&plan_path, &render_action_plan_markdown(&plan))?;
    }

    if !plan.actions.is_empty()
        && (options.no_prompt || prompt_yes("Show a dry-run of the current action plan?", true)?)
    {
        dry_run_action_plan(&plan);
    }

    if options.apply {
        maybe_apply(&plan, options.no_prompt)?;
    } else if executable_action_count(&plan) > 0 {
        println!(
            "{}",
            "Safe apply is disabled in this guide run. Re-run with `macroscope guide --apply` to enable guarded Move-to-Trash execution."
                .dimmed()
        );
        println!();
    }

    if options.no_prompt || prompt_yes("Write AI/human handoff brief?", true)? {
        let brief = render_brief(&report, &plan, true);
        write_file(&options.brief_path, &brief)?;
    }

    if options.apply
        && !options.no_prompt
        && prompt_yes("Rescan now to verify current state?", false)?
    {
        let verified = scan_with_cli_progress("Guide verification scan");
        let verified_plan = generate_action_plan(&verified);
        println!(
            "{} Before: {} action(s). After: {} action(s).",
            "Verification:".bold(),
            plan.summary.total,
            verified_plan.summary.total
        );
    }

    println!("{}", "Guide complete.".green().bold());
    println!(
        "{}",
        format!(
            "Next: review `{}` or hand it to Codex/Claude Code with your cleanup goals.",
            options.brief_path.display()
        )
        .dimmed()
    );

    Ok(())
}

fn print_header() {
    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Guide".bright_cyan().bold()
    );
    println!(
        "{}",
        "A guided session: scan → plan → decide → safe apply/manual/handoff → optional verification."
            .dimmed()
    );
    println!();
}

fn print_session_summary(report: &Report, plan: &ActionPlan) {
    let (risks, warns, infos) = finding_counts(report);
    let executable = executable_action_count(plan);

    println!("{}", "Guide step 2/4: session summary".bold());
    println!("  Findings: {risks} risk · {warns} warn · {infos} info");
    println!(
        "  Plan: {} action(s), {} executable by Macroscope, {} destructive",
        plan.summary.total, executable, plan.summary.destructive
    );
    println!(
        "  Homebrew: {} formulae · {} casks · {} outdated",
        report.homebrew.formulae.len(),
        report.homebrew.casks.len(),
        report.homebrew.outdated_formulae.len() + report.homebrew.outdated_casks.len()
    );
    println!(
        "  Apps/local bins: {} apps scanned · {} /usr/local/bin entries",
        report.apps.apps.len(),
        report.local_bins.len()
    );
    println!();

    if plan.actions.is_empty() {
        println!(
            "{}",
            "No actions proposed. The brief can still capture system evidence.".green()
        );
    } else {
        println!("{}", "Action disposition model:".bold());
        println!("  1. Apply now: only explicitly confirmed Move-to-Trash actions");
        println!("  2. Manual: package-manager/app-specific instructions");
        println!("  3. Handoff: ambiguous work for you or an AI coding agent");
        println!("  4. Ignore/snooze: leave low-priority items for later");
    }
    println!();
}

fn maybe_apply(plan: &ActionPlan, no_prompt: bool) -> Result<()> {
    let executable = executable_action_count(plan);
    if executable == 0 {
        println!(
            "{}",
            "No executable Move-to-Trash actions are present.".green()
        );
        println!();
        return Ok(());
    }

    println!("{}", "Guide step 3/4: guarded apply".bold());
    println!(
        "{}",
        format!(
            "Macroscope can execute {executable} Move-to-Trash action(s). Manual/package-manager actions will only be printed."
        )
        .yellow()
    );

    if no_prompt {
        println!(
            "{}",
            "--no-prompt never performs real mutations; dry-run only.".dimmed()
        );
        dry_run_action_plan(plan);
        return Ok(());
    }

    dry_run_action_plan(plan);
    let expected = format!("APPLY {executable}");
    println!(
        "{}",
        format!(
            "Type `{expected}` to execute the Move-to-Trash action(s), or press Enter to skip:"
        )
        .red()
        .bold()
    );
    let input = read_line()?;
    if input.trim() == expected {
        apply_action_plan(plan, true)?;
    } else {
        println!("{}", "Apply skipped.".dimmed());
    }
    println!();
    Ok(())
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))?;
    println!("{} {}", "Wrote".green().bold(), path.display());
    Ok(())
}

fn prompt_yes(question: &str, default: bool) -> Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    print!("{question} {suffix} ");
    io::stdout().flush()?;
    let input = read_line()?;
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Ok(default);
    }
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

fn read_line() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
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
