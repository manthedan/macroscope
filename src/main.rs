use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use macroscope::{
    apply::{apply_action_plan, dry_run_action_plan, load_or_generate_plan},
    brief::render_brief,
    correlation::print_correlation_graph,
    decisions::{clear_decision, load_decisions, record_decision},
    guide::{GuideOptions, run_guide},
    markdown::render_markdown,
    model::DecisionKind,
    output::{print_explanation, print_summary},
    plan::{generate_action_plan, print_action_plan, render_action_plan_markdown},
    scan::{scan, scan_with_cli_progress},
    snapshot::{
        diff_reports, load_snapshot, print_diff, print_verification, save_snapshot, verify_reports,
    },
};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "macroscope")]
#[command(version)]
#[command(about = "Collect macOS cleanup evidence for humans and AI agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan macOS persistence, runtime state, and developer-environment evidence.
    Scan {
        /// Write a Markdown report to this path.
        #[arg(long)]
        markdown: Option<PathBuf>,

        /// Emit JSON instead of the pretty text summary.
        #[arg(long)]
        json: bool,
    },

    /// Save a versioned evidence snapshot for later diff or verification.
    Snapshot {
        /// Snapshot JSON output path.
        output: PathBuf,
    },

    /// Compare two snapshots, or a snapshot with a fresh live scan.
    Diff {
        /// Baseline snapshot.
        before: PathBuf,

        /// Optional second snapshot; omit to scan the current Mac.
        after: Option<PathBuf>,

        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
    },

    /// Verify baseline persistence/runtime findings against a fresh scan.
    Verify {
        /// Baseline snapshot.
        baseline: PathBuf,

        /// Verify only these finding IDs; repeat for multiple targets.
        #[arg(long = "finding")]
        findings: Vec<String>,

        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,

        /// Return a non-zero status when any target remains.
        #[arg(long)]
        strict: bool,
    },

    /// Print the launch → process → listener → executable → owner graph.
    Graph {
        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
    },

    /// Record a keep, ignore, or snooze decision for a stable finding ID.
    Decide {
        finding_id: String,
        decision: DecisionArg,

        /// Reason recorded with the decision.
        #[arg(long)]
        reason: Option<String>,

        /// Snooze duration; ignored for keep/ignore.
        #[arg(long, default_value_t = 30)]
        days: u64,
    },

    /// Remove a recorded decision so the finding becomes active again.
    Undecide { finding_id: String },

    /// List recorded finding decisions.
    Decisions {
        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
    },

    /// Generate a read-only cleanup/migration action plan.
    Plan {
        /// Write a Markdown action plan to this path.
        #[arg(long)]
        markdown: Option<PathBuf>,

        /// Emit JSON instead of the pretty text plan.
        #[arg(long)]
        json: bool,
    },

    /// Explain a path, action ID, bundle ID, or finding text.
    Explain {
        /// Path, action ID, bundle ID, or text to explain.
        target: String,
    },

    /// Generate an AI/human handoff brief.
    Brief {
        /// Write the brief to this path. If omitted, print Markdown to stdout.
        #[arg(long)]
        markdown: Option<PathBuf>,

        /// Add extra guardrails/instructions for AI coding agents.
        #[arg(long)]
        for_llm: bool,

        /// Include uncapped finding/action detail and extra raw evidence.
        #[arg(long)]
        full: bool,
    },

    /// Walk through scan, plan, decision, handoff, and optional guarded apply.
    Guide {
        /// Enable guarded apply controls. Without this, guide is read-only.
        #[arg(long)]
        apply: bool,

        /// Handoff brief output path.
        #[arg(long, default_value = "macroscope-brief.md")]
        brief: PathBuf,

        /// Run without prompts. This writes reports/briefs and dry-runs only; it never mutates.
        #[arg(long)]
        no_prompt: bool,
    },

    /// Apply or dry-run an action plan.
    Apply {
        /// Read an action plan JSON file. If omitted, generate a fresh plan.
        plan: Option<PathBuf>,

        /// Print what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,

        /// Required for real mutations. Without this, apply refuses to change the system.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DecisionArg {
    Keep,
    Ignore,
    Snooze,
}

impl From<DecisionArg> for DecisionKind {
    fn from(value: DecisionArg) -> Self {
        match value {
            DecisionArg::Keep => DecisionKind::Keep,
            DecisionArg::Ignore => DecisionKind::Ignore,
            DecisionArg::Snooze => DecisionKind::Snooze,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { markdown, json } => {
            let report = if json {
                scan()
            } else {
                scan_with_cli_progress("Scanning this Mac")
            };

            if let Some(path) = markdown {
                let rendered = render_markdown(&report);
                fs::write(&path, rendered).with_context(|| {
                    format!("failed to write Markdown report to {}", path.display())
                })?;
                eprintln!("Wrote {}", path.display());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_summary(&report);
            }
        }
        Commands::Snapshot { output } => {
            let report = scan_with_cli_progress("Capturing evidence snapshot");
            save_snapshot(&output, &report)?;
            println!("Wrote {}", output.display());
        }
        Commands::Diff {
            before,
            after,
            json,
        } => {
            let before = load_snapshot(&before)?;
            let after = if let Some(path) = after {
                load_snapshot(&path)?
            } else if json {
                scan()
            } else {
                scan_with_cli_progress("Scanning for snapshot diff")
            };
            let diff = diff_reports(&before, &after);
            if json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                print_diff(&diff);
            }
        }
        Commands::Verify {
            baseline,
            findings,
            json,
            strict,
        } => {
            let before = load_snapshot(&baseline)?;
            let after = if json {
                scan()
            } else {
                scan_with_cli_progress("Verifying current state")
            };
            let verification = verify_reports(&before, &after, &findings);
            if json {
                println!("{}", serde_json::to_string_pretty(&verification)?);
            } else {
                print_verification(&verification);
            }
            if strict && !verification.passed {
                anyhow::bail!(
                    "verification incomplete: {} remaining, {} unknown, {} inconclusive, {} collector error(s)",
                    verification.remaining.len(),
                    verification.unknown_targets.len(),
                    verification.inconclusive_targets.len(),
                    verification.inconclusive_errors.len()
                );
            }
        }
        Commands::Graph { json } => {
            let report = if json {
                scan()
            } else {
                scan_with_cli_progress("Building correlation graph")
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report.correlations)?);
            } else {
                print_correlation_graph(&report.correlations);
            }
        }
        Commands::Decide {
            finding_id,
            decision,
            reason,
            days,
        } => {
            let record = record_decision(finding_id, decision.into(), reason, Some(days))?;
            println!("Recorded {:?} for {}", record.decision, record.finding_id);
        }
        Commands::Undecide { finding_id } => {
            if clear_decision(&finding_id)? {
                println!("Removed decision for {finding_id}");
            } else {
                println!("No decision recorded for {finding_id}");
            }
        }
        Commands::Decisions { json } => {
            let decisions = load_decisions()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&decisions)?);
            } else if decisions.is_empty() {
                println!("No recorded decisions.");
            } else {
                for decision in decisions {
                    println!(
                        "{:?}\t{}\t{}",
                        decision.decision,
                        decision.finding_id,
                        decision.reason.as_deref().unwrap_or("")
                    );
                }
            }
        }
        Commands::Plan { markdown, json } => {
            let report = if json {
                scan()
            } else {
                scan_with_cli_progress("Scanning for action plan")
            };
            let plan = generate_action_plan(&report);

            if let Some(path) = markdown {
                let rendered = render_action_plan_markdown(&plan);
                fs::write(&path, rendered).with_context(|| {
                    format!("failed to write Markdown action plan to {}", path.display())
                })?;
                eprintln!("Wrote {}", path.display());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print_action_plan(&plan);
            }
        }
        Commands::Explain { target } => {
            let report = scan_with_cli_progress("Scanning before explanation");
            let plan = generate_action_plan(&report);
            print_explanation(&target, &report, &plan);
        }
        Commands::Brief {
            markdown,
            for_llm,
            full,
        } => {
            let report = scan_with_cli_progress("Scanning for handoff brief");
            let plan = generate_action_plan(&report);
            let rendered = render_brief(&report, &plan, for_llm, full);

            if let Some(path) = markdown {
                fs::write(&path, rendered).with_context(|| {
                    format!("failed to write handoff brief to {}", path.display())
                })?;
                eprintln!("Wrote {}", path.display());
            } else {
                println!("{rendered}");
            }
        }
        Commands::Guide {
            apply,
            brief,
            no_prompt,
        } => {
            run_guide(GuideOptions {
                apply,
                brief_path: brief,
                no_prompt,
            })?;
        }
        Commands::Apply { plan, dry_run, yes } => {
            let plan = load_or_generate_plan(plan.as_deref())?;
            if dry_run {
                dry_run_action_plan(&plan)?;
            } else {
                apply_action_plan(&plan, yes)?;
            }
        }
    }

    Ok(())
}
