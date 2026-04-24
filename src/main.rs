use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use macroscope::{
    apply::{apply_action_plan, dry_run_action_plan, load_or_generate_plan},
    markdown::render_markdown,
    output::{print_explanation, print_summary},
    plan::{generate_action_plan, print_action_plan, render_action_plan_markdown},
    scan::{scan, scan_with_cli_progress},
    tui::run_tui,
};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "macroscope")]
#[command(about = "Audit your macOS developer environment", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan this Mac and print a pretty developer-environment audit.
    Scan {
        /// Write a Markdown report to this path.
        #[arg(long)]
        markdown: Option<PathBuf>,

        /// Emit JSON instead of the pretty text summary.
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

    /// Open an interactive terminal dashboard.
    Tui {
        /// Enable guarded apply controls in the TUI. Plain `tui` remains read-only.
        #[arg(long)]
        apply: bool,
    },
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
        Commands::Apply { plan, dry_run, yes } => {
            let plan = load_or_generate_plan(plan.as_deref())?;
            if dry_run {
                dry_run_action_plan(&plan);
            } else {
                apply_action_plan(&plan, yes)?;
            }
        }
        Commands::Tui { apply } => {
            run_tui(apply)?;
        }
    }

    Ok(())
}
